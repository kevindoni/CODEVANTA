"""Live-bridges lane tests: canned transcripts and fake runners, all offline.

No frida/lldb/rizin binary or Python module is ever required: the parsers are
fed byte-for-byte canned transcripts, the live wrappers run against injected
fakes of ``subprocess.run`` (the ``Runner`` protocol) and of the frida module,
and the CLI/MCP layers run through stubbed lane functions.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis import frida_bridge, lldb_bridge, rizin_bridge
from codevanta.analysis.frida_bridge import (
    FridaDevice,
    FridaDevicesResult,
    FridaMessage,
    FridaScriptResult,
    FridaSession,
    frida_available,
    frida_status,
    list_devices,
    list_processes,
    parse_devices,
    parse_processes,
    parse_script_output,
    start_session,
)
from codevanta.analysis.lldb_bridge import (
    lldb_available,
    parse_lldb_transcript,
    run_under_lldb,
)
from codevanta.analysis.rizin_bridge import (
    functions_of,
    info_of,
    parse_afl,
    parse_ii,
    rizin_available,
)
from codevanta.cli import live as live_cli
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_live
from codevanta.mcp_server.server import build_server

runner_cli = CliRunner()


@dataclass
class FakeOutcome:
    """``subprocess.CompletedProcess``-shape with plain text streams."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class FakeRunner:
    """Stand-in for ``subprocess.run``; records commands, returns one script."""

    outcome: FakeOutcome | None = None
    error: Exception | None = None
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(self, command: Any, **_kwargs: Any) -> FakeOutcome:
        self.commands.append(tuple(command))
        if self.error is not None:
            raise self.error
        assert self.outcome is not None, "FakeRunner needs outcome or error"
        return self.outcome


@dataclass
class BadOutcome:
    """Violates the injection contract: ``returncode`` is not an ``int``."""

    returncode: Any = "zero"
    stdout: Any = ""
    stderr: Any = ""


DEVICES_TRANSCRIPT = (
    "id                 type   name            os\n"
    "-----------------  -----  --------------  -------------\n"
    "1ae740a            usb    Nexus 5         Android 6.0\n"
    "local              local  Local System    Kali GNU/Linux Rolling\n"
    "emulator-5554      socket  Emulator        Android 9\n"
)

PROCESSES_TRANSCRIPT = (
    " PID  Name\n"
    "----  ------------------------------\n"
    "4280  Spotify\n"
    " 512  Settings\n"
    "4280  Spotify  com.spotify.music\n"
)

SCRIPT_TRANSCRIPT = (
    '[Pixel 4::hook]-> {"type":"send","payload":"entered main"}\n'
    "\n"
    '[Pixel 4::hook]-> {"type":"error","description":"boom"}\n'
    "console line about something\n"
)

LLDB_STOP_TRANSCRIPT = (
    '(lldb) target create "demo"\n'
    "Current executable set to 'demo' (x86_64).\n"
    "(lldb) breakpoint set --name main\n"
    "Breakpoint 1: where = demo`main, address = demo[0x0000000000401000]\n"
    "(lldb) run\n"
    "Process 1234 stopped\n"
    "* thread #1, name = 'demo', stop reason = breakpoint 1.1\n"
    "    frame #0: 0x0000000000401000 demo`main\n"
    "    frame #1: 0x00007ffff7a2d090 libc.so.6`__libc_start_main + 0x76\n"
    "(lldb) register read\n"
    "General Purpose Registers:\n"
    "       rax = 0x0000000000000001\n"
    "       rsp = 0x00007fffffffe000\n"
    "       rip = 0x0000000000401000\n"
    "(lldb) bt\n"
    "* frame #0: 0x0000000000401000 demo`main\n"
    "  frame #1: 0x00007ffff7a2d090 libc.so.6`__libc_start_main + 0x76\n"
    "(lldb) quit\n"
    "quitting demo\n"
)

LLDB_EXIT_TRANSCRIPT = "Process 1234 exited with status = 0\n"

AFL_TRANSCRIPT = (
    "0x00001060    1     33 0x00001060   1  33 entry0\n"
    "0x00001100    2     57 0x00001100   2  57 main\n"
    "0x00001140    1     21 0x00001140   1  21 sym.imp.exit\n"
    "not-a-rizin-line\n"
)

II_TRANSCRIPT = (
    "arch     x86\n"
    "bits     64\n"
    "format   ELF64\n"
    "os       linux\n"
    "arch     arm\n"
    "singlewordjunk\n"
)


def _json_output(result: Any) -> dict[str, Any]:
    """Parse the JSON payload a ``--json`` CLI invocation printed."""
    return json.loads(result.output)


# ---------------------------------------------------------------------------
# frida_bridge -- parsers
# ---------------------------------------------------------------------------


def test_parse_devices_reads_the_table() -> None:
    result = parse_devices(DEVICES_TRANSCRIPT)
    assert [device.device_id for device in result.devices] == [
        "1ae740a",
        "local",
        "emulator-5554",
    ]
    assert result.devices[0].kind == "usb"
    assert result.devices[0].name == "Nexus 5"
    assert result.devices[0].os == "Android 6.0"
    assert result.devices[2].os == "Android 9"
    assert result.truncated is False
    assert result.warnings == []
    assert result.evidence.source == "live.frida"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_parse_devices_junk_rows_become_warnings() -> None:
    result = parse_devices("garbage row here\n")
    assert result.devices == ()
    assert result.warnings and "garbage row here" in result.warnings[0]


def test_parse_devices_bounds_the_list() -> None:
    rows = "".join(f"dev{i:02d}  usb  Device {i}  Android\n" for i in range(18))
    result = parse_devices(rows)
    assert len(result.devices) == frida_bridge.MAX_DEVICES
    assert result.truncated is True
    assert any("cap" not in warning and "16" in warning for warning in result.warnings)


def test_parse_devices_rejects_non_string() -> None:
    with pytest.raises(AnalysisError):
        parse_devices(b"bytes")  # type: ignore[arg-type]


def test_parse_processes_reads_pid_name_and_identifier() -> None:
    result = parse_processes(PROCESSES_TRANSCRIPT)
    assert [process.pid for process in result.processes] == [4280, 512, 4280]
    assert result.processes[0].name == "Spotify"
    assert result.processes[0].identifier is None
    assert result.processes[2].identifier == "com.spotify.music"
    assert result.warnings == []
    assert result.evidence.source == "live.frida"


def test_parse_processes_junk_and_bounds() -> None:
    rows = "".join(f"{1000 + i}  proc{i}\n" for i in range(300))
    result = parse_processes(rows)
    assert len(result.processes) == frida_bridge.MAX_PROCESSES
    assert result.truncated is True
    junk = parse_processes("PID-NOT-NUMERIC  name\n")
    assert junk.processes == ()
    assert junk.warnings
    with pytest.raises(AnalysisError):
        parse_processes(None)  # type: ignore[arg-type]


def test_parse_script_output_classifies_lines() -> None:
    batch = parse_script_output(SCRIPT_TRANSCRIPT)
    assert [message.kind for message in batch.messages] == ["send", "error", "log"]
    assert batch.messages[0].payload == "entered main"
    assert batch.messages[2].payload == "console line about something"
    assert batch.truncated is False


def test_parse_script_output_json_payload_with_structure() -> None:
    line = '{"type":"send","payload":{"count": 3}}'
    batch = parse_script_output(line)
    assert batch.messages[0].kind == "send"
    assert json.loads(batch.messages[0].payload) == {"count": 3}


def test_parse_script_output_caps_at_two_hundred() -> None:
    transcript = "\n".join(f'{{"type":"send","payload":"m{i}"}}' for i in range(205))
    batch = parse_script_output(transcript)
    assert len(batch.messages) == frida_bridge.MAX_MESSAGES
    assert batch.truncated is True
    assert any("5 more messages" in warning for warning in batch.warnings)
    with pytest.raises(AnalysisError):
        parse_script_output(42)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# frida_bridge -- availability gates
# ---------------------------------------------------------------------------


def test_frida_gates_are_the_dual_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(frida_bridge, "_which", lambda name: "/usr/bin/frida")
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    assert frida_bridge.frida_cli_available() is True
    assert frida_bridge.frida_module_available() is False
    assert frida_available() is True
    assert frida_status() == {"cli": True, "module": False, "available": True}
    monkeypatch.setattr(frida_bridge, "_which", lambda name: None)
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: object())
    assert frida_bridge.frida_cli_available() is False
    assert frida_bridge.frida_module_available() is True
    assert frida_status() == {"cli": False, "module": True, "available": True}
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    assert frida_available() is False
    assert frida_status()["available"] is False


# ---------------------------------------------------------------------------
# frida_bridge -- CLI probes through the injected runner
# ---------------------------------------------------------------------------


def test_list_devices_runs_the_cli_through_the_runner() -> None:
    fake = FakeRunner(FakeOutcome(0, stdout=DEVICES_TRANSCRIPT))
    result = list_devices(runner=fake)
    assert fake.commands == [("frida-ls-devices",)]
    assert len(result.devices) == 3
    assert result.devices[1].kind == "local"


def test_list_devices_skip_gates_when_the_cli_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(frida_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError) as excinfo:
        list_devices()
    assert "frida-ls-devices" in str(excinfo.value)
    assert "pip install frida-tools" in str(excinfo.value)


def test_list_devices_nonzero_exit_is_typed() -> None:
    fake = FakeRunner(FakeOutcome(3, stderr="frida-server not running"))
    with pytest.raises(AnalysisError) as excinfo:
        list_devices(runner=fake)
    assert "exited with code 3" in str(excinfo.value)
    assert "frida-server" in str(excinfo.value)


def test_list_processes_passes_the_device_flag() -> None:
    fake = FakeRunner(FakeOutcome(0, stdout=PROCESSES_TRANSCRIPT))
    result = list_processes("1ae740a", runner=fake)
    assert fake.commands == [("frida-ps", "-D", "1ae740a")]
    assert len(result.processes) == 3
    plain = FakeRunner(FakeOutcome(0, stdout=PROCESSES_TRANSCRIPT))
    list_processes(runner=plain)
    assert plain.commands == [("frida-ps",)]
    with pytest.raises(AnalysisError):
        list_processes("bad device id!")


# ---------------------------------------------------------------------------
# frida_bridge -- the one-shot CLI session fallback
# ---------------------------------------------------------------------------


def _script_file(tmp_path: Path, body: str = "send('hi');\n") -> Path:
    path = tmp_path / "hook.js"
    path.write_text(body, encoding="utf-8")
    return path


def test_start_session_cli_fallback_captures_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    script = _script_file(tmp_path)
    fake = FakeRunner(FakeOutcome(0, stdout=SCRIPT_TRANSCRIPT))
    handle = start_session(4280, script_path=script, duration=5, runner=fake)
    assert handle.one_shot is True
    assert handle.messages[0] == FridaMessage(kind="send", payload="entered main")
    assert handle.messages[2].kind == "log"
    assert handle.closed is False
    assert handle.to_dict()["result"]["timeout_reached"] is False
    command = fake.commands[0]
    assert command[:2] == ("frida", "-l")
    assert str(script) in command
    assert command[-1] == "4280"


def test_start_session_cli_spawn_mode_and_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    script = _script_file(tmp_path)
    fake = FakeRunner(FakeOutcome(0, stdout=""))
    handle = start_session(
        "com.example.app",
        frida_bridge.MODE_SPAWN,
        device_id="1ae740a",
        script_path=script,
        duration=5,
        runner=fake,
    )
    command = fake.commands[0]
    assert command[:4] == ("frida", "-D", "1ae740a", "-f")
    assert handle.to_dict()["mode"] == "spawn"


def test_start_session_cli_timeout_is_the_duration_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    script = _script_file(tmp_path)
    expired = subprocess.TimeoutExpired(cmd="frida", timeout=5, output=SCRIPT_TRANSCRIPT)
    fake = FakeRunner(error=expired)
    handle = start_session(4280, script_path=script, duration=5, runner=fake)
    record = handle.result
    assert record is not None and record.timeout_reached is True
    assert record.messages[0].kind == "send"
    assert handle.to_dict()["result"]["timeout_reached"] is True


def test_start_session_cli_nonzero_exit_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    script = _script_file(tmp_path)
    fake = FakeRunner(FakeOutcome(1, stderr="Failed to attach: no such process"))
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, script_path=script, duration=5, runner=fake)
    assert "exited with code 1" in str(excinfo.value)
    assert "Failed to attach" in str(excinfo.value)


def test_start_session_cli_requires_a_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, runner=FakeRunner(FakeOutcome(0)))
    assert "pass script_path" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, script_path=tmp_path / "missing.js", duration=5, runner=FakeRunner())
    assert "script file not found" in str(excinfo.value)
    big = tmp_path / "big.js"
    big.write_text("x" * (frida_bridge.MAX_SCRIPT_BYTES + 1), encoding="utf-8")
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, script_path=big, duration=5, runner=FakeRunner())
    assert "64 KiB" in str(excinfo.value)


def test_start_session_duration_and_target_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    with pytest.raises(AnalysisError):
        start_session(4280, duration=0)  # checked before any process work
    with pytest.raises(AnalysisError):
        start_session(4280, duration=61)
    with pytest.raises(AnalysisError):
        start_session(0)
    with pytest.raises(AnalysisError):
        start_session("bad name!", script_path="x")
    with pytest.raises(AnalysisError):
        start_session(4280, "trace")


def test_start_session_unavailable_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    monkeypatch.setattr(frida_bridge, "_which", lambda name: None)
    script = _script_file(tmp_path)
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, script_path=script, duration=5)
    assert excinfo.value.args[0] == frida_bridge.FRIDA_SESSION_MISSING_MESSAGE


def test_one_shot_handle_lifecycle_is_typed(tmp_path: Path) -> None:
    handle = FridaSession(
        target=4280,
        mode=frida_bridge.MODE_ATTACH,
        device_id=None,
        result=FridaScriptResult(
            target="4280",
            mode=frida_bridge.MODE_ATTACH,
            device_id=None,
            script_path="hook.js",
            duration=5.0,
            messages=(),
            truncated=False,
            timeout_reached=False,
        ),
    )
    with pytest.raises(AnalysisError) as excinfo:
        handle.load_script(tmp_path / "hook.js")
    assert "one-shot" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        handle.resume()
    assert "one-shot" in str(excinfo.value)
    handle.close()
    assert handle.closed is True


# ---------------------------------------------------------------------------
# frida_bridge -- module-backed session (fake frida module)
# ---------------------------------------------------------------------------


class FakeScript:
    """``frida.core.Script``-shape: records the handler, emits on load."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.loaded = False
        self.unloaded = False

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback

    def load(self) -> None:
        self.loaded = True
        handler = self.handlers.get("message")
        if handler is not None:
            handler({"type": "send", "payload": "loaded"}, None)
            handler({"type": "log", "level": "info", "payload": "console"}, None)

    def unload(self) -> None:
        self.unloaded = True


class FakeModuleSession:
    """``frida.core.Session``-shape: create_script + detach."""

    def __init__(self) -> None:
        self.sources: list[str] = []
        self.scripts: list[FakeScript] = []
        self.detached = False

    def create_script(self, source: str) -> FakeScript:
        self.sources.append(source)
        script = FakeScript()
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        self.detached = True


class FakeDevice:
    """``frida.core.Device``-shape: attach/spawn/resume records."""

    def __init__(self) -> None:
        self.session = FakeModuleSession()
        self.attached: list[Any] = []
        self.spawned: list[list[str]] = []
        self.resumed: list[int] = []
        self.fail_attach = False

    def attach(self, target: Any) -> FakeModuleSession:
        if self.fail_attach:
            raise RuntimeError("process not found")
        self.attached.append(target)
        return self.session

    def spawn(self, programs: list[str]) -> int:
        self.spawned.append(programs)
        return 4242

    def resume(self, pid: int) -> None:
        self.resumed.append(pid)


class FakeFridaModule:
    """``frida`` module-shape used by start_session(module=...)."""

    def __init__(self) -> None:
        self.device = FakeDevice()
        self.requested_device: str | None = None
        self.fail_device = False

    def get_local_device(self) -> FakeDevice:
        if self.fail_device:
            raise RuntimeError("no frida-server")
        return self.device

    def get_device(self, device_id: str) -> FakeDevice:
        self.requested_device = device_id
        return self.get_local_device()


def test_start_session_module_attach_loads_scripts(tmp_path: Path) -> None:
    fake = FakeFridaModule()
    script = _script_file(tmp_path)
    handle = start_session(4280, module=fake)
    assert handle.one_shot is False
    assert fake.device.attached == [4280]
    count = handle.load_script(script)
    assert count == 2
    assert fake.device.session.sources == ["send('hi');\n"]
    assert fake.device.session.scripts[0].loaded is True
    assert handle.messages[0] == FridaMessage(kind="send", payload="loaded")
    assert handle.resumed is False
    handle.resume()  # attach mode: marks resumed without device.resume
    assert fake.device.resumed == []
    handle.close()
    assert fake.device.session.detached is True
    assert fake.device.session.scripts[0].unloaded is True
    assert handle.closed is True


def test_start_session_module_spawn_resumes_once(tmp_path: Path) -> None:
    fake = FakeFridaModule()
    handle = start_session(
        "com.example.app",
        frida_bridge.MODE_SPAWN,
        device_id="1ae740a",
        module=fake,
    )
    assert fake.requested_device == "1ae740a"
    assert fake.device.spawned == [["com.example.app"]]
    assert fake.device.attached == [4242]
    handle.resume()
    handle.resume()  # idempotent at the device level
    assert fake.device.resumed == [4242]


def test_start_session_module_lifecycle_guards(tmp_path: Path) -> None:
    fake = FakeFridaModule()
    handle = start_session(4280, module=fake)
    handle.close()
    with pytest.raises(AnalysisError) as excinfo:
        handle.load_script(_script_file(tmp_path))
    assert "already closed" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        handle.resume()
    assert "cannot resume" in str(excinfo.value)
    handle.close()  # idempotent
    assert handle.closed is True


def test_start_session_module_script_bounds(tmp_path: Path) -> None:
    fake = FakeFridaModule()
    handle = start_session(4280, module=fake)
    with pytest.raises(AnalysisError):
        handle.load_script(tmp_path / "missing.js")
    big = tmp_path / "big.js"
    big.write_text("x" * (frida_bridge.MAX_SCRIPT_BYTES + 1), encoding="utf-8")
    with pytest.raises(AnalysisError):
        handle.load_script(big)


def test_start_session_module_errors_are_typed() -> None:
    failing_device = FakeFridaModule()
    failing_device.fail_device = True
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, module=failing_device)
    assert "frida refused to open device local" in str(excinfo.value)
    failing_attach = FakeFridaModule()
    failing_attach.device.fail_attach = True
    with pytest.raises(AnalysisError) as excinfo:
        start_session(4280, module=failing_attach)
    assert "frida refused to attach" in str(excinfo.value)


def test_start_session_run_for_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeFridaModule()
    handle = start_session(4280, module=fake)
    monkeypatch.setattr(frida_bridge.time, "sleep", lambda seconds: None)
    assert handle.run_for(1) == 0
    with pytest.raises(AnalysisError):
        handle.run_for(0)
    handle.close()
    with pytest.raises(AnalysisError):
        handle.run_for(1)


def test_session_message_collector_is_bounded() -> None:
    fake = FakeFridaModule()
    handle = start_session(4280, module=fake)
    for i in range(frida_bridge.MAX_MESSAGES + 5):
        handle._on_message({"type": "send", "payload": i}, None)
    assert len(handle.messages) == frida_bridge.MAX_MESSAGES
    assert handle.dropped_messages == 5
    handle._on_message({"payload": 1}, None)  # untyped payload -> log kind
    handle._on_message("not a dict", None)  # tolerated, rendered as a log line
    assert len(handle.messages) == frida_bridge.MAX_MESSAGES
    assert handle.dropped_messages == 7


def test_session_context_manager_closes_on_exit() -> None:
    fake = FakeFridaModule()
    with start_session(4280, module=fake) as handle:
        assert handle.closed is False
    assert handle.closed is True
    assert fake.device.session.detached is True


# ---------------------------------------------------------------------------
# lldb_bridge -- parser (canned transcripts)
# ---------------------------------------------------------------------------


def test_parse_lldb_transcript_reads_stop_registers_and_frames() -> None:
    result = parse_lldb_transcript(LLDB_STOP_TRANSCRIPT)
    assert result.stopped_reason == "breakpoint 1.1"
    assert result.registers == {
        "rax": "0x0000000000000001",
        "rsp": "0x00007fffffffe000",
        "rip": "0x0000000000401000",
    }
    assert len(result.frames) == 2  # stop report + bt dedupe to the same two rows
    assert result.frames[0].index == 0
    assert result.frames[0].address == "0x0000000000401000"
    assert result.frames[0].module == "demo"
    assert result.frames[0].symbol == "main"
    assert result.frames[0].current is True
    assert result.frames[1].symbol == "__libc_start_main"
    assert result.frames[1].current is False
    assert result.warnings == []
    assert result.evidence.source == "live.lldb"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_parse_lldb_transcript_recognises_a_clean_exit() -> None:
    result = parse_lldb_transcript(LLDB_EXIT_TRANSCRIPT)
    assert result.stopped_reason == "exited with status = 0"
    assert result.frames == ()


def test_parse_lldb_transcript_warns_when_nothing_stopped() -> None:
    result = parse_lldb_transcript("(lldb) quit\n")
    assert result.stopped_reason is None
    assert any("no stop reason" in warning for warning in result.warnings)


def test_parse_lldb_transcript_bounds_and_rejects() -> None:
    frame_lines = "".join(
        f"  frame #{i}: 0x00000000004{i:05x} demo`func{i}\n" for i in range(40)
    )
    result = parse_lldb_transcript(frame_lines)
    assert len(result.frames) == lldb_bridge.MAX_FRAMES
    assert result.truncated_frames is True
    assert any("32 frames" in warning for warning in result.warnings)
    register_lines = "\n".join(
        f"       r{i} = 0x000000000000000{i % 10}" for i in range(70)
    )
    result = parse_lldb_transcript(register_lines)
    assert len(result.registers) == lldb_bridge.MAX_REGISTERS
    assert any("64 registers" in warning for warning in result.warnings)
    tail = parse_lldb_transcript("\n".join(f"line {i}" for i in range(250)))
    assert len(tail.raw_tail) == lldb_bridge.MAX_TAIL_LINES
    assert tail.raw_tail[-1] == "line 249"
    with pytest.raises(AnalysisError):
        parse_lldb_transcript(3.14)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# lldb_bridge -- batch wrapper through the injected runner
# ---------------------------------------------------------------------------


def test_lldb_available_follows_the_path_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lldb_bridge.shutil, "which", lambda name: "/usr/bin/lldb")
    assert lldb_available() is True
    monkeypatch.setattr(lldb_bridge.shutil, "which", lambda name: None)
    assert lldb_available() is False


def test_run_under_lldb_builds_the_batch_and_parses(tmp_path: Path) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    fake = FakeRunner(FakeOutcome(0, stdout=LLDB_STOP_TRANSCRIPT))
    result = run_under_lldb(target, break_at="main", runner=fake)
    argv = fake.commands[0]
    assert argv[:4] == ("lldb", "-b", "-o", f'target create "{target}"')
    assert "breakpoint set --name main" in argv
    assert "run" in argv and "register read" in argv and "bt" in argv
    assert argv[-2:] == ("-o", "quit")
    assert result.stopped_reason == "breakpoint 1.1"
    assert result.command == argv
    assert result.warnings == []


def test_run_under_lldb_break_address_and_extra_commands(tmp_path: Path) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    fake = FakeRunner(FakeOutcome(0, stdout=LLDB_EXIT_TRANSCRIPT))
    result = run_under_lldb(
        target,
        break_at="0x401000",
        commands=("settings set target.x86-disassembly-flavor intel",),
        runner=fake,
    )
    argv = fake.commands[0]
    assert "breakpoint set --address 0x401000" in argv
    assert "settings set target.x86-disassembly-flavor intel" in argv
    assert argv.index("settings set target.x86-disassembly-flavor intel") < argv.index("quit")
    assert result.stopped_reason == "exited with status = 0"


def test_run_under_lldb_input_validation(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        run_under_lldb(123)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(tmp_path / "missing.exe")
    assert "target binary not found" in str(excinfo.value)
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    with pytest.raises(AnalysisError):
        run_under_lldb(target, timeout_s=0)
    with pytest.raises(AnalysisError):
        run_under_lldb(target, timeout_s=121)
    with pytest.raises(AnalysisError):
        run_under_lldb(target, commands="not a list")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        run_under_lldb(target, commands=("ok", ""))
    with pytest.raises(AnalysisError):
        run_under_lldb(target, commands=("ok", 5))  # type: ignore
    with pytest.raises(AnalysisError):
        run_under_lldb(target, commands=tuple(f"c{i}" for i in range(40)))
    with pytest.raises(AnalysisError):
        run_under_lldb(target, break_at="   ")
    with pytest.raises(AnalysisError):
        run_under_lldb(target, break_at="0xnothex")
    with pytest.raises(AnalysisError):
        run_under_lldb(target, break_at="0x0")
    with pytest.raises(AnalysisError):
        run_under_lldb(target, break_at=7)  # type: ignore[arg-type]


def test_run_under_lldb_skip_gates_and_runtime_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    monkeypatch.setattr(lldb_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(target)
    assert excinfo.value.args[0] == lldb_bridge.LLDB_MISSING_MESSAGE
    expired = subprocess.TimeoutExpired(cmd="lldb", timeout=30, output="partial")
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(target, timeout_s=30, runner=FakeRunner(error=expired))
    assert "exceeded its timeout of 30" in str(excinfo.value)
    missing = FakeRunner(error=FileNotFoundError("lldb"))
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(target, runner=missing)
    assert "vanished between the PATH probe" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(target, runner=FakeRunner(BadOutcome()))  # type: ignore[arg-type]
    assert "injection contract" in str(excinfo.value)


def test_run_under_lldb_nonzero_exit_is_typed_or_warned(tmp_path: Path) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    silent = FakeRunner(FakeOutcome(1, stdout="(lldb) quit\n", stderr="error: no symbols"))
    with pytest.raises(AnalysisError) as excinfo:
        run_under_lldb(target, runner=silent)
    assert "without a stop report" in str(excinfo.value)
    assert "no symbols" in str(excinfo.value)
    noisy = FakeRunner(FakeOutcome(1, stdout=LLDB_STOP_TRANSCRIPT))
    result = run_under_lldb(target, runner=noisy)
    assert result.stopped_reason == "breakpoint 1.1"
    assert any("exited with code 1" in warning for warning in result.warnings)


# ---------------------------------------------------------------------------
# rizin_bridge -- parsers and wrappers
# ---------------------------------------------------------------------------


def test_parse_afl_reads_functions_and_warns_on_junk() -> None:
    result = parse_afl(AFL_TRANSCRIPT)
    assert [function.name for function in result.functions] == [
        "entry0",
        "main",
        "sym.imp.exit",
    ]
    assert result.functions[0].address == 0x1060
    assert result.functions[0].size == 33
    assert result.warnings and "not-a-rizin-line" in result.warnings[0]
    assert result.evidence.source == "live.rizin"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()
    no_size = parse_afl("0x40 0x40 main\n")
    assert no_size.functions[0].size is None


def test_parse_afl_bounds_and_rejects() -> None:
    rows = "".join(f"0x{0x1000 + i:08x}    1     10 0  1  10 f{i}\n" for i in range(300))
    result = parse_afl(rows)
    assert len(result.functions) == rizin_bridge.MAX_FUNCTIONS
    assert result.truncated is True
    with pytest.raises(AnalysisError):
        parse_afl(None)  # type: ignore[arg-type]


def test_parse_ii_reads_fields_and_warns() -> None:
    result = parse_ii(II_TRANSCRIPT)
    assert result.fields["arch"] == "x86"  # first occurrence wins
    assert result.fields["bits"] == "64"
    assert result.fields["os"] == "linux"
    assert any("duplicate iI key: arch" in warning for warning in result.warnings)
    assert any("singlewordjunk" in warning for warning in result.warnings)
    assert result.evidence.source == "live.rizin"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()
    with pytest.raises(AnalysisError):
        parse_ii([])  # type: ignore[arg-type]


def test_parse_ii_bounds_the_field_count() -> None:
    rows = "\n".join(f"key{i}     value{i}" for i in range(80))
    result = parse_ii(rows)
    assert len(result.fields) == rizin_bridge.MAX_INFO_FIELDS
    assert any("64 fields" in warning for warning in result.warnings)


def test_rizin_available_follows_the_path_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rizin_bridge.shutil, "which", lambda name: "/usr/bin/rizin")
    assert rizin_available() is True
    monkeypatch.setattr(rizin_bridge.shutil, "which", lambda name: None)
    assert rizin_available() is False


def test_functions_of_runs_the_batch_through_the_runner(tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 8)
    fake = FakeRunner(FakeOutcome(0, stdout=AFL_TRANSCRIPT))
    result = functions_of(target, runner=fake)
    assert fake.commands == [("rizin", "-q", "-c", "aaa; afl", str(target))]
    assert len(result.functions) == 3


def test_info_of_runs_the_batch_through_the_runner(tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 8)
    fake = FakeRunner(FakeOutcome(0, stdout=II_TRANSCRIPT))
    result = info_of(target, runner=fake)
    assert fake.commands == [("rizin", "-q", "-c", "iI", str(target))]
    assert result.fields["format"] == "ELF64"


def test_rizin_wrappers_validate_and_skip_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(missing)
    assert "file not found" in str(excinfo.value)
    with pytest.raises(AnalysisError):
        info_of(123)  # type: ignore[arg-type]
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 8)
    with pytest.raises(AnalysisError):
        functions_of(target, timeout=0)
    with pytest.raises(AnalysisError):
        info_of(target, timeout=121)
    monkeypatch.setattr(rizin_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(target)
    assert excinfo.value.args[0] == rizin_bridge.RIZIN_MISSING_MESSAGE
    with pytest.raises(AnalysisError):
        info_of(target)
    expired = subprocess.TimeoutExpired(cmd="rizin", timeout=30, output="")
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(target, timeout=30, runner=FakeRunner(error=expired))
    assert "exceeded its timeout of 30" in str(excinfo.value)


def test_rizin_wrappers_surface_runner_failures(tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 8)
    failed = FakeRunner(FakeOutcome(1, stderr="cannot open file"))
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(target, runner=failed)
    assert "exited with code 1" in str(excinfo.value)
    assert "cannot open file" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        info_of(target, runner=FakeRunner(BadOutcome()))  # type: ignore[arg-type]
    assert "injection contract" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(target, timeout=0, runner=FakeRunner(FakeOutcome(0)))
    assert "timeout must be a positive" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        info_of(target, timeout=121, runner=FakeRunner(FakeOutcome(0)))
    assert "out of range" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(target, runner=FakeRunner(error=FileNotFoundError("gone")))
    assert "vanished between the PATH probe" in str(excinfo.value)
    bytesy = FakeRunner(FakeOutcome(0, stdout=AFL_TRANSCRIPT.encode("utf-8")))
    assert len(functions_of(target, runner=bytesy).functions) == 3
    blank = parse_afl("\n\n" + AFL_TRANSCRIPT)
    assert len(blank.functions) == 3
    blank_ii = parse_ii("\n\n" + II_TRANSCRIPT)
    assert blank_ii.fields["bits"] == "64"
    with pytest.raises(AnalysisError) as excinfo:
        functions_of(5)  # type: ignore[arg-type]
    assert "path must be a str or Path" in str(excinfo.value)


def test_rizin_note_cap_and_size_fallback() -> None:
    junk = "\n".join(f"junkrow{i}" for i in range(40))
    result = parse_afl(junk)
    assert result.functions == ()
    assert len(result.warnings) == rizin_bridge.MAX_WARNINGS + 1
    assert result.warnings[-1].endswith("...")
    odd = parse_afl("0x40 notasize main\n")
    assert odd.functions[0].size is None
    assert odd.functions[0].name == "main"


# ---------------------------------------------------------------------------
# CLI -- codevanta frida / lldb / rizin through stubbed lane functions
# ---------------------------------------------------------------------------


def _canned_devices() -> FridaDevicesResult:
    return FridaDevicesResult(
        devices=(
            FridaDevice(device_id="1ae740a", kind="usb", name="Nexus 5", os="Android 6.0"),
            FridaDevice(device_id="local", kind="local", name="Local System"),
        ),
        truncated=False,
    )


def test_cli_frida_devices_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live_cli, "list_devices", lambda: _canned_devices())
    result = runner_cli.invoke(live_cli.frida_app, ["devices", "--json"])
    assert result.exit_code == 0, result.output
    payload = _json_output(result)
    assert payload["count"] == 2
    assert payload["evidence"]["source"] == "live.frida"


def test_cli_frida_devices_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live_cli, "list_devices", lambda: _canned_devices())
    result = runner_cli.invoke(live_cli.frida_app, ["devices"])
    assert result.exit_code == 0, result.output
    assert "frida devices" in result.output
    assert "Nexus 5" in result.output
    assert "evidence: live.frida" in result.output


def test_cli_frida_devices_maps_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> FridaDevicesResult:
        raise AnalysisError("frida-ls-devices is not on PATH")

    monkeypatch.setattr(live_cli, "list_devices", boom)
    result = runner_cli.invoke(live_cli.frida_app, ["devices"])
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_frida_ps_passes_the_device(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_ps(device_id: str | None = None) -> Any:
        seen["device_id"] = device_id
        return frida_bridge.FridaProcessesResult(
            processes=(frida_bridge.FridaProcess(pid=4280, name="Spotify"),),
            truncated=False,
        )

    monkeypatch.setattr(live_cli, "list_processes", fake_ps)
    result = runner_cli.invoke(live_cli.frida_app, ["ps", "--device", "1ae740a"])
    assert result.exit_code == 0, result.output
    assert seen["device_id"] == "1ae740a"
    assert "4280" in result.output


def test_cli_frida_script_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "hook.js"
    script.write_text("send('hi');\n", encoding="utf-8")
    seen: dict[str, Any] = {}

    def fake_session(pid: int, mode: str, **kwargs: Any) -> FridaSession:
        seen["pid"] = pid
        seen["mode"] = mode
        seen.update(kwargs)
        return FridaSession(
            target=pid,
            mode=mode,
            device_id=None,
            result=FridaScriptResult(
                target=str(pid),
                mode=mode,
                device_id=None,
                script_path=str(script),
                duration=5.0,
                messages=(FridaMessage(kind="send", payload="hi"),),
                truncated=False,
                timeout_reached=True,
            ),
        )

    monkeypatch.setattr(live_cli, "start_session", fake_session)
    result = runner_cli.invoke(
        live_cli.frida_app, ["script", "4280", str(script), "--duration", "5", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = _json_output(result)
    assert seen["pid"] == 4280
    assert seen["mode"] == "attach"
    assert payload["result"]["message_count"] == 1
    assert payload["result"]["timeout_reached"] is True


def test_cli_frida_script_missing_file_exits_two(tmp_path: Path) -> None:
    result = runner_cli.invoke(live_cli.frida_app, ["script", "1", str(tmp_path / "x.js")])
    assert result.exit_code == 2
    assert "script file not found" in result.output


def test_cli_lldb_run_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    seen: dict[str, Any] = {}

    def fake_run(target: Any, break_at: Any = None, timeout_s: Any = None, **_kw: Any) -> Any:
        seen["target"] = target
        seen["break_at"] = break_at
        seen["timeout_s"] = timeout_s
        return parse_lldb_transcript(LLDB_STOP_TRANSCRIPT)

    monkeypatch.setattr(live_cli, "run_under_lldb", fake_run)
    result = runner_cli.invoke(
        live_cli.lldb_app, ["run", str(target), "--break", "main", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = _json_output(result)
    assert seen["break_at"] == "main"
    assert payload["stopped_reason"] == "breakpoint 1.1"
    assert payload["evidence"]["source"] == "live.lldb"


def test_cli_lldb_run_maps_typed_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*_args: Any, **_kw: Any) -> Any:
        raise AnalysisError("lldb is not on PATH; install the LLVM toolchain")

    monkeypatch.setattr(live_cli, "run_under_lldb", boom)
    result = runner_cli.invoke(live_cli.lldb_app, ["run", str(tmp_path / "x.bin")])
    assert result.exit_code == 2
    assert "install the LLVM toolchain" in result.output


def test_cli_rizin_functions_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 4)
    monkeypatch.setattr(live_cli, "functions_of", lambda path, **kw: parse_afl(AFL_TRANSCRIPT))
    result = runner_cli.invoke(live_cli.rizin_app, ["functions", str(target), "--json"])
    assert result.exit_code == 0, result.output
    payload = _json_output(result)
    assert payload["count"] == 3
    assert payload["functions"][0]["address"] == "0x1060"
    assert payload["evidence"]["source"] == "live.rizin"


def test_cli_rizin_info_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 4)
    monkeypatch.setattr(live_cli, "info_of", lambda path, **kw: parse_ii(II_TRANSCRIPT))
    result = runner_cli.invoke(live_cli.rizin_app, ["info", str(target)])
    assert result.exit_code == 0, result.output
    assert "rizin info" in result.output
    assert "ELF64" in result.output
    assert "evidence: live.rizin" in result.output


def test_cli_live_apps_are_registered() -> None:
    from codevanta.cli.main import app as main_app  # noqa: PLC0415 -- import at use site

    groups = {group.name for group in main_app.registered_groups}
    assert {"frida", "lldb", "rizin"} <= groups


# ---------------------------------------------------------------------------
# MCP -- ext_live functions and the registered server tools
# ---------------------------------------------------------------------------


def test_mcp_frida_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_devices(**_kw: Any) -> Any:
        return _canned_devices()

    monkeypatch.setattr(frida_bridge, "list_devices", fake_devices)
    payload = ext_live.codevanta_frida("devices")
    assert payload["count"] == 2


def test_mcp_frida_ps(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_ps(device_id: str | None = None, **_kw: Any) -> Any:
        seen["device_id"] = device_id
        return frida_bridge.FridaProcessesResult(processes=(), truncated=False)

    monkeypatch.setattr(frida_bridge, "list_processes", fake_ps)
    ext_live.codevanta_frida("ps", device_id="usb-1")
    assert seen["device_id"] == "usb-1"


def test_mcp_frida_script(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "hook.js"
    script.write_text("send(1);\n", encoding="utf-8")
    seen: dict[str, Any] = {}

    def fake_session(pid: Any, mode: Any, **kwargs: Any) -> Any:
        seen["pid"] = pid
        seen["kwargs"] = kwargs
        return FridaSession(
            target=pid,
            mode=mode,
            device_id=None,
            result=FridaScriptResult(
                target=str(pid),
                mode=mode,
                device_id=None,
                script_path=str(script),
                duration=10.0,
                messages=(),
                truncated=False,
                timeout_reached=False,
            ),
        )

    monkeypatch.setattr(frida_bridge, "start_session", fake_session)
    payload = ext_live.codevanta_frida("script", pid=99, script_path=str(script))
    assert seen["pid"] == 99
    assert seen["kwargs"]["duration"] == ext_live.frida_bridge.DEFAULT_DURATION
    assert payload["one_shot"] is True


def test_mcp_frida_rejects_bad_calls() -> None:
    with pytest.raises(AnalysisError):
        ext_live.codevanta_frida("frobnicate")
    with pytest.raises(AnalysisError):
        ext_live.codevanta_frida("script")
    with pytest.raises(AnalysisError):
        ext_live.codevanta_frida("script", pid=4)
    with pytest.raises(AnalysisError):
        ext_live.codevanta_frida("script", pid=4, script_path=None)


def test_mcp_functions_honour_the_runner_seam() -> None:
    outcome = FakeOutcome(0, stdout=DEVICES_TRANSCRIPT)
    payload = ext_live.codevanta_frida("devices", runner=FakeRunner(outcome))
    assert payload["count"] == 3
    ps_outcome = FakeOutcome(0, stdout=PROCESSES_TRANSCRIPT)
    payload = ext_live.codevanta_frida(
        "ps", device_id="usb-1", runner=FakeRunner(ps_outcome)
    )
    assert payload["count"] == 3
    script = Path("hook_live_tmp.js")
    script.write_text("send(1);\n", encoding="utf-8")
    try:
        payload = ext_live.codevanta_frida(
            "script", pid=4280, script_path=str(script), runner=FakeRunner(outcome)
        )
        assert payload["one_shot"] is True
        payload = ext_live.codevanta_lldb_run(
            str(script),
            break_at="main",
            runner=FakeRunner(FakeOutcome(0, stdout=LLDB_STOP_TRANSCRIPT)),
        )
        assert payload["stopped_reason"] == "breakpoint 1.1"
        payload = ext_live.codevanta_rizin_functions(
            str(script), runner=FakeRunner(FakeOutcome(0, stdout=AFL_TRANSCRIPT))
        )
        assert payload["count"] == 3
    finally:
        script.unlink(missing_ok=True)


def test_mcp_lldb_run_and_rizin_functions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(target: Any, break_at: Any = None, timeout_s: Any = None, **_kw: Any) -> Any:
        seen["break_at"] = break_at
        seen["timeout_s"] = timeout_s
        return parse_lldb_transcript(LLDB_STOP_TRANSCRIPT)

    monkeypatch.setattr(lldb_bridge, "run_under_lldb", fake_run)
    payload = ext_live.codevanta_lldb_run("demo.exe", break_at="main", timeout_s=11)
    assert seen == {"break_at": "main", "timeout_s": 11}
    assert payload["stopped_reason"] == "breakpoint 1.1"
    monkeypatch.setattr(rizin_bridge, "functions_of", lambda path, **kw: parse_afl(AFL_TRANSCRIPT))
    payload = ext_live.codevanta_rizin_functions(str(tmp_path / "a.bin"))
    assert payload["count"] == 3


def test_server_registers_the_three_live_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import asyncio

    monkeypatch.setattr(rizin_bridge, "functions_of", lambda path, **kw: parse_afl(AFL_TRANSCRIPT))
    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert {"codevanta_frida", "codevanta_lldb_run", "codevanta_rizin_functions"} <= names
    result = asyncio.run(
        build_server().call_tool(
            "codevanta_rizin_functions", {"path": str(tmp_path / "whatever.bin")}
        )
    )
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        for block in getattr(result, "content", []):
            text = getattr(block, "text", None)
            if text:
                structured = json.loads(text)
                break
    assert structured is not None and structured["count"] == 3


# ---------------------------------------------------------------------------
# branch coverage: bounds, contracts, best-effort shutdown, table rendering
# ---------------------------------------------------------------------------


def test_parse_devices_warn_cap_and_dedupe() -> None:
    junk = "\n".join(f"junkrow{i}" for i in range(40))
    result = parse_devices(junk)
    assert result.devices == ()
    assert len(result.warnings) == frida_bridge.MAX_WARNINGS + 1
    assert result.warnings[-1].endswith("...")
    dedup = parse_devices("junk row\njunk row\n")
    assert dedup.warnings == ["skipping unrecognised frida-ls-devices row: junk row"]
    slim = parse_devices("usb-1  usb  Phone\n")
    assert slim.devices[0].os is None


def test_probe_budgets_are_validated() -> None:
    for bad in (0, -1, 61, "5", True):
        with pytest.raises(AnalysisError):
            list_devices(timeout=bad)  # type: ignore[arg-type]


def test_start_session_target_and_mode_validation_matrix() -> None:
    with pytest.raises(AnalysisError):
        start_session(True)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        start_session(-3)
    with pytest.raises(AnalysisError):
        start_session("x" * 300)
    with pytest.raises(AnalysisError):
        start_session(None)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        start_session(4280, "spawn")
    with pytest.raises(AnalysisError):
        start_session(4280, "sushi")


def test_start_session_device_id_validation() -> None:
    fake = FakeFridaModule()
    assert start_session(1, device_id="usb-1", module=fake) is not None
    assert fake.requested_device == "usb-1"
    with pytest.raises(AnalysisError):
        start_session(1, device_id=5, module=fake)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        start_session(1, device_id="   ", module=fake)
    with pytest.raises(AnalysisError):
        start_session(1, device_id="x" * 200, module=fake)


def test_run_cli_budget_contract_and_stream_decoding() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        list_devices(runner=FakeRunner(BadOutcome()))  # type: ignore[arg-type]
    assert "injection contract" in str(excinfo.value)
    expired = subprocess.TimeoutExpired(cmd="frida-ls-devices", timeout=5, output=b"\xff bytes")
    with pytest.raises(AnalysisError) as excinfo:
        list_devices(timeout=5, runner=FakeRunner(error=expired))
    assert "exceeded its timeout" in str(excinfo.value)
    with pytest.raises(AnalysisError) as excinfo:
        list_devices(runner=FakeRunner(error=FileNotFoundError("gone")))
    assert "vanished between the PATH probe" in str(excinfo.value)
    bytesy = FakeRunner(
        FakeOutcome(0, stdout=DEVICES_TRANSCRIPT.encode("utf-8"), stderr=b"warn")
    )
    result = list_devices(runner=bytesy)
    assert len(result.devices) == 3


def test_session_close_is_best_effort(tmp_path: Path) -> None:
    class RaisingScript(FakeScript):
        def unload(self) -> None:
            raise RuntimeError("unload refused")

    class RaisingSession(FakeModuleSession):
        def detach(self) -> None:
            raise RuntimeError("detach refused")

    class RaisingDevice(FakeDevice):
        def __init__(self) -> None:
            super().__init__()
            self.session = RaisingSession()

    fake = FakeFridaModule()
    fake.device = RaisingDevice()
    handle = start_session(4280, module=fake)
    handle.load_script(_script_file(tmp_path))
    handle.close()  # both unload and detach refuse; still closes cleanly
    assert handle.closed is True


def test_message_payload_rendering_variants() -> None:
    batch = parse_script_output('{"type":"send","payload":{"k": 1}}')
    assert json.loads(batch.messages[0].payload) == {"k": 1}
    batch = parse_script_output('{"type":"send"}')
    assert batch.messages[0].payload == ""
    batch = parse_script_output("{not json at all")
    assert batch.messages[0].kind == "log"
    handle = start_session(4280, module=FakeFridaModule())
    handle._on_message({"type": "error", "payload": None}, None)
    assert handle.messages[0].kind == "error"


def test_cli_frida_ps_table(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_ps(device_id: str | None = None) -> Any:
        return _ps_result()

    monkeypatch.setattr(live_cli, "list_processes", fake_ps)
    result = runner_cli.invoke(live_cli.frida_app, ["ps"])
    assert result.exit_code == 0, result.output
    assert "frida processes" in result.output
    assert "Spotify" in result.output
    assert "com.spotify.music" in result.output


def test_cli_frida_script_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "hook.js"
    script.write_text("send('hi');\n", encoding="utf-8")
    monkeypatch.setattr(live_cli, "start_session", lambda *a, **k: _one_shot(script))
    result = runner_cli.invoke(live_cli.frida_app, ["script", "4280", str(script)])
    assert result.exit_code == 0, result.output
    assert "frida script" in result.output
    assert "send: hi" in result.output
    assert "duration budget" in result.output


def test_cli_frida_script_typed_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*_a: Any, **_k: Any) -> FridaSession:
        raise AnalysisError("frida is not available: install frida-tools")

    monkeypatch.setattr(live_cli, "start_session", boom)
    script = tmp_path / "hook.js"
    script.write_text("send(1);\n", encoding="utf-8")
    result = runner_cli.invoke(live_cli.frida_app, ["script", "4280", str(script)])
    assert result.exit_code == 2
    assert "install frida-tools" in result.output


def test_cli_lldb_run_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ")
    monkeypatch.setattr(
        live_cli, "run_under_lldb", lambda t, break_at=None, timeout_s=None: _lldb_result()
    )
    result = runner_cli.invoke(live_cli.lldb_app, ["run", str(target)])
    assert result.exit_code == 0, result.output
    assert "lldb run" in result.output
    assert "breakpoint 1.1" in result.output
    assert "backtrace" in result.output
    assert "libc.so.6" in result.output
    assert "evidence: live.lldb" in result.output


def test_cli_rizin_functions_and_info_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 4)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise AnalysisError("rizin is not on PATH; install rizin (https://rizin.re)")

    monkeypatch.setattr(live_cli, "functions_of", boom)
    result = runner_cli.invoke(live_cli.rizin_app, ["functions", str(target)])
    assert result.exit_code == 2
    assert "install rizin" in result.output
    monkeypatch.setattr(live_cli, "info_of", boom)
    result = runner_cli.invoke(live_cli.rizin_app, ["info", str(target)])
    assert result.exit_code == 2


def test_cli_rizin_functions_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.bin"
    target.write_bytes(b"\x90" * 4)
    monkeypatch.setattr(live_cli, "functions_of", lambda path, **kw: parse_afl(AFL_TRANSCRIPT))
    result = runner_cli.invoke(live_cli.rizin_app, ["functions", str(target)])
    assert result.exit_code == 0, result.output
    assert "rizin functions" in result.output
    assert "entry0" in result.output


def _ps_result() -> Any:
    return frida_bridge.FridaProcessesResult(
        processes=(
            frida_bridge.FridaProcess(pid=4280, name="Spotify", identifier="com.spotify.music"),
        ),
        truncated=False,
    )


def _one_shot(script: Path) -> FridaSession:
    return FridaSession(
        target=4280,
        mode=frida_bridge.MODE_ATTACH,
        device_id=None,
        result=FridaScriptResult(
            target="4280",
            mode=frida_bridge.MODE_ATTACH,
            device_id=None,
            script_path=str(script),
            duration=5.0,
            messages=(FridaMessage(kind="send", payload="hi"),),
            truncated=False,
            timeout_reached=True,
        ),
    )


def _lldb_result() -> Any:
    return parse_lldb_transcript(LLDB_STOP_TRANSCRIPT)










