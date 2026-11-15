"""Tests for the persistent Frida session MCP tools (fake frida only).

``codevanta.mcp_server.ext_fridasession`` never imports or launches frida in
tests: the availability gate is an injected :class:`FridaAvailability`
snapshot, module-backed sessions run against tiny ``frida``-module-shaped
doubles (exactly the contract ``codevanta.analysis.frida_bridge`` expects),
and the one-shot CLI fallback runs through an injected runner returning a
canned transcript. Nothing here needs frida to be installed.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import frida_bridge
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_fridasession
from codevanta.mcp_server.ext_fridasession import (
    MAX_FRIDA_SESSIONS,
    FridaAvailability,
    codevanta_frida_close,
    codevanta_frida_load,
    codevanta_frida_sessions,
    codevanta_frida_start,
    codevanta_frida_status,
)

#: Probe doubles: injected, never computed from the real environment.
MODULE_PROBE = FridaAvailability(module_available=True, cli_available=True)
CLI_PROBE = FridaAvailability(module_available=False, cli_available=True)
DEAD_PROBE = FridaAvailability(module_available=False, cli_available=False)

#: A plausible gadget script; only its bytes matter to the doubles.
SCRIPT_SOURCE = (
    "Interceptor.attach(Module.getBaseAddress('target'), { onEnter() {} });"
)


class _FakeScript:
    """``frida.Script``-shaped double: delivers one canned message on load."""

    def __init__(self, source: str, pending: list[dict[str, Any]]) -> None:
        self.source = source
        self._pending = pending
        self._handler: Any = None
        self.unloaded = False

    def on(self, event: str, handler: Any) -> None:
        assert event == "message", "the bridge must subscribe to script messages"
        self._handler = handler

    def load(self) -> None:
        if self._pending:
            self._handler(self._pending.pop(0), None)

    def unload(self) -> None:
        self.unloaded = True


class _FakeSession:
    """``frida.Session``-shaped double holding the canned message queue."""

    def __init__(self, target: Any, pending: list[dict[str, Any]]) -> None:
        self.target = target
        self.detached = False
        self.scripts: list[_FakeScript] = []
        self._pending = pending

    def create_script(self, source: str) -> _FakeScript:
        script = _FakeScript(source, self._pending)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        self.detached = True


class _FakeDevice:
    """``frida.Device``-shaped double recording every lifecycle call."""

    def __init__(
        self,
        pending: list[dict[str, Any]] | None = None,
        fail_attach: Exception | None = None,
    ) -> None:
        self.attached: list[Any] = []
        self.sessions: list[_FakeSession] = []
        self.spawned: list[str] = []
        self.resumed: list[int] = []
        self._fail_attach = fail_attach
        self._pending = (
            pending if pending is not None else [{"type": "send", "payload": "hook armed"}]
        )

    def attach(self, target: Any) -> _FakeSession:
        if self._fail_attach is not None:
            raise self._fail_attach
        self.attached.append(target)
        session = _FakeSession(target, self._pending)
        self.sessions.append(session)
        return session

    def spawn(self, program: list[str]) -> int:
        self.spawned.append(program[0])
        return 4242

    def resume(self, pid: int) -> None:
        self.resumed.append(pid)


class _FakeFridaModule:
    """``frida``-module-shaped double (never the real package)."""

    def __init__(
        self,
        pending: list[dict[str, Any]] | None = None,
        fail_attach: Exception | None = None,
    ) -> None:
        self.device = _FakeDevice(pending, fail_attach)

    def get_local_device(self) -> _FakeDevice:
        return self.device


class _BoomModule:
    """A module double that fails loudly if the bridge ever touches it."""

    def get_local_device(self) -> None:
        raise AssertionError("frida must not be touched while unavailable")


class _FakeOutcome:
    """``subprocess.CompletedProcess``-shaped stand-in."""

    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _RecordingRunner:
    """Runner double for the one-shot CLI fallback: canned outcome only."""

    def __init__(self, outcome: _FakeOutcome) -> None:
        self.outcome = outcome
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        self.commands.append(tuple(command))
        return self.outcome


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the module-level registry and remove leftover session dirs."""
    for stale in Path(tempfile.gettempdir()).glob("codevanta-frida-session-*"):
        shutil.rmtree(stale, ignore_errors=True)
    yield
    for session in ext_fridasession._REGISTRY.sessions.values():
        if session.handle is not None:
            session.handle.close()
        shutil.rmtree(session.work_dir, ignore_errors=True)
    ext_fridasession._REGISTRY.sessions.clear()
    ext_fridasession._REGISTRY.next_number = 1


def _start_attach(module: Any) -> dict[str, Any]:
    """Start one canned module-backed attach session, return its payload."""
    return codevanta_frida_start(
        mode="attach",
        pid=1234,
        script=SCRIPT_SOURCE,
        duration=1.0,
        module=module,
        probe=MODULE_PROBE,
    )


def _canned_cli_transcript() -> str:
    """Return a `frida -l` transcript as parse_script_output expects it."""
    lines = [
        '[notepad.exe::1234]-> {"type": "send", "payload": "hook armed"}',
        "console line from the target",
    ]
    return "\n".join(lines) + "\n"


def test_start_status_close_happy_path() -> None:
    """start registers frida-001, status reports the stored run, close closes."""
    module = _FakeFridaModule()
    payload = _start_attach(module)
    device = module.device

    assert payload["session_id"] == "frida-001"
    assert payload["state"] == "completed"
    assert payload["mode"] == "attach"
    assert payload["target"] == "1234"
    assert payload["pid"] == 1234
    assert payload["session_kind"] == "module"
    assert payload["live"] is True
    assert payload["frida_available"] is True
    assert payload["message_count"] == 1
    assert payload["recent_messages"] == [{"kind": "send", "payload": "hook armed"}]
    assert device.attached == [1234]

    script_file = Path(payload["script_path"])
    assert script_file.is_file()
    assert script_file.read_text(encoding="utf-8") == SCRIPT_SOURCE
    capture = Path(payload["capture_path"]).read_text(encoding="utf-8")
    assert '"kind": "send"' in capture

    fake_session = device.sessions[0]
    assert len(fake_session.scripts) == 1
    assert fake_session.scripts[0].source == SCRIPT_SOURCE

    status = codevanta_frida_status("frida-001")
    assert status["session_id"] == "frida-001"
    assert status["state"] == "completed"
    assert status["message_count"] == payload["message_count"]
    assert status["recent_messages"] == payload["recent_messages"]

    closed = codevanta_frida_close("frida-001")
    assert closed["session_id"] == "frida-001"
    assert closed["state"] == "closed"
    assert closed["removed"] == [str(script_file), payload["capture_path"]]
    assert closed["work_dir_removed"] is True
    assert fake_session.detached is True
    assert fake_session.scripts[0].unloaded is True
    final = codevanta_frida_status("frida-001")
    assert final["state"] == "closed"
    assert final["live"] is False

    listing = codevanta_frida_sessions()
    assert listing["count"] == 1
    assert listing["max_sessions"] == MAX_FRIDA_SESSIONS
    assert listing["sessions"][0] == {
        "session_id": "frida-001",
        "state": "closed",
        "mode": "attach",
        "target": "1234",
        "message_count": 1,
    }


def test_spawn_resumes_the_target_after_loading_the_script() -> None:
    """spawn attaches, loads the initial script, then resumes the program."""
    module = _FakeFridaModule()
    payload = codevanta_frida_start(
        mode="spawn",
        target="com.example.app",
        script=SCRIPT_SOURCE,
        duration=1.0,
        module=module,
        probe=MODULE_PROBE,
    )
    assert payload["pid"] == 4242
    assert payload["target"] == "com.example.app"
    assert payload["resumed"] is True
    assert module.device.spawned == ["com.example.app"]
    assert module.device.resumed == [4242]
    assert module.device.sessions[0].scripts[0].source == SCRIPT_SOURCE


def test_load_attaches_another_script_to_a_live_session() -> None:
    """load adds one script plus one bounded slice to a module-backed session."""
    module = _FakeFridaModule(
        pending=[
            {"type": "send", "payload": "first"},
            {"type": "send", "payload": "second"},
        ]
    )
    payload = _start_attach(module)
    assert payload["message_count"] == 1

    loaded = codevanta_frida_load("frida-001", source="send(Object.keys(this));")
    assert loaded["message_count"] == 2
    assert loaded["scripts_loaded"] == 1
    assert loaded["recent_messages"][-1] == {"kind": "send", "payload": "second"}

    fake_session = module.device.sessions[0]
    assert len(fake_session.scripts) == 2
    load_file = Path(loaded["script_path"]).parent / "load-001.js"
    assert load_file.is_file()

    assert codevanta_frida_close("frida-001")["work_dir_removed"] is True
    assert not load_file.exists()


def test_load_refused_for_one_shot_cli_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CLI-fallback session refuses loads with the honest typed error."""
    monkeypatch.setattr(frida_bridge, "_import_frida", lambda: None)
    runner = _RecordingRunner(_FakeOutcome(124, _canned_cli_transcript()))
    payload = codevanta_frida_start(
        mode="attach",
        target="notepad.exe",
        script=SCRIPT_SOURCE,
        duration=1.0,
        runner=runner,
        probe=CLI_PROBE,
    )
    assert payload["session_kind"] == "one-shot-cli"
    assert payload["live"] is False
    assert payload["timeout_reached"] is True
    assert payload["message_count"] == 2

    command = runner.commands[0]
    assert command[0] == "frida"
    assert "-l" in command
    assert command[-1] == "notepad.exe"

    with pytest.raises(AnalysisError) as excinfo:
        codevanta_frida_load("frida-001", source="send(1);")
    message = str(excinfo.value)
    assert "frida-001" in message
    assert "not supported for this session kind" in message

    assert codevanta_frida_close("frida-001")["state"] == "closed"


def test_unavailable_frida_is_a_typed_error_and_registers_nothing() -> None:
    """A dead gate is one honest typed error; nothing runs or registers."""
    boom = _BoomModule()
    with pytest.raises(AnalysisError) as excinfo:
        codevanta_frida_start(mode="attach", pid=1234, module=boom, probe=DEAD_PROBE)
    message = str(excinfo.value)
    assert "frida is not installed" in message
    assert "frida CLI" in message
    assert "python bindings" in message
    assert "pip install frida-tools" in message

    assert codevanta_frida_sessions()["count"] == 0
    leftover = list(Path(tempfile.gettempdir()).glob("codevanta-frida-session-*"))
    assert leftover == []


def test_unknown_session_id_raises_analysis_error_naming_the_id() -> None:
    """status/load/close on an unknown id raise AnalysisError naming the id."""
    for tool in (codevanta_frida_status, codevanta_frida_close):
        with pytest.raises(AnalysisError) as excinfo:
            tool("frida-999")
        assert "frida-999" in str(excinfo.value)
        assert "unknown session id" in str(excinfo.value)
    with pytest.raises(AnalysisError) as load_error:
        codevanta_frida_load("frida-999", source="send(1);")
    assert "frida-999" in str(load_error.value)
    assert "unknown session id" in str(load_error.value)


def test_close_cleans_up_script_and_capture() -> None:
    """After close the script, the capture and the directory are gone."""
    module = _FakeFridaModule()
    payload = _start_attach(module)

    script_path = Path(payload["script_path"])
    capture_path = Path(payload["capture_path"])
    work_dir = capture_path.parent
    assert script_path.is_file()
    assert capture_path.is_file()

    closed = codevanta_frida_close(payload["session_id"])
    assert closed["removed"] == [str(script_path), str(capture_path)]
    assert not script_path.exists()
    assert not capture_path.exists()
    assert not work_dir.exists()

    # A closed id is stale: closing it again is a typed error naming the id.
    with pytest.raises(AnalysisError) as stale_error:
        codevanta_frida_close(payload["session_id"])
    assert payload["session_id"] in str(stale_error.value)
    assert "already closed" in str(stale_error.value)
    with pytest.raises(AnalysisError) as load_error:
        codevanta_frida_load(payload["session_id"], source="send(1);")
    assert "already closed" in str(load_error.value)


def test_max_sessions_rejects_the_ninth_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry caps at MAX_FRIDA_SESSIONS records; the 9th is refused."""
    monkeypatch.setattr(frida_bridge.time, "sleep", lambda _seconds: None)
    for _ in range(MAX_FRIDA_SESSIONS):
        assert _start_attach(_FakeFridaModule())["state"] == "completed"
    assert codevanta_frida_sessions()["count"] == MAX_FRIDA_SESSIONS

    with pytest.raises(AnalysisError) as excinfo:
        _start_attach(_FakeFridaModule())
    message = str(excinfo.value)
    assert str(MAX_FRIDA_SESSIONS) in message
    assert "registry is full" in message


def test_sessions_listing_is_bounded_and_evicts_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The listing never exceeds MAX_FRIDA_SESSIONS and evicts the oldest closed."""
    monkeypatch.setattr(frida_bridge.time, "sleep", lambda _seconds: None)
    for _ in range(MAX_FRIDA_SESSIONS):
        _start_attach(_FakeFridaModule())
    codevanta_frida_close("frida-001")
    codevanta_frida_close("frida-002")

    payload = _start_attach(_FakeFridaModule())  # evicts frida-001, id stays monotonic

    assert payload["session_id"] == f"frida-{MAX_FRIDA_SESSIONS + 1:03d}"
    listing = codevanta_frida_sessions()
    assert listing["count"] == MAX_FRIDA_SESSIONS
    ids = [record["session_id"] for record in listing["sessions"]]
    assert "frida-001" not in ids
    assert ids == [f"frida-{number:03d}" for number in range(2, MAX_FRIDA_SESSIONS + 2)]
    states = {record["session_id"]: record["state"] for record in listing["sessions"]}
    assert states["frida-002"] == "closed"
    assert states[payload["session_id"]] == "completed"


def test_failed_start_registers_nothing() -> None:
    """A refused attach is a typed error; no session and no leftovers."""
    module = _FakeFridaModule(fail_attach=RuntimeError("no such process"))
    with pytest.raises(AnalysisError) as excinfo:
        _start_attach(module)
    assert "frida refused" in str(excinfo.value)

    assert codevanta_frida_sessions()["count"] == 0
    leftover = list(Path(tempfile.gettempdir()).glob("codevanta-frida-session-*"))
    assert leftover == []


def test_start_rejects_invalid_argument_pairs_without_touching_frida() -> None:
    """Bad mode/target/script pairs fail before the bridge or registry run."""
    boom = _BoomModule()
    cases = (
        {"mode": "spawn", "pid": 1234},  # spawn needs a program name
        {"mode": "attach", "pid": 1234, "target": "app"},  # pid and target
        {"mode": "attach"},  # neither pid nor target
        {"mode": "hover", "target": "app"},  # not a mode
        {"mode": "attach", "pid": 0},  # non-positive pid
        {  # inline source and file at once
            "mode": "attach",
            "pid": 1234,
            "script": SCRIPT_SOURCE,
            "script_path": "gone.js",
        },
    )
    for kwargs in cases:
        with pytest.raises(AnalysisError):
            codevanta_frida_start(module=boom, probe=MODULE_PROBE, **kwargs)
    assert codevanta_frida_sessions()["count"] == 0

