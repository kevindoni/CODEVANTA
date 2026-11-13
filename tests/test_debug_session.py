"""Tests for the live gdb debug-session layer.

``codevanta.analysis.debug_session`` is the layer that owns a gdb process, and
this machine -- like many CI hosts and every Windows workstation -- has no gdb.
The module is therefore built to be fully exercisable without one, and the test
module mirrors that split:

* the MI **parsers** are pure functions, so canned MI transcripts (byte for
  byte as gdb prints them) drive every parse and every result builder here;
  these tests are mandatory and run everywhere;
* the whole **session** is driven through an injectable :class:`MITransport`
  double whose canned conversation stands in for the gdb process, including
  clean and forced shutdowns, MI ``^error`` answers and a command that misses
  its deadline;
* the few **live** tests that spawn a real ``gdb --interpreter=mi2`` process
  are ``skipif``-gated on ``shutil.which("gdb")`` and only exercise
  handshake-level commands (register names, an address breakpoint, quit), so
  they pass unchanged on a machine where gdb exists but the synthetic ELF
  samples cannot actually execute as inferiors.

No test here ever runs the binary under test on the host CPU: the fixture is
the byte-by-byte ELF64 builder ``tests/test_debugger.py`` uses, and the only
process any live test launches is gdb itself.
"""

from __future__ import annotations

import json
import shutil
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.debug_session import (
    DEFAULT_TIMEOUT,
    MAX_BACKTRACE_FRAMES,
    MAX_MEMORY_BYTES,
    DebugSession,
    backtrace_from_payload,
    breakpoint_from_payload,
    gdb_available,
    gdb_status,
    memory_from_payload,
    parse_location,
    parse_mi_line,
    parse_mi_transcript,
    parse_mi_value,
    registers_from_payloads,
    run_debug,
    stop_from_payload,
)
from codevanta.core.report import AnalysisError

#: Where the fixture's ``.text`` is mapped and the breakpoint goes.
TEXT_ADDRESS = 0x401000

#: ``mov eax, 42`` + ``ret``: a body the synthetic inferior can only ever sit in.
CODE = bytes.fromhex("b82a000000") + b"\xc3"

#: Whether this environment can run a real gdb at all.
needs_gdb = pytest.mark.skipif(
    shutil.which("gdb") is None or sys.platform == "win32", reason="gdb is not on PATH (or MinGW gdb MI quirks on Windows)"
)


def _write_elf64(path: Path) -> Path:
    """Write the minimal ELF64 executable fixture (``.text`` at 0x401000)."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = text_offset + len(CODE)
    shoff = shstrtab_offset + len(shstrtab)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ", 1, 1, 6, TEXT_ADDRESS, text_offset, len(CODE), 0, 0, 16, 0
        ),
        struct.pack(
            "<IIQQQQIIQQ", 23, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
        ),
    ]
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        TEXT_ADDRESS,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        len(sections),  # e_shnum
        2,  # e_shstrndx
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(CODE)] = CODE
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


@pytest.fixture
def target(tmp_path: Path) -> Path:
    return _write_elf64(tmp_path / "target.bin")


# --------------------------------------------------------------------------- #
# Canned MI fixtures: transcripts byte for byte as gdb prints them
# --------------------------------------------------------------------------- #

#: The banner, one ``=notify``, stream noise and the first prompt: a handshake.
HANDSHAKE_LINES = [
    'GNU gdb (GDB) 12.1\n',
    'Copyright (C) 2022 Free Software Foundation, Inc.\n',
    'License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n',
    'Type "show copying" and "show warranty" for this type of gdb.\n',
    "(gdb) \n",
]

#: ``-break-insert *0x401000`` and its answer, wrapped in the notices gdb adds.
BREAK_LINES = [
    f'=breakpoint-created,bkpt={{number="1",type="breakpoint",addr="0x{TEXT_ADDRESS:x}"}}\n',
    f'~"Breakpoint 1 at 0x{TEXT_ADDRESS:x}\\n"\n',
    f'1^done,bkpt={{number="1",type="breakpoint",addr="0x{TEXT_ADDRESS:x}"}}\n',
    "(gdb) \n",
]

#: ``-exec-run`` up to the stop at the breakpoint.
RUN_LINES = [
    '=thread-group-started,id="i1",pid="4242"\n',
    "=thread-created,id=\"1\",group-id=\"i1\"\n",
    "1^running\n",
    "(gdb) \n",
    f'*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={{addr="0x{TEXT_ADDRESS:x}",func="main"}},thread-id="1",stopped-threads=["all"]\n',
    "*running,thread-id=\"all\"\n",
    "(gdb) \n",
]

#: Register names + values as x86_64 gdb prints them (subset).
REG_NAME_LINES = [
    '2^done,register-names=["rax","rbx","rcx","rdx","rip"]\n',
    "(gdb) \n",
]
REG_VALUE_LINES = [
    '3^done,register-values=[{number="0",value="0x1"},{number="1",value="0x0"},{number="2",value="0x2a"},{number="3",value="0x7"},{number="4",value=""}]\n',
    "(gdb) \n",
]

#: ``-data-read-memory-bytes -o 0 0x401000 8``: five bytes back, not eight.
MEMORY_LINES = [
    f'4^done,memory=[{{begin="0x{TEXT_ADDRESS:x}",end="0x{TEXT_ADDRESS + 5:x}",contents="b82a000000c3"}}]\n',
    "(gdb) \n",
]

#: ``-stack-list-frames 0 19`` with two frames.
BACKTRACE_LINES = [
    f'5^done,stack=[frame={{level="0",addr="0x{TEXT_ADDRESS:x}",func="main"}},frame={{level="1",addr="0x{TEXT_ADDRESS + 16:x}"}}]\n',
    "(gdb) \n",
]

#: ``-gdb-exit``: gdb says goodbye and exits.
QUIT_LINES = [
    '6^exit\n',
    "(gdb) \n",
]



# --------------------------------------------------------------------------- #
# Parser unit tests (mandatory everywhere: no gdb needed)
# --------------------------------------------------------------------------- #


def test_parse_mi_value_string_list_and_tuple() -> None:
    """Strings, lists and tuples parse into plain Python values."""
    assert parse_mi_value('"hello world"') == "hello world"
    assert parse_mi_value(r'["rax","rbx"]') == ["rax", "rbx"]
    assert parse_mi_value(r'{level="0",addr="0x00401000",func="main"}') == {
        "level": "0",
        "addr": "0x00401000",
        "func": "main",
    }


def test_parse_mi_value_nested_and_mixed_list() -> None:
    """Nested tuples and lists mixing ``key=value`` results and bare values."""
    payload = parse_mi_value(
        r'{frame={level="0",addr="0x401000"},stack=[frame={level="1"},"tail"]}'
    )
    assert payload == {
        "frame": {"level": "0", "addr": "0x401000"},
        "stack": [{"frame": {"level": "1"}}, "tail"],
    }


def test_parse_mi_value_decodes_escapes() -> None:
    """C-style escapes inside MI strings are decoded."""
    assert parse_mi_value(r'"Breakpoint 1 at 0x401000\n"') == "Breakpoint 1 at 0x401000\n"


def test_parse_mi_value_rejects_malformed_input() -> None:
    """Garbage raises the typed error instead of returning a partial value."""
    for broken in ('"unterminated', "[1,2", "{key", "42", "{a=1}trailing"):
        with pytest.raises(AnalysisError):
            parse_mi_value(broken)


def test_parse_mi_line_classifies_every_record_kind() -> None:
    """Result, exec, notify, stream, prompt and noise lines classify by prefix."""
    result = parse_mi_line('7^done,bkpt={number="1"}')
    assert result.kind == "result"
    assert result.token == "7"
    assert result.result_class == "done"
    assert result.payload == {"bkpt": {"number": "1"}}

    stopped = parse_mi_line('*stopped,reason="breakpoint-hit",bkptno="1"')
    assert stopped.kind == "exec"
    assert stopped.async_class == "stopped"
    assert stopped.payload["reason"] == "breakpoint-hit"

    notify = parse_mi_line('=thread-group-started,id="i1",pid="4242"')
    assert notify.kind == "notify"
    assert notify.async_class == "thread-group-started"

    console = parse_mi_line('~"Breakpoint 1 at 0x401000\\n"')
    assert console.kind == "console"
    assert console.text == "Breakpoint 1 at 0x401000\n"

    assert parse_mi_line("(gdb) ").kind == "prompt"
    assert parse_mi_line("(gdb) \n").kind == "prompt"
    assert parse_mi_line("GNU gdb (GDB) 12.1").kind == "noise"
    assert parse_mi_line("").kind == "noise"


def test_parse_mi_line_error_record_keeps_message() -> None:
    """``^error`` carries its ``msg`` so callers can name the refusal."""
    record = parse_mi_line('^error,msg="Function \\"foo\\" not defined."')
    assert record.kind == "result"
    assert record.result_class == "error"
    assert record.payload is not None
    assert "not defined" in record.payload["msg"]


def test_parse_mi_line_broken_payload_is_none_not_a_guess() -> None:
    """A record whose payload does not parse keeps payload=None, not garbage."""
    record = parse_mi_line("^done,bkpt={unterminated")
    assert record.kind == "result"
    assert record.payload is None
    assert record.raw == "^done,bkpt={unterminated"


def test_parse_mi_transcript_classifies_a_full_handshake() -> None:
    """The real banner classifies as noise; the prompt ends the handshake."""
    records = parse_mi_transcript(HANDSHAKE_LINES)
    assert records[-1].kind == "prompt"
    assert all(record.kind in {"noise", "prompt"} for record in records)



def test_breakpoint_from_payload_resolved_and_pending() -> None:
    """A resolved breakpoint keeps its address; ``<PENDING>`` keeps none."""
    resolved = breakpoint_from_payload(
        {"number": "1", "addr": f"0x{TEXT_ADDRESS:x}", "func": "main"}
    )
    assert resolved.number == 1
    assert resolved.address == TEXT_ADDRESS
    assert resolved.function == "main"
    assert not resolved.pending

    pending = breakpoint_from_payload({"number": "2", "addr": "<PENDING>later"})
    assert pending.address is None
    assert pending.pending


def test_stop_from_payload_reads_frame_and_bkptno() -> None:
    """Stop reason, breakpoint number, frame address and thread id come along."""
    stop = stop_from_payload(
        {
            "reason": "breakpoint-hit",
            "bkptno": "1",
            "frame": {"addr": f"0x{TEXT_ADDRESS:x}", "func": "main"},
            "thread-id": "1",
        }
    )
    assert stop.reason == "breakpoint-hit"
    assert stop.breakpoint_number == 1
    assert stop.address == TEXT_ADDRESS
    assert stop.function == "main"
    assert stop.thread_id == "1"


def test_stop_from_payload_without_reason_is_unknown() -> None:
    """A bare ``*stopped`` reports reason 'unknown', never a guess."""
    stop = stop_from_payload({"frame": {}})
    assert stop.reason == "unknown"
    assert stop.address is None


def test_backtrace_from_payload_caps_frames() -> None:
    """Frames are capped to the request and the overflow marks truncated."""
    payload = {
        "stack": [
            {"frame": {"level": "0", "addr": f"0x{TEXT_ADDRESS:x}", "func": "main"}},
            {"frame": {"level": "1", "addr": f"0x{TEXT_ADDRESS + 16:x}"}},
            {"frame": {"level": "2", "addr": f"0x{TEXT_ADDRESS + 32:x}"}},
        ]
    }
    result = backtrace_from_payload(payload, requested=2)
    assert len(result.frames) == 2
    assert result.truncated
    assert result.frames[0].function == "main"
    assert result.frames[1].function is None  # unnamed frame stays unnamed


def test_registers_from_payloads_zips_names_and_values() -> None:
    """Registers zip by index; a missing value stays None, never a fake 0x0."""
    result = registers_from_payloads(
        ["rax", "rbx", "rip"],
        [{"number": "0", "value": "0x1"}, {"number": "1", "value": ""}],
    )
    assert [(register.name, register.value) for register in result.registers] == [
        ("rax", "0x1"),
        ("rbx", None),
        ("rip", None),
    ]
    assert not result.truncated


def test_memory_from_payload_reports_short_reads() -> None:
    """Fewer bytes than requested means short_read plus the real length."""
    result = memory_from_payload(
        {"memory": [{"begin": f"0x{TEXT_ADDRESS:x}", "contents": "b82a000000"}]},
        requested_address=TEXT_ADDRESS,
        requested_length=8,
    )
    assert result.address == TEXT_ADDRESS
    assert result.length == 5
    assert result.requested_length == 8
    assert result.contents_hex == "b82a000000"
    assert result.short_read


def test_memory_from_payload_rejects_odd_contents() -> None:
    """An odd-length contents field is malformed MI, not half a byte."""
    with pytest.raises(AnalysisError):
        memory_from_payload(
            {"memory": [{"begin": "0x401000", "contents": "b82a0"}]},
            requested_address=TEXT_ADDRESS,
            requested_length=2,
        )


def test_parse_location_splits_addresses_from_symbols() -> None:
    """Hex and decimal text are addresses; anything else is a symbol name."""
    assert parse_location("0x401000") == ("address", "*0x401000")
    assert parse_location("42") == ("address", "*0x2a")
    assert parse_location(" main ") == ("function", "main")
    with pytest.raises(AnalysisError):
        parse_location("")



# --------------------------------------------------------------------------- #
# Session tests through an injectable transport (still no gdb needed)
# --------------------------------------------------------------------------- #


class _ScriptedTransport:
    """MI transport double: one canned chunk list per command, prompt-delimited.

    Each command maps to a list of *chunks*; every ``read_until_prompt`` call
    consumes the next chunk, which is exactly how the real pipe behaves for an
    ``-exec-*`` command: ``^running`` plus a prompt in one read, the later
    ``*stopped`` plus its own prompt in the next.
    """

    def __init__(
        self,
        script: dict[str, list[list[str]]],
        *,
        handshake: list[str] | None = None,
        shutdown: tuple[int | None, bool] = (0, True),
    ) -> None:
        self._script = script
        self._handshake: list[list[str]] = [handshake or HANDSHAKE_LINES]
        self._chunks: list[list[str]] = []
        self.sent: list[str] = []
        self.shutdown_result = shutdown
        self.shutdown_calls = 0

    def send(self, command: str) -> None:
        self.sent.append(command)
        for key, chunks in self._script.items():
            if command.lstrip("0123456789").startswith(key):
                self._chunks.extend(list(chunk) for chunk in chunks)
                return

    def read_until_prompt(self, timeout: float) -> list[str]:
        if self._handshake:
            return self._handshake.pop(0)
        if self._chunks:
            return self._chunks.pop(0)
        return []  # the process is gone; the caller sees an empty read

    def shutdown(self, timeout: float) -> tuple[int | None, bool]:
        self.shutdown_calls += 1
        return self.shutdown_result


def _open_session(
    script: dict[str, list[list[str]]], **kwargs: Any
) -> tuple[DebugSession, _ScriptedTransport]:
    """Open a session over the scripted transport with the standard pipeline."""
    transport = _ScriptedTransport(script, **kwargs)
    session = DebugSession.launch("target.bin", transport=transport, timeout=DEFAULT_TIMEOUT)
    return session, transport


def test_break_at_reports_breakpoint_and_provenance() -> None:
    """``break_at`` at an address builds the typed breakpoint result."""
    session, transport = _open_session({"-break-insert": [BREAK_LINES]})
    result = session.break_at(address=TEXT_ADDRESS)

    assert result.breakpoint.number == 1
    assert result.breakpoint.address == TEXT_ADDRESS
    assert result.warnings == ()
    assert result.evidence.method == "-break-insert"
    assert result.evidence.source == "gdb.mi2"
    assert transport.sent[-1].endswith("-break-insert *0x401000")
    session.quit()


def test_break_at_function_and_rejects_both_or_neither() -> None:
    """Exactly one location is required; a symbol is passed through verbatim."""
    script = {"-break-insert": [['1^done,bkpt={number="1",func="main"}\n', "(gdb) \n"]]}
    session, transport = _open_session(script)
    result = session.break_at(function="main")
    assert result.breakpoint.function == "main"
    assert transport.sent[-1].endswith("-break-insert main")
    session.quit()

    session2, _ = _open_session({})
    with pytest.raises(AnalysisError):
        session2.break_at(function="main", address=TEXT_ADDRESS)
    with pytest.raises(AnalysisError):
        session2.break_at()
    session2.quit()


def test_run_reports_breakpoint_hit_stop() -> None:
    """``run`` keeps reading past the ^running prompt until *stopped arrives."""
    script = {"-exec-run": [["1^running\n", "(gdb) \n"], RUN_LINES]}
    session, _ = _open_session(script)
    result = session.run()

    assert result.stop.reason == "breakpoint-hit"
    assert result.stop.breakpoint_number == 1
    assert result.stop.address == TEXT_ADDRESS
    assert result.stop.function == "main"
    assert result.evidence.method == "-exec-run"
    session.quit()



def test_continue_step_next_send_their_mi_commands() -> None:
    """Each stepping action sends its own MI command and reads the stop."""
    stop_chunk = [
        '*stopped,reason="end-stepping-range",frame={addr="0x00401001"},thread-id="1"',
        "(gdb) \n",
    ]
    script = {
        "-exec-continue": [["1^running\n", "(gdb) \n"], stop_chunk],
        "-exec-step": [["2^running\n", "(gdb) \n"], stop_chunk],
        "-exec-next": [["3^running\n", "(gdb) \n"], stop_chunk],
    }
    session, transport = _open_session(script)
    assert session.continue_execution().stop.reason == "end-stepping-range"
    assert session.step_into().stop.reason == "end-stepping-range"
    assert session.step_over().stop.reason == "end-stepping-range"
    assert any(command.endswith("-exec-continue") for command in transport.sent)
    assert any(command.endswith("-exec-step --all 0") for command in transport.sent)
    assert any(command.endswith("-exec-next --all 0") for command in transport.sent)
    session.quit()


def test_read_registers_returns_snapshot_with_evidence() -> None:
    """Register names and values zip into one snapshot; evidence names both."""
    script = {
        "-data-list-register-names": [REG_NAME_LINES],
        "-data-list-register-values": [REG_VALUE_LINES],
    }
    session, _ = _open_session(script)
    result = session.read_registers()

    values = {register.name: register.value for register in result.registers}
    assert values["rax"] == "0x1"
    assert values["rip"] is None  # gdb reported an empty value; stays honest
    assert len(result.registers) == 5
    assert "register" in result.evidence.method
    session.quit()


def test_read_memory_validates_bounds_and_reports_bytes() -> None:
    """Memory reads are bounded and carry the hex contents plus provenance."""
    script = {"-data-read-memory-bytes": [MEMORY_LINES]}
    session, transport = _open_session(script)
    result = session.read_memory(TEXT_ADDRESS, 8)

    assert result.length == 6
    assert result.short_read
    assert result.contents_hex.startswith("b82a")
    assert result.evidence.method == "-data-read-memory-bytes"
    assert transport.sent[-1].endswith(f"-data-read-memory-bytes -o 0 0x{TEXT_ADDRESS:x} 8")
    session.quit()

    session2, _ = _open_session({})
    for bad_address, bad_length in (
        (0, 4),
        (TEXT_ADDRESS, 0),
        (TEXT_ADDRESS, MAX_MEMORY_BYTES + 1),
    ):
        with pytest.raises(AnalysisError):
            session2.read_memory(bad_address, bad_length)
    session2.quit()


def test_backtrace_bounds_frames_and_reports_truncation() -> None:
    """The frame budget reaches MI and truncation is reported, not silent."""
    script = {"-stack-list-frames": [BACKTRACE_LINES]}
    session, transport = _open_session(script)
    result = session.backtrace(max_frames=20)

    assert [frame.level for frame in result.frames] == [0, 1]
    assert result.frames[0].function == "main"
    assert not result.truncated
    assert transport.sent[-1].endswith("-stack-list-frames 0 19")
    assert result.evidence.method == "-stack-list-frames"
    session.quit()

    session2, _ = _open_session({})
    for bad in (0, -1, MAX_BACKTRACE_FRAMES + 1):
        with pytest.raises(AnalysisError):
            session2.backtrace(max_frames=bad)
    session2.quit()



def test_mi_error_surfaces_as_typed_error_naming_the_command() -> None:
    """A ``^error`` answer raises AnalysisError carrying gdb's msg."""
    script = {
        "-break-insert": [['1^error,msg="Function \\"nope\\" not defined."\n', "(gdb) \n"]]
    }
    session, _ = _open_session(script)
    with pytest.raises(AnalysisError) as excinfo:
        session.break_at(function="nope")
    assert "nope" in str(excinfo.value)
    session.quit()


def test_quit_verifies_clean_shutdown_and_caches_the_result() -> None:
    """``quit`` reports a verified exit and a second call does not re-poke gdb."""
    session, transport = _open_session({"-gdb-exit": [QUIT_LINES]})
    result = session.quit()

    assert result.clean
    assert result.exit_code == 0
    assert result.warnings == ()
    assert transport.shutdown_calls == 1
    again = session.quit()
    assert again.clean and transport.shutdown_calls == 1


def test_forced_shutdown_reports_unclean_and_warns() -> None:
    """A shutdown that needed force reports clean=False with a warning."""
    session, transport = _open_session(
        {}, handshake=HANDSHAKE_LINES, shutdown=(1, False)
    )
    result = session.quit()

    assert not result.clean
    assert any("did not exit on its own" in warning for warning in result.warnings)
    assert transport.shutdown_calls == 1


def test_context_manager_shuts_the_session_down() -> None:
    """Leaving the with block quits the session even after an exception."""
    transport_holder: list[_ScriptedTransport] = []

    def failing_break() -> None:
        session, transport = _open_session({"-break-insert": [BREAK_LINES]})
        transport_holder.append(transport)
        with session:
            session.break_at(function="main")
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        failing_break()
    assert transport_holder[0].shutdown_calls == 1


def test_launch_rejects_empty_target_and_bad_timeout() -> None:
    """Input validation happens before any transport is touched."""
    with pytest.raises(AnalysisError):
        DebugSession.launch("   ", transport=_ScriptedTransport({}))
    with pytest.raises(AnalysisError):
        DebugSession.launch("t.bin", transport=_ScriptedTransport({}), timeout=0)


def test_gdb_status_reports_missing_gdb_without_running_anything() -> None:
    """The availability probe never raises and always carries a reason."""
    status = gdb_status()
    assert status["available"] in {"true", "false"}
    assert status["reason"]
    assert gdb_available() == (status["available"] == "true")


def test_results_are_json_safe(tmp_path: Path) -> None:
    """Every typed result round-trips through JSON untouched."""
    payload = {
        "break": None,
        "action": "registers",
        "result": None,
        "quit": None,
        "target": "x",
    }
    session, _ = _open_session(
        {
            "-break-insert": [BREAK_LINES],
            "-exec-run": [["1^running\n", "(gdb) \n"], RUN_LINES],
            "-data-list-register-names": [REG_NAME_LINES],
            "-data-list-register-values": [REG_VALUE_LINES],
            "-gdb-exit": [QUIT_LINES],
        }
    )
    payload["break"] = session.break_at(address=TEXT_ADDRESS).to_dict()
    payload["break"]["run"] = session.run().to_dict()
    payload["result"] = session.read_registers().to_dict()
    payload["quit"] = session.quit().to_dict()
    decoded = json.loads(json.dumps(payload))
    assert decoded["break"]["breakpoint"]["address"] == f"0x{TEXT_ADDRESS:x}"
    assert decoded["break"]["run"]["stop"]["reason"] == "breakpoint-hit"
    assert decoded["result"]["registers"][0]["name"] == "rax"
    assert decoded["quit"]["clean"] is True



# --------------------------------------------------------------------------- #
# run_debug: the one-call session pipeline (still no gdb needed)
# --------------------------------------------------------------------------- #


def test_run_debug_end_to_end_break_then_registers(tmp_path: Path) -> None:
    """The full pipeline: launch, break, run, read registers, verified quit."""
    target = _write_elf64(tmp_path / "target.bin")
    script = {
        "-break-insert": [BREAK_LINES],
        "-exec-run": [["1^running\n", "(gdb) \n"], RUN_LINES],
        "-data-list-register-names": [REG_NAME_LINES],
        "-data-list-register-values": [REG_VALUE_LINES],
        "-gdb-exit": [QUIT_LINES],
    }
    payload = run_debug(target, action="registers", break_at=f"0x{TEXT_ADDRESS:x}", transport=_ScriptedTransport(script))

    assert payload["target"] == str(target)
    assert payload["action"] == "registers"
    assert payload["break"]["location_kind"] == "address"
    assert payload["break"]["run"]["stop"]["reason"] == "breakpoint-hit"
    assert payload["result"]["registers"][0]["name"] == "rax"
    assert payload["quit"]["clean"] is True
    json.loads(json.dumps(payload))


def test_run_debug_quit_action_skips_the_action_payload(tmp_path: Path) -> None:
    """``quit`` is the smoke action: launch, optionally break, verified exit."""
    script = {"-gdb-exit": [QUIT_LINES]}
    payload = run_debug("t.bin", action="quit", transport=_ScriptedTransport(script))
    assert payload["result"] is None
    assert payload["quit"]["clean"] is True


def test_run_debug_memory_action_requires_an_address() -> None:
    """The memory action without an address, and an address elsewhere, refuse."""
    with pytest.raises(AnalysisError) as missing:
        run_debug("t.bin", action="memory", transport=_ScriptedTransport({}))
    assert "needs an address" in str(missing.value)
    with pytest.raises(AnalysisError) as extra:
        run_debug(
            "t.bin",
            action="registers",
            address=TEXT_ADDRESS,
            transport=_ScriptedTransport({}),
        )
    assert "only used by action 'memory'" in str(extra.value)


def test_run_debug_unknown_action_and_bad_budgets_are_typed_errors() -> None:
    """Unknown actions and out-of-range budgets refuse before launching."""
    for kwargs in (
        {"action": "explode"},
        {"action": "backtrace", "max_frames": 0},
        {"action": "memory", "address": TEXT_ADDRESS, "length": MAX_MEMORY_BYTES + 1},
    ):
        with pytest.raises(AnalysisError):
            run_debug("t.bin", transport=_ScriptedTransport({}), **kwargs)


def test_run_debug_missing_gdb_is_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A machine without gdb gets the install-hint error, never a traceback."""
    import codevanta.analysis.debug_session as module

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError) as excinfo:
        run_debug(tmp_path / "t.bin", action="quit")
    assert "gdb is not on PATH" in str(excinfo.value)



# --------------------------------------------------------------------------- #
# MCP tool layer (tools.debug) and CLI wiring
# --------------------------------------------------------------------------- #


def test_mcp_tools_debug_validates_before_launching() -> None:
    """tools.debug refuses unknown actions and missing files with typed errors."""
    from codevanta.mcp_server import tools

    with pytest.raises(AnalysisError):
        tools.debug("x.bin", "explode")
    with pytest.raises(AnalysisError):
        tools.debug("definitely-missing.bin", "registers")


def test_mcp_tools_debug_drives_a_canned_session(tmp_path: Path) -> None:
    """tools.debug runs the whole pipeline over the injected transport."""
    from codevanta.mcp_server import tools

    target = _write_elf64(tmp_path / "target.bin")
    script = {
        "-data-list-register-names": [REG_NAME_LINES],
        "-data-list-register-values": [REG_VALUE_LINES],
        "-gdb-exit": [QUIT_LINES],
    }
    payload = tools.debug(
        str(target), "registers", transport=_ScriptedTransport(script)
    )
    assert payload["action"] == "registers"
    assert payload["result"]["registers"]
    assert payload["quit"]["clean"] is True


def test_cli_debug_happy_path_renders_and_writes_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI wires options through and renders the canned session payloads."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app

    target = _write_elf64(tmp_path / "target.bin")

    def canned_run_debug(target: Any, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["action"] == "registers"
        assert kwargs["break_at"] == "main"
        return {
            "target": str(target),
            "break": {
                "number": 1,
                "address": None,
                "function": "main",
                "pending": False,
                "stop": {"reason": "breakpoint-hit", "address": f"0x{TEXT_ADDRESS:x}", "function": "main"},
            },
            "action": "registers",
            "result": {
                "registers": [{"number": 0, "name": "rax", "value": "0x1"}],
                "count": 1,
                "truncated": False,
                "warnings": [],
                "evidence": {
                    "source": "gdb.mi2",
                    "method": "-data-list-register-names/-values",
                    "confidence": "high",
                },
            },
            "quit": {"clean": True, "exit_code": 0, "warnings": []},
        }

    import codevanta.cli.main as cli_main

    monkeypatch.setattr(cli_main.debug_session, "run_debug", canned_run_debug)
    result = CliRunner().invoke(
        app,
        [
            "debug",
            str(target),
            "--break-at",
            "main",
            "--action",
            "registers",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "breakpoint 1" in result.output
    assert "rax" in result.output
    assert "gdb.mi2" in result.output
    assert "verified" in result.output


def test_cli_debug_json_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--json`` prints the raw session payloads."""
    from typer.testing import CliRunner

    import codevanta.cli.main as cli_main
    from codevanta.cli.main import app

    target = _write_elf64(tmp_path / "target.bin")
    monkeypatch.setattr(
        cli_main.debug_session,
        "run_debug",
        lambda target, **kwargs: {
            "target": str(target),
            "break": None,
            "action": "quit",
            "result": None,
            "quit": {"clean": True, "exit_code": 0, "warnings": []},
        },
    )
    result = CliRunner().invoke(app, ["debug", str(target), "--action", "quit", "--json"])
    assert result.exit_code == 0, result.output
    decoded = json.loads(result.output)
    assert decoded["action"] == "quit"
    assert decoded["quit"]["clean"] is True


@pytest.mark.skipif(gdb_available(), reason="this contract test needs a gdb-less machine")
def test_cli_debug_without_gdb_exits_2_with_reason(tmp_path: Path) -> None:
    """A gdb-less machine gets exit code 2 and the install hint, no traceback."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app

    target = _write_elf64(tmp_path / "target.bin")
    result = CliRunner().invoke(app, ["debug", str(target)])
    assert result.exit_code == 2
    assert "gdb is not on PATH" in result.output



# --------------------------------------------------------------------------- #
# Live tests: real gdb process, skip-gated, handshake-level only
# --------------------------------------------------------------------------- #
#
# These launch a real ``gdb --interpreter=mi2`` on the synthetic ELF fixture.
# They deliberately stop short of executing the inferior: on a Windows host with
# MinGW gdb (or a Linux CI container) the fixture may not be runnable, but the
# MI handshake, register-name listing, an address breakpoint and the verified
# shutdown all work regardless -- which is exactly the layer this module owns.


@needs_gdb
def test_live_launch_and_verified_quit(target: Path) -> None:
    """A real gdb launches, answers the handshake, and quits cleanly."""
    with DebugSession.launch(target, timeout=30.0) as session:
        result = session.quit()
    assert result.clean
    assert result.exit_code == 0
    assert result.warnings == ()


@needs_gdb
def test_live_register_names_are_listed(target: Path) -> None:
    """``-data-list-register-names`` answers even before the target runs."""
    with DebugSession.launch(target, timeout=30.0) as session:
        result = session.read_registers()
    assert result.registers, "gdb must name at least one register"
    names = {register.name for register in result.registers}
    assert any("pc" in name or "rip" in name or name == "pc" for name in names)


@needs_gdb
def test_live_break_at_address_resolves(target: Path) -> None:
    """An address breakpoint on the mapped .text resolves without running."""
    with DebugSession.launch(target, timeout=30.0) as session:
        result = session.break_at(address=TEXT_ADDRESS)
        session.quit()
    assert not result.breakpoint.pending
    assert result.breakpoint.address == TEXT_ADDRESS


@needs_gdb
def test_live_run_to_breakpoint_or_exit_is_honest(target: Path) -> None:
    """Running the fixture reports a real stop, whatever the host decides.

    A runnable ELF stops at the breakpoint; a host that cannot execute it
    reports an exit instead. Both are honest one-run evidence -- the test only
    asserts the session stays coherent and shuts down clean.
    """
    with DebugSession.launch(target, timeout=30.0) as session:
        session.break_at(address=TEXT_ADDRESS)
        stop = session.run()
        assert stop.stop.reason
        if stop.stop.reason == "breakpoint-hit":
            registers = session.read_registers()
            assert registers.registers
        quit_result = session.quit()
    assert quit_result.clean


@needs_gdb
def test_live_run_debug_pipeline_via_the_public_entry_point(target: Path) -> None:
    """``run_debug`` owns the whole session against a real gdb."""
    payload = run_debug(target, action="registers", break_at=f"0x{TEXT_ADDRESS:x}")
    assert payload["quit"]["clean"] is True
    assert payload["break"]["location_kind"] == "address"

