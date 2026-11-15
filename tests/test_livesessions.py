"""Tests for the persistent gdb session MCP tools (fake runners only).

``codevanta.mcp_server.ext_livesession`` never launches a real gdb in tests:
every start goes through an injected ``runner`` returning a canned gdb capture
(the same double pattern as ``tests/test_debugger.py``), so the full
reserve-id -> build -> write -> run -> parse -> register pipeline is driven
offline. The binary fixture is the tiny ELF64 builder with named symbols, so
the stored trace summary can attribute hits to functions.
"""

from __future__ import annotations

import shutil
import struct
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_livesession
from codevanta.mcp_server.ext_livesession import (
    MAX_SESSIONS,
    codevanta_debug_close,
    codevanta_debug_sessions,
    codevanta_debug_start,
    codevanta_debug_status,
)

#: Where the fixture's ``.text`` is mapped; both hits land in ``main``.
TEXT_ADDRESS = 0x401000
#: Start of the second fixture function, where the second hit lands.
SECOND_ADDRESS = 0x401002

#: ``mov eax, 42`` + ``ret``: a straight-line body both symbols can enclose.
CODE = bytes.fromhex("b82a000000") + b"\xc3"

#: ``(name, address)`` pairs of the fixture symbol table.
SYMBOLS = (("main", TEXT_ADDRESS), ("second", SECOND_ADDRESS))


def _canned_gdb_output() -> str:
    """Return a gdb capture as the generated script would print it."""
    lines = [
        f"Breakpoint 1 at 0x{TEXT_ADDRESS:x}",
        (
            f"HIT 0x{TEXT_ADDRESS:x} pc=0x{TEXT_ADDRESS:x} sp=0x7ffffffde0 "
            f"fp=0x7ffffffde0 ps=0x246 rip=0x{TEXT_ADDRESS:x} rax=0x1\n"
            f"BACKTRACE\n"
            f"#0  0x{TEXT_ADDRESS:016x} in main ()"
        ),
        (
            f"HIT 0x{SECOND_ADDRESS:x} pc=0x{SECOND_ADDRESS:x} sp=0x7ffffffdd0 "
            f"fp=0x7ffffffdd0 ps=0x202 rip=0x{SECOND_ADDRESS:x} rax=0x0\n"
            f"BACKTRACE\n"
            f"#0  0x{SECOND_ADDRESS:016x} in second ()"
        ),
        "[Inferior 1 (process 1234) exited normally]",
        "DONE 2 hits",
    ]
    return "\n".join(lines) + "\n"


def _write_elf64_with_symbols(
    path: Path,
    code: bytes,
    symbols: Sequence[tuple[str, int]],
    *,
    text_address: int = TEXT_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    Copied from ``tests/test_debugger.py``: ``.text`` is mapped at
    ``TEXT_ADDRESS`` and one global ``STT_FUNC`` per ``(name, address)`` is
    appended to an ``.symtab``/``.strtab`` pair, which is what gives the parsed
    trace its function names.
    """
    if not code:
        raise ValueError("code must not be empty")
    shstrtab = b"\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00"
    names: list[bytes] = []
    offsets: list[int] = []
    cursor = 1
    for name, _ in symbols:
        offsets.append(cursor)
        encoded = name.encode() + b"\x00"
        names.append(encoded)
        cursor += len(encoded)
    strtab = b"\x00" + b"".join(names)
    entries = [bytes(24)]  # STN_UNDEF
    for index, (_, value) in enumerate(symbols):
        entries.append(
            struct.pack(
                "<IBBHQQ",
                offsets[index],
                0x12,  # STB_GLOBAL | STT_FUNC
                0,  # st_other
                1,  # st_shndx: .text
                value,  # st_value
                len(code),  # st_size
            )
        )
    symtab = b"".join(entries)
    text_offset = 0x40
    strtab_offset = text_offset + len(code)
    symtab_offset = strtab_offset + len(strtab)
    shstrtab_offset = symtab_offset + len(symtab)
    shoff = shstrtab_offset + len(shstrtab)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ", 1, 1, 6, TEXT_ADDRESS, text_offset, len(code), 0, 0, 16, 0
        ),
        struct.pack(  # .strtab: SHT_STRTAB
            "<IIQQQQIIQQ", 7, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0
        ),
        struct.pack(  # .symtab: SHT_SYMTAB, link=.strtab, first global = 1
            "<IIQQQQIIQQ", 15, 2, 0, 0, symtab_offset, len(symtab), 2, 1, 8, 24
        ),
        struct.pack(  # .shstrtab: SHT_STRTAB
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
        4,  # e_shstrndx
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[strtab_offset : strtab_offset + len(strtab)] = strtab
    blob[symtab_offset : symtab_offset + len(symtab)] = symtab
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _fixture(tmp_path: Path) -> Path:
    """Write the fixture binary under ``tmp_path`` and return its path."""
    return _write_elf64_with_symbols(tmp_path / "sample.bin", CODE, SYMBOLS)


class _FakeOutcome:
    """``subprocess.CompletedProcess``-shaped stand-in."""

    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _RecordingRunner:
    """Runner double: returns a canned outcome and records what it was given."""

    def __init__(self, outcome: _FakeOutcome) -> None:
        self.outcome = outcome
        self.commands: list[tuple[str, ...]] = []
        self.script_at_call: str | None = None

    def __call__(self, command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        self.commands.append(tuple(command))
        self.script_at_call = str(command[4])
        script = Path(self.script_at_call)
        assert script.is_file(), "the session script must exist when the runner is called"
        assert script.read_text(encoding="utf-8").startswith("# CODEVANTA")
        return self.outcome


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the module-level registry and remove leftover session dirs."""
    yield
    for session in ext_livesession._REGISTRY.sessions.values():
        shutil.rmtree(session.work_dir, ignore_errors=True)
    ext_livesession._REGISTRY.sessions.clear()
    ext_livesession._REGISTRY.next_number = 1



def _start_session(sample: Path) -> tuple[_RecordingRunner, dict[str, Any]]:
    """Start one canned session on ``sample`` and return its runner + payload."""
    runner = _RecordingRunner(_FakeOutcome(0, _canned_gdb_output()))
    payload = codevanta_debug_start(
        str(sample), (TEXT_ADDRESS, SECOND_ADDRESS), runner=runner
    )
    return runner, payload


def test_start_status_close_happy_path(tmp_path: Path) -> None:
    """start registers dbg-001, status reports the stored run, close closes it."""
    sample = _fixture(tmp_path)
    runner, payload = _start_session(sample)

    assert payload["session_id"] == "dbg-001"
    assert payload["state"] == "completed"
    assert payload["path"] == str(sample)
    assert payload["addresses"] == [TEXT_ADDRESS, SECOND_ADDRESS]
    assert payload["exit_code"] == 0
    assert payload["total_hits"] == 2
    assert payload["unique_hit_count"] == 2
    assert payload["function_coverage"] == {
        f"0x{TEXT_ADDRESS:x}": 1,
        f"0x{SECOND_ADDRESS:x}": 1,
    }
    assert len(payload["recent_hits"]) == 2
    assert payload["recent_hits"][0]["function_name"] == "main"
    assert payload["script_removed"] is True
    assert payload["capture_present"] is True

    command = runner.commands[0]
    assert command[:4] == ("gdb", "-q", "-batch", "-x")
    assert command[-2:] == ("--args", str(sample))

    status = codevanta_debug_status("dbg-001")
    assert status["session_id"] == "dbg-001"
    assert status["state"] == "completed"
    assert status["total_hits"] == payload["total_hits"]
    assert status["recent_hits"] == payload["recent_hits"]

    closed = codevanta_debug_close("dbg-001")
    assert closed["session_id"] == "dbg-001"
    assert closed["state"] == "closed"
    assert closed["removed"] == [payload["capture_path"]]
    assert closed["work_dir_removed"] is True
    assert codevanta_debug_status("dbg-001")["state"] == "closed"

    listing = codevanta_debug_sessions()
    assert listing["count"] == 1
    assert listing["max_sessions"] == MAX_SESSIONS
    assert listing["sessions"][0] == {
        "session_id": "dbg-001",
        "state": "closed",
        "path": str(sample),
        "total_hits": 2,
    }


def test_close_cleans_up_script_and_capture(tmp_path: Path) -> None:
    """After close the script file, the capture file and the directory are gone."""
    sample = _fixture(tmp_path)
    _, payload = _start_session(sample)

    script_path = Path(payload["script_path"])
    capture_path = Path(payload["capture_path"])
    work_dir = capture_path.parent
    assert not script_path.exists()  # removed by the run itself
    assert capture_path.is_file()  # persisted for status/close

    codevanta_debug_close(payload["session_id"])

    assert not script_path.exists()
    assert not capture_path.exists()
    assert not work_dir.exists()



def test_unknown_session_id_raises_analysis_error_naming_the_id(tmp_path: Path) -> None:
    """status and close on an unknown id raise AnalysisError naming the id."""
    _fixture(tmp_path)

    with pytest.raises(AnalysisError) as status_error:
        codevanta_debug_status("dbg-999")
    assert "dbg-999" in str(status_error.value)
    assert "unknown session id" in str(status_error.value)

    with pytest.raises(AnalysisError) as close_error:
        codevanta_debug_close("dbg-999")
    assert "dbg-999" in str(close_error.value)

    # A closed id is stale: closing it again is a typed error naming the id.
    _, payload = _start_session(tmp_path / "sample.bin")
    codevanta_debug_close(payload["session_id"])
    with pytest.raises(AnalysisError) as stale_error:
        codevanta_debug_close(payload["session_id"])
    assert payload["session_id"] in str(stale_error.value)
    assert "already closed" in str(stale_error.value)


def test_max_sessions_rejects_the_ninth_session(tmp_path: Path) -> None:
    """The registry caps at MAX_SESSIONS records; the 9th start is refused."""
    sample = _fixture(tmp_path)

    def quick_start() -> dict[str, Any]:
        return codevanta_debug_start(
            str(sample),
            (TEXT_ADDRESS,),
            runner=_RecordingRunner(_FakeOutcome(0, "")),
        )

    for _ in range(MAX_SESSIONS):
        assert quick_start()["state"] == "completed"
    assert codevanta_debug_sessions()["count"] == MAX_SESSIONS

    with pytest.raises(AnalysisError) as excinfo:
        quick_start()
    message = str(excinfo.value)
    assert str(MAX_SESSIONS) in message
    assert "registry is full" in message


def test_sessions_listing_is_bounded_and_evicts_closed(tmp_path: Path) -> None:
    """The listing never exceeds MAX_SESSIONS and evicts the oldest closed."""
    sample = _fixture(tmp_path)

    def quick_start() -> dict[str, Any]:
        return codevanta_debug_start(
            str(sample),
            (TEXT_ADDRESS,),
            runner=_RecordingRunner(_FakeOutcome(0, "")),
        )

    for _ in range(MAX_SESSIONS):
        quick_start()
    codevanta_debug_close("dbg-001")
    codevanta_debug_close("dbg-002")

    payload = quick_start()  # evicts dbg-001, id counter stays monotonic

    assert payload["session_id"] == f"dbg-{MAX_SESSIONS + 1:03d}"
    listing = codevanta_debug_sessions()
    assert listing["count"] == MAX_SESSIONS
    ids = [record["session_id"] for record in listing["sessions"]]
    assert "dbg-001" not in ids
    assert ids == [f"dbg-{number:03d}" for number in range(2, MAX_SESSIONS + 2)]
    states = {record["session_id"]: record["state"] for record in listing["sessions"]}
    assert states["dbg-002"] == "closed"
    assert states[payload["session_id"]] == "completed"


def test_failed_start_registers_nothing(tmp_path: Path) -> None:
    """A missing gdb (FileNotFoundError runner) is a typed error, no session."""
    sample = _fixture(tmp_path)

    def missing_runner(command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        raise FileNotFoundError(2, "gdb")

    with pytest.raises(AnalysisError) as excinfo:
        codevanta_debug_start(str(sample), (TEXT_ADDRESS,), runner=missing_runner)
    assert "gdb" in str(excinfo.value)

    assert codevanta_debug_sessions()["count"] == 0
    leftover = list(Path(tempfile.gettempdir()).glob("codevanta-debug-session-*"))
    assert leftover == []


def test_start_refuses_empty_addresses_without_running(tmp_path: Path) -> None:
    """An empty address list is refused before the runner is ever called."""
    sample = _fixture(tmp_path)

    def boom(command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        raise AssertionError("runner must not run on invalid input")

    with pytest.raises(AnalysisError) as excinfo:
        codevanta_debug_start(str(sample), (), runner=boom)
    assert "empty" in str(excinfo.value)
    assert codevanta_debug_sessions()["count"] == 0

