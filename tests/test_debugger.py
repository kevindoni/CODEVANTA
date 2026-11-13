"""Tests for the gdb runner: build -> write -> run -> parse -> cleanup.

``codevanta.analysis.debugger`` is the only layer that needs a real gdb, and
this machine (like many CI hosts) has none. Every test therefore drives
:func:`run_breakpoints` through an injected ``runner`` callable that either
returns a canned gdb capture or raises the exception a real ``subprocess.run``
would raise (``FileNotFoundError`` for a missing gdb,
``subprocess.TimeoutExpired`` for a hung session). The binary fixture is the
tiny ELF64 builder ``tests/test_cli_trace.py`` uses, so the parsed report can
attribute its hits to named functions and no test launches a process.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from collections.abc import Sequence
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.debugger import (
    DEFAULT_TIMEOUT,
    GdbRunResult,
    gdb_available,
    run_breakpoints,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

#: Where the fixture's ``.text`` is mapped; the first and third hits land here.
TEXT_ADDRESS = 0x401000
#: Start of the second fixture function, where the second hit lands.
SECOND_ADDRESS = 0x401002

#: ``mov eax, 42`` + ``ret``: a straight-line body both symbols can enclose.
CODE = bytes.fromhex("b82a000000") + b"\xc3"

#: ``(name, address)`` pairs of the fixture symbol table.
SYMBOLS = (("main", TEXT_ADDRESS), ("second", SECOND_ADDRESS))


def _canned_gdb_output() -> str:
    """Return a gdb capture as the generated script would print it.

    Three well-formed hits (``main`` twice, ``second`` once), each with a
    ``BACKTRACE`` marker and ``bt`` frames, plus one malformed ``HIT`` line
    (``HIT`` prefix, no address) so the parse has exactly one warning, all
    wrapped in the noise gdb adds on its own.
    """
    hits = [
        (
            f"HIT 0x{TEXT_ADDRESS:x} pc=0x{TEXT_ADDRESS:x} sp=0x7ffffffde0 "
            f"fp=0x7ffffffde0 ps=0x246 rip=0x{TEXT_ADDRESS:x} rax=0x1\n"
            f"BACKTRACE\n"
            f"#0  0x{TEXT_ADDRESS:016x} in main ()\n"
            f"#1  0x{TEXT_ADDRESS + 0x10:016x} in ?? ()"
        ),
        (
            f"HIT 0x{SECOND_ADDRESS:x} pc=0x{SECOND_ADDRESS:x} sp=0x7ffffffdd0 "
            f"fp=0x7ffffffdd0 ps=0x202 rip=0x{SECOND_ADDRESS:x} rax=0x0\n"
            f"BACKTRACE\n"
            f"#0  0x{SECOND_ADDRESS:016x} in second ()"
        ),
        (
            f"HIT 0x{TEXT_ADDRESS:x} pc=0x{TEXT_ADDRESS:x} sp=0x7ffffffdc0 "
            f"fp=0x7ffffffdc0 ps=0x246 rip=0x{TEXT_ADDRESS:x} rax=0x2\n"
            f"BACKTRACE\n"
            f"#0  0x{TEXT_ADDRESS:016x} in main ()"
        ),
    ]
    lines = [
        f"Breakpoint 1 at 0x{TEXT_ADDRESS:x}",
        *hits,
        "HIT broken pc=0x" + f"{TEXT_ADDRESS:x}",  # malformed: no usable address
        "[Inferior 1 (process 1234) exited normally]",
        "DONE 3 hits",
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

    Copied from ``tests/test_cli_trace.py``: ``.text`` is mapped at
    :data:`TEXT_ADDRESS` and ``e_entry`` points at it; ``symbols`` appends one
    global ``STT_FUNC`` per ``(name, address)`` to an ``.symtab``/``.strtab``
    pair, which is what gives the parsed trace its function names.
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


def _fixture(tmp_path: Path) -> tuple[Path, BinaryInfo]:
    """Write the fixture binary under ``tmp_path`` and load its metadata."""
    sample = _write_elf64_with_symbols(tmp_path / "sample.bin", CODE, SYMBOLS)
    return sample, BinaryLoader().load(sample)


class _FakeOutcome:
    """Stand-in for ``subprocess.CompletedProcess`` with fixed attributes."""

    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _RecordingRunner:
    """Runner double: returns a canned outcome and records what it was given."""

    def __init__(self, outcome: _FakeOutcome, *, fail_if_called: bool = False) -> None:
        self.outcome = outcome
        self.fail_if_called = fail_if_called
        self.commands: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, Any]] = []
        self.script_at_call: str | None = None

    def __call__(self, command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        if self.fail_if_called:
            raise AssertionError("runner must not be called before inputs are validated")
        self.commands.append(tuple(command))
        self.kwargs.append(dict(kwargs))
        # The script must exist on disk by the time gdb would read it.
        self.script_at_call = str(command[4])
        script = Path(self.script_at_call)
        assert script.is_file(), "the session script must exist when the runner is called"
        assert script.read_text(encoding="utf-8").startswith("# CODEVANTA")
        return self.outcome


def test_gdb_available_is_false_where_gdb_is_missing() -> None:
    """On a machine without gdb the probe reports ``False``."""
    if shutil.which("gdb") is not None:
        pytest.skip("gdb is installed on this machine")
    assert gdb_available() is False


def test_missing_gdb_raises_analysis_error_naming_gdb(tmp_path: Path) -> None:
    """A runner that cannot find gdb becomes an AnalysisError naming gdb."""

    def missing_runner(command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        raise FileNotFoundError(2, "gdb")

    sample, info = _fixture(tmp_path)
    with pytest.raises(AnalysisError) as excinfo:
        run_breakpoints(sample, info, (TEXT_ADDRESS,), runner=missing_runner)
    assert "gdb" in str(excinfo.value)


def test_injected_runner_parses_a_canned_session(tmp_path: Path) -> None:
    """Canned gdb output flows through the full run -> parse pipeline."""
    sample, info = _fixture(tmp_path)
    runner = _RecordingRunner(_FakeOutcome(0, _canned_gdb_output()))

    result = run_breakpoints(sample, info, (TEXT_ADDRESS, SECOND_ADDRESS), runner=runner)

    assert isinstance(result, GdbRunResult)
    assert result.exit_code == 0
    assert result.warnings == ()
    assert result.raw_output_path is None

    report = result.report
    assert report.provider == "gdb"
    assert len(report.hits) == 3
    assert report.total_hits == 3
    assert not report.truncated
    assert len(report.warnings) == 1
    assert "HIT" in report.warnings[0]
    assert report.unique_addresses == (TEXT_ADDRESS, SECOND_ADDRESS)
    assert [hit.function_name for hit in report.hits] == ["main", "second", "main"]
    assert report.function_coverage == {TEXT_ADDRESS: 2, SECOND_ADDRESS: 1}
    assert report.hits[0].backtrace == (TEXT_ADDRESS, TEXT_ADDRESS + 0x10)
    assert report.hits[0].registers["pc"] == TEXT_ADDRESS

    command = runner.commands[0]
    assert command[:4] == ("gdb", "-q", "-batch", "-x")
    assert command[-2:] == ("--args", str(sample))
    assert command == result.command
    assert runner.kwargs[0]["capture_output"] is True
    assert runner.kwargs[0]["text"] is True
    assert runner.kwargs[0]["timeout"] == DEFAULT_TIMEOUT

    # The script existed while gdb would have read it and is gone afterwards.
    script_path = Path(result.script_path)
    assert runner.script_at_call == str(script_path)
    assert not script_path.exists()


def test_timeout_raises_analysis_error_naming_timeout(tmp_path: Path) -> None:
    """A session that exceeds its budget raises AnalysisError naming the timeout."""

    def timeout_runner(command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        assert kwargs["timeout"] == 2.5  # the budget must reach the real runner
        raise subprocess.TimeoutExpired(cmd=list(command), timeout=2.5)

    sample, info = _fixture(tmp_path)
    with pytest.raises(AnalysisError) as excinfo:
        run_breakpoints(
            sample, info, (TEXT_ADDRESS,), timeout=2.5, runner=timeout_runner
        )
    assert "timeout" in str(excinfo.value)


def test_nonzero_exit_still_parses_with_a_warning(tmp_path: Path) -> None:
    """A non-zero gdb exit is a warning, not an error: output is still parsed."""
    sample, info = _fixture(tmp_path)
    runner = _RecordingRunner(_FakeOutcome(1, _canned_gdb_output()))

    result = run_breakpoints(sample, info, (TEXT_ADDRESS,), runner=runner)

    assert result.exit_code == 1
    assert len(result.warnings) == 1
    assert "code 1" in result.warnings[0]
    assert len(result.report.hits) == 3
    assert len(result.report.warnings) == 1


def test_to_dict_round_trips_through_json(tmp_path: Path) -> None:
    """``to_dict`` is JSON-safe and survives a dumps/loads round trip."""
    sample, info = _fixture(tmp_path)
    runner = _RecordingRunner(_FakeOutcome(0, _canned_gdb_output()))
    result = run_breakpoints(sample, info, (TEXT_ADDRESS,), runner=runner)
    with pytest.raises(FrozenInstanceError):
        result.exit_code = 5

    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["exit_code"] == 0
    assert payload["command"] == list(result.command)
    assert payload["script_path"] == result.script_path
    assert payload["raw_output_path"] is None
    assert payload["warnings"] == []
    assert payload["report"]["provider"] == "gdb"
    assert len(payload["report"]["hits"]) == 3
    assert payload["report"]["function_coverage"] == {
        f"0x{TEXT_ADDRESS:x}": 2,
        f"0x{SECOND_ADDRESS:x}": 1,
    }


def test_addresses_are_validated_before_anything_runs(tmp_path: Path) -> None:
    """Empty, non-int and bool addresses are refused without calling the runner."""
    sample, info = _fixture(tmp_path)
    runner = _RecordingRunner(_FakeOutcome(0, ""), fail_if_called=True)

    with pytest.raises(AnalysisError) as empty:
        run_breakpoints(sample, info, (), runner=runner)
    assert "empty" in str(empty.value)

    with pytest.raises(AnalysisError) as not_int:
        run_breakpoints(sample, info, (f"0x{TEXT_ADDRESS:x}",), runner=runner)
    assert "must be an int" in str(not_int.value)

    with pytest.raises(AnalysisError) as boolean:
        run_breakpoints(sample, info, (True,), runner=runner)
    assert "must be an int" in str(boolean.value)

    assert runner.commands == []


def test_script_dir_keeps_the_directory_but_not_the_script(tmp_path: Path) -> None:
    """An explicit ``script_dir`` hosts the script, which is still cleaned up."""
    sample, info = _fixture(tmp_path)
    holder = tmp_path / "scripts"
    holder.mkdir()
    runner = _RecordingRunner(_FakeOutcome(0, _canned_gdb_output()))

    result = run_breakpoints(
        sample, info, (TEXT_ADDRESS,), runner=runner, script_dir=holder
    )

    assert Path(result.script_path).parent == holder
    assert not Path(result.script_path).exists()
    assert holder.is_dir()
