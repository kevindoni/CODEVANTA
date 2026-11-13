"""Replay the committed sample traces in ``samples/`` end to end.

``samples/gdb_trace.log`` and ``samples/frida_trace.jsonl`` are saved dynamic
sessions that hit two functions, ``main`` @ ``0x401000`` and ``helper`` @
``0x401002``. The binary itself is not committed: this module assembles it byte
by byte under ``tmp_path`` with the same ELF64 builder
``tests/test_cli_trace.py`` uses, so the committed traces always replay against
a fresh, reproducible fixture. The tests feed both files through the parser pair
the CLI uses and then smoke ``codevanta trace`` itself; no provider is ever
launched and nothing outside ``tmp_path`` is written.
"""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Sequence
from pathlib import Path

from typer.testing import CliRunner, Result

from codevanta.analysis.trace import parse_frida_trace, parse_gdb_trace
from codevanta.cli.main import app
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader

runner = CliRunner()

#: Where the committed sample traces live, relative to this file.
SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"
GDB_TRACE_PATH = SAMPLES_DIR / "gdb_trace.log"
FRIDA_TRACE_PATH = SAMPLES_DIR / "frida_trace.jsonl"

#: Where the fixture's ``.text`` is mapped; the committed traces address it.
TEXT_ADDRESS = 0x401000
#: Start of ``helper``, the second address the committed traces hit.
HELPER_ADDRESS = 0x401002

#: ``mov eax, 42`` + ``ret``: a straight-line function that is not interesting on
#: its own, but gives the two symbols a body to enclose.
CODE = bytes.fromhex("b82a000000") + b"\xc3"

#: ``(name, address)`` pairs of the fixture symbol table. Both sizes cover the
#: whole ``.text``, so attribution rests on the greatest start below the address.
SYMBOLS = (("main", TEXT_ADDRESS), ("helper", HELPER_ADDRESS))

#: What the committed traces record: ``main`` twice, ``helper`` once.
EXPECTED_COVERAGE = {TEXT_ADDRESS: 2, HELPER_ADDRESS: 1}

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``, keeping its layout."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _sample(tmp_path: Path) -> Path:
    """Write the ELF64 fixture the committed traces replay against."""
    return _write_elf64_with_symbols(tmp_path / "trace_fixture.bin", CODE, SYMBOLS)


def _fixture_info(tmp_path: Path) -> BinaryInfo:
    """Load the fixture through the real loader, the way ``codevanta trace`` does."""
    return BinaryLoader().load(_sample(tmp_path))


def _write_elf64_with_symbols(
    path: Path,
    code: bytes,
    symbols: Sequence[tuple[str, int]],
    *,
    text_address: int = TEXT_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    ``.text`` is mapped at :data:`TEXT_ADDRESS` and ``e_entry`` points at it, so
    the entry point and an explicit address name the same window; ``symbols``
    appends one global ``STT_FUNC`` per ``(name, address)`` to an
    ``.symtab``/``.strtab`` pair, which is what gives the trace table function
    names to print.
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


# ---- the fixture the committed traces replay against ------------------------


def test_fixture_carries_the_named_trace_targets(tmp_path: Path) -> None:
    """The fixture's symbol table must name exactly the addresses the traces hit."""
    info = _fixture_info(tmp_path)
    named = {(candidate.address, candidate.name) for candidate in discover_functions(info)}

    assert (TEXT_ADDRESS, "main") in named
    assert (HELPER_ADDRESS, "helper") in named


# ---- replaying the committed samples through the parsers --------------------


def test_committed_gdb_trace_replays_with_named_functions(tmp_path: Path) -> None:
    """``samples/gdb_trace.log`` replays into an attributed, unbounded gdb report."""
    info = _fixture_info(tmp_path)
    report = parse_gdb_trace(
        GDB_TRACE_PATH.read_text(encoding="utf-8"),
        info=info,
        functions=discover_functions(info),
    )

    assert report.provider == "gdb"
    assert report.total_hits == len(report.hits) == 3
    assert report.function_coverage == EXPECTED_COVERAGE
    assert {hit.function_name for hit in report.hits} == {"main", "helper"}
    for hit in report.hits:
        assert (hit.function, hit.function_name) in {
            (TEXT_ADDRESS, "main"),
            (HELPER_ADDRESS, "helper"),
        }
        assert hit.kind == "breakpoint"
        assert hit.registers, "a gdb hit keeps the register snapshot the script printed"
        assert hit.registers["rip"] == hit.address
        assert hit.backtrace, "a gdb hit keeps the frames its BACKTRACE printed"
    assert report.hits[0].backtrace == (TEXT_ADDRESS, HELPER_ADDRESS)
    assert {hit.registers["rax"] for hit in report.hits} == {0x0, 0x1, 0x2A}
    assert report.unique_addresses == (TEXT_ADDRESS, HELPER_ADDRESS)
    assert not report.truncated
    assert report.warnings == ()
    assert json.dumps(report.to_dict()), "TraceReport.to_dict() must be JSON-safe"
    assert json.dumps(report.hits[0].to_dict()), "TraceHit.to_dict() must be JSON-safe"


def test_committed_frida_trace_replays_with_named_functions(tmp_path: Path) -> None:
    """``samples/frida_trace.jsonl`` replays into an attributed, unbounded frida report."""
    info = _fixture_info(tmp_path)
    report = parse_frida_trace(
        FRIDA_TRACE_PATH.read_text(encoding="utf-8"),
        info=info,
        functions=discover_functions(info),
    )

    assert report.provider == "frida"
    assert report.total_hits == len(report.hits) == 3
    assert report.function_coverage == EXPECTED_COVERAGE
    assert {hit.function_name for hit in report.hits} == {"main", "helper"}
    for hit in report.hits:
        assert hit.function is not None, "every committed hit must be attributed"
        assert hit.kind == "message"
        assert hit.registers["tid"] == 4242
        assert "arg0" in hit.registers
        assert hit.backtrace == (), "frida messages carry no stack"
    assert {hit.registers["arg3"] for hit in report.hits} == {0x0, 0x2A}
    assert not report.truncated
    assert report.warnings == ()
    payload = report.to_dict()
    assert json.dumps(payload), "TraceReport.to_dict() must be JSON-safe"
    assert payload["provider"] == "frida"
    assert payload["unique_addresses"] == ["0x401000", "0x401002"]
    assert payload["function_coverage"] == {"0x401000": 2, "0x401002": 1}


# ---- CLI smoke: ``codevanta trace`` on the committed files ------------------


def test_cli_trace_replays_the_committed_gdb_sample(tmp_path: Path) -> None:
    """``codevanta trace`` auto-detects gdb in the committed log and exits 0."""
    fixture = _sample(tmp_path)

    result = runner.invoke(app, ["trace", str(fixture), "--input", str(GDB_TRACE_PATH)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "Trace hits by function (2)" in output, output
    assert "main" in output and "helper" in output, output
    assert "unattributed: 0" in output, output


def test_cli_trace_replays_the_committed_frida_sample_as_json(tmp_path: Path) -> None:
    """``codevanta trace --json`` auto-detects frida in the committed file and exits 0."""
    fixture = _sample(tmp_path)

    result = runner.invoke(
        app, ["trace", str(fixture), "--input", str(FRIDA_TRACE_PATH), "--json"]
    )

    assert result.exit_code == 0, _output(result)
    output = _plain(result.stdout)
    assert '"provider": "frida"' in output, output
    assert '"total_hits": 3' in output, output
    assert '"unattributed' not in output, output  # nothing was dropped silently
