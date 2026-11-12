"""CLI tests for the phase 2b commands: ``callgraph`` plus session annotations.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module so the tests stay self-contained and never depend on shared fixtures or
real-world binaries.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: ``a``: call 0x401010 ; ret — then 10 nops — then ``b``: call 0x401000 ; ret.
#: Two direct calls whose call sites are at or below a discovered candidate.
CALL_CODE = bytes.fromhex("e80b000000c3") + b"\x90" * 10 + bytes.fromhex("e8fbffffffc3")

_SESSION_ID = re.compile(r"session saved:\s*([0-9A-Za-z_-]+)")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = _align(text_offset + len(code), 8)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        text_address,  # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        3,             # e_shnum (null, .text, .shstrtab)
        2,             # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,             # sh_name -> ".text"
        1,             # sh_type = SHT_PROGBITS
        6,             # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,  # sh_addr
        text_offset,   # sh_offset
        len(code),     # sh_size
        0,             # sh_link
        0,             # sh_info
        16,            # sh_addralign
        0,             # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                 # sh_name -> ".shstrtab"
        3,                 # sh_type = SHT_STRTAB
        0,                 # sh_flags
        0,                 # sh_addr
        shstrtab_offset,   # sh_offset
        len(shstrtab),     # sh_size
        0,                 # sh_link
        0,                 # sh_info
        1,                 # sh_addralign
        0,                 # sh_entsize
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    # The 64 bytes at ``shoff`` stay zero: that is the SHT_NULL section header.
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def _payload(stdout: str) -> str:
    """Return the JSON object printed before the dim summary line."""
    start = stdout.index("{")
    end = stdout.rindex("}")
    return stdout[start : end + 1]


def _save_session(sample: Path) -> str:
    """Run ``session save`` and return the persisted session id."""
    saved = runner.invoke(app, ["session", "save", str(sample)])
    assert saved.exit_code == 0, saved.stdout
    match = _SESSION_ID.search(saved.stdout)
    assert match is not None, saved.stdout
    return match.group(1)


# ---- callgraph -------------------------------------------------------------


def test_callgraph_json_emits_nodes_and_edges(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls.bin", CALL_CODE)

    result = runner.invoke(app, ["callgraph", str(sample), "--format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(_payload(result.stdout))
    assert "nodes" in payload
    assert "edges" in payload
    assert payload["edges"], result.stdout
    assert payload["node_count"] == len(payload["nodes"])


def test_callgraph_dot_emits_digraph(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_dot.bin", CALL_CODE)

    result = runner.invoke(app, ["callgraph", str(sample), "--format", "dot"])

    assert result.exit_code == 0, result.stdout
    assert "digraph" in result.stdout
    assert "->" in result.stdout


def test_callgraph_output_file_receives_graphml(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_graphml.bin", CALL_CODE)
    target = tmp_path / "graph.graphml"

    result = runner.invoke(
        app, ["callgraph", str(sample), "--format", "graphml", "-o", str(target)]
    )

    assert result.exit_code == 0, result.stdout
    assert target.exists()
    assert "<graphml" in target.read_text(encoding="utf-8")
    assert "graph written" in result.stdout
    # The payload goes to the file, not to stdout.
    assert "<graphml" not in result.stdout


def test_callgraph_rejects_unknown_format(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_badformat.bin", CALL_CODE)

    result = runner.invoke(app, ["callgraph", str(sample), "--format", "yaml"])

    assert result.exit_code == 2, result.stdout


def test_callgraph_rejects_out_of_range_limits(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "calls_limits.bin", CALL_CODE)

    result = runner.invoke(app, ["callgraph", str(sample), "--limit-edges", "0"])

    assert result.exit_code == 2, result.stdout


# ---- session annotations ---------------------------------------------------


def test_session_annotate_then_notes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))
    # Widen the Rich console so table cells (notably the note) never wrap.
    monkeypatch.setenv("COLUMNS", "200")
    sample = _write_elf64(tmp_path / "plain.bin", CALL_CODE)
    session_id = _save_session(sample)

    annotated = runner.invoke(
        app, ["session", "annotate", session_id, "0x401000", "interesting call site"]
    )
    assert annotated.exit_code == 0, annotated.stdout
    assert "annotation saved" in annotated.stdout

    listed = runner.invoke(app, ["session", "notes", session_id])
    assert listed.exit_code == 0, listed.stdout
    assert "0x401000" in listed.stdout
    assert "interesting call site" in listed.stdout


def test_session_notes_without_annotation_is_friendly(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))
    sample = _write_elf64(tmp_path / "plain_empty.bin", CALL_CODE)
    session_id = _save_session(sample)

    result = runner.invoke(app, ["session", "notes", session_id])

    assert result.exit_code == 0, result.stdout
    assert "no notes" in result.stdout


def test_session_notes_unknown_session_exits_nonzero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))

    result = runner.invoke(app, ["session", "notes", "does-not-exist"])

    assert result.exit_code != 0


def test_session_annotate_unknown_session_exits_nonzero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))

    result = runner.invoke(app, ["session", "annotate", "does-not-exist", "0x401000", "note"])

    assert result.exit_code != 0


@pytest.mark.parametrize("bad_address", ["not-a-number", "0xzz", "0x", "12g4"])
def test_session_annotate_invalid_address_exits_nonzero(
    tmp_path: Path, monkeypatch, bad_address: str
) -> None:
    monkeypatch.setenv("CODEVANTA_DB", str(tmp_path / "sessions.db"))
    sample = _write_elf64(tmp_path / "plain_bad.bin", CALL_CODE)
    session_id = _save_session(sample)
    db = tmp_path / "sessions.db"
    before = db.stat().st_mtime_ns

    result = runner.invoke(app, ["session", "annotate", session_id, bad_address, "note"])

    assert result.exit_code != 0, result.stdout
    assert "invalid address" in result.stdout
    # Rejected before the store is touched, so the database stays untouched.
    assert db.stat().st_mtime_ns == before
