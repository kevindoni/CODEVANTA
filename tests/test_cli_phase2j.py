"""CLI tests for the phase 2j additions: the ``struct`` signedness footer line
and ``diff --semantic`` / ``diff --threshold``.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module, so the tests stay self-contained and never depend on a compiler, a
shared fixture or a real-world binary. Nothing here executes the samples: every
assertion is about the bytes the CLI reads and the text or JSON it prints.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000

# ---- struct fixture bytes --------------------------------------------------

#: ``movsx rax, byte ptr [rdi + 0x10]`` -- 1-byte field 0x10 read, signed hint.
MOVSX_RAX_RDI_10 = bytes.fromhex("480fbe4710")
#: ``movzx eax, word ptr [rdi + 0x18]`` -- 2-byte field 0x18 read, unsigned hint.
MOVZX_EAX_RDI_18 = bytes.fromhex("0fb74718")
#: ``mov qword ptr [rdi + 0x20], rbx`` -- 8-byte field 0x20 written, no hint.
MOV_RDI_20_RBX = bytes.fromhex("48895f20")
#: ``mov rax, qword ptr [rdi + 0x10]`` -- 8-byte field 0x10 read, no hint.
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")
#: ``mov qword ptr [rdi + 0x18], rbx`` -- 8-byte field 0x18 written, no hint.
MOV_RDI_18_RBX = bytes.fromhex("48895f18")
#: ``mov rax, qword ptr [rdi + 0x20]`` -- 8-byte field 0x20 read, no hint.
MOV_RAX_RDI_20 = bytes.fromhex("488b4720")
#: ``ret``
RET = bytes.fromhex("c3")

#: Two sign-hinting accesses plus one plain one: hints at 0x10 and 0x18 only.
SIGNED_HINTS = MOVSX_RAX_RDI_10 + MOVZX_EAX_RDI_18 + MOV_RDI_20_RBX + RET
#: Three plain accesses: no mnemonic hints a signedness, so the footer says none.
NO_HINTS = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_RAX_RDI_20 + RET

#: ``mov eax, 42; ret`` -- the same shape in both diff samples.
MOV_RET_42 = bytes.fromhex("b82a000000c3")

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
#: One semantic detail line as the CLI renders it.
_SIMILARITY_LINE = re.compile(r"semantic pair 0x[0-9a-f]+ -> 0x[0-9a-f]+ .* similarity 1\.0000")


def _write_elf64(path: Path, code: bytes, *, entry: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    The ``.text`` section is mapped at ``entry`` (and ``e_entry`` points at it),
    so a different ``entry`` moves the whole function candidate -- which is what
    the semantic-pairing fixtures need.
    """
    if not code:
        raise ValueError("code must not be empty")
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = text_offset + len(code)
    shoff = shstrtab_offset + len(shstrtab)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        entry,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        3,  # e_shnum: null, .text, .shstrtab
        2,  # e_shstrndx
    )
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ", 1, 1, 6, entry, text_offset, len(code), 0, 0, 16, 0
        ),
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ", 7, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
        ),
    ]
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, name: str, code: bytes) -> Path:
    """Write one fixture binary under ``tmp_path``."""
    return _write_elf64(tmp_path / name, code)


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(stdout: str) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _table_rows(stdout: str, columns: int) -> list[list[str]]:
    """Return the cell lists of every data row in a Rich table."""
    rows: list[list[str]] = []
    for line in _plain(stdout).splitlines():
        stripped = line.strip()
        for bar in ("\u2502", "|"):
            if stripped.count(bar) != columns + 1:
                continue
            cells = [cell.strip() for cell in stripped.strip(bar).split(bar)]
            if len(cells) == columns:
                rows.append(cells)
            break
    return rows


def _field_rows(result: Result) -> list[list[str]]:
    """Return the Offset/Width/Reads/Writes rows of the ``struct`` table."""
    return [row for row in _table_rows(result.stdout, 4) if row[0].startswith(("0x", "-0x"))]


# ---- struct: signed footer line --------------------------------------------


def test_struct_signed_footer_lists_the_hinted_offsets(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "signed_hints.bin", SIGNED_HINTS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "signed: 0x10 signed, 0x18 unsigned" in output, output
    # The hint is one footer line, never a new table column.
    assert output.count("signed:") == 1, output
    assert _field_rows(result) == [
        ["0x10", "1", "1", "0"],
        ["0x18", "2", "1", "0"],
        ["0x20", "8", "0", "1"],
    ], result.stdout


def test_struct_signed_footer_says_none_without_hints(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "no_hints.bin", NO_HINTS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "signed: none" in output, output
    assert output.count("signed:") == 1, output
    # A hint-free run invents no limitation beyond the footer itself.
    assert "warning:" not in output, output
    # The phase 2i/2h footer lines are untouched.
    assert "alignment: 8" in output, output
    assert _field_rows(result) == [
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
        ["0x20", "8", "1", "0"],
    ], result.stdout


def test_struct_signed_footer_keeps_the_four_table_columns(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "columns.bin", SIGNED_HINTS)

    result = runner.invoke(app, ["struct", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    header = [line for line in _plain(result.stdout).splitlines() if "Width" in line]
    assert len(header) == 1, result.stdout
    assert "Signed" not in output, output
    # The signed line closes the dim footer block.
    assert output.index("signed:") > output.index("alignment:"), output


# ---- diff --semantic -------------------------------------------------------


def test_diff_semantic_pairs_moved_code_and_prints_the_score(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "left.bin", MOV_RET_42, entry=TEXT_ADDRESS)
    right = _write_elf64(tmp_path / "right.bin", MOV_RET_42, entry=TEXT_ADDRESS + 0x10)

    result = runner.invoke(app, ["diff", str(left), str(right), "--semantic"])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # The move is one changed entry, not a removal plus an addition.
    assert "semantic pair 0x401000 -> 0x401010 (<unknown>): similarity 1.0000" in output, output
    rows = [row for row in _table_rows(result.stdout, 3) if row[0].startswith("0x")]
    assert rows == [["0x401010", "<unknown>", "changed"]], result.stdout
    counts = {row[0]: row[1:] for row in _table_rows(result.stdout, 4)}
    assert counts["Functions"] == ["0", "0", "1"], result.stdout
    # The table keeps its columns: no digest and no similarity column.
    assert "Digest" not in output, output
    assert "Similarity" not in output, output
    # The score is reported by exactly one detail line.
    assert output.count("similarity") == 1, output


def test_diff_without_semantic_reports_the_same_move_structurally(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "plain_left.bin", MOV_RET_42, entry=TEXT_ADDRESS)
    right = _write_elf64(tmp_path / "plain_right.bin", MOV_RET_42, entry=TEXT_ADDRESS + 0x10)

    result = runner.invoke(app, ["diff", str(left), str(right)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "similarity" not in output, output
    rows = [row for row in _table_rows(result.stdout, 3) if row[0].startswith("0x")]
    assert rows == [
        ["0x401000", "<unknown>", "removed"],
        ["0x401010", "<unknown>", "added"],
    ], result.stdout


def test_diff_semantic_accepts_both_threshold_bounds(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "bound_left.bin", MOV_RET_42, entry=TEXT_ADDRESS)
    right = _write_elf64(tmp_path / "bound_right.bin", MOV_RET_42, entry=TEXT_ADDRESS + 0x10)

    for threshold in ("0", "1"):
        result = runner.invoke(
            app,
            ["diff", str(left), str(right), "--semantic", "--threshold", threshold],
        )

        assert result.exit_code == 0, _output(result)
        assert _SIMILARITY_LINE.search(_output(result)), _output(result)


def test_diff_semantic_detail_line_follows_the_function_table(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "order_left.bin", MOV_RET_42, entry=TEXT_ADDRESS)
    right = _write_elf64(tmp_path / "order_right.bin", MOV_RET_42, entry=TEXT_ADDRESS + 0x10)

    result = runner.invoke(app, ["diff", str(left), str(right), "--semantic"])

    assert result.exit_code == 0, _output(result)
    lines = [line.strip() for line in _plain(result.stdout).splitlines() if line.strip()]
    scored = [index for index, line in enumerate(lines) if line.startswith("semantic pair")]
    assert len(scored) == 1, result.stdout
    assert lines[scored[0]].startswith("semantic pair 0x401000 -> 0x401010"), result.stdout
    # One dim detail line per matched function, printed after the delta row.
    delta_row = max(
        index
        for index, line in enumerate(lines)
        if "0x401010" in line and ("\u2502" in line or "|" in line)
    )
    assert scored[0] > delta_row, result.stdout


def test_diff_semantic_json_carries_the_similarity(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "json_left.bin", MOV_RET_42, entry=TEXT_ADDRESS)
    right = _write_elf64(tmp_path / "json_right.bin", MOV_RET_42, entry=TEXT_ADDRESS + 0x10)

    result = runner.invoke(app, ["diff", str(left), str(right), "--semantic", "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["identical"] is False
    assert payload["functions_added"] == []
    assert payload["functions_removed"] == []
    changed = payload["functions_changed"]
    assert [delta["address"] for delta in changed] == ["0x401010"], changed
    assert changed[0]["similarity"] == 1.0
    assert changed[0]["left"]["address"] == "0x401000"
    assert payload["evidence"]["extra"]["semantic"] is True
    assert payload["evidence"]["extra"]["semantic_threshold"] == 0.9


# ---- diff --threshold validation -------------------------------------------


def test_diff_threshold_above_one_exits_two(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "threshold_high.bin", MOV_RET_42)

    result = runner.invoke(app, ["diff", str(sample), str(sample), "--threshold", "1.01"])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "error:" in output, output
    assert "threshold" in output and "1.01" in output, output
    # No table is printed for an invalid input.
    assert "Deltas" not in output, output


def test_diff_threshold_below_zero_exits_two(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "threshold_low.bin", MOV_RET_42)

    result = runner.invoke(app, ["diff", str(sample), str(sample), "--threshold", "-0.01"])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "threshold" in output and "-0.01" in output, output


def test_diff_threshold_is_validated_even_without_semantic(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "threshold_shallow.bin", MOV_RET_42)

    result = runner.invoke(app, ["diff", str(sample), str(sample), "--threshold", "2"])

    assert result.exit_code == 2, _output(result)
    assert "threshold" in _output(result), _output(result)


def test_diff_threshold_is_checked_before_the_files_are_loaded(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"

    result = runner.invoke(
        app, ["diff", str(missing), str(missing), "--semantic", "--threshold", "1.5"]
    )

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    # The threshold error wins: neither path was opened.
    assert "threshold" in output, output
    assert "missing.bin" not in output, output


def test_diff_help_documents_the_semantic_flags() -> None:
    result = runner.invoke(app, ["diff", "--help"])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "--semantic" in output, output
    assert "--threshold" in output, output
