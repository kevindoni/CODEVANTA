"""CLI tests for the phase 2g additions: ``jump-table --mode/--base`` and
``diff --deep``.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module, so the tests stay self-contained and never depend on shared fixtures or
real-world binaries. Nothing here executes the samples: every assertion is about
the bytes the CLI reads and the text or JSON it prints.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000
RODATA_ADDRESS = 0x402000
#: 48 bytes of `ret` + nops, so 0x401000 .. 0x40102f (and thus 0x401020) map.
PLAIN_CODE = b"\xc3" + b"\x90" * 0x2F
#: Same size, different instruction shapes: a deep-mode fingerprint must differ.
NOP_CODE = b"\x90" * 0x30

_SHSTRTAB_PLAIN = b"\x00.text\x00.shstrtab\x00"
_SHSTRTAB_RODATA = b"\x00.text\x00.rodata\x00.shstrtab\x00"



def _write_elf64(
    path: Path,
    code: bytes,
    *,
    entry: int | None = None,
    rodata: bytes | None = None,
    text_address: int = TEXT_ADDRESS,
    rodata_address: int = RODATA_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable with ``.text`` and optional ``.rodata``.

    Args:
        path: Destination file.
        code: Bytes of the executable ``.text`` section, mapped at ``text_address``.
        entry: ``e_entry`` value; defaults to ``text_address``.
        rodata: When given, the bytes of a read-only ``.rodata`` section mapped at
            ``rodata_address`` (jump tables start at its first byte).
        text_address: Virtual address of ``.text``.
        rodata_address: Virtual address of ``.rodata``.
    """
    has_rodata = rodata is not None
    shstrtab = _SHSTRTAB_RODATA if has_rodata else _SHSTRTAB_PLAIN
    text_offset = 0x40
    rodata_offset = _align(text_offset + len(code), 8)
    data = (rodata or b"").ljust(_align(len(rodata or b""), 8), b"\x00")
    shstrtab_offset = rodata_offset + len(data)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    entry_point = text_address if entry is None else entry
    shnum = 4 if has_rodata else 3
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        entry_point,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        shnum,  # e_shnum
        shnum - 1,  # e_shstrndx -> .shstrtab
    )
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ",
            1,
            1,
            6,
            text_address,
            text_offset,
            len(code),
            0,
            0,
            16,
            0,
        ),
    ]
    if has_rodata:
        sections.append(
            struct.pack(  # .rodata: SHF_ALLOC only
                "<IIQQQQIIQQ",
                7,
                1,
                2,
                rodata_address,
                rodata_offset,
                len(data),
                0,
                0,
                8,
                0,
            )
        )
    sections.append(
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ",
            15 if has_rodata else 7,
            3,
            0,
            0,
            shstrtab_offset,
            len(shstrtab),
            0,
            0,
            1,
            0,
        )
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    if has_rodata:
        blob[rodata_offset : rodata_offset + len(data)] = data
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


def _flat(result: Result) -> str:
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


def _relative_sample(
    tmp_path: Path, name: str, offsets: list[int], code: bytes = PLAIN_CODE
) -> Path:
    """Write a sample whose ``.rodata`` holds ``offsets`` as signed 32-bit slots."""
    table = struct.pack(f"<{len(offsets)}i", *offsets)
    return _write_elf64(tmp_path / name, code, rodata=table)


def _absolute_sample(tmp_path: Path, name: str, pointers: list[int]) -> Path:
    """Write a sample whose ``.rodata`` holds ``pointers`` plus a zero terminator."""
    return _write_elf64(
        tmp_path / name, PLAIN_CODE, rodata=struct.pack(f"<{len(pointers) + 1}Q", *pointers, 0)
    )

#: A truncated shape digest pair as the CLI renders it.
_DIGEST_PAIR = re.compile(r"[0-9a-f]{12} -> [0-9a-f]{12}")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


# ---- jump-table --mode / --base --------------------------------------------


def test_jump_table_relative_with_base_lists_targets(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "relative.bin", [0x10, 0x20])

    result = runner.invoke(
        app,
        [
            "jump-table",
            str(sample),
            "--address",
            "0x402000",
            "--mode",
            "relative",
            "--base",
            "0x401000",
        ],
    )

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 2) if row[1].startswith("0x")]
    # Each target is base + offset, decoded as a signed 32-bit value.
    assert rows == [["0", "0x401010"], ["1", "0x401020"]], result.stdout
    output = _flat(result)
    assert "mode: relative" in output, output
    assert "base: 0x401000" in output, output
    assert "pointer size: 4 bytes" in output, output


def test_jump_table_relative_applies_signed_offsets(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "relative_signed.bin", [8, -8])

    result = runner.invoke(
        app,
        [
            "jump-table",
            str(sample),
            "--address",
            "0x402000",
            "--mode",
            "relative",
            "--base",
            "0x401010",
        ],
    )

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 2) if row[1].startswith("0x")]
    # A negative slot is a delta, not a terminator: it resolves below the base.
    assert rows == [["0", "0x401018"], ["1", "0x401008"]], result.stdout
    assert "base: 0x401010" in _flat(result)


def test_jump_table_relative_without_base_exits_two(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "relative_no_base.bin", [0x10])

    result = runner.invoke(
        app, ["jump-table", str(sample), "--address", "0x402000", "--mode", "relative"]
    )

    assert result.exit_code == 2, result.stdout
    output = _flat(result)
    assert "error" in output, output
    assert "--base" in output, output


@pytest.mark.parametrize("bad_base", ["not-a-number", "-1"])
def test_jump_table_relative_with_invalid_base_exits_two(
    tmp_path: Path, bad_base: str
) -> None:
    sample = _relative_sample(tmp_path, "relative_bad_base.bin", [0x10])

    result = runner.invoke(
        app,
        [
            "jump-table",
            str(sample),
            "--address",
            "0x402000",
            "--mode",
            "relative",
            "--base",
            bad_base,
        ],
    )

    assert result.exit_code == 2, result.stdout
    output = _flat(result)
    assert "error" in output, output
    assert "base" in output, output


def test_jump_table_relative_json_reports_relative_evidence(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "relative_json.bin", [0x10, 0x20])

    result = runner.invoke(
        app,
        [
            "jump-table",
            str(sample),
            "--address",
            "0x402000",
            "--mode",
            "relative",
            "--base",
            "0x401000",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["pointer_size"] == 4
    assert [entry["target"] for entry in payload["entries"]] == ["0x401010", "0x401020"]
    assert payload["evidence"]["source"] == "jump_table.relative_offsets"


def test_jump_table_invalid_mode_exits_two(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "bad_mode.bin", [0x10])

    result = runner.invoke(
        app, ["jump-table", str(sample), "--address", "0x402000", "--mode", "sideways"]
    )

    assert result.exit_code == 2, result.stdout
    output = _flat(result)
    assert "error" in output, output
    assert "absolute" in output and "relative" in output, output


def test_jump_table_without_mode_flag_keeps_the_old_footer(tmp_path: Path) -> None:
    sample = _absolute_sample(
        tmp_path, "absolute_default.bin", [TEXT_ADDRESS, TEXT_ADDRESS + 0x10]
    )

    result = runner.invoke(app, ["jump-table", str(sample), "--address", "0x402000"])

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 2) if row[1].startswith("0x")]
    assert rows == [["0", "0x401000"], ["1", "0x401010"]], result.stdout
    output = _flat(result)
    assert "pointer size: 8 bytes" in output, output
    # Omitting the new flags must not add anything to the historical footer.
    assert "mode:" not in output, output
    assert "base:" not in output, output


def test_jump_table_explicit_absolute_mode_shows_mode_only(tmp_path: Path) -> None:
    sample = _absolute_sample(tmp_path, "absolute_explicit.bin", [TEXT_ADDRESS])

    result = runner.invoke(
        app, ["jump-table", str(sample), "--address", "0x402000", "--mode", "absolute"]
    )

    assert result.exit_code == 0, result.stdout
    output = _flat(result)
    assert "mode: absolute" in output, output
    assert "base:" not in output, output


def test_jump_table_mode_is_case_insensitive(tmp_path: Path) -> None:
    sample = _relative_sample(tmp_path, "relative_case.bin", [0x10, 0x20])

    result = runner.invoke(
        app,
        [
            "jump-table",
            str(sample),
            "--address",
            "4202496",  # 0x402000 in decimal
            "--mode",
            "Relative",
            "--base",
            "4198400",  # 0x401000 in decimal
        ],
    )

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 2) if row[1].startswith("0x")]
    assert rows == [["0", "0x401010"], ["1", "0x401020"]], result.stdout
    assert "mode: relative" in _flat(result)


def test_jump_table_help_documents_mode_and_base() -> None:
    result = runner.invoke(app, ["jump-table", "--help"])

    assert result.exit_code == 0, result.stdout
    output = _flat(result)
    assert "--mode" in output, output
    assert "--base" in output, output


# ---- diff --deep -----------------------------------------------------------


def test_diff_deep_same_file_is_identical(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "deep_same.bin", PLAIN_CODE)

    result = runner.invoke(app, ["diff", str(sample), str(sample), "--deep"])

    assert result.exit_code == 0, result.stdout
    output = _plain(result.stdout)
    assert "Identical" in output
    assert "no function deltas" in output, result.stdout
    # Identical content means no digest column and nothing to explain.
    assert "Digest" not in output, result.stdout


def test_diff_without_deep_still_reports_the_metadata_verdict(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "shallow_left.bin", PLAIN_CODE)
    right = _write_elf64(tmp_path / "shallow_right.bin", NOP_CODE)

    result = runner.invoke(app, ["diff", str(left), str(right)])

    assert result.exit_code == 0, result.stdout
    # Same address and size: without --deep the pair is structurally identical.
    assert "Identical" in _plain(result.stdout)
    assert "Digest" not in _plain(result.stdout), result.stdout


def test_diff_deep_reports_changed_functions_with_short_digests(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "deep_left.bin", PLAIN_CODE)
    right = _write_elf64(tmp_path / "deep_right.bin", NOP_CODE)

    result = runner.invoke(app, ["diff", str(left), str(right), "--deep"])

    assert result.exit_code == 0, result.stdout
    assert "Identical no" in _flat(result), result.stdout
    # The count matrix reports exactly one changed function and no additions.
    counts = {row[0]: row[1:] for row in _table_rows(result.stdout, 4)}
    assert counts["Functions"] == ["0", "0", "1"], result.stdout
    rows = [row for row in _table_rows(result.stdout, 4) if row[0].startswith("0x")]
    assert [row[0] for row in rows] == ["0x401000"], result.stdout
    assert [row[2] for row in rows] == ["changed"], result.stdout
    assert _DIGEST_PAIR.fullmatch(rows[0][3]), rows[0][3]
    left_digest, right_digest = rows[0][3].split(" -> ")
    assert left_digest != right_digest, rows[0][3]
    assert "equal digests are not byte equality" in _flat(result)


def test_diff_deep_json_carries_full_digests(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "deep_json_left.bin", PLAIN_CODE)
    right = _write_elf64(tmp_path / "deep_json_right.bin", NOP_CODE)

    result = runner.invoke(app, ["diff", str(left), str(right), "--deep", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["identical"] is False
    assert payload["functions_added"] == []
    assert payload["functions_removed"] == []
    changed = payload["functions_changed"]
    assert [delta["address"] for delta in changed] == ["0x401000"], changed
    assert len(changed[0]["left_digest"]) == 64
    assert len(changed[0]["right_digest"]) == 64
    assert changed[0]["left_digest"] != changed[0]["right_digest"]
    # Deep mode is recorded in the evidence, not by inventing new top-level keys.
    assert payload["evidence"]["extra"]["deep"] is True


def test_diff_deep_help_documents_the_flag() -> None:
    result = runner.invoke(app, ["diff", "--help"])

    assert result.exit_code == 0, result.stdout
    assert "--deep" in _flat(result)

