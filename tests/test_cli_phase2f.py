"""CLI tests for the phase 2f commands: ``diff``, ``jump-table`` and
``cfg --resolve-indirect``.

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
from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000
RODATA_ADDRESS = 0x402000
#: 32 bytes of `ret` + nops: enough valid targets for a small pointer table.
PLAIN_CODE = b"\xc3" + b"\x90" * 0x1F
#: `test eax, eax; je 0x401006; nop; nop; ret` -> one conditional branch.
BRANCHY_CODE = bytes.fromhex("85c074029090c3")
#: `jmp qword ptr [rip + 0xffa]` (-> 0x402000); `ret` at 0x401006; `ret` at
#: 0x401010 and 0x401020, the two addresses the table below dispatches to.
DISPATCH_CODE = (
    bytes.fromhex("ff25fa0f0000")  # 0x401000: jmp qword ptr [rip + 0xffa]
    + b"\xc3"  # 0x401006: ret
    + b"\x90" * 9  # padding up to 0x401010
    + b"\xc3"  # 0x401010: ret
    + b"\x90" * 15  # padding up to 0x401020
    + b"\xc3"  # 0x401020: ret
)
#: Two absolute pointers plus the conventional zero terminator.
DISPATCH_TABLE = struct.pack("<QQQ", 0x401010, 0x401020, 0)

_SHSTRTAB_PLAIN = b"\x00.text\x00.shstrtab\x00"
_SHSTRTAB_TABLE = b"\x00.text\x00.rodata\x00.shstrtab\x00"

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(
    path: Path,
    code: bytes,
    *,
    entry: int | None = None,
    table: bytes | None = None,
    text_address: int = TEXT_ADDRESS,
    rodata_address: int = RODATA_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable with ``.text`` and optional ``.rodata``.

    Args:
        path: Destination file.
        code: Bytes of the executable ``.text`` section, mapped at ``text_address``.
        entry: ``e_entry`` value; defaults to ``text_address``.
        table: When given, the bytes of a read-only ``.rodata`` section mapped at
            ``rodata_address`` (pointer arrays start at its first byte).
        text_address: Virtual address of ``.text``.
        rodata_address: Virtual address of ``.rodata``.
    """
    has_rodata = table is not None
    shstrtab = _SHSTRTAB_TABLE if has_rodata else _SHSTRTAB_PLAIN
    text_offset = 0x40
    rodata_offset = _align(text_offset + len(code), 8)
    rodata = (table or b"").ljust(_align(len(table or b""), 8), b"\x00")
    shstrtab_offset = rodata_offset + len(rodata)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    entry_point = text_address if entry is None else entry
    shnum = 4 if has_rodata else 3
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        entry_point,   # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        shnum,         # e_shnum
        shnum - 1,     # e_shstrndx -> .shstrtab
    )
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ",
            1, 1, 6, text_address, text_offset, len(code), 0, 0, 16, 0,
        ),
    ]
    if has_rodata:
        sections.append(
            struct.pack(  # .rodata: SHF_ALLOC only
                "<IIQQQQIIQQ",
                7, 1, 2, rodata_address, rodata_offset, len(rodata), 0, 0, 8, 0,
            )
        )
    sections.append(
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ",
            15 if has_rodata else 7, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0,
        )
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    if has_rodata:
        blob[rodata_offset : rodata_offset + len(rodata)] = rodata
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


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


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _table_sample(tmp_path: Path, name: str, pointers: list[int]) -> Path:
    """Write a sample whose ``.rodata`` holds ``pointers`` plus a zero terminator."""
    table = struct.pack(f"<{len(pointers) + 1}Q", *pointers, 0)
    return _write_elf64(tmp_path / name, PLAIN_CODE, table=table)


# ---- diff ------------------------------------------------------------------


def test_diff_same_elf_twice_is_identical(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "same.bin", PLAIN_CODE)

    result = runner.invoke(app, ["diff", str(sample), str(sample)])

    assert result.exit_code == 0, result.stdout
    output = _plain(result.stdout)
    assert "Identical" in output
    assert "yes" in output
    # The count matrix reports zero deltas on all four rows.
    zero_rows = [row for row in _table_rows(result.stdout, 4) if row[1:] == ["0", "0", "0"]]
    assert len(zero_rows) == 4, result.stdout
    assert "no function deltas" in output


def test_diff_same_elf_json_is_identical(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "same_json.bin", PLAIN_CODE)

    result = runner.invoke(app, ["diff", str(sample), str(sample), "--json"])

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["identical"] is True
    assert payload["functions_added"] == []
    assert payload["functions_removed"] == []
    assert payload["sections_added"] == []
    assert payload["sections_removed"] == []


def test_diff_different_entry_points_reports_deltas(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "entry_left.bin", PLAIN_CODE)
    # Same bytes, different e_entry: the entry candidate moves by four bytes.
    right = _write_elf64(tmp_path / "entry_right.bin", PLAIN_CODE, entry=TEXT_ADDRESS + 4)

    result = runner.invoke(app, ["diff", str(left), str(right)])

    assert result.exit_code == 0, result.stdout
    output = _plain(result.stdout)
    assert "Identical" in output
    assert "Function deltas" in output
    delta_rows = [row for row in _table_rows(result.stdout, 3) if row[0].startswith("0x")]
    assert delta_rows, result.stdout
    changes = {row[2] for row in delta_rows}
    assert "added" in changes, result.stdout
    assert "removed" in changes, result.stdout
    addresses = {row[0] for row in delta_rows}
    assert "0x401000" in addresses, result.stdout
    assert "0x401004" in addresses, result.stdout


def test_diff_json_reports_the_same_deltas(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "entry_left_json.bin", PLAIN_CODE)
    right = _write_elf64(
        tmp_path / "entry_right_json.bin", PLAIN_CODE, entry=TEXT_ADDRESS + 4
    )

    result = runner.invoke(app, ["diff", str(left), str(right), "--json"])

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["identical"] is False
    assert [item["address"] for item in payload["functions_added"]] == ["0x401004"]
    assert [item["change"] for item in payload["functions_added"]] == ["added"]
    assert [item["address"] for item in payload["functions_removed"]] == ["0x401000"]
    assert [item["change"] for item in payload["functions_removed"]] == ["removed"]


def test_diff_max_functions_is_forwarded(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "bounded_left.bin", PLAIN_CODE)
    right = _write_elf64(tmp_path / "bounded_right.bin", PLAIN_CODE, entry=TEXT_ADDRESS + 4)

    result = runner.invoke(
        app, ["diff", str(left), str(right), "--max-functions", "2", "--json"]
    )

    assert result.exit_code == 0, result.stdout
    assert _payload(result.stdout)["evidence"]["extra"]["max_functions"] == 2


def test_diff_missing_file_exits_two(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "present.bin", PLAIN_CODE)

    result = runner.invoke(app, ["diff", str(sample), str(tmp_path / "missing.bin")])

    assert result.exit_code == 2, result.stdout
    assert "error" in _output(result)


# ---- jump-table ------------------------------------------------------------


def test_jump_table_lists_targets_from_rodata(tmp_path: Path) -> None:
    sample = _table_sample(tmp_path, "table.bin", [TEXT_ADDRESS, TEXT_ADDRESS + 0x10])

    result = runner.invoke(app, ["jump-table", str(sample), "--address", "0x402000"])

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 2) if row[1].startswith("0x")]
    assert rows == [["0", "0x401000"], ["1", "0x401010"]], result.stdout
    output = _plain(result.stdout)
    assert "pointer size: 8 bytes" in output
    assert "truncated: no" in output
    # The zero terminator that stopped the scan is reported, not silently dropped.
    assert "zero pointer" in output


def test_jump_table_address_accepts_decimal(tmp_path: Path) -> None:
    sample = _table_sample(tmp_path, "table_decimal.bin", [TEXT_ADDRESS])

    result = runner.invoke(app, ["jump-table", str(sample), "-a", str(RODATA_ADDRESS)])

    assert result.exit_code == 0, result.stdout
    assert "0x401000" in _plain(result.stdout)


def test_jump_table_json_payload_parses(tmp_path: Path) -> None:
    sample = _table_sample(tmp_path, "table_json.bin", [TEXT_ADDRESS, TEXT_ADDRESS + 0x10])

    result = runner.invoke(
        app, ["jump-table", str(sample), "--address", "0x402000", "--json"]
    )

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["table_address"] == "0x402000"
    assert payload["entry_count"] == 2
    assert payload["pointer_size"] == 8
    assert payload["truncated"] is False
    assert [entry["target"] for entry in payload["entries"]] == ["0x401000", "0x401010"]
    assert payload["evidence"]["source"] == "jump_table.pointer_array"


def test_jump_table_executable_only_flag_controls_the_scan(tmp_path: Path) -> None:
    sample = _table_sample(
        tmp_path, "table_rodata_pointer.bin", [TEXT_ADDRESS, RODATA_ADDRESS, TEXT_ADDRESS + 0x10]
    )

    default = runner.invoke(app, ["jump-table", str(sample), "--address", "0x402000"])
    relaxed = runner.invoke(
        app,
        ["jump-table", str(sample), "--address", "0x402000", "--no-executable-only"],
    )

    assert default.exit_code == 0, default.stdout
    assert relaxed.exit_code == 0, relaxed.stdout
    default_rows = [row for row in _table_rows(default.stdout, 2) if row[1].startswith("0x")]
    relaxed_rows = [row for row in _table_rows(relaxed.stdout, 2) if row[1].startswith("0x")]
    assert len(default_rows) == 1, default.stdout
    assert ".rodata" in _plain(default.stdout)
    assert [row[1] for row in relaxed_rows] == ["0x401000", "0x402000", "0x401010"]


def test_jump_table_entries_caps_the_table(tmp_path: Path) -> None:
    sample = _table_sample(
        tmp_path,
        "table_capped.bin",
        [TEXT_ADDRESS, TEXT_ADDRESS + 0x10, TEXT_ADDRESS + 0x20],
    )

    result = runner.invoke(
        app,
        ["jump-table", str(sample), "--address", "0x402000", "--entries", "1", "--json"],
    )

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["entry_count"] == 1
    assert payload["truncated"] is True


@pytest.mark.parametrize("bad_address", ["not-an-address", "0x900000"])
def test_jump_table_invalid_address_exits_nonzero(tmp_path: Path, bad_address: str) -> None:
    sample = _table_sample(tmp_path, "table_bad_address.bin", [TEXT_ADDRESS])

    result = runner.invoke(app, ["jump-table", str(sample), "--address", bad_address])

    assert result.exit_code == 2, result.stdout
    assert "error" in _output(result)


def test_jump_table_missing_address_option_exits_nonzero(tmp_path: Path) -> None:
    sample = _table_sample(tmp_path, "table_no_address.bin", [TEXT_ADDRESS])

    result = runner.invoke(app, ["jump-table", str(sample)])

    assert result.exit_code != 0
    assert "--address" in _output(result)


def test_jump_table_missing_file_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["jump-table", str(tmp_path / "missing.bin"), "--address", "0x402000"]
    )

    assert result.exit_code == 2, result.stdout


# ---- cfg --resolve-indirect ------------------------------------------------


def test_cfg_recursive_with_resolve_indirect_exits_zero(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "dispatch.bin", DISPATCH_CODE, table=DISPATCH_TABLE)

    result = runner.invoke(
        app, ["cfg", str(sample), "--traversal", "recursive", "--resolve-indirect"]
    )

    assert result.exit_code == 0, result.stdout
    rows = [row for row in _table_rows(result.stdout, 5) if row[0].startswith("0x")]
    assert rows, result.stdout
    # The two table targets become reachable blocks, so three blocks are reported.
    starts = {row[0] for row in rows}
    assert starts == {"0x401000", "0x401010", "0x401020"}, result.stdout


def test_cfg_recursive_with_resolve_indirect_json_successors(tmp_path: Path) -> None:
    sample = _write_elf64(
        tmp_path / "dispatch_json.bin", DISPATCH_CODE, table=DISPATCH_TABLE
    )

    result = runner.invoke(
        app,
        ["cfg", str(sample), "--traversal", "recursive", "--resolve-indirect", "--json"],
    )

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["block_count"] >= 3
    assert payload["blocks"][0]["successors"] == ["0x401010", "0x401020"], payload["blocks"][0]
    assert not any("indirect branch target" in warning for warning in payload["warnings"])


def test_cfg_recursive_without_resolve_indirect_keeps_indirect_jumps_unresolved(
    tmp_path: Path,
) -> None:
    sample = _write_elf64(
        tmp_path / "dispatch_plain.bin", DISPATCH_CODE, table=DISPATCH_TABLE
    )

    result = runner.invoke(app, ["cfg", str(sample), "--traversal", "recursive", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = _payload(result.stdout)
    assert payload["blocks"][0]["successors"] == []
    assert any("indirect branch target" in warning for warning in payload["warnings"])


@pytest.mark.parametrize("traversal_args", [[], ["--traversal", "linear"]])
def test_cfg_linear_with_resolve_indirect_exits_nonzero(
    tmp_path: Path, traversal_args: list[str]
) -> None:
    sample = _write_elf64(tmp_path / "linear.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), *traversal_args, "--resolve-indirect"])

    assert result.exit_code == 2, result.stdout
    output = _output(result)
    assert "--resolve-indirect" in output, output
    assert "recursive" in output, output


def test_cfg_linear_without_resolve_indirect_still_exits_zero(tmp_path: Path) -> None:
    sample = _write_elf64(tmp_path / "linear_plain.bin", BRANCHY_CODE)

    result = runner.invoke(app, ["cfg", str(sample), "--traversal", "linear"])

    assert result.exit_code == 0, result.stdout


def test_cfg_help_documents_resolve_indirect() -> None:
    result = runner.invoke(app, ["cfg", "--help"])

    assert result.exit_code == 0, result.stdout
    assert "--resolve-indirect" in _output(result)
