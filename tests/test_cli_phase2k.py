"""CLI tests for the phase 2k additions: the repeatable ``struct --address``.

One ``--address`` keeps the phase 2j single-window sweep; two or more are merged
by :func:`codevanta.analysis.type_recovery.suggest_structs` into one field per
offset and add a single ``windows:`` footer line. Every fixture is an ELF64 file
assembled byte-by-byte in this module, so the tests stay self-contained and never
depend on a compiler, a shared fixture or a real-world binary. Nothing here
executes the samples: the assertions are about the bytes the CLI reads and the
text or JSON it prints.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from typer.testing import CliRunner, Result

import codevanta.cli.main as cli_main
from codevanta.analysis.type_recovery import DEFAULT_MAX_FIELDS, MAX_MERGED_WINDOWS
from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000

# ---- instruction bytes -----------------------------------------------------

#: ``mov rax, qword ptr [rdi + 0x10]`` -- 8-byte field 0x10 read through rdi.
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")
#: ``mov qword ptr [rdi + 0x18], rbx`` -- 8-byte field 0x18 written through rdi.
MOV_RDI_18_RBX = bytes.fromhex("48895f18")
#: ``mov eax, dword ptr [rsi + 8]`` -- 4-byte field 0x8 read through rsi.
MOV_EAX_RSI_08 = bytes.fromhex("8b4608")
#: ``ret``
RET = bytes.fromhex("c3")


def _mov_eax_rdi(displacement: int) -> bytes:
    """Return ``mov eax, dword ptr [rdi + displacement]`` (``8B 47 ib``).

    The ModRM byte is ``01 000 111``: a signed 8-bit displacement, ``eax`` as the
    destination and ``rdi`` as the base, so ``displacement`` has to stay inside
    ``0x00 .. 0x7f`` for the encoding to be valid.
    """
    if not 0 <= displacement <= 0x7F:
        raise ValueError("the disp8 form only covers 0x00 .. 0x7f")
    return bytes([0x8B, 0x47, displacement])


def _window_with_offsets(offsets: range) -> bytes:
    """Return one 4-byte read per offset in ``offsets``, followed by ``ret``."""
    return b"".join(_mov_eax_rdi(offset) for offset in offsets) + RET


#: Window one: one 8-byte read of 0x10, then ``ret`` (5 bytes).
WINDOW_ONE = MOV_RAX_RDI_10 + RET
#: Window two: a write of 0x18 through rdi and a read of 0x8 through rsi.
WINDOW_TWO = MOV_RDI_18_RBX + MOV_EAX_RSI_08 + RET
#: Both windows back to back: the second starts at ``TEXT_ADDRESS + 5``.
TWO_WINDOWS = WINDOW_ONE + WINDOW_TWO
SECOND_WINDOW = TEXT_ADDRESS + len(WINDOW_ONE)

#: Instruction budget that keeps each window's sweep inside its own bytes.
WINDOW_BUDGET = "2"

#: Cells and footer text of one single-window run of ``WINDOW_ONE``. Rich picks a
#: different box style per platform (Windows legacy vs Unix), so the rendering is
#: asserted by content instead of by box art.
SINGLE_WINDOW_ROWS = [["0x10", "8", "1", "0"]]
SINGLE_WINDOW_FOOTERS = (
    "Struct at 0x401000",
    "base registers: rdi - fields: 1",
    "instructions: 2 - max fields: 64 - truncated: no",
    "alignment: unknown",
    "arrays: none",
    "signed: none",
)

#: Cells and footer text of the two-window merge of :data:`TWO_WINDOWS`: one field
#: per offset, the merge's own field cap, no base-register union (the merge records
#: none) and one ``windows:`` footer line.
MERGED_ROWS = [
    ["0x8", "4", "1", "0"],
    ["0x10", "8", "1", "0"],
    ["0x18", "8", "0", "1"],
]
MERGED_FOOTERS = (
    "Struct at 0x401000",
    "base registers: not recorded by the merge - fields: 3",
    "instructions: 4 - max fields: 64 - truncated: no",
    "windows: 2 (0x401000, 0x401005)",
    "alignment: 8",
    "arrays: none",
    "signed: none",
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")



def _write_elf64(path: Path, code: bytes, *, entry: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    ``.text`` is mapped at ``entry`` and ``e_entry`` points at it, so the entry
    point and an explicit ``--address`` name the same window.
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


def _assert_rendering(
    stdout: str,
    rows: list[list[str]],
    footers: tuple[str, ...],
    *,
    merged: bool,
) -> None:
    """Assert a ``struct`` rendering by cells and footer text, not by box art.

    Rich draws its tables with a platform-dependent box style (legacy Windows versus
    Unicode), so only the cell values, the footer texts and whether the ``windows:``
    line is present can be asserted portably.
    """
    plain = _plain(stdout)
    data_rows = [row for row in _table_rows(plain, 4) if row[0].startswith(("0x", "-0x"))]
    assert data_rows == rows, plain
    for text in footers:
        assert text in plain, plain
    if merged:
        assert "windows:" in plain, plain
    else:
        assert "windows:" not in plain, plain


def _window_args(*addresses: str) -> list[str]:
    """Return the repeated ``--address`` pairs for ``addresses``."""
    return [part for value in addresses for part in ("-a", value)]


# ---- single window: unchanged output ---------------------------------------


def test_single_address_output_is_byte_for_byte_unchanged(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "two_windows.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        ["struct", str(sample), "--address", "0x401000", "--max-instructions", WINDOW_BUDGET],
    )

    assert result.exit_code == 0, _output(result)
    _assert_rendering(result.stdout, SINGLE_WINDOW_ROWS, SINGLE_WINDOW_FOOTERS, merged=False)
    # The merge marker belongs to the merged path only.
    assert "windows:" not in result.stdout


def test_single_address_matches_the_entry_point_default(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "two_windows_default.bin", TWO_WINDOWS)

    explicit = runner.invoke(
        app,
        ["struct", str(sample), "-a", str(TEXT_ADDRESS), "--max-instructions", WINDOW_BUDGET],
    )
    implicit = runner.invoke(app, ["struct", str(sample), "--max-instructions", WINDOW_BUDGET])

    assert explicit.exit_code == 0, _output(explicit)
    assert implicit.exit_code == 0, _output(implicit)
    assert explicit.stdout == implicit.stdout
    _assert_rendering(explicit.stdout, SINGLE_WINDOW_ROWS, SINGLE_WINDOW_FOOTERS, merged=False)


def test_single_address_json_stays_the_single_window_payload(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "two_windows_json.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        ["struct", str(sample), "-a", "0x401000", "--max-instructions", WINDOW_BUDGET, "--json"],
    )

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    assert payload["address"] == "0x401000"
    assert payload["evidence"]["source"] == "type_recovery.suggestion"
    assert [field["offset"] for field in payload["fields"]] == ["0x10"]
    # A single window is never routed through the merge.
    assert "window_count" not in payload["evidence"]["extra"]


# ---- two or more windows: merged output -----------------------------------


def test_two_addresses_merge_the_windows_into_one_field_per_offset(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_two.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            *_window_args("0x401000", hex(SECOND_WINDOW)),
            "--max-instructions",
            WINDOW_BUDGET,
        ],
    )

    assert result.exit_code == 0, _output(result)
    _assert_rendering(result.stdout, MERGED_ROWS, MERGED_FOOTERS, merged=True)
    # One line per merged fact, and the table keeps its four columns.
    for label in ("windows:", "base registers:", "instructions:", "alignment:", "signed:"):
        assert _output(result).count(label) == 1, _output(result)
    assert _field_rows(result) == [
        ["0x8", "4", "1", "0"],
        ["0x10", "8", "1", "0"],
        ["0x18", "8", "0", "1"],
    ]


def test_merged_output_is_identical_for_any_window_order(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_order.bin", TWO_WINDOWS)
    base = ["struct", str(sample), "--max-instructions", WINDOW_BUDGET]

    forward = runner.invoke(app, [*base, *_window_args("0x401000", hex(SECOND_WINDOW))])
    backward = runner.invoke(app, [*base, *_window_args(hex(SECOND_WINDOW), "0x401000")])

    assert forward.exit_code == 0, _output(forward)
    assert backward.exit_code == 0, _output(backward)
    # Addresses are sorted before the merge, so the render is order independent.
    assert forward.stdout == backward.stdout
    _assert_rendering(forward.stdout, MERGED_ROWS, MERGED_FOOTERS, merged=True)


def test_merged_alignment_is_recomputed_across_windows(tmp_path: Path) -> None:
    # One offset per window: alone, neither window can derive an alignment.
    window_one = MOV_RAX_RDI_10 + RET
    second = TEXT_ADDRESS + len(window_one)
    sample = _sample(tmp_path, "merge_alignment.bin", window_one + MOV_RDI_18_RBX + RET)
    base = ["struct", str(sample), "--max-instructions", WINDOW_BUDGET]

    first_only = runner.invoke(app, [*base, "-a", "0x401000"])
    second_only = runner.invoke(app, [*base, "-a", hex(second)])
    merged = runner.invoke(app, [*base, *_window_args("0x401000", hex(second))])

    # Neither window alone sees two distinct offsets, so both report unknown...
    assert "alignment: unknown" in _output(first_only), _output(first_only)
    assert "alignment: unknown" in _output(second_only), _output(second_only)
    assert _field_rows(first_only) == [["0x10", "8", "1", "0"]]
    assert _field_rows(second_only) == [["0x18", "8", "0", "1"]]
    # ...while the merge sees 0x10 and 0x18 and derives a GCD of 8.
    assert "alignment: 8" in _output(merged), _output(merged)
    assert f"windows: 2 (0x401000, 0x{second:x})" in _output(merged), _output(merged)
    assert _field_rows(merged) == [["0x10", "8", "1", "0"], ["0x18", "8", "0", "1"]]



def test_merged_json_lists_every_window(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_json.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            *_window_args("0x401000", hex(SECOND_WINDOW)),
            "--max-instructions",
            WINDOW_BUDGET,
            "--json",
        ],
    )

    assert result.exit_code == 0, _output(result)
    payload = _payload(result.stdout)
    extra = payload["evidence"]["extra"]
    assert payload["address"] == "0x401000"
    assert payload["evidence"]["source"] == "type_recovery.merged_suggestion"
    assert extra["window_count"] == 2
    assert extra["windows"] == ["0x401000", hex(SECOND_WINDOW)]
    assert extra["max_fields"] == payload["max_fields"] == 64
    assert extra["instruction_count"] == payload["instruction_count"] == 4
    assert [field["offset"] for field in payload["fields"]] == ["0x8", "0x10", "0x18"]
    assert payload["alignment"] == 8


def test_max_fields_equal_to_the_default_is_accepted_for_a_merge(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_max_fields_default.bin", TWO_WINDOWS)
    base = ["struct", str(sample), "--max-instructions", WINDOW_BUDGET]

    without = runner.invoke(app, [*base, *_window_args("0x401000", hex(SECOND_WINDOW))])
    with_default = runner.invoke(
        app, [*base, *_window_args("0x401000", hex(SECOND_WINDOW)), "--max-fields", "64"]
    )

    assert with_default.exit_code == 0, _output(with_default)
    assert with_default.stdout == without.stdout
    _assert_rendering(with_default.stdout, MERGED_ROWS, MERGED_FOOTERS, merged=True)


def test_merged_run_without_memory_operands_warns_once(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_no_fields.bin", RET + RET)

    result = runner.invoke(
        app, ["struct", str(sample), *_window_args("0x401000", hex(TEXT_ADDRESS + 1))]
    )

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "windows: 2 (0x401000, 0x401001)" in output, output
    assert output.count("warning:") == 1, output
    assert "no field-shaped memory operand was decoded in the window" in output, output


def test_truncated_merge_points_at_splitting_the_windows(tmp_path: Path) -> None:
    # 40 distinct offsets per window, disjoint: neither window reaches its own
    # cap of 64, while the merge of both exceeds it, so only the merge truncates.
    first_window = _window_with_offsets(range(0x00, 0x28))
    second_window = _window_with_offsets(range(0x28, 0x50))
    second = TEXT_ADDRESS + len(first_window)
    sample = _sample(tmp_path, "merge_truncated.bin", first_window + second_window)
    budget = str(len(range(0x00, 0x28)) + 1)  # 40 movs + the closing ret

    merged = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            *_window_args("0x401000", hex(second)),
            "--max-instructions",
            budget,
        ],
    )

    assert merged.exit_code == 0, _output(merged)
    output = _output(merged)
    assert "truncated: yes" in output, output
    assert len(_field_rows(merged)) == DEFAULT_MAX_FIELDS, _field_rows(merged)
    # The merged sweep compacts to its own cap, which --max-fields cannot raise
    # next to a merge: the hint must not send the user to a rejected flag.
    assert "raise --max-fields" not in output, output
    assert "field cap reached" in output, output
    assert f"the merged sweep keeps at most {DEFAULT_MAX_FIELDS} offsets" in output, output
    assert "split the windows into separate runs" in output, output

    # A single window is capped by --max-fields, so its hint is unchanged.
    single = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            "-a",
            "0x401000",
            "--max-instructions",
            str(len(range(0x00, 0x50)) + 1),
        ],
    )

    assert single.exit_code == 0, _output(single)
    single_output = _output(single)
    assert "truncated: yes" in single_output, single_output
    assert "raise --max-fields" in single_output, single_output
    assert "split the windows" not in single_output, single_output


def test_merged_run_does_not_decode_a_window_a_second_time(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = _sample(tmp_path, "merge_no_resweep.bin", TWO_WINDOWS)
    calls: list[int] = []
    real = cli_main.disassemble_region

    def counting_decoder(path: str | Path, info: Any, start: int, *, count: int = 50) -> Any:
        calls.append(start)
        return real(path, info, start, count=count)

    monkeypatch.setattr(cli_main, "disassemble_region", counting_decoder)

    merged = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            *_window_args("0x401000", hex(SECOND_WINDOW)),
            "--max-instructions",
            WINDOW_BUDGET,
        ],
    )

    assert merged.exit_code == 0, _output(merged)
    # The sweep belongs to suggest_structs, so the footer must not sweep again.
    assert calls == [], calls
    output = _output(merged)
    assert "windows: 2 (0x401000, 0x401005)" in output, output
    # With no base register in the evidence, the footer says the merge did not
    # record them instead of claiming a window used none.
    assert "base registers: not recorded by the merge" in output, output

    # A single address keeps its unchanged footer, which costs exactly one pass.
    single = runner.invoke(
        app, ["struct", str(sample), "-a", "0x401000", "--max-instructions", WINDOW_BUDGET]
    )

    assert single.exit_code == 0, _output(single)
    _assert_rendering(single.stdout, SINGLE_WINDOW_ROWS, SINGLE_WINDOW_FOOTERS, merged=False)
    assert calls == [TEXT_ADDRESS], calls


def test_the_window_cap_accepts_exactly_max_merged_windows_addresses(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_window_cap.bin", RET * 32)
    addresses = [hex(TEXT_ADDRESS + index) for index in range(MAX_MERGED_WINDOWS)]

    result = runner.invoke(app, ["struct", str(sample), *_window_args(*addresses)])

    assert result.exit_code == 0, _output(result)
    assert f"windows: {MAX_MERGED_WINDOWS} " in _output(result), _output(result)


# ---- rejected input: exit 2 -------------------------------------------------


def test_duplicate_address_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_duplicate.bin", TWO_WINDOWS)

    # The same address in decimal and in hex is still one window.
    result = runner.invoke(
        app, ["struct", str(sample), *_window_args("0x401000", str(TEXT_ADDRESS))]
    )

    assert result.exit_code == 2, _output(result)
    assert "window address 0x401000 appears more than once" in _output(result), _output(result)


def test_function_with_two_addresses_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_function_conflict.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        ["struct", str(sample), "-f", "main", *_window_args("0x401000", hex(SECOND_WINDOW))],
    )

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "error:" in output, output
    assert "--function names one start" in output, output
    assert "give either --function or --address, not both" in output, output


def test_function_with_one_address_exits_2(tmp_path: Path) -> None:
    # One address used to win over --function silently (exit 0), which is the
    # same conflict as a merge: the rule has to hold for any --address.
    sample = _sample(tmp_path, "single_function_conflict.bin", TWO_WINDOWS)

    result = runner.invoke(app, ["struct", str(sample), "-a", "0x401000", "-f", "main"])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "error:" in output, output
    assert "--function names one start" in output, output
    assert "give either --function or --address, not both" in output, output
    # Nothing was swept: the conflict is rejected before the file is read.
    assert "Struct at" not in output, output

    # A lone --address is untouched by the rule.
    alone = runner.invoke(
        app, ["struct", str(sample), "-a", "0x401000", "--max-instructions", WINDOW_BUDGET]
    )
    assert alone.exit_code == 0, _output(alone)
    _assert_rendering(alone.stdout, SINGLE_WINDOW_ROWS, SINGLE_WINDOW_FOOTERS, merged=False)


def test_max_fields_with_two_addresses_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_max_fields_conflict.bin", TWO_WINDOWS)

    result = runner.invoke(
        app,
        [
            "struct",
            str(sample),
            *_window_args("0x401000", hex(SECOND_WINDOW)),
            "--max-fields",
            "2",
        ],
    )

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "--max-fields applies to a single --address" in output, output
    assert "at most 64 fields" in output, output


def test_too_many_addresses_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_too_many.bin", RET * 32)
    addresses = [hex(TEXT_ADDRESS + index) for index in range(MAX_MERGED_WINDOWS + 1)]

    result = runner.invoke(app, ["struct", str(sample), *_window_args(*addresses)])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert f"too many window addresses (limit {MAX_MERGED_WINDOWS})" in output, output
    assert f"got {MAX_MERGED_WINDOWS + 1}" in output, output


def test_window_outside_an_executable_section_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_bad_section.bin", TWO_WINDOWS)

    result = runner.invoke(app, ["struct", str(sample), *_window_args("0x401000", "0x1000")])

    assert result.exit_code == 2, _output(result)
    assert "address 0x1000 is not inside an executable section" in _output(result), _output(result)


def test_empty_address_value_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "merge_empty.bin", TWO_WINDOWS)

    result = runner.invoke(app, ["struct", str(sample), "-a", ""])

    assert result.exit_code == 2, _output(result)
    assert "invalid address ''" in _output(result), _output(result)

