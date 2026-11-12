"""CLI tests for the phase 3 additions: ``codevanta decompile`` and ``emulate``.

Both commands sit in front of an analysis layer that already has its own tests
(``tests/test_decompile.py``, ``tests/test_decompile_backends.py``,
``tests/test_emulate.py``); what is asserted here is the wiring only: arguments,
options, the text rendering, the ``--json`` payloads and the exit code of every
``AnalysisError`` path. Each fixture is an ELF64 file assembled byte by byte in
this module, so the tests stay self-contained -- no compiler, no shared fixture,
no real-world binary. Nothing here executes a sample: the emulator runs the
copied bytes on its own virtual CPU, exactly as the analysis layer documents.

``unicorn`` gates the emulation tests (they are skipped, not failed, when the
optional engine is missing) and ``angr`` gates the one test that expects a strict
backend request to be refused, so the module starts passing the moment either
optional dependency is installed.
"""

from __future__ import annotations

import faulthandler
import json
import re
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

import codevanta.analysis.emulate as emulate
from codevanta.analysis.decompile import DEFAULT_MAX_BLOCKS, DEFAULT_MAX_INSTRUCTIONS
from codevanta.analysis.decompilers import get_backend
from codevanta.cli.main import app

runner = CliRunner()

TEXT_ADDRESS = 0x401000

#: ``mov eax, 42`` + ``ret``: a straight-line function whose only job is to
#: return 42.
MOV_EAX_42 = bytes.fromhex("b82a000000") + b"\xc3"
#: ``mov eax, edi`` / ``add eax, esi`` / ``ret``: returns the sum of two seeds.
ADD_EDI_ESI = bytes.fromhex("89f8") + bytes.fromhex("01f0") + b"\xc3"
#: ``mov eax, dword ptr [0x600000]`` / ``ret``: reads the seeded block below.
MOV_EAX_MEM = bytes.fromhex("8b0425") + bytes.fromhex("00006000") + b"\xc3"
#: ``jmp rax`` first, then the ``mov eax, 42``/``ret`` tail: the target of the
#: indirect branch is the second instruction.
JMP_RAX = bytes.fromhex("ffe0") + MOV_EAX_42
JMP_RAX_TARGET = TEXT_ADDRESS + 2
#: ``nop`` / ``jmp rax``: the indirect branch is the *second* instruction, so a
#: one-instruction budget stops before it can be resolved.
NOP_JMP_RAX = b"\x90" + bytes.fromhex("ffe0")

#: Address the emulated ``mov eax, dword ptr [0x600000]`` reads from, and the
#: ``--mem`` argument that places the little-endian 42 there.
MEM_BLOCK = 0x600000
MEM_BLOCK_SEED = "0x600000=2a000000"

#: ``(name, address)`` pairs of the fixture symbol table, so ``--function`` has a
#: discovered name to resolve (the builder below only adds one when asked).
MAIN_SYMBOL = (("main", TEXT_ADDRESS),)

#: Skip conditions for the two optional dependencies the commands talk to.
ANGR_AVAILABLE = get_backend("angr").availability().available
GHIDRA_AVAILABLE = get_backend("ghidra").availability().available
needs_unicorn = pytest.mark.skipif(
    not emulate.EMULATOR_AVAILABLE, reason="the optional unicorn engine is not installed"
)
#: ``auto`` only reports the skips it made, so a test that asserts both external
#: backends were skipped needs a machine without either of them.
needs_no_external_backend = pytest.mark.skipif(
    ANGR_AVAILABLE or GHIDRA_AVAILABLE,
    reason="an external decompiler is installed, so auto does not fall back",
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def _faulthandler_stays_off() -> Iterator[None]:
    """Keep CPython's fault handler disabled for every test in this module.

    The emulation layer disables ``faulthandler`` around ``emu_start`` and
    re-enables it afterwards, and re-enabling it needs a real stderr file
    descriptor. ``CliRunner`` swaps ``sys.stderr`` for an in-memory stream, so a
    run that starts with the handler enabled would fail on that restore. Turning
    it off here is the same state a script gets when it never enabled it, and the
    analysis layer then leaves it alone.
    """
    faulthandler.disable()
    yield


def _write_elf64(
    path: Path,
    code: bytes,
    *,
    entry: int = TEXT_ADDRESS,
    symbols: tuple[tuple[str, int], ...] = (),
) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    ``.text`` is mapped at ``entry`` and ``e_entry`` points at it, so the entry
    point and an explicit address name the same window. ``symbols`` appends an
    ``.symtab``/``.strtab`` pair with one global ``STT_FUNC`` per
    ``(name, address)``, which is what gives ``--function`` a name to resolve;
    with no symbols the file is byte for byte the three-section layout
    ``tests/test_cli_phase2k.py`` builds.
    """
    if not code:
        raise ValueError("code must not be empty")
    shstrtab = b"\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00"
    strtab = b""
    symtab = b""
    if symbols:
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
            "<IIQQQQIIQQ", 1, 1, 6, entry, text_offset, len(code), 0, 0, 16, 0
        ),
    ]
    shstrndx = 2
    if symbols:
        sections.append(
            struct.pack(  # .strtab: SHT_STRTAB
                "<IIQQQQIIQQ", 7, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0
            )
        )
        sections.append(
            struct.pack(  # .symtab: SHT_SYMTAB, link=.strtab, first global = 1
                "<IIQQQQIIQQ", 15, 2, 0, 0, symtab_offset, len(symtab), 2, 1, 8, 24
            )
        )
        shstrndx = 4
    sections.append(
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ", 23, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
        )
    )
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
        len(sections),  # e_shnum
        shstrndx,  # e_shstrndx
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    if symbols:
        blob[strtab_offset : strtab_offset + len(strtab)] = strtab
        blob[symtab_offset : symtab_offset + len(symtab)] = symtab
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _sample(
    tmp_path: Path,
    name: str,
    code: bytes,
    *,
    symbols: tuple[tuple[str, int], ...] = (),
) -> Path:
    """Write one fixture binary under ``tmp_path``."""
    return _write_elf64(tmp_path / name, code, symbols=symbols)


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(result: Result) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(result.stdout)
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


#: Row labels of the ``emulate`` fact table, in print order.
FACT_LABELS = ("stopped reason", "instructions", "return value", "indirect targets")


def _facts(result: Result) -> dict[str, str]:
    """Return the ``emulate`` fact table as a label -> value mapping."""
    return {row[0]: row[1] for row in _table_rows(result.stdout, 2) if row[0] in FACT_LABELS}


# ---- decompile: the rendering ----------------------------------------------


def test_decompile_renders_the_straight_line_fixture(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "straight_line.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # The pseudo-C names the function the heuristic derives from the address...
    assert "sub_401000" in output, output
    # ...and every emitted line keeps its instruction as a comment.
    assert "/* mov eax, 0x2a */" in output, output
    assert "eax = 0x2a;" in output, output
    # The panel names the window, the backend and the language it rendered in.
    assert "Decompilation at 0x401000" in output, output
    assert "backend: native" in output, output
    assert "language: c" in output, output
    # The dim footer repeats the counts the renderer stated.
    assert "blocks: 1" in output, output
    assert "instructions: 2" in output, output
    assert "truncated: no" in output, output


def test_decompile_uses_the_symbol_name_when_the_binary_has_one(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "symbol.bin", MOV_EAX_42, symbols=MAIN_SYMBOL)

    result = runner.invoke(app, ["decompile", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "symbol: main" in output, output
    assert "main(void)" in output, output
    assert "/* mov eax, 0x2a */" in output, output


def test_decompile_defaults_to_the_entry_point(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "entry_default.bin", MOV_EAX_42)

    implicit = runner.invoke(app, ["decompile", str(sample)])
    explicit = runner.invoke(app, ["decompile", str(sample), hex(TEXT_ADDRESS)])

    assert implicit.exit_code == 0, _output(implicit)
    assert explicit.exit_code == 0, _output(explicit)
    assert implicit.stdout == explicit.stdout


def test_decompile_resolves_a_function_name(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "function_name.bin", MOV_EAX_42, symbols=MAIN_SYMBOL)

    result = runner.invoke(app, ["decompile", str(sample), "--function", "main"])

    assert result.exit_code == 0, _output(result)
    assert "symbol: main" in _output(result), _output(result)


def test_decompile_with_unknown_function_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "function_missing.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "-f", "nope"])

    assert result.exit_code == 2, _output(result)
    assert "function 'nope' not found" in _output(result), _output(result)


def test_decompile_explicit_native_backend_reports_no_fallback(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "native_backend.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--backend", "native"])

    assert result.exit_code == 0, _output(result)
    assert "backend: native" in _output(result), _output(result)
    # A strict request never falls back, so nothing is reported as skipped.
    assert "warning:" not in _output(result), _output(result)


@needs_no_external_backend
def test_decompile_auto_backend_reports_every_skipped_backend(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "auto_backend.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # Both external probes are recorded, so the native fallback is never silent.
    assert "warning:" in output, output
    assert "backend 'angr' was unavailable" in output, output
    assert "backend 'ghidra' was unavailable" in output, output


def test_decompile_json_carries_the_rendering(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "rendering_json.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["backend"] == "native"
    assert payload["language"] == "c"
    assert "sub_401000" in payload["text"]
    assert "/* mov eax, 0x2a */" in payload["text"]
    # The block facts travel with the rendering: the header line states the
    # decoded counts and the evidence records the budget that produced them.
    assert "blocks: 1" in payload["text"]
    assert payload["evidence"]["extra"]["max_blocks"] == DEFAULT_MAX_BLOCKS
    assert payload["evidence"]["extra"]["max_instructions"] == DEFAULT_MAX_INSTRUCTIONS
    # No panel is printed next to the payload.
    assert "Decompilation at" not in _output(result)


@needs_no_external_backend
def test_decompile_json_keeps_the_fallback_warnings(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "warnings_json.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    warnings = _payload(result)["warnings"]
    assert any("angr" in warning for warning in warnings), warnings


def test_decompile_writes_the_rendering_to_output(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "written.bin", MOV_EAX_42)
    target = tmp_path / "rendered.c"

    result = runner.invoke(app, ["decompile", str(sample), "--output", str(target)])

    assert result.exit_code == 0, _output(result)
    assert "rendering written:" in _output(result), _output(result)
    written = target.read_text(encoding="utf-8")
    assert "sub_401000" in written
    assert "/* mov eax, 0x2a */" in written
    # The file is the plain body, so it ends the way the renderer ended it.
    assert written.endswith("}\n")


def test_decompile_output_with_json_writes_the_payload(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "written_json.bin", MOV_EAX_42)
    target = tmp_path / "rendered.json"

    result = runner.invoke(app, ["decompile", str(sample), "--json", "--output", str(target)])

    assert result.exit_code == 0, _output(result)
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["backend"] == "native"
    assert written["text"] == _payload(result)["text"]


def test_decompile_bad_address_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "bad_address.bin", MOV_EAX_42)

    outside = runner.invoke(app, ["decompile", str(sample), "0x1000"])
    garbage = runner.invoke(app, ["decompile", str(sample), "not-an-address"])

    assert outside.exit_code == 2, _output(outside)
    assert "0x1000 is not inside an executable section" in _output(outside), _output(outside)
    assert garbage.exit_code == 2, _output(garbage)
    assert "invalid address 'not-an-address'" in _output(garbage), _output(garbage)


def test_decompile_out_of_range_budget_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "bad_budget.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--max-blocks", "0"])

    assert result.exit_code == 2, _output(result)
    assert "max_blocks must be >= 1" in _output(result), _output(result)


def test_decompile_unknown_backend_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "unknown_backend.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--backend", "bochs"])

    assert result.exit_code == 2, _output(result)
    assert "unknown decompiler backend 'bochs'" in _output(result), _output(result)


@pytest.mark.skipif(ANGR_AVAILABLE, reason="angr is installed, so the request succeeds")
def test_decompile_strict_angr_backend_exits_2_naming_angr(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "strict_angr.bin", MOV_EAX_42)

    result = runner.invoke(app, ["decompile", str(sample), "--backend", "angr"])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "error:" in output, output
    assert "angr" in output, output
    assert "unavailable" in output, output
    # The install hint reaches the user instead of an ImportError traceback.
    assert "pip install angr" in output, output


# ---- emulate: the run ------------------------------------------------------


@needs_unicorn
def test_emulate_reports_the_return_value(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "returns_42.bin", MOV_EAX_42)

    result = runner.invoke(app, ["emulate", str(sample)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "Emulation at 0x401000" in output, output
    facts = _facts(result)
    assert facts["stopped reason"] == "return", facts
    assert facts["instructions"] == "1", facts
    # 42 is printed in hex and in decimal, so both readings of the value agree.
    assert facts["return value"] == "0x2a (42)", facts
    assert facts["indirect targets"] == "none", facts
    # The non-zero registers keep their own dim line under the table.
    assert "registers:" in output, output
    assert "rax=0x2a" in output, output


@needs_unicorn
def test_emulate_seeded_registers_add_up(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "adds.bin", ADD_EDI_ESI)

    result = runner.invoke(app, ["emulate", str(sample), "--set", "rdi=2", "--set", "rsi=3"])

    assert result.exit_code == 0, _output(result)
    assert _facts(result)["return value"] == "0x5 (5)", _facts(result)
    assert "rdi=0x2" in _output(result), _output(result)
    assert "rsi=0x3" in _output(result), _output(result)


@needs_unicorn
def test_emulate_accepts_hexadecimal_seeds(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "adds_hex.bin", ADD_EDI_ESI)

    decimal = runner.invoke(app, ["emulate", str(sample), "--set", "rdi=2", "--set", "rsi=3"])
    hexadecimal = runner.invoke(
        app, ["emulate", str(sample), "--set", "rdi=0x2", "--set", "rsi=0x3"]
    )

    assert hexadecimal.exit_code == 0, _output(hexadecimal)
    # The seed spelling does not change the machine state or the rendering.
    assert hexadecimal.stdout == decimal.stdout


@needs_unicorn
def test_emulate_seeds_memory_with_mem(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "reads_memory.bin", MOV_EAX_MEM)

    seeded = runner.invoke(app, ["emulate", str(sample), "--mem", MEM_BLOCK_SEED])
    unseeded = runner.invoke(app, ["emulate", str(sample)])

    assert seeded.exit_code == 0, _output(seeded)
    assert _facts(seeded)["return value"] == "0x2a (42)", _facts(seeded)
    # Without the block the same read faults at that address instead of
    # inventing a value, which is what makes the flag worth asserting.
    assert unseeded.exit_code == 0, _output(unseeded)
    assert _facts(unseeded)["stopped reason"] == "unmapped", _facts(unseeded)
    assert f"0x{MEM_BLOCK:x}" in _output(unseeded), _output(unseeded)
    assert "warning:" in _output(unseeded), _output(unseeded)


@needs_unicorn
def test_emulate_json_is_parseable(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "returns_json.bin", MOV_EAX_42)

    result = runner.invoke(app, ["emulate", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["address"] == "0x401000"
    assert payload["stopped_reason"] == "return"
    assert payload["instructions"] == 1
    assert payload["return_value"] == "0x2a"
    assert payload["registers"]["rax"] == "0x2a"
    assert payload["warnings"] == []
    assert payload["evidence"]["source"] == "emulate.unicorn"
    assert payload["evidence"]["extra"]["max_instructions"] == emulate.DEFAULT_MAX_INSTRUCTIONS
    # The table is replaced by the payload, so nothing is printed twice.
    assert "Emulation at" not in _output(result)


@needs_unicorn
def test_emulate_budget_stop_is_reported(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "budget.bin", ADD_EDI_ESI)

    result = runner.invoke(app, ["emulate", str(sample), "--max-instructions", "1"])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert _facts(result)["stopped reason"] == "budget", _facts(result)
    assert _facts(result)["instructions"] == "1", _facts(result)
    # A budget stop has no return value, and it says so instead of guessing.
    assert _facts(result)["return value"] == "none", _facts(result)
    assert "warning:" in output, output
    assert "budget" in output, output


@needs_unicorn
def test_emulate_budget_stop_json_carries_the_warning(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "budget_json.bin", ADD_EDI_ESI)

    result = runner.invoke(app, ["emulate", str(sample), "--max-instructions", "1", "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["stopped_reason"] == "budget"
    assert payload["instructions"] == 1
    assert payload["return_value"] is None
    assert any("budget" in warning for warning in payload["warnings"]), payload["warnings"]
    assert payload["evidence"]["extra"]["max_instructions"] == 1


# ---- emulate: indirect targets ---------------------------------------------


@needs_unicorn
def test_emulate_resolve_target_prints_the_indirect_target(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "jmp_rax.bin", JMP_RAX)

    result = runner.invoke(
        app, ["emulate", str(sample), "--resolve-target", "--set", f"rax={JMP_RAX_TARGET}"]
    )

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert f"indirect target: 0x{JMP_RAX_TARGET:x}" in output, output
    assert f"({JMP_RAX_TARGET})" in output, output
    # No emulation table is printed: this mode answers one question.
    assert "stopped reason" not in output, output


@needs_unicorn
def test_emulate_resolve_target_json_is_parseable(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "jmp_rax_json.bin", JMP_RAX)

    result = runner.invoke(
        app,
        [
            "emulate",
            str(sample),
            "--resolve-target",
            "--json",
            "--set",
            f"rax=0x{JMP_RAX_TARGET:x}",
        ],
    )

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["mode"] == "resolve_indirect_target"
    assert payload["resolved"] is True
    assert payload["indirect_target"] == f"0x{JMP_RAX_TARGET:x}"
    assert payload["address"] == "0x401000"


@needs_unicorn
def test_emulate_resolve_target_reports_an_unresolved_branch(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "nop_jmp_rax.bin", NOP_JMP_RAX)

    result = runner.invoke(
        app, ["emulate", str(sample), "--resolve-target", "--max-instructions", "1"]
    )

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # The budget stopped the run before the branch: "unresolved", never "no
    # target".
    assert "indirect target: unresolved" in output, output
    assert "never 'no target'" in output, output


# ---- emulate: rejected requests --------------------------------------------


@needs_unicorn
def test_emulate_without_an_available_emulator_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = _sample(tmp_path, "no_emulator.bin", MOV_EAX_42)
    monkeypatch.setattr(emulate, "EMULATOR_AVAILABLE", False)

    result = runner.invoke(app, ["emulate", str(sample)])

    assert result.exit_code == 2, _output(result)
    output = _output(result)
    assert "emulation is unavailable" in output, output
    # The message points at the probe instead of leaking an ImportError.
    assert "emulator_status()" in output, output
    assert "pip install unicorn" in output, output
    assert result.exception is None or isinstance(result.exception, SystemExit), output


@needs_unicorn
def test_emulate_rejects_malformed_seeds(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "bad_seeds.bin", ADD_EDI_ESI)

    missing_value = runner.invoke(app, ["emulate", str(sample), "--set", "rdi"])
    bad_hex = runner.invoke(app, ["emulate", str(sample), "--set", "rdi=0xzz"])
    negative = runner.invoke(app, ["emulate", str(sample), "--set", "rdi=-1"])
    unknown = runner.invoke(app, ["emulate", str(sample), "--set", "nope=1"])

    assert missing_value.exit_code == 2, _output(missing_value)
    assert "invalid --set 'rdi'" in _output(missing_value), _output(missing_value)
    assert bad_hex.exit_code == 2, _output(bad_hex)
    assert "invalid --set value '0xzz'" in _output(bad_hex), _output(bad_hex)
    assert negative.exit_code == 2, _output(negative)
    assert "must not be negative" in _output(negative), _output(negative)
    # The register name is validated by the analysis layer, not guessed here.
    assert unknown.exit_code == 2, _output(unknown)
    assert "unknown 64-bit register name 'nope'" in _output(unknown), _output(unknown)


@needs_unicorn
def test_emulate_rejects_malformed_memory_blocks(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "bad_blocks.bin", ADD_EDI_ESI)

    no_separator = runner.invoke(app, ["emulate", str(sample), "--mem", "deadbeef"])
    odd_digits = runner.invoke(app, ["emulate", str(sample), "--mem", "0x600000=abc"])
    bad_address = runner.invoke(app, ["emulate", str(sample), "--mem", "zz=deadbeef"])

    assert no_separator.exit_code == 2, _output(no_separator)
    assert "invalid --mem 'deadbeef'" in _output(no_separator), _output(no_separator)
    assert odd_digits.exit_code == 2, _output(odd_digits)
    assert "even number of hex digits" in _output(odd_digits), _output(odd_digits)
    assert bad_address.exit_code == 2, _output(bad_address)
    assert "invalid --mem address 'zz'" in _output(bad_address), _output(bad_address)


@needs_unicorn
def test_emulate_bad_address_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "emulate_bad_address.bin", MOV_EAX_42)

    outside = runner.invoke(app, ["emulate", str(sample), "0x1000"])
    garbage = runner.invoke(app, ["emulate", str(sample), "not-an-address"])

    assert outside.exit_code == 2, _output(outside)
    assert "0x1000" in _output(outside), _output(outside)
    # 0x1000 is inside neither an executable section nor a mapped one, and the
    # emulator says which of the two it is instead of guessing.
    refused = _output(outside).lower()
    assert "not executable" in refused or "not mapped" in refused, refused
    assert garbage.exit_code == 2, _output(garbage)
    assert "invalid address 'not-an-address'" in _output(garbage), _output(garbage)


@needs_unicorn
def test_emulate_defaults_to_the_entry_point(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "emulate_entry.bin", MOV_EAX_42)

    implicit = runner.invoke(app, ["emulate", str(sample)])
    explicit = runner.invoke(app, ["emulate", str(sample), hex(TEXT_ADDRESS)])

    assert implicit.exit_code == 0, _output(implicit)
    assert explicit.exit_code == 0, _output(explicit)
    assert implicit.stdout == explicit.stdout
    assert _facts(implicit)["return value"] == "0x2a (42)", _facts(implicit)
