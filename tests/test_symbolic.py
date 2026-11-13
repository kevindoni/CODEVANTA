"""Tests for symbolic-style path exploration over tiny synthetic ELF samples.

Every sample is assembled byte by byte with :mod:`struct` in this module, so the
tests stay self-contained: no shared fixtures, no real binaries, and no host code
is ever executed -- the bytes only ever run inside unicorn's emulator.

The module is skipped wholesale when unicorn is not installed, so the rest of the
suite keeps passing without the optional extra. The angr bridge is exercised
through the unavailable path, which is the path every CI machine without the
``decompilers`` extra takes.

What these tests pin down, beyond "it returns something": a straight-line
function yields exactly one path with its return value; a two-way conditional
yields **two** paths (the observed side and a flag-seeded side, both reported,
the seeded one flagged as an assumption); the budget, unmapped and unresolvable
cases each end a path with the right stop reason and a note; and the evidence
states what was explored versus what was only assumed.

Note for Windows runs: unicorn's ``Uc.mem_map`` raises and handles a first-chance
access violation internally, which CPython's ``faulthandler`` prints even though
nothing failed. The module silences it around its own runs; run pytest with
``-p no:faulthandler`` to silence anything else.
"""

from __future__ import annotations

import ast
import inspect
import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import symbolic
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_PATHS,
    DEFAULT_MAX_STEPS,
    MAX_MAX_PATHS,
    MAX_MAX_STEPS,
    Entry,
    PathExploration,
    angr_available,
    explore_paths,
    explore_with_angr,
)
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

pytest.importorskip("unicorn")

#: Virtual address of .text in the ELF64 samples.
TEXT_VA = 0x401000

#: An address no sample maps, used for the unmapped-access case.
UNMAPPED_VA = 0x700000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 ``mov eax, 42; ret`` -- straight line, one path.
CODE_MOV_EAX_42 = bytes.fromhex("b82a000000c3")

#: x86-64 ``test edi, edi; jz +6; mov eax, 1; ret; mov eax, 2; ret``.
#: Offsets: ``test`` at 0x0, ``je`` at 0x2 (target 0xa), the two mov/ret pairs
#: at 0x4/0x9 and 0xa/0xf, so the two sides return different values.
CODE_TWO_WAY = (
    bytes.fromhex("85ff")            # 0x00: test edi, edi
    + bytes.fromhex("7406")          # 0x02: je 0xa   (Capstone spells 0x74 "je")
    + bytes.fromhex("b801000000")    # 0x04: mov eax, 1
    + bytes.fromhex("c3")            # 0x09: ret
    + bytes.fromhex("b802000000")    # 0x0a: mov eax, 2
    + bytes.fromhex("c3")            # 0x0f: ret
)

#: Addresses inside :data:`CODE_TWO_WAY`, relative to ``TEXT_VA``.
JUMP_VA = TEXT_VA + 0x02
TAKEN_VA = TEXT_VA + 0x0A
FALLTHROUGH_VA = TEXT_VA + 0x04

#: x86-64 ``jmp $`` -- spins, so only the instruction budget can stop it.
CODE_SPIN = bytes.fromhex("ebfe")

#: x86-64 ``mov rax, [rbx]; ret`` -- faults when ``rbx`` is not mapped.
CODE_LOAD_RBX = bytes.fromhex("488b03" "c3")

#: x86-64 ``loop $`` -- decides on a decremented ``rcx``, which is not modelled.
CODE_LOOP_SELF = bytes.fromhex("e2fe")

#: x86-64 ``call +7; ret; nop*6; mov eax, 9; ret`` -- the callee is in the same
#: section, so its ``ret`` returns into the caller and the path continues.
CODE_CALL_IN_SECTION = (
    bytes.fromhex("e807000000")      # 0x00: call 0x0c
    + bytes.fromhex("c3")            # 0x05: ret (this is the path's return)
    + b"\x90" * 6                    # 0x06..0x0b: padding
    + bytes.fromhex("b809000000")    # 0x0c: mov eax, 9
    + bytes.fromhex("c3")            # 0x11: ret -> 0x05
)

CALLEE_VA = TEXT_VA + 0x0C
RESUME_VA = TEXT_VA + 0x05

#: x86-64 ``jrcxz +6; mov eax, 1; ret; mov eax, 2; ret`` -- the counter form.
#: Offsets: ``jrcxz`` at 0x0 (target 0x8), ``mov eax, 1``/``ret`` at 0x2/0x7,
#: ``mov eax, 2``/``ret`` at 0x8/0xd.
CODE_JRCXZ = (
    bytes.fromhex("e306")            # 0x00: jrcxz 0x08
    + bytes.fromhex("b801000000")    # 0x02: mov eax, 1
    + bytes.fromhex("c3")            # 0x07: ret
    + bytes.fromhex("b802000000")    # 0x08: mov eax, 2
    + bytes.fromhex("c3")            # 0x0d: ret
)


def _write_elf(path: Path, code: bytes, *, va: int) -> Path:
    """Write a tiny ELF64 whose ``.text`` holds ``code`` at ``va``.

    Three sections (null, ``.text``, ``.shstrtab``), no program headers and no
    other content: enough for :class:`~codevanta.core.loader.BinaryLoader` and
    for the explorer.

    Args:
        path: Destination file.
        code: Bytes placed at the start of ``.text``.
        va: Virtual address of ``.text``.

    Returns:
        ``path``, written to disk.
    """
    shstr_offset = _TEXT_OFFSET + len(code)
    sh_offset = (shstr_offset + len(_SHSTRTAB) + 7) & ~7
    blob = bytearray(sh_offset)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        62,         # e_machine = EM_X86_64
        1,          # e_version
        va,         # e_entry
        0,          # e_phoff
        sh_offset,  # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        3,          # e_shnum: null, .text, .shstrtab
        2,          # e_shstrndx
    )
    text_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        va, _TEXT_OFFSET, len(code), 0, 0, 16, 0,
    )
    str_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
    )
    blob[0 : len(header)] = header
    blob[_TEXT_OFFSET : _TEXT_OFFSET + len(code)] = code
    blob[shstr_offset : shstr_offset + len(_SHSTRTAB)] = _SHSTRTAB
    blob += bytes(64) + text_header + str_header
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, code: bytes, *, name: str = "sample.elf") -> Path:
    """Write a sample ELF with ``code`` in ``.text`` at :data:`TEXT_VA`."""
    return _write_elf(tmp_path / name, code, va=TEXT_VA)


def _load(path: Path) -> BinaryInfo:
    """Load a sample through the real loader."""
    return BinaryLoader().load(path)


# ---- availability ---------------------------------------------------------


def test_unicorn_explorer_is_available() -> None:
    assert symbolic.EMULATOR_AVAILABLE is True
    assert angr_available() is False or angr_available() is True
    assert isinstance(symbolic.ANGR_AVAILABLE, bool)


# ---- straight-line path ---------------------------------------------------


def test_straight_line_function_yields_one_path_with_its_return(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="straight.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA)

    assert isinstance(exploration, PathExploration)
    assert exploration.explorer == "unicorn"
    assert exploration.paths == 1
    entry = exploration.entries[0]
    assert isinstance(entry, Entry)
    assert entry.stopped_reason == "return"
    assert entry.return_value == 42
    assert entry.registers["rax"] == 42
    assert entry.decisions == ()
    assert entry.taken_targets == ()
    assert entry.instructions == 1  # the mov; a ret completes the path unexecuted
    assert entry.warnings == ()
    assert exploration.complete is True
    assert exploration.unresolved == 0
    assert exploration.return_values == (42,)
    assert exploration.steps == 1


def test_evidence_reports_that_nothing_was_assumed(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="evidence.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, max_paths=8, max_steps=32)

    evidence = exploration.evidence
    assert evidence.source == "symbolic.unicorn"
    assert evidence.method == "branch_decision_replay"
    assert evidence.confidence.value == "medium"
    assert evidence.address == TEXT_VA
    assert evidence.extra["paths"] == 1
    assert evidence.extra["observed_branches"] == 0
    assert evidence.extra["seeded_branches"] == 0
    assert evidence.extra["max_paths"] == 8
    assert evidence.extra["max_steps"] == 32
    assert evidence.extra["stopped_reasons"] == {"return": 1}
    assumptions = " ".join(evidence.extra["assumptions"])
    assert "never proven" in assumptions  # the seeded side is always caveated
    assert "no constraint was solved" in assumptions
    kinds = {region["kind"] for region in evidence.extra["regions"]}
    assert {"image", "stack"} <= kinds


# ---- a two-way conditional ------------------------------------------------


def test_two_way_conditional_yields_two_paths(tmp_path: Path) -> None:
    """``test edi, edi; je`` yields exactly two paths: observed + seeded.

    With ``edi=5`` the observed side is the fall-through (``ZF=0``), so the
    explorer reports that path as observed and reaches the other one by flipping
    ``ZF``. Both are real entries; the seeded one carries a warning saying the
    direction is assumed, not proven.
    """
    path = _sample(tmp_path, CODE_TWO_WAY, name="branch.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, initial_registers={"edi": 5})

    assert exploration.paths == 2  # not "one path + one unresolved"
    fallthrough_path, taken_path = exploration.entries

    # 1. the observed side: jz fell through to `mov eax, 1`
    assert fallthrough_path.return_value == 1
    assert fallthrough_path.stopped_reason == "return"
    assert len(fallthrough_path.decisions) == 1
    observed = fallthrough_path.decisions[0]
    assert (observed.address, observed.mnemonic) == (JUMP_VA, "je")
    assert observed.taken is False
    assert observed.target == FALLTHROUGH_VA
    assert observed.basis == "observed"
    assert observed.note == ""
    assert fallthrough_path.taken_targets == ()
    assert fallthrough_path.warnings == ()

    # 2. the seeded side: rflags rewritten so jz is taken, then executed
    assert taken_path.return_value == 2
    assert taken_path.stopped_reason == "return"
    seeded = taken_path.decisions[0]
    assert (seeded.address, seeded.mnemonic) == (JUMP_VA, "je")
    assert seeded.taken is True
    assert seeded.target == TAKEN_VA
    assert seeded.basis == "seeded"
    assert taken_path.taken_targets == (TAKEN_VA,)
    assert "ZF 0->1" in seeded.note
    assert "assumed feasible, not proven" in seeded.note
    assert "no constraint was solved" in seeded.note
    assert any("assumed feasible" in warning for warning in taken_path.warnings)
    assert taken_path.seeded == 1
    assert fallthrough_path.seeded == 0

    # both sides were explored, so the tree is complete, but the evidence says
    # one direction rests on an assumption -- hence low confidence, not medium.
    assert exploration.complete is True
    assert exploration.evidence.confidence.value == "low"
    assert exploration.evidence.extra["observed_branches"] == 1
    assert exploration.evidence.extra["seeded_branches"] == 1
    assert sorted(exploration.return_values) == [1, 2]


def test_two_way_conditional_is_deterministic(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_WAY, name="deterministic.elf")
    info = _load(path)

    first = explore_paths(path, info, TEXT_VA, initial_registers={"edi": 5})
    second = explore_paths(path, info, TEXT_VA, initial_registers={"edi": 5})

    assert first.to_dict() == second.to_dict()
    assert [entry.index for entry in first.entries] == [0, 1]


def test_seeded_branch_follows_the_requested_direction_from_the_other_seed(
    tmp_path: Path,
) -> None:
    """With ``edi=0`` the observed side is the *taken* one; the pairs swap."""
    path = _sample(tmp_path, CODE_TWO_WAY, name="seed0.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, initial_registers={"edi": 0})

    assert exploration.paths == 2
    first, second = exploration.entries
    assert first.return_value == 2
    assert first.decisions[0].basis == "observed"
    assert second.return_value == 1
    assert second.decisions[0].basis == "seeded"
    assert sorted(exploration.return_values) == [1, 2]


# ---- budget, unmapped and unresolved paths --------------------------------


def test_budget_exhaustion_stops_the_path(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_SPIN, name="spin.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, max_steps=5)

    assert exploration.paths == 1
    entry = exploration.entries[0]
    assert entry.stopped_reason == "budget"
    assert entry.instructions == 5
    assert entry.return_value is None  # a truncated path has no return value
    assert entry.decisions == ()
    assert any("truncated" in warning for warning in entry.warnings)
    assert exploration.steps == 5
    assert exploration.max_steps == 5
    assert exploration.complete is False
    assert exploration.warnings  # the shortfall is stated, never hidden
    assert exploration.evidence.extra["stopped_reasons"] == {"budget": 1}
    assert exploration.evidence.confidence.value == "low"


def test_unmapped_access_stops_the_path(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_LOAD_RBX, name="unmapped.elf")
    info = _load(path)

    exploration = explore_paths(
        path, info, TEXT_VA, initial_registers={"rbx": UNMAPPED_VA}
    )

    assert exploration.paths == 1
    entry = exploration.entries[0]
    assert entry.stopped_reason == "unmapped"
    assert entry.return_value is None
    assert any("not mapped" in warning for warning in entry.warnings)
    assert exploration.unresolved == 1
    assert exploration.complete is False
    assert exploration.evidence.extra["unresolved_paths"] == 1


def test_unresolvable_branch_is_reported_not_guessed(tmp_path: Path) -> None:
    """``loop`` decrements ``rcx`` before testing it, so the path is blocked."""
    path = _sample(tmp_path, CODE_LOOP_SELF, name="loop.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA)

    assert exploration.paths == 1
    entry = exploration.entries[0]
    assert entry.stopped_reason == "blocked"
    assert entry.return_value is None
    assert entry.decisions == ()  # nothing was claimed as a decision
    notes = " ".join(entry.warnings)
    assert "does not model" in notes
    assert "unresolved" in notes
    assert exploration.unresolved == 1


def test_path_cap_truncates_and_says_so(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_WAY, name="cap.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, max_paths=1)

    assert exploration.paths == 1
    assert exploration.complete is False
    assert any("path limit" in warning for warning in exploration.warnings)
    assert exploration.max_paths == 1


def test_call_into_the_same_section_resumes_the_caller(tmp_path: Path) -> None:
    """A callee's ``ret`` pops a return address inside the section, so it continues.

    This is the same rule ``emulate`` uses: only a ``ret`` that leaves the
    section completes a path, so a called function does not cut the path short.
    """
    path = _sample(tmp_path, CODE_CALL_IN_SECTION, name="call.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA)

    assert exploration.paths == 1
    entry = exploration.entries[0]
    assert entry.stopped_reason == "return"
    assert entry.return_value == 9  # the callee's value, kept across the return
    assert entry.taken_targets == (CALLEE_VA, RESUME_VA)
    assert entry.decisions == ()
    assert exploration.complete is True


def test_counter_jump_is_seeded_through_its_register(tmp_path: Path) -> None:
    """``jrcxz`` tests a register, so the seed writes ``rcx`` rather than a flag."""
    path = _sample(tmp_path, CODE_JRCXZ, name="counter.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, initial_registers={"rcx": 0})

    assert exploration.paths == 2
    taken_path, fallthrough_path = exploration.entries
    assert taken_path.return_value == 2
    assert taken_path.decisions[0].basis == "observed"
    assert fallthrough_path.return_value == 1
    seeded = fallthrough_path.decisions[0]
    assert seeded.basis == "seeded"
    assert "rcx 0 -> 1" in seeded.note


# ---- unsupported machines and bad input -----------------------------------


def test_unsupported_architecture_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="arm.elf")
    info = _load(path)
    monkeypatch.setattr(info, "architecture", "aarch64")

    with pytest.raises(AnalysisError) as excinfo:
        explore_paths(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "x86" in message
    assert "aarch64" in message
    assert "no code was run" in message


def test_missing_emulator_raises_naming_unicorn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="nounicorn.elf")
    info = _load(path)
    monkeypatch.setattr(symbolic, "EMULATOR_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        explore_paths(path, info, TEXT_VA)

    assert "unicorn" in str(excinfo.value)


def test_bad_input_raises_analysis_error(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="bad.elf")
    info = _load(path)
    data_address = next(s for s in info.sections if s.name == ".shstrtab").virtual_address + 1

    with pytest.raises(AnalysisError):
        explore_paths(path, info, UNMAPPED_VA)  # not mapped by any section
    with pytest.raises(AnalysisError):
        explore_paths(path, info, data_address)  # not executable
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, max_paths=0)
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, max_steps=0)
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, max_paths=MAX_MAX_PATHS + 1)
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, max_steps=MAX_MAX_STEPS + 1)
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, initial_registers={"nope": 1})
    with pytest.raises(AnalysisError):
        explore_paths(path, info, TEXT_VA, initial_registers={"edi": -1})


def test_defaults_are_the_documented_constants(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="defaults.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA)

    assert exploration.max_paths == DEFAULT_MAX_PATHS
    assert exploration.max_steps == DEFAULT_MAX_STEPS
    assert exploration.address == TEXT_VA
    assert exploration.architecture == "x86_64"
    assert exploration.bitness == 64


# ---- serialization --------------------------------------------------------


def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_WAY, name="dict.elf")
    info = _load(path)

    exploration = explore_paths(path, info, TEXT_VA, initial_registers={"edi": 0})

    payload = exploration.to_dict()
    text = json.dumps(payload)  # no bytes, no Paths, no enums, no sets
    reloaded = json.loads(text)

    assert reloaded["address"] == f"0x{TEXT_VA:x}"
    assert reloaded["explorer"] == "unicorn"
    assert reloaded["paths"] == 2
    assert isinstance(reloaded["steps"], int)
    assert isinstance(reloaded["complete"], bool)
    assert [value for value in reloaded["return_values"]] == ["0x2", "0x1"]
    entry = reloaded["entries"][0]
    assert isinstance(entry["taken_targets"], list)
    assert all(target.startswith("0x") for target in entry["taken_targets"])
    assert isinstance(entry["decisions"], list)
    decision = entry["decisions"][0]
    assert set(decision) == {"address", "mnemonic", "taken", "target", "basis", "note"}
    assert isinstance(decision["taken"], bool)
    assert isinstance(entry["registers"], dict)
    assert all(isinstance(value, str) for value in entry["registers"].values())
    assert reloaded["evidence"]["source"] == "symbolic.unicorn"
    assert isinstance(reloaded["evidence"]["extra"]["assumptions"], list)


# ---- the optional angr bridge ---------------------------------------------


def test_angr_bridge_raises_naming_angr_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="noangr.elf")
    info = _load(path)
    monkeypatch.setattr(symbolic, "ANGR_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        explore_with_angr(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "angr" in message
    assert "not installed" in message
    assert "pip install" in message
    assert "unicorn" in message  # points at the explorer that always works


def test_angr_bridge_without_the_extra_raises(tmp_path: Path) -> None:
    """The real probe, not the monkeypatch: this is what a CI machine sees."""
    if angr_available():  # pragma: no cover - angr is not installed in CI
        pytest.skip("angr is installed here, so the unavailable path cannot be tested")
    path = _sample(tmp_path, CODE_MOV_EAX_42, name="realnoangr.elf")
    info = _load(path)

    with pytest.raises(AnalysisError):
        explore_with_angr(path, info, TEXT_VA)


def test_angr_is_never_imported_at_module_import_time() -> None:
    tree = ast.parse(inspect.getsource(symbolic))
    imported: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name.split(".")[0] == "angr"]
    assert "angr" not in vars(symbolic)  # no module-level binding either

