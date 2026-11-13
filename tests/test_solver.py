"""Tests for the solver lane over tiny synthetic ELF samples.

Three families live here, and the module runs green in every environment:

* **The angr explorer** (:func:`codevanta.analysis.solver.explore_symbolic`)
  -- skipped when angr is absent (the ``decompile-parity`` CI job is where
  angr is real; ``pip install 'codevanta[decompilers]'`` enables it anywhere).
* **The z3-backed path checker** (:func:`translate_path`, :func:`check_path`,
  :func:`enumerate_feasible_paths`, :func:`summarize_result`) -- skipped when
  z3 is absent (``python -m pip install z3-solver`` enables it; z3 is
  deliberately not a dependency).
* **Mandatory-everywhere tests** -- the naive fallback contract (payload
  byte-identical, typed ``z3 not installed - naive evaluation`` warning with
  the ``sym.naive`` evidence source), the bounded rules (timeouts, caps,
  constraint ceiling), and the pipeline logic driven through the solver seam
  (a stub exposing the exact ``add``/``check``/``model`` interface), so the
  pruning and augmentation behavior is tested without z3 installed.
"""

from __future__ import annotations

import faulthandler
import json
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis import solver, symbolic
from codevanta.analysis.solver import (
    SolverPath,
    SymbolicResult,
    explore_symbolic,
    solver_status,
)
from codevanta.analysis.symbolic import Branch, Entry, PathExploration
from codevanta.cli.main import app
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

#: The angr explorer tests need angr; everywhere else they skip.
needs_angr = pytest.mark.skipif(
    not solver.SOLVER_AVAILABLE,
    reason="the angr explorer tests need angr, which only the decompile-parity CI job "
    "installs (locally: pip install 'codevanta[decompilers]')",
)

#: The z3 translation tests need z3; everywhere else they skip.
needs_z3 = pytest.mark.skipif(
    not solver.HAS_Z3,
    reason=f"the z3 translation tests need z3 ({solver.Z3_INSTALL_HINT} enables them)",
)

#: The naive-fallback contract only exists when z3 is absent.
needs_no_z3 = pytest.mark.skipif(
    solver.HAS_Z3,
    reason="the naive fallback only runs when z3 is absent",
)

#: The CLI end-to-end tests need the unicorn engine.
needs_unicorn = pytest.mark.skipif(
    not symbolic.EMULATOR_AVAILABLE,
    reason="the CLI tests need the unicorn engine (pip install unicorn)",
)

#: Virtual address of .text in the ELF64 samples.
TEXT_VA = 0x401000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 ``mov rax, rdi; add rax, rsi; ret`` -- straight line, one path.
CODE_ADD_RDI_RSI = (
    bytes.fromhex("4889f8")            # mov rax, rdi
    + bytes.fromhex("4801f0")          # add rax, rsi
    + bytes.fromhex("c3")              # ret
)

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

#: x86-64 ``jmp $; ret`` -- spins, so only the step budget can stop it. The
#: unreachable ``ret`` exists so the find set is not empty.
CODE_SPIN = bytes.fromhex("ebfe") + bytes.fromhex("c3")


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


# ---- availability ----------------------------------------------------------


@needs_angr
def test_availability_probe_and_status() -> None:
    """With angr installed (the only place this module runs) both say so."""
    assert solver.SOLVER_AVAILABLE is True
    assert isinstance(solver.SOLVER_AVAILABLE, bool)
    status = solver_status()
    assert isinstance(status, str)
    assert status
    assert "angr" in status  # the "not installed" reason names angr too


# ---- straight line: concrete seeds in, concrete sum out --------------------


@needs_angr
def test_straight_line_returns_the_seeded_sum_with_its_inputs(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="straight.elf")
    info = _load(path)

    result = explore_symbolic(
        path, info, TEXT_VA, initial_registers={"rdi": 0x10, "rsi": 0x20}
    )

    assert isinstance(result, SymbolicResult)
    assert isinstance(result.solver, str) and result.solver
    assert result.truncated is False
    assert all(isinstance(warning, str) for warning in result.warnings)
    assert len(result.paths) == 1
    entry = result.paths[0]
    assert isinstance(entry, SolverPath)
    assert entry.stopped_reason == "return"
    assert entry.return_value == 0x30  # 0x10 + 0x20, solved from the concrete seeds
    assert entry.steps >= 2  # the mov and the add; the ret is found, not executed
    assert entry.input_registers["rdi"] == 0x10
    assert entry.input_registers["rsi"] == 0x20
    assert all(isinstance(value, int) and value >= 0 for value in entry.input_registers.values())

    evidence = result.evidence
    assert evidence.source == "solver.angr"
    assert evidence.method == "solver_symbolic_execution"
    assert evidence.confidence.value == "medium"
    assert evidence.address == TEXT_VA
    assert evidence.detail is not None
    assert "no proof all paths were found" in evidence.detail
    assert any("no proof all paths were found" in item for item in evidence.extra["assumptions"])


# ---- a two-way conditional: two paths, two constraints, two returns --------


@needs_angr
def test_two_way_conditional_yields_both_sides_with_their_constraints(tmp_path: Path) -> None:
    """With no concrete seeds, ``rdi`` stays symbolic and angr forks at the ``je``."""
    path = _sample(tmp_path, CODE_TWO_WAY, name="twoway.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA)

    returning = [entry for entry in result.paths if entry.stopped_reason == "return"]
    assert len(result.paths) >= 2
    assert {entry.return_value for entry in returning} == {1, 2}
    assert all(entry.constraints for entry in returning)  # each side carries its je constraint
    assert all("rdi" in entry.input_registers for entry in returning)
    assert all(
        isinstance(value, int) and value >= 0
        for entry in returning
        for value in entry.input_registers.values()
    )


# ---- the step budget is reachable and flags truncation ----------------------


@needs_angr
def test_step_budget_truncates_and_reports_budget_paths(tmp_path: Path) -> None:
    """``jmp $`` never reaches its ret, so a small budget must cut it -- and say so."""
    path = _sample(tmp_path, CODE_SPIN, name="spin.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA, max_steps=3)

    assert result.truncated is True
    assert result.warnings
    assert any("budget" in warning for warning in result.warnings)
    budget_paths = [entry for entry in result.paths if entry.stopped_reason == "budget"]
    assert len(budget_paths) == 1
    assert budget_paths[0].return_value is None  # never reached a ret: no return value
    assert 1 <= budget_paths[0].steps <= 3
    assert not [entry for entry in result.paths if entry.stopped_reason == "return"]


# ---- caller mistakes --------------------------------------------------------


@needs_angr
def test_unsupported_architecture_raises_naming_angr(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="arch.elf")
    info = BinaryInfo(
        path=path,
        format="elf",
        architecture="arm64",
        bitness=64,
        endianness="little",
        entry_point=TEXT_VA,
        image_base=0x400000,
        sha256="0" * 64,
        file_size=path.stat().st_size,
    )

    with pytest.raises(AnalysisError) as excinfo:
        explore_symbolic(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "arm64" in message
    assert "angr" in message
    assert "pip install" in message


@needs_angr
def test_missing_angr_raises_naming_angr_and_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate, forced: what every machine without the decompilers extra sees."""
    path = _sample(tmp_path, CODE_ADD_RDI_RSI, name="noangr.elf")
    info = _load(path)
    monkeypatch.setattr(solver, "SOLVER_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        explore_symbolic(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "angr" in message
    assert "not installed" in message
    assert "pip install" in message


# ---- serialization ----------------------------------------------------------


@needs_angr
def test_to_dict_is_json_safe(tmp_path: Path) -> None:
    path = _sample(tmp_path, CODE_TWO_WAY, name="dict.elf")
    info = _load(path)

    result = explore_symbolic(path, info, TEXT_VA, max_paths=4)

    reloaded = json.loads(json.dumps(result.to_dict()))  # no bytes, no solver objects
    assert reloaded["address"] == f"0x{TEXT_VA:x}"
    assert reloaded["solver"] == result.solver
    assert reloaded["truncated"] is False
    assert reloaded["path_count"] == len(result.paths)
    assert isinstance(reloaded["warnings"], list)
    entry = reloaded["paths"][0]
    assert set(entry) == {
        "return_value",
        "constraints",
        "input_registers",
        "stopped_reason",
        "steps",
    }
    assert entry["stopped_reason"] == "return"
    assert entry["return_value"].startswith("0x")
    assert isinstance(entry["constraints"], list)
    assert all(isinstance(constraint, str) for constraint in entry["constraints"])
    assert isinstance(entry["input_registers"], dict)
    assert all(
        isinstance(value, str) and value.startswith("0x")
        for value in entry["input_registers"].values()
    )
    assert isinstance(entry["steps"], int)
    assert reloaded["evidence"]["confidence"] == "medium"
    assert "no proof all paths were found" in reloaded["evidence"]["detail"]


# ---- z3-backed translation and checking (skipped without z3) -----------------


def _branch(address: int, mnemonic: str, taken: bool) -> Branch:
    """Build one naive explorer decision for the translation tests."""
    return Branch(
        address=address, mnemonic=mnemonic, taken=taken, target=address + 4, basis="observed"
    )


@needs_z3
def test_translate_path_maps_flags_and_counters_onto_bitvecs() -> None:
    """``je`` becomes a per-site rflags predicate, ``jrcxz`` a counter BitVec."""
    decisions = (_branch(0x401000, "je", True), _branch(0x401010, "jrcxz", False))

    constraints = solver.translate_path(decisions, bits=64, path_index=2)

    assert constraints.path_index == 2
    assert constraints.bits == 64
    assert len(constraints.expressions) == 2
    assert set(constraints.inputs) == {"codevanta_rflags@0x401000", "codevanta_rcx"}
    assert constraints.dropped == 0
    reloaded = json.loads(json.dumps(constraints.to_dict()))  # no solver objects
    assert reloaded["constraint_count"] == 2
    assert reloaded["inputs"] == ["codevanta_rcx", "codevanta_rflags@0x401000"]


@needs_z3
def test_translate_path_rejects_bad_width_and_non_branches() -> None:
    """Only 32/64-bit machines translate; only Branch decisions translate."""
    with pytest.raises(AnalysisError, match="bits must be 32 or 64"):
        solver.translate_path((_branch(0x401000, "je", True),), bits=16)
    with pytest.raises(AnalysisError, match="must be a symbolic Branch"):
        solver.translate_path(("not-a-branch",), bits=32)  # type: ignore[list-item]


@needs_z3
def test_check_path_sat_assigns_flag_bits_and_skips_unknown_mnemonics() -> None:
    """A satisfiable path gets a model; an untranslatable branch is a note, not an error."""
    decisions = (
        _branch(0x401000, "jle", True),
        _branch(0x401002, "bogus", True),
    )
    constraints = solver.translate_path(decisions, bits=64)

    assert any("has no z3 translation" in note for note in constraints.notes)
    assert len(constraints.expressions) == 1  # the untranslatable one was skipped

    verdict = solver.check_path(constraints, timeout_ms=1000)

    assert verdict.verdict == "sat"
    assert verdict.solver_ms >= 0
    flags = verdict.model["codevanta_rflags@0x401000"]
    zf = (flags >> 6) & 1
    sf = (flags >> 7) & 1
    of = (flags >> 11) & 1
    assert zf == 1 or sf != of  # exactly what a taken jle asserts
    summary = solver.summarize_result(verdict, constraints)
    assert summary["verdict"] == "sat"
    assert summary["model"]["codevanta_rflags@0x401000"] == f"0x{flags:x}"


@needs_z3
def test_check_path_unsat_on_contradictory_counter_decisions() -> None:
    """One shared rcx cannot be both zero and non-zero: honest ``unsat``."""
    decisions = (_branch(0x401000, "jrcxz", True), _branch(0x401004, "jrcxz", False))
    constraints = solver.translate_path(decisions, bits=64)

    verdict = solver.check_path(constraints, timeout_ms=1000)

    assert verdict.verdict == "unsat"
    assert verdict.model == {}


@needs_z3
def test_enumerate_feasible_paths_keeps_only_sat_and_respects_the_cap() -> None:
    """Only satisfiable sets survive, with model values, and the cap bounds output."""
    sat = solver.translate_path((_branch(0x401000, "jz", True),), bits=32, path_index=0)
    unsat = solver.translate_path(
        (_branch(0x401000, "jrcxz", True), _branch(0x401004, "jrcxz", False)), bits=64,
        path_index=1,
    )
    sat_two = solver.translate_path((_branch(0x401008, "jnz", False),), bits=64, path_index=2)

    feasible = solver.enumerate_feasible_paths([sat, unsat, sat_two], max_paths=16)
    assert [verdict.path_index for verdict in feasible] == [0, 2]
    assert all(verdict.model for verdict in feasible)

    capped = solver.enumerate_feasible_paths([sat, unsat, sat_two], max_paths=1)
    assert [verdict.path_index for verdict in capped] == [0]


@needs_z3
def test_constraint_ceiling_sixty_four_per_path() -> None:
    """70 flag decisions: 64 asserted, the rest counted and named."""
    decisions = tuple(_branch(0x500000 + 8 * index, "je", True) for index in range(70))

    constraints = solver.translate_path(decisions, bits=64)

    assert len(constraints.expressions) == solver.MAX_CONSTRAINTS_PER_PATH
    assert constraints.dropped == 6
    assert any("cap" in note for note in constraints.notes)


# ---- bounded rules (validated before any solver is touched: run everywhere) ---


def test_solver_time_and_report_budgets_are_enforced() -> None:
    """Timeouts and caps are validated as ints in range, everywhere."""
    constraints = solver.PathConstraints(
        path_index=0, bits=64, expressions=(), inputs={}, dropped=0, notes=()
    )
    for bad_timeout in (0, -1, solver.MAX_TIMEOUT_MS + 1, "1000", True):
        with pytest.raises(AnalysisError, match="timeout_ms"):
            solver.check_path(constraints, timeout_ms=bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(AnalysisError, match="timeout_ms"):
            solver.solve_exploration(_exploration(), timeout_ms=bad_timeout)  # type: ignore[arg-type]
    for bad_cap in (0, -1, solver.MAX_ENUMERATE_PATHS + 1, "16"):
        with pytest.raises(AnalysisError, match="max_paths"):
            solver.enumerate_feasible_paths([constraints], max_paths=bad_cap)  # type: ignore[arg-type]
        with pytest.raises(AnalysisError, match="max_paths"):
            solver.solve_exploration(_exploration(), max_paths=bad_cap)  # type: ignore[arg-type]


def test_solve_exploration_rejects_an_unknown_mode() -> None:
    """Only auto and naive exist; anything else is a typed error, not a fallback."""
    with pytest.raises(AnalysisError, match="mode must be 'auto' or 'naive'"):
        solver.solve_exploration(_exploration(), mode="z3")


# ---- the fake-solver seam: pipeline logic without z3 -------------------------


def _exploration() -> PathExploration:
    """A three-path naive exploration built literally (no unicorn, no angr)."""
    evidence = Evidence(
        source="symbolic.unicorn",
        method="branch_decision_replay",
        confidence=Confidence.MEDIUM,
        address=TEXT_VA,
    )
    entries = tuple(
        Entry(
            index=index,
            decisions=(_branch(TEXT_VA + index, "je", index != 1),),
            taken_targets=(),
            registers={"rax": index},
            return_value=index if index != 1 else None,
            stopped_reason="return",
            instructions=5 + index,
            warnings=(),
        )
        for index in range(3)
    )
    return PathExploration(
        address=TEXT_VA,
        explorer="unicorn",
        architecture="x86_64",
        bitness=64,
        max_paths=8,
        max_steps=2000,
        steps=18,
        complete=True,
        entries=entries,
        warnings=(),
        evidence=evidence,
    )


class _FakeModel:
    """Stub for the one z3 model call the checker makes."""

    def __init__(self, values: dict[str, int]) -> None:
        self._values = values

    def eval(self, expression: Any, model_completion: bool = True) -> Any:
        return _FakeValue(self._values[str(expression)])


class _FakeValue:
    """Stub for the one z3 value call the checker makes."""

    def __init__(self, value: int) -> None:
        self._value = value

    def as_long(self) -> int:
        return self._value


class _FakeSolver:
    """Stub with the solver seam's exact interface: ``add``/``check``/``model``."""

    def __init__(
        self,
        answer: str,
        values: dict[str, int] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.answer = answer
        self.values = values or {}
        self.error = error
        self.added: list[Any] = []

    def add(self, expression: Any) -> None:
        self.added.append(expression)

    def check(self) -> str:
        if self.error is not None:
            raise self.error
        return self.answer

    def model(self) -> _FakeModel:
        return _FakeModel(self.values)


def _stub_constraints(path_index: int) -> solver.PathConstraints:
    """Constraints whose expressions are dummies (the stub solver ignores them)."""
    return solver.PathConstraints(
        path_index=path_index,
        bits=64,
        expressions=(f"c{path_index}",),
        inputs={"codevanta_rcx": f"rcx{path_index}"},
        dropped=0,
        notes=(),
    )


def test_check_path_with_stub_solver_sat_unknown_and_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seam drives all three verdicts plus the typed z3-failure error."""
    constraints = _stub_constraints(7)
    fake = _FakeSolver("sat", {"rcx7": 0x2A})
    monkeypatch.setattr(solver, "HAS_Z3", True)
    monkeypatch.setattr(solver, "_import_z3", lambda: None)
    monkeypatch.setattr(solver, "_new_solver", lambda timeout_ms: fake)

    verdict = solver.check_path(constraints, timeout_ms=250)
    assert verdict.verdict == "sat"
    assert verdict.model == {"codevanta_rcx": 0x2A}
    assert fake.added == ["c7"]  # the constraint really was asserted

    monkeypatch.setattr(solver, "_new_solver", lambda timeout_ms: _FakeSolver("unknown"))
    unknown = solver.check_path(constraints)
    assert unknown.verdict == "unknown"
    assert unknown.model == {}

    broken = _FakeSolver("sat", error=RuntimeError("boom"))
    monkeypatch.setattr(solver, "_new_solver", lambda timeout_ms: broken)
    with pytest.raises(AnalysisError, match="z3 failed while checking path 7"):
        solver.check_path(constraints)


def test_solve_exploration_pipeline_prunes_annotates_and_augments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsat is pruned with a warning, unknown is kept, survivors gain solver fields."""
    exploration = _exploration()
    monkeypatch.setattr(solver, "HAS_Z3", True)
    monkeypatch.setattr(solver, "_import_z3", lambda: None)
    monkeypatch.setattr(
        solver, "translate_path", lambda decisions, bits, path_index: _stub_constraints(path_index)
    )
    solvers = iter([_FakeSolver("sat", {"rcx0": 1}), _FakeSolver("unsat"), _FakeSolver("unknown")])
    monkeypatch.setattr(solver, "_new_solver", lambda timeout_ms: next(solvers))

    overlay = solver.solve_exploration(exploration, mode="auto", max_paths=16)

    assert overlay.ran is True
    assert overlay.solver == "z3"
    assert overlay.checked == 3
    assert overlay.pruned == (1,)
    assert [verdict.path_index for verdict in overlay.entries] == [0, 2]

    document = overlay.augmented_dict(exploration)
    assert [entry["index"] for entry in document["entries"]] == [0, 2]
    assert document["entries"][0]["solver"]["feasible"] is True
    assert document["entries"][0]["solver"]["model"] == {"codevanta_rcx": "0x1"}
    assert isinstance(document["entries"][0]["solver"]["solver_ms"], int)
    assert document["entries"][1]["solver"]["feasible"] is None  # unknown kept, honestly
    assert document["solver"]["pruned"] == [1]
    assert "path 1 pruned: infeasible under its branch constraints" in document["warnings"]
    assert json.dumps(document)  # JSON-safe end to end


def test_solve_exploration_report_cap_keeps_first_and_warns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """max_paths bounds the reported survivors; the surplus is named, not lost."""
    exploration = _exploration()
    monkeypatch.setattr(solver, "HAS_Z3", True)
    monkeypatch.setattr(solver, "_import_z3", lambda: None)
    monkeypatch.setattr(
        solver, "translate_path", lambda decisions, bits, path_index: _stub_constraints(path_index)
    )
    solvers = iter(
        [
            _FakeSolver("sat", {"rcx0": 1}),
            _FakeSolver("sat", {"rcx1": 2}),
            _FakeSolver("sat", {"rcx2": 3}),
        ]
    )
    monkeypatch.setattr(solver, "_new_solver", lambda timeout_ms: next(solvers))

    overlay = solver.solve_exploration(exploration, mode="auto", max_paths=1)

    assert [verdict.path_index for verdict in overlay.entries] == [0]
    assert any("max_paths=1" in warning for warning in overlay.warnings)


# ---- the naive contract: today's behavior, exactly, plus the typed warning ----


def test_naive_mode_leaves_the_payload_exactly_unchanged() -> None:
    """``--solver naive`` means today's output, byte for byte."""
    exploration = _exploration()

    overlay = solver.solve_exploration(exploration, mode="naive")

    assert overlay.ran is False
    assert overlay.solver == "naive"
    assert overlay.warnings == ()
    assert overlay.augmented_dict(exploration) == exploration.to_dict()


@needs_no_z3
def test_auto_without_z3_falls_back_with_the_typed_warning() -> None:
    """No z3: today's payload plus exactly one warning, evidence source ``sym.naive``."""
    exploration = _exploration()

    overlay = solver.solve_exploration(exploration, mode="auto")

    assert overlay.ran is False
    assert overlay.solver == "naive"
    assert overlay.warnings == ("z3 not installed - naive evaluation",)
    assert overlay.evidence.source == "sym.naive"
    assert overlay.evidence.extra["solver"] == "naive"

    document = overlay.augmented_dict(exploration)
    base = exploration.to_dict()
    assert set(document) == set(base)  # no new keys: exactly today, plus the warning
    assert document == {**base, "warnings": [*base["warnings"], *overlay.warnings]}


@needs_z3
def test_auto_with_z3_checks_real_branch_decisions() -> None:
    """With z3 present the overlay really runs on literal decisions."""
    exploration = _exploration()

    overlay = solver.solve_exploration(exploration, mode="auto")

    assert overlay.ran is True
    assert overlay.solver == "z3"
    assert overlay.checked == 3
    assert overlay.pruned == ()
    assert overlay.evidence.source == "sym.solver"
    assert overlay.evidence.extra["solver"] == "z3"
    document = overlay.augmented_dict(exploration)
    assert all(entry["solver"]["feasible"] is True for entry in document["entries"])


def test_translate_path_without_z3_is_a_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The translation gate names z3 and the install command, never an ImportError."""
    monkeypatch.setattr(solver, "HAS_Z3", False)
    with pytest.raises(AnalysisError, match="z3-solver"):
        solver.translate_path((_branch(0x401000, "je", True),))


# ---- CLI: the --solver flag end to end (needs unicorn; z3 world flagged) ------


@pytest.fixture()
def _faulthandler_stays_off() -> Iterator[None]:
    """Keep CPython's fault handler off: the emulator re-arms it with a real
    stderr descriptor, which CliRunner's in-memory stream cannot provide
    (the same workaround as ``tests/test_cli_phase7.py``)."""
    faulthandler.disable()
    yield


def _run_symbolic(tmp_path: Path, code: bytes, *extra: str):
    path = _sample(tmp_path, code, name="cli.elf")
    runner = CliRunner()
    return runner.invoke(app, ["symbolic", str(path), f"0x{TEXT_VA:x}", "--json", *extra])


@needs_unicorn
@needs_no_z3
@pytest.mark.usefixtures("_faulthandler_stays_off")
def test_symbolic_cli_auto_without_z3_warns_and_naive_does_not(tmp_path: Path) -> None:
    """The typed warning appears on auto, never on naive; the rest is identical."""
    auto = _run_symbolic(tmp_path, CODE_TWO_WAY)
    naive = _run_symbolic(tmp_path, CODE_TWO_WAY, "--solver", "naive")

    assert auto.exit_code == 0, auto.output
    assert naive.exit_code == 0, naive.output
    auto_payload = json.loads(auto.output)
    naive_payload = json.loads(naive.output)
    assert solver.NAIVE_FALLBACK_WARNING in auto_payload["warnings"]
    assert naive_payload == {
        **auto_payload,
        "warnings": [w for w in auto_payload["warnings"] if w != solver.NAIVE_FALLBACK_WARNING],
    }


@needs_unicorn
@needs_z3
@pytest.mark.usefixtures("_faulthandler_stays_off")
def test_symbolic_cli_auto_with_z3_augments_the_payload(tmp_path: Path) -> None:
    """With z3, auto prunes nothing here but every entry gains solver fields."""
    result = _run_symbolic(tmp_path, CODE_TWO_WAY)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["solver"]["solver"] == "z3"
    assert payload["solver"]["ran"] is True
    assert all(entry["solver"]["feasible"] is True for entry in payload["entries"])
