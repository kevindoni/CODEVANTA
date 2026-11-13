"""Tests for ``scripts/fuzz_parsers.py``, the deterministic parser fuzzer.

Two kinds of test live here. The ones that drive the script the way a developer
does -- through a subprocess -- cover the CLI contract: exit status, the JSON
document, and the promise that a run writes nothing to disk. The ones that
import the script as a module cover what a subprocess cannot reach: the mutation
strategies, the replayable generator, and -- the important one -- the finding
pipeline itself. A parser that raises an undocumented exception has to end up
*reported*, so the fuzzer's reading of the documented contract is tested by
breaking a parser underneath it.

``--seed 7 --iterations 20`` is the clean baseline: it must stay silent while the
parsers hold their contract. The fuzzer is not toothless -- it already reports a
real defect elsewhere: a Mach-O whose section-header flags carry unknown bits
makes ``BinaryLoader.load`` raise LIEF's ``ValueError`` instead of
``BinaryLoadError`` (reproduce with ``--seed 4 --iterations 4 --target loader``,
root cause ``loader._macho_section``'s ``getattr(section, "flags", 0)``). That is
an open bug in the loader, not a behaviour of this script, so it is deliberately
not locked in by a test here.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from types import ModuleType

import pytest

from codevanta.core.disassembler import DisassemblyError
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError

REPO_ROOT = Path(__file__).resolve().parents[1]
FUZZER = REPO_ROOT / "scripts" / "fuzz_parsers.py"

#: Directories that are caches or VCS internals, not artefacts of a fuzz run.
SKIP_DIRS = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "dist"}
)


@lru_cache(maxsize=1)
def fuzzer() -> ModuleType:
    """Import ``scripts/fuzz_parsers.py`` as a module (it is not a package)."""
    spec = importlib.util.spec_from_file_location("fuzz_parsers", FUZZER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through ``sys.modules``, so the
    # module has to be registered before ``exec_module`` runs.
    sys.modules["fuzz_parsers"] = module
    spec.loader.exec_module(module)
    return module


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run the script as a developer would, capturing both streams."""
    return subprocess.run(
        [sys.executable, str(FUZZER), *args],
        cwd=None if cwd is None else str(cwd),
        capture_output=True,
        text=True,
        timeout=120.0,
        check=False,
    )


def _tree(root: Path) -> set[str]:
    """Every file under ``root``, ignoring caches and VCS internals."""
    found: set[str] = set()
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        base = Path(current)
        found.update((base / name).relative_to(root).as_posix() for name in filenames)
    return found


# ---- cli contract ----------------------------------------------------------


def test_short_clean_run_exits_zero_with_no_findings(tmp_path: Path) -> None:
    """The documented baseline: 20 mutants at seed 7 are handled cleanly."""
    completed = _run_cli("--iterations", "20", "--seed", "7", cwd=tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "no findings" in completed.stdout
    assert "finding(s)" not in completed.stdout
    # Every target ran and is accounted for in the table.
    for target in ("loader", "strings", "disasm", "decompile", "emulate"):
        assert target in completed.stdout


def test_json_document_parses_and_states_the_contract(tmp_path: Path) -> None:
    """``--json`` prints one machine-readable summary and nothing else."""
    completed = _run_cli("--json", "--iterations", "5", "--seed", "7", cwd=tmp_path)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["seed"] == 7
    assert payload["iterations"] == 5
    assert payload["mutants"] == 5
    assert payload["targets"] == ["loader", "strings", "disasm", "decompile", "emulate"]
    assert payload["status"] == "ok"
    assert payload["findings"] == []
    assert payload["exit_code"] == 0
    assert payload["stopped_early"] is False
    assert isinstance(payload["elapsed_seconds"], float)
    assert payload["runs"] == sum(payload["runs_per_target"].values())


def test_a_run_writes_nothing_to_disk(tmp_path: Path) -> None:
    """Mutants live in a temporary directory that is gone when the run ends."""
    scratch_glob = "codevanta-fuzz-*"
    before = _tree(REPO_ROOT)
    temp_before = set(Path(tempfile.gettempdir()).glob(scratch_glob))
    completed = _run_cli("--iterations", "5", "--seed", "7", cwd=tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert list(tmp_path.iterdir()) == [], "the fuzzer dropped artefacts in its cwd"
    assert _tree(REPO_ROOT) == before, "the fuzzer wrote into the checkout"
    # Scoped to this run: a directory some other, killed process left behind is
    # not evidence against this one.
    assert set(Path(tempfile.gettempdir()).glob(scratch_glob)) == temp_before


def test_unknown_target_and_bad_budgets_are_rejected() -> None:
    """Argument validation fails fast instead of fuzzing the wrong thing."""
    parser = fuzzer()._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--target", "nonsense"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--iterations", "-1"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--time-budget", "0"])


# ---- the finding pipeline --------------------------------------------------


def test_unexpected_exception_is_reported_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A parser raising ``KeyError`` must become a finding, not a traceback."""

    def broken_load(self: BinaryLoader, path: str | Path) -> BinaryInfo:
        raise KeyError("section name table")

    monkeypatch.setattr(BinaryLoader, "load", broken_load)

    exit_code = fuzzer().main(["--iterations", "3", "--seed", "7", "--target", "loader"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "findings (3)" in out
    assert "KeyError" in out
    assert "strategy=" in out
    assert "sha256=" in out


def test_broken_target_json_names_the_exact_mutant(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each finding carries the seed, iteration, strategy and SHA-256 to replay it."""

    def broken_load(self: BinaryLoader, path: str | Path) -> BinaryInfo:
        raise IndexError("section table index out of range")

    monkeypatch.setattr(BinaryLoader, "load", broken_load)

    exit_code = fuzzer().main(
        ["--json", "--iterations", "2", "--seed", "7", "--target", "loader"]
    )

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "findings"
    assert payload["exit_code"] == 1
    assert payload["runs"] == 2
    assert len(payload["findings"]) == 2  # one per mutant: the parser is broken
    finding = payload["findings"][0]
    assert finding["target"] == "loader"
    assert finding["iteration"] == 0
    assert finding["exception"].startswith("IndexError")
    assert finding["location"]
    assert finding["traceback"]
    mutant = finding["mutant"]
    assert len(mutant["sha256"]) == 64
    assert mutant["strategy"] in {name for name, _ in fuzzer().STRATEGIES}
    assert mutant["description"]
    assert mutant["size"] > 0


@pytest.mark.parametrize(
    "error",
    [BinaryLoadError, AnalysisError, DisassemblyError, OSError],
    ids=lambda error: error.__name__,
)
def test_documented_exceptions_are_not_findings(
    error: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The four documented "unusable input" exceptions are the parser answering."""

    def documented_failure(self: BinaryLoader, path: str | Path) -> BinaryInfo:
        raise error("not a usable binary")

    monkeypatch.setattr(BinaryLoader, "load", documented_failure)

    exit_code = fuzzer().main(["--iterations", "2", "--seed", "7", "--target", "loader"])

    assert exit_code == 0
    assert "no findings" in capsys.readouterr().out


@pytest.mark.parametrize(
    "error",
    [KeyError, IndexError, AttributeError, struct.error, RecursionError, ValueError],
    ids=lambda error: error.__name__,
)
def test_every_other_exception_is_a_finding(
    error: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """KeyError/IndexError/AttributeError/struct.error/RecursionError mean "bug"."""

    def undocumented_failure(self: BinaryLoader, path: str | Path) -> BinaryInfo:
        raise error("parser defect")

    monkeypatch.setattr(BinaryLoader, "load", undocumented_failure)

    exit_code = fuzzer().main(["--iterations", "1", "--seed", "7", "--target", "loader"])

    assert exit_code == 1
    assert error.__name__ in capsys.readouterr().out


# ---- mutation engine -------------------------------------------------------


def test_the_generator_is_replayable() -> None:
    """Same seed, same mutants: a finding can always be regenerated."""
    module = fuzzer()
    seeds = module._seed_inputs()

    def simulate(seed: int) -> list[tuple[str, str, str]]:
        rng = random.Random(seed)
        return [
            (mutant.seed_name, mutant.strategy, mutant.sha256)
            for mutant in (module._mutate(rng, seeds) for _ in range(25))
        ]

    assert simulate(11) == simulate(11)
    assert simulate(11) != simulate(12)


def test_every_strategy_is_reachable_and_described() -> None:
    """All seven mutation strategies appear in a short run, each with a reason."""
    module = fuzzer()
    rng = random.Random(0)
    seeds = module._seed_inputs()
    mutants = [module._mutate(rng, seeds) for _ in range(80)]

    assert {mutant.strategy for mutant in mutants} == {
        name for name, _ in module.STRATEGIES
    }
    for mutant in mutants:
        assert mutant.description, "a mutant must say what was changed"
        assert len(mutant.data) <= module.MAX_MUTANT_BYTES


def test_mutants_differ_from_their_seeds_the_way_the_strategy_says() -> None:
    """Each strategy is checked against its own description, not just "changed"."""
    module = fuzzer()
    elf = module._build_elf(64)
    rng = random.Random(3)

    truncated = module._strategy_truncate(rng, "elf", elf)
    assert len(truncated.data) <= len(elf)
    assert elf.startswith(truncated.data)

    flipped = module._strategy_byteflip(rng, "elf", elf)
    differing = sum(1 for a, b in zip(elf, flipped.data, strict=True) if a != b)
    assert 1 <= differing <= 4
    assert len(flipped.data) == len(elf)

    zeroed = module._strategy_zero_sizes(rng, "elf", elf)
    assert zeroed.description.endswith("= 0x0")

    huge = module._strategy_huge_counts(rng, "elf", elf)
    assert "0x" in huge.description

    grown = module._strategy_splice(rng, "elf", elf)
    assert len(grown.data) > len(elf)


def test_empty_payload_does_not_break_the_generator() -> None:
    """A zero-byte sample is legal input, so no strategy may crash on it."""
    module = fuzzer()
    rng = random.Random(0)
    for name, strategy in module.STRATEGIES:
        mutant = strategy(rng, "empty.bin", b"")
        assert mutant.strategy == name
        assert mutant.description
        assert mutant.data == b""


def test_synthetic_elf_seeds_are_real_binaries() -> None:
    """The in-memory seeds must parse, or the fuzzer only tests rejections."""
    module = fuzzer()
    with tempfile.TemporaryDirectory() as scratch:
        for bitness, machine_bits in ((64, 64), (32, 32)):
            path = Path(scratch) / f"elf{bitness}.bin"
            path.write_bytes(module._build_elf(bitness))
            info = BinaryLoader().load(path)
            assert info.format == "ELF"
            assert info.bitness == machine_bits
            assert info.entry_point is not None
            assert any(section.is_executable for section in info.sections)

        header_only = Path(scratch) / "header.bin"
        header_only.write_bytes(module._elf_header_only(64))
        assert BinaryLoader().load(header_only).sections == []


# ---- runner ----------------------------------------------------------------


def test_target_selection_runs_only_the_named_surface() -> None:
    """``--target strings`` must not quietly run the other four."""
    report = fuzzer().fuzz(iterations=3, seed=7, targets=("strings",))

    assert report.targets == ("strings",)
    assert report.runs_per_target == {"strings": 3}
    assert report.runs == 3
    assert report.exit_code == 0


def test_time_budget_stops_the_run_between_mutants() -> None:
    """A budget much shorter than the work ends the run early, and says so."""
    report = fuzzer().fuzz(iterations=5000, seed=0, targets=("loader",), time_budget=0.4)

    assert report.stopped_early is True
    assert 0 < report.mutants < 5000
    # The loop can stop after generating a mutant but before running it, so the
    # run count never exceeds the mutant count; with one target they differ by
    # at most that one.
    assert 0 < report.runs <= report.mutants
    assert report.runs_per_target == {"loader": report.runs}


def test_skipped_targets_are_reported_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """A target whose dependency is missing is named, not silently dropped."""
    monkeypatch.setattr(fuzzer(), "emulator_status", lambda: "unicorn is not installed")

    report = fuzzer().fuzz(iterations=2, seed=7, targets=("loader", "emulate"))

    assert "emulate" in report.skipped
    assert "unicorn" in report.skipped["emulate"]
    assert report.runs_per_target == {"loader": 2}
    assert report.to_dict()["skipped"] == {"emulate": "unicorn is not installed"}



