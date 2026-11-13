#!/usr/bin/env python3
"""Turn the micro-benchmark of ``scripts/bench.py`` into a regression gate.

``scripts/bench.py`` answers "how fast is this checkout?"; this script answers
"is this checkout slower than the one we shipped?". It runs *the same*
benchmarks -- by importing bench.py's measurement helpers, never by copying them
-- and compares every ``best_ms`` against a committed baseline::

    python scripts/bench_gate.py                        # gate against the platform baseline
    python scripts/bench_gate.py --repeat 1             # cheaper, noisier
    python scripts/bench_gate.py --json                 # machine-readable verdict
    python scripts/bench_gate.py --update-baseline      # accept the new numbers
    python scripts/bench_gate.py --platform linux       # pick a platform explicitly

Tolerance
---------
A row fails when ``current_ms > baseline_ms * (1 + --tolerance)``. With the
default ``--tolerance 0.5`` a benchmark may be up to 50% slower before it counts
as a regression. The comparison uses the unrounded measurements; only the table
and the JSON show 3 decimals. A row that is *missing* from the baseline also
fails: a benchmark with no reference cannot be gated, and letting it slide would
quietly disarm the gate for exactly the code that was just added.

Same protocol on both sides
---------------------------
``best_ms`` is the *minimum* of ``--repeat`` runs, and a minimum is a statistic:
the min of one run sits 20-50% above the min of fifteen on the sub-millisecond
rows of ``samples/`` (a single sample rarely lands on the floor of the noise).
Comparing those two numbers would measure the repeat count, not the code, so the
baseline records the repeat it was taken with and the gate never measures with
fewer: ``effective_repeat = max(--repeat, baseline repeat)``. ``--repeat`` can
therefore raise the precision of a run but not lower it below what the baseline
needs to stay comparable. For the same reason the committed baseline is a
best-of-15 rather than a best-of-3 -- at 15 runs the minimum has converged.

Confirming a failure
--------------------
A shared runner occasionally loses the CPU for a few milliseconds, which on a
0.1 ms benchmark looks exactly like a regression. So when a row comes out beyond
tolerance the gate measures once more and keeps the better of the two passes --
the same estimator with more samples, not a bigger tolerance -- and only then
reports failure. A real regression is slow in both passes and is reported as
usual.

Why a committed baseline is machine-dependent
---------------------------------------------
``best_ms`` is wall-clock time on the machine that recorded it. A different CPU,
a different Python patch release, a container sharing a core, or a loaded CI
runner can all shift the absolute numbers -- the *shape* of the benchmarks stays
comparable, the milliseconds do not. The committed baseline therefore holds the
numbers of one reference machine and ``--tolerance`` is what absorbs the
difference between that machine and yours. Re-record the baseline where CI runs
rather than on a laptop on battery, and treat a *consistent* 2x shift as "the
baseline is stale" (re-record it deliberately) rather than as a per-PR failure.
The sub-millisecond rows (``discover_functions``) are timer noise as much as
work, so read their delta as suggestive, not as a verdict.

Platforms
---------
Windows and Linux do not agree on milliseconds any better than two laptops do,
so the reference numbers are kept *per platform*: ``bench/baseline.<label>.json``.
The label is resolved once per run, in this order:

1. an explicit ``--platform LABEL`` (one of windows/linux/macos/unknown),
2. ``$RUNNER_OS`` on CI, case-insensitive (``Windows``/``Linux``/``macOS``),
3. ``os.name``: ``nt`` is windows; ``posix`` is macos when ``sys.platform`` is
   ``darwin`` and linux otherwise; anything else is unknown.

Every run line names the platform, and the ``--json`` report carries it as the
``platform`` key, so a red build can be traced to the file that judged it.
``--update-baseline`` writes the resolved platform's file only -- record the
linux numbers on a linux runner with ``python scripts/bench_gate.py
--update-baseline``, not by hand-editing ``bench/baseline.linux.json``, which
currently holds Windows-timed numbers and is consulted only by the
informational CI benchmark job.

Exit status
-----------
``0`` every row is within tolerance, ``1`` at least one row is slower than
``baseline * (1 + tolerance)`` or missing from the baseline, ``2`` the gate could
not evaluate at all (no baseline file, an unreadable or malformed baseline, an
unreadable sample).

Side effects
------------
Inputs are only ever read. The single file this script can write is the baseline,
and only when ``--update-baseline`` asks for it. The written document is
deterministic -- sorted keys, values rounded to 3 decimals, LF newlines -- so
re-recording an unchanged baseline produces byte-identical output and no diff.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The measurement helpers live in ``scripts/bench.py``; importing them keeps one
#: definition of "what a benchmark is" instead of a drifting second copy.
_SCRIPTS_DIR = Path(__file__).resolve().parent
_SRC_DIR = REPO_ROOT / "src"
for _extra in (_SCRIPTS_DIR, _SRC_DIR):
    if _extra.is_dir() and str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

import bench  # noqa: E402  (reused on purpose, see the module docstring)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Inputs compared when ``--samples`` is absent, as repository-relative paths.
DEFAULT_SAMPLE_PATHS: tuple[str, ...] = ("samples/pe64_text.bin", "samples/elf64_text.bin")

#: Directory holding the committed reference numbers, repository-relative. One
#: file per platform: ``baseline.<label>.json`` -- see the "Platforms" section.
BASELINE_DIR = "bench"

#: Relative slack: 0.5 means "up to 50% slower than the baseline still passes".
DEFAULT_TOLERANCE = 0.5

#: Every platform label ``--platform`` accepts, including the fallback.
PLATFORMS: tuple[str, ...] = ("windows", "linux", "macos", "unknown")

#: GitHub Actions' ``$RUNNER_OS`` values, lower-cased, that map onto a label.
#: Anything else leaves the decision to ``os.name``.
RUNNER_OS_ALIASES = {"windows": "windows", "linux": "linux", "macos": "macos"}

BASELINE_FORMAT = "codevanta-bench-gate"
BASELINE_VERSION = 1

#: Table headers, in display order.
HEADERS: tuple[str, ...] = ("benchmark", "baseline_ms", "current_ms", "delta%", "status")

#: Verdicts that fail the gate.
FAILING_STATUSES = frozenset({"regressed", "missing"})

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_UNEVALUABLE = 2


# ---------------------------------------------------------------------------
# Paths and rows
# ---------------------------------------------------------------------------


def resolve(path_text: str) -> Path:
    """Resolve ``path_text`` so the gate works from any directory.

    Relative paths -- the defaults included -- are repository-relative, which is
    what keeps the baseline keys, and therefore the committed file, independent
    of the current working directory.
    """
    path = Path(path_text)
    return path if path.is_absolute() else REPO_ROOT / path


def display(path: Path) -> str:
    """Render ``path`` relative to the repository when it lives inside it."""
    return bench.label_for(path)


def resolve_platform(explicit: str | None) -> str:
    """Return the platform label this run is measured on.

    The rule, in order: an explicit ``--platform`` wins; then ``$RUNNER_OS``
    (GitHub Actions, case-insensitive); then ``os.name`` -- ``nt`` is windows,
    ``posix`` is macos when ``sys.platform`` is ``darwin`` and linux otherwise;
    anything else is ``unknown``. CI needs the ``$RUNNER_OS`` step because a
    macos runner and a linux runner share ``os.name == "posix"`` and only the
    environment can tell them apart.
    """
    if explicit:
        return explicit
    runner_os = os.environ.get("RUNNER_OS")
    if runner_os:
        label = RUNNER_OS_ALIASES.get(runner_os.strip().lower())
        if label is not None:
            return label
    if os.name == "nt":
        return "windows"
    if os.name == "posix":
        return "macos" if sys.platform == "darwin" else "linux"
    return "unknown"


def default_baseline_path(platform: str) -> Path:
    """Return the committed baseline document for ``platform``."""
    return REPO_ROOT / BASELINE_DIR / f"baseline.{platform}.json"


def select_baseline_path(platform: str, baseline: str | None) -> Path:
    """Return the baseline to use: ``--baseline`` when given, else the platform's.

    ``--baseline`` keeps its old meaning -- one named file, wherever it lives --
    so scripts that already pass a path are unaffected by the split.
    """
    return resolve(baseline) if baseline else default_baseline_path(platform)


def row_key(row: bench.Row) -> str:
    """Return the stable baseline key of ``row``: the benchmark plus its input.

    ``load`` runs once per sample, so the benchmark name alone is not unique;
    ``diff_binaries`` already spells out its pair of inputs in ``row.path``.
    """
    return f"{row.benchmark} ({row.path})"


def was_measured(row: bench.Row) -> bool:
    """Report whether ``row`` carries a number (bench.py reports refusals as 0/0)."""
    return row.iterations > 0


def collect_rows(
    samples: Sequence[Path],
    *,
    repeat: int,
    limit_functions: int,
    max_instructions: int,
    warnings: list[str],
) -> list[bench.Row]:
    """Measure every sample the way ``bench.py`` does and return its rows.

    Raises:
        bench.BinaryLoadError: When a sample cannot be parsed; :func:`main` turns
            that into "the gate could not evaluate" instead of a fake verdict.
    """
    rows: list[bench.Row] = []
    for path in samples:
        rows.extend(
            bench.measure_path(
                path,
                repeat=repeat,
                limit_functions=limit_functions,
                max_instructions=max_instructions,
                warnings=warnings,
            )
        )
    if len(samples) >= 2:
        rows.extend(
            bench.measure_diff(
                samples[0],
                samples[1],
                repeat=repeat,
                limit_functions=limit_functions,
                warnings=warnings,
            )
        )
    return rows


def merge_best(left: Sequence[bench.Row], right: Sequence[bench.Row]) -> list[bench.Row]:
    """Return the better measurement of every row across two measurement passes.

    ``best_ms`` is already a minimum, so keeping the smaller of two passes is the
    same estimator with more samples -- not a relaxed threshold.
    """
    merged: dict[str, bench.Row] = {}
    for row in (*left, *right):
        key = row_key(row)
        previous = merged.get(key)
        if previous is None:
            merged[key] = row
        elif was_measured(row) and (not was_measured(previous) or row.best_ms < previous.best_ms):
            merged[key] = row
    return [merged[key] for key in sorted(merged)]


# ---------------------------------------------------------------------------
# Baseline document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Baseline:
    """The committed reference numbers plus the protocol that produced them."""

    benchmarks: dict[str, float]
    repeat: int


def effective_repeat(requested: int, baseline: Baseline | None) -> int:
    """Return the number of runs to measure with: never fewer than the baseline's.

    ``best_ms`` is a minimum, and the minimum of one run is systematically higher
    than the minimum of fifteen. Measuring with fewer runs than the baseline would
    therefore report a slowdown that the code did not cause; measuring with more is
    always allowed.
    """
    if baseline is None:
        return requested
    return max(requested, baseline.repeat)


def build_baseline_document(
    measurements: dict[str, float],
    *,
    repeat: int,
    limit_functions: int,
    max_instructions: int,
) -> dict[str, Any]:
    """Assemble the baseline document; ``measurements`` maps a row key to ms."""
    return {
        "format": BASELINE_FORMAT,
        "version": BASELINE_VERSION,
        "unit": "ms",
        "repeat": repeat,
        "limits": {
            "limit_functions": limit_functions,
            "max_instructions": max_instructions,
        },
        "benchmarks": {key: round(value, 3) for key, value in measurements.items()},
    }


def render_document(payload: dict[str, Any]) -> str:
    """Serialise ``payload`` deterministically: sorted keys, 3 decimals, LF."""
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_baseline(path: Path, payload: dict[str, Any]) -> None:
    """Write the baseline document to ``path``, creating its directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_document(payload), encoding="utf-8", newline="\n")


def load_baseline(path: Path) -> Baseline:
    """Read ``path`` and return its measurements plus the protocol they used.

    Raises:
        ValueError: When the file is unreadable, is not JSON, is not a baseline
            document, or holds a value that is not a number.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must hold a JSON object, got {type(payload).__name__}")
    if payload.get("format") != BASELINE_FORMAT:
        raise ValueError(
            f"{path} is not a {BASELINE_FORMAT} baseline "
            f"(format={payload.get('format')!r}); re-record it with --update-baseline"
        )
    raw = payload.get("benchmarks")
    if not isinstance(raw, dict):
        raise ValueError(f"{path} has no 'benchmarks' object")
    repeat = payload.get("repeat", bench.DEFAULT_REPEAT)
    if isinstance(repeat, bool) or not isinstance(repeat, int) or repeat < 1:
        raise ValueError(f"{path}: 'repeat' must be a positive integer, got {repeat!r}")
    benchmarks: dict[str, float] = {}
    for key, value in raw.items():
        # ``bool`` is an ``int`` in Python, and ``true`` is never a duration.
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(
                f"{path}: {key!r} maps to {value!r}, expected milliseconds as a number"
            )
        benchmarks[key] = float(value)
    return Baseline(benchmarks=benchmarks, repeat=repeat)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """One row of the gate table: a benchmark measured against its baseline."""

    key: str
    baseline_ms: float | None
    current_ms: float | None
    status: str
    delta_pct: float | None = None

    @property
    def failed(self) -> bool:
        """Report whether this verdict fails the gate."""
        return self.status in FAILING_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.key,
            "baseline_ms": self.baseline_ms,
            "current_ms": self.current_ms,
            "delta_pct": None if self.delta_pct is None else round(self.delta_pct, 1),
            "status": self.status,
        }


def compare(
    rows: Sequence[bench.Row],
    baseline: dict[str, float],
    tolerance: float,
) -> list[Verdict]:
    """Compare ``rows`` against ``baseline``; return one verdict per row, sorted.

    The rule is the whole gate: ``current_ms > baseline_ms * (1 + tolerance)`` is
    a regression. A row bench.py refused to measure carries no number and is
    reported as ``skipped`` rather than passing on a 0.0 that means nothing.
    """
    allowed_factor = 1.0 + tolerance
    verdicts: list[Verdict] = []
    for row in sorted(rows, key=row_key):
        key = row_key(row)
        base = baseline.get(key)
        if not was_measured(row):
            verdicts.append(Verdict(key, base, None, "skipped"))
            continue
        current = row.best_ms
        if base is None:
            verdicts.append(Verdict(key, None, round(current, 3), "missing"))
            continue
        # A baseline of 0 cannot be scaled up; any positive measurement regresses.
        status = "regressed" if current > base * allowed_factor else "ok"
        delta = None if base <= 0 else (current - base) / base * 100.0
        verdicts.append(Verdict(key, round(base, 3), round(current, 3), status, delta))

    seen = {verdict.key for verdict in verdicts}
    verdicts.extend(
        Verdict(key, round(value, 3), None, "unmeasured")
        for key, value in baseline.items()
        if key not in seen
    )
    return sorted(verdicts, key=lambda verdict: verdict.key)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_table(verdicts: Sequence[Verdict]) -> str:
    """Render ``verdicts`` as a fixed-width table with stable column widths."""

    def cell(value: float | None, pattern: str) -> str:
        return "-" if value is None else pattern.format(value)

    body = [
        (
            verdict.key,
            cell(verdict.baseline_ms, "{:.3f}"),
            cell(verdict.current_ms, "{:.3f}"),
            cell(verdict.delta_pct, "{:+.1f}%"),
            verdict.status,
        )
        for verdict in verdicts
    ]
    widths = [len(header) for header in HEADERS]
    for cells in body:
        widths = [max(width, len(value)) for width, value in zip(widths, cells, strict=True)]

    def line(cells: tuple[str, ...]) -> str:
        padded = (value.ljust(width) for value, width in zip(cells, widths, strict=True))
        return "  ".join(padded).rstrip()

    lines = [line(HEADERS), line(tuple("-" * width for width in widths))]
    lines.extend(line(cells) for cells in body)
    return "\n".join(lines)


def build_report(
    verdicts: Sequence[Verdict],
    *,
    tolerance: float,
    repeat: int,
    limit_functions: int,
    max_instructions: int,
    samples: Sequence[Path],
    baseline_path: Path,
    platform: str,
    warnings: Sequence[str],
) -> dict[str, Any]:
    """Assemble the ``--json`` document."""
    failures = [verdict.key for verdict in verdicts if verdict.failed]
    return {
        "tool": BASELINE_FORMAT,
        "unit": "ms",
        "platform": platform,
        "tolerance": tolerance,
        "repeat": repeat,
        "limits": {
            "limit_functions": limit_functions,
            "max_instructions": max_instructions,
        },
        "samples": [display(path) for path in samples],
        "baseline": display(baseline_path),
        "passed": not failures,
        "failures": failures,
        "results": [verdict.to_dict() for verdict in verdicts],
        "warnings": list(warnings),
    }


def announce(warnings: Sequence[str]) -> None:
    """Write bench.py's per-row warnings to stderr, prefixed for this tool."""
    for warning in warnings:
        print(f"bench_gate: warning: {warning}", file=sys.stderr)


def summarise(verdicts: Sequence[Verdict], tolerance: float, platform: str) -> str:
    """Return the one-line pass/fail summary meant for stderr."""
    failed = [verdict for verdict in verdicts if verdict.failed]
    if not failed:
        return (
            f"bench_gate: PASS {len(verdicts)}/{len(verdicts)} within {tolerance:.0%} tolerance "
            f"(platform {platform})"
        )
    names = ", ".join(verdict.key for verdict in failed)
    return (
        f"bench_gate: FAIL {len(failed)}/{len(verdicts)} beyond {tolerance:.0%} tolerance: "
        f"{names} (platform {platform})"
    )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def positive_int(text: str) -> int:
    """argparse type: an integer >= 1."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value}")
    return value


def tolerance_value(text: str) -> float:
    """argparse type: a non-negative relative tolerance such as ``0.5``."""
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number, got {text!r}") from exc
    if value < 0:
        raise argparse.ArgumentTypeError(
            f"tolerance must not be negative, got {value} (0.5 means 50% slower still passes)"
        )
    return value


def platform_label(text: str) -> str:
    """argparse type: one of the known platform labels, case-insensitive."""
    label = text.strip().lower()
    if label not in PLATFORMS:
        raise argparse.ArgumentTypeError(f"expected one of {', '.join(PLATFORMS)}, got {text!r}")
    return label


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        prog="bench_gate.py",
        description=(
            "Fail when a micro-benchmark is slower than the committed baseline by more "
            "than --tolerance. Exit 0 = within tolerance, 1 = a regression or a benchmark "
            "missing from the baseline, 2 = the gate could not evaluate."
        ),
    )
    parser.add_argument(
        "--samples",
        nargs="+",
        metavar="PATH",
        default=list(DEFAULT_SAMPLE_PATHS),
        help=(
            "inputs to benchmark, repository-relative or absolute "
            f"(default: {' '.join(DEFAULT_SAMPLE_PATHS)})"
        ),
    )
    parser.add_argument(
        "--repeat",
        type=positive_int,
        default=bench.DEFAULT_REPEAT,
        metavar="N",
        help=(
            "runs per benchmark, the best one is kept; the baseline's own repeat is a "
            f"floor so both sides are a best-of-N (default: {bench.DEFAULT_REPEAT})"
        ),
    )
    parser.add_argument(
        "--platform",
        type=platform_label,
        default=None,
        metavar="LABEL",
        help=(
            "which committed baseline to gate against; resolved from $RUNNER_OS, then "
            f"os.name when absent (one of {', '.join(PLATFORMS)})"
        ),
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "baseline document to compare against, overriding the per-platform default "
            "(default: bench/baseline.<platform>.json)"
        ),
    )
    parser.add_argument(
        "--tolerance",
        type=tolerance_value,
        default=DEFAULT_TOLERANCE,
        metavar="F",
        help=(
            "relative slack; 0.5 means up to 50%% slower than the baseline still passes "
            f"(default: {DEFAULT_TOLERANCE})"
        ),
    )
    parser.add_argument(
        "--limit-functions",
        type=positive_int,
        default=bench.DEFAULT_LIMIT_FUNCTIONS,
        metavar="N",
        help=(
            "function budget for the graph and diff steps, as in bench.py; the baseline "
            f"must have been recorded with the same value (default: {bench.DEFAULT_LIMIT_FUNCTIONS})"
        ),
    )
    parser.add_argument(
        "--max-instructions",
        type=positive_int,
        default=bench.DEFAULT_MAX_INSTRUCTIONS,
        metavar="N",
        help=(
            "instruction budget for the code steps, as in bench.py; the baseline must "
            f"have been recorded with the same value (default: {bench.DEFAULT_MAX_INSTRUCTIONS})"
        ),
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="record the current measurements as the new baseline and exit 0",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one JSON document instead of the table",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the gate; return the process exit status."""
    args = build_parser().parse_args(argv)
    platform = resolve_platform(args.platform)
    baseline_path = select_baseline_path(platform, args.baseline)
    samples = [resolve(item) for item in args.samples]

    # Name the platform first: every verdict after this line was judged by the
    # per-platform file it points at.
    print(
        f"bench_gate: platform {platform}, baseline {display(baseline_path)}",
        file=sys.stderr,
    )

    # Check the reference first: there is no point measuring against nothing.
    reference: Baseline | None = None
    if not args.update_baseline:
        if not baseline_path.is_file():
            print(
                f"bench_gate: no baseline at {display(baseline_path)} for platform "
                f"{platform}; record one with --update-baseline",
                file=sys.stderr,
            )
            return EXIT_UNEVALUABLE
        try:
            reference = load_baseline(baseline_path)
        except ValueError as exc:
            print(f"bench_gate: unusable baseline: {exc}", file=sys.stderr)
            return EXIT_UNEVALUABLE

    repeat = effective_repeat(args.repeat, reference)
    if reference is not None and repeat != args.repeat:
        print(
            f"bench_gate: measuring {repeat} runs per benchmark, the baseline's repeat, "
            f"so both sides are a best-of-{repeat}",
            file=sys.stderr,
        )

    warnings: list[str] = []
    try:
        rows = collect_rows(
            samples,
            repeat=repeat,
            limit_functions=args.limit_functions,
            max_instructions=args.max_instructions,
            warnings=warnings,
        )
    except (bench.BinaryLoadError, OSError) as exc:
        print(f"bench_gate: cannot benchmark the samples: {exc}", file=sys.stderr)
        return EXIT_UNEVALUABLE

    if args.update_baseline:
        announce(warnings)
        measurements = {row_key(row): row.best_ms for row in rows if was_measured(row)}
        payload = build_baseline_document(
            measurements,
            repeat=args.repeat,
            limit_functions=args.limit_functions,
            max_instructions=args.max_instructions,
        )
        try:
            write_baseline(baseline_path, payload)
        except OSError as exc:
            print(f"bench_gate: cannot write {display(baseline_path)}: {exc}", file=sys.stderr)
            return EXIT_UNEVALUABLE
        if args.json:
            print(render_document(payload), end="")
        else:
            print(
                f"bench_gate: wrote {len(measurements)} measurements to "
                f"{display(baseline_path)} (platform {platform})"
            )
        return EXIT_OK

    assert reference is not None  # set above: the --update-baseline branch returned
    verdicts = compare(rows, reference.benchmarks, args.tolerance)
    if any(verdict.failed for verdict in verdicts):
        # Confirm before failing: one scheduling hiccup on a shared runner should
        # not turn into a red build. This keeps the better of two measurement
        # passes, so a real regression (slow in both) still fails.
        retry_warnings: list[str] = []
        print(
            "bench_gate: something is beyond tolerance, re-measuring once to rule out a hiccup",
            file=sys.stderr,
        )
        rows = merge_best(
            rows,
            collect_rows(
                samples,
                repeat=repeat,
                limit_functions=args.limit_functions,
                max_instructions=args.max_instructions,
                warnings=retry_warnings,
            ),
        )
        warnings.extend(retry_warnings)
        warnings.append("a failing measurement was confirmed with a second pass")
        verdicts = compare(rows, reference.benchmarks, args.tolerance)
    announce(warnings)
    if args.json:
        report = build_report(
            verdicts,
            tolerance=args.tolerance,
            repeat=repeat,
            limit_functions=args.limit_functions,
            max_instructions=args.max_instructions,
            samples=samples,
            baseline_path=baseline_path,
            platform=platform,
            warnings=warnings,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_table(verdicts))
    print(summarise(verdicts, args.tolerance, platform), file=sys.stderr)
    return EXIT_REGRESSION if any(verdict.failed for verdict in verdicts) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
