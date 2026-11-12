#!/usr/bin/env python3
"""Reproducible micro-benchmarks for the CODEVANTA analysis pipeline.

The script times the public analysis entry points on real input so that a
performance regression shows up as a number instead of a hunch: ``load``,
``discover_functions``, ``extract_strings``, ``disassemble_entry``,
``find_xrefs``, ``build_cfg``, ``build_call_graph``, ``function_fingerprint``,
``suggest_struct``, and -- when two inputs are given -- ``diff_binaries``.

Only the standard library is used for timing (``time.perf_counter``). Every
measurement runs ``--repeat`` times and the *shortest* run is reported: the
minimum is the sample least polluted by scheduler noise and by a cold disk
cache. Inputs default to the committed ``samples/`` files, so the benchmark
needs nothing but this checkout -- no system binaries, no external tools.

Work is bounded everywhere: the code-facing benchmarks never sweep more than
``--max-instructions`` instruction slots (the xref byte window is derived from
the same number) and the graph/fingerprint work is capped by
``--limit-functions``. Input files are only ever read -- never mapped, never
executed -- and the script writes nothing to disk.

Usage::

    python scripts/bench.py                                    # three samples
    python scripts/bench.py samples/elf64_text.bin --json
    python scripts/bench.py a.bin b.bin --repeat 5 --limit-functions 32

The table is sorted by ``(benchmark, path)`` and reports ``best_ms`` in
milliseconds. A row whose ``iterations`` is 0 was refused by the analysis layer
and is not a measurement; the reason goes to stderr as a warning. The
``diff_binaries`` row needs a pair, so with more than two inputs it compares the
first two and its ``path`` column spells out which two ran.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
#: Let ``python scripts/bench.py`` run from a checkout without an install. An
#: existing install wins, so the script benchmarks the code the user imports.
_SRC_DIR = REPO_ROOT / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from codevanta.analysis.binary_diff import (  # noqa: E402
    MAX_MAX_FUNCTIONS,
    MIN_MAX_FUNCTIONS,
    diff_binaries,
)
from codevanta.analysis.callgraph import (  # noqa: E402
    DEFAULT_MAX_EDGES,
    MAX_LIMIT,
    build_call_graph,
)
from codevanta.analysis.cfg import build_cfg  # noqa: E402
from codevanta.analysis.function_hash import function_fingerprint  # noqa: E402
from codevanta.analysis.type_recovery import suggest_struct  # noqa: E402
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES as XREF_MAX_BYTES  # noqa: E402
from codevanta.analysis.xrefs import find_xrefs  # noqa: E402
from codevanta.core.disassembler import Disassembler, DisassemblyError  # noqa: E402
from codevanta.core.functions import FunctionCandidate, discover_functions  # noqa: E402
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError  # noqa: E402
from codevanta.core.report import AnalysisError, read_code  # noqa: E402
from codevanta.core.strings import StringExtractor  # noqa: E402

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Samples benchmarked when no path is given on the command line.
DEFAULT_SAMPLE_NAMES: tuple[str, ...] = ("pe64_text.bin", "macho64_text.bin", "elf64_text.bin")

DEFAULT_REPEAT = 3
DEFAULT_LIMIT_FUNCTIONS = 64
DEFAULT_MAX_INSTRUCTIONS = 2_000

#: Blocks a bounded CFG build may report.
MAX_BLOCKS = 500

#: An x86 instruction slot is at most 15 bytes, so the instruction budget turns
#: into a byte window for the byte-bounded xref scan.
MAX_BYTES_PER_INSTRUCTION = 15

#: Edges a bounded call-graph build may report per function of its budget.
EDGES_PER_FUNCTION = 4

#: Benchmark ids in display order; every row is sorted by ``(benchmark, path)``.
BENCHMARKS: tuple[str, ...] = (
    "load",
    "discover_functions",
    "extract_strings",
    "disassemble_entry",
    "find_xrefs",
    "build_cfg",
    "build_call_graph",
    "function_fingerprint",
    "suggest_struct",
    "diff_binaries",
)

#: Benchmarks that need executable bytes; skipped together when there are none.
CODE_BENCHMARKS: tuple[str, ...] = (
    "disassemble_entry",
    "find_xrefs",
    "build_cfg",
    "build_call_graph",
    "function_fingerprint",
    "suggest_struct",
)

#: Refusals an input may legitimately cause. Anything else is a bug in this
#: script and must not be hidden behind a "skipped" row.
REFUSALS = (AnalysisError, DisassemblyError, OSError, ValueError)


@dataclass(frozen=True)
class Row:
    """One benchmark on one input, reduced to its best run."""

    benchmark: str
    path: str
    best_ms: float
    iterations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "path": self.path,
            "best_ms": round(self.best_ms, 3),
            "iterations": self.iterations,
        }


def best_of(call: Callable[[], Any], repeat: int) -> float:
    """Run ``call`` ``repeat`` times and return the shortest elapsed time in ms."""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def label_for(path: Path) -> str:
    """Render ``path`` relative to the repository when it lives inside it."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def code_start(info: BinaryInfo, functions: Sequence[FunctionCandidate]) -> int | None:
    """Return the first address that is executable *and* mapped to file bytes.

    The entry point comes first, then the discovered candidates (lowest address
    first), then the executable sections themselves, so a stripped binary
    without an entry point still benchmarks its code.
    """
    candidates: list[int] = []
    if info.entry_point:
        candidates.append(info.entry_point)
    candidates.extend(candidate.address for candidate in functions)
    candidates.extend(section.virtual_address for section in info.sections if section.is_executable)
    for address in candidates:
        section = info.section_for_va(address)
        if section is not None and section.is_executable:
            if info.va_to_offset(address) is not None:
                return address
    return None


def add_row(
    rows: list[Row],
    warnings: list[str],
    benchmark: str,
    label: str,
    call: Callable[[], Any],
    repeat: int,
) -> None:
    """Time ``call`` into ``rows``; a refusal becomes an unmeasured row."""
    try:
        call()  # untimed warm-up: validates the arguments, primes the file cache
    except REFUSALS as exc:
        warnings.append(f"{label}: {benchmark} not measured ({type(exc).__name__}: {exc})")
        rows.append(Row(benchmark, label, 0.0, 0))
        return
    rows.append(Row(benchmark, label, best_of(call, repeat), repeat))


def measure_path(
    path: Path,
    *,
    repeat: int,
    limit_functions: int,
    max_instructions: int,
    warnings: list[str],
) -> list[Row]:
    """Load ``path`` once, then time every pipeline step on it.

    Raises:
        BinaryLoadError: When ``path`` cannot be parsed; :func:`main` turns that
            into exit status 1 instead of a half-filled table.
    """
    label = label_for(path)
    loader = BinaryLoader()
    info = loader.load(path)
    rows: list[Row] = []

    add_row(rows, warnings, "load", label, lambda: loader.load(path), repeat)
    functions = discover_functions(info)
    add_row(rows, warnings, "discover_functions", label, lambda: discover_functions(info), repeat)
    extractor = StringExtractor()
    add_row(
        rows,
        warnings,
        "extract_strings",
        label,
        lambda: extractor.extract(path, info=info),
        repeat,
    )

    start = code_start(info, functions)
    if start is None:
        warnings.append(f"{label}: no executable section with file bytes; code not measured")
        rows.extend(Row(name, label, 0.0, 0) for name in CODE_BENCHMARKS)
        return rows

    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    except DisassemblyError as exc:
        warnings.append(f"{label}: disassembly unavailable ({exc}); code not measured")
        rows.extend(Row(name, label, 0.0, 0) for name in CODE_BENCHMARKS)
        return rows

    # The decoder is built once per input, so the row measures re-reading the
    # bytes plus decoding them rather than Capstone's constructor.
    byte_budget = max_instructions * MAX_BYTES_PER_INSTRUCTION

    def decode() -> Any:
        code = read_code(path, info, start, byte_budget)
        return disassembler.disassemble(code, base_address=start, max_instructions=max_instructions)

    add_row(rows, warnings, "disassemble_entry", label, decode, repeat)
    add_row(
        rows,
        warnings,
        "find_xrefs",
        label,
        lambda: find_xrefs(
            path, info, functions=functions, max_bytes=min(byte_budget, XREF_MAX_BYTES)
        ),
        repeat,
    )
    add_row(
        rows,
        warnings,
        "build_cfg",
        label,
        lambda: build_cfg(
            path,
            info,
            start,
            max_instructions=max_instructions,
            max_blocks=min(MAX_BLOCKS, max_instructions),
        ),
        repeat,
    )
    add_row(
        rows,
        warnings,
        "build_call_graph",
        label,
        lambda: build_call_graph(
            path,
            info,
            functions=functions,
            max_functions=min(limit_functions, MAX_LIMIT),
            max_edges=min(
                max(1, limit_functions * EDGES_PER_FUNCTION), DEFAULT_MAX_EDGES, MAX_LIMIT
            ),
        ),
        repeat,
    )
    add_row(
        rows,
        warnings,
        "function_fingerprint",
        label,
        lambda: function_fingerprint(path, info, start, max_instructions=max_instructions),
        repeat,
    )
    add_row(
        rows,
        warnings,
        "suggest_struct",
        label,
        lambda: suggest_struct(path, info, start, max_instructions=max_instructions),
        repeat,
    )
    return rows


def measure_diff(
    left: Path,
    right: Path,
    *,
    repeat: int,
    limit_functions: int,
    warnings: list[str],
) -> list[Row]:
    """Time :func:`diff_binaries` between two inputs."""
    label = f"{label_for(left)} -> {label_for(right)}"
    budget = min(max(limit_functions, MIN_MAX_FUNCTIONS), MAX_MAX_FUNCTIONS)
    rows: list[Row] = []
    add_row(
        rows,
        warnings,
        "diff_binaries",
        label,
        lambda: diff_binaries(left, right, max_functions=budget),
        repeat,
    )
    return rows


def render_table(rows: Sequence[Row]) -> str:
    """Render ``rows`` as a fixed-width table with stable column widths."""
    headers = ("benchmark", "path", "best_ms", "iterations")
    body = [(row.benchmark, row.path, f"{row.best_ms:.3f}", str(row.iterations)) for row in rows]
    widths = [len(header) for header in headers]
    for cells in body:
        widths = [max(width, len(cell)) for width, cell in zip(widths, cells, strict=True)]

    def line(cells: tuple[str, ...]) -> str:
        padded = (cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
        return "  ".join(padded).rstrip()

    lines = [line(headers), line(tuple("-" * width for width in widths))]
    lines.extend(line(cells) for cells in body)
    return "\n".join(lines)


def build_payload(
    rows: Sequence[Row],
    args: argparse.Namespace,
    paths: Sequence[Path],
    warnings: Sequence[str],
) -> dict[str, Any]:
    """Assemble the ``--json`` document."""
    return {
        "tool": "codevanta-bench",
        "unit": "ms",
        "repeat": args.repeat,
        "limits": {
            "limit_functions": args.limit_functions,
            "max_instructions": args.max_instructions,
        },
        "paths": [label_for(path) for path in paths],
        "benchmarks": list(BENCHMARKS),
        "results": [row.to_dict() for row in rows],
        "warnings": list(warnings),
    }


def positive_int(text: str) -> int:
    """argparse type: an integer >= 1."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value}")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description=(
            "Micro-benchmark the CODEVANTA analysis pipeline. Each row is the best "
            "of --repeat runs; inputs are only ever read, never executed."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help=(
            "binaries to benchmark (default: the three samples/ files); "
            "passing two paths adds a diff_binaries row"
        ),
    )
    parser.add_argument(
        "--repeat",
        type=positive_int,
        default=DEFAULT_REPEAT,
        metavar="N",
        help=f"runs per benchmark, the best one is kept (default: {DEFAULT_REPEAT})",
    )
    parser.add_argument(
        "--limit-functions",
        type=positive_int,
        default=DEFAULT_LIMIT_FUNCTIONS,
        metavar="N",
        help=f"function budget for the graph and diff steps (default: {DEFAULT_LIMIT_FUNCTIONS})",
    )
    parser.add_argument(
        "--max-instructions",
        type=positive_int,
        default=DEFAULT_MAX_INSTRUCTIONS,
        metavar="N",
        help=f"instruction budget for the code steps (default: {DEFAULT_MAX_INSTRUCTIONS})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one JSON object instead of the table",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the benchmark; return the process exit status."""
    args = build_parser().parse_args(argv)
    paths = [Path(item) for item in args.paths] or [
        REPO_ROOT / "samples" / name for name in DEFAULT_SAMPLE_NAMES
    ]

    rows: list[Row] = []
    warnings: list[str] = []
    for path in paths:
        try:
            rows.extend(
                measure_path(
                    path,
                    repeat=args.repeat,
                    limit_functions=args.limit_functions,
                    max_instructions=args.max_instructions,
                    warnings=warnings,
                )
            )
        except BinaryLoadError as exc:
            print(f"bench: cannot load {label_for(path)}: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"bench: cannot read {label_for(path)}: {exc}", file=sys.stderr)
            return 1

    # ``diff_binaries`` takes a pair, so the row compares the first two inputs;
    # its ``path`` column spells out which two ran.
    if len(paths) >= 2:
        rows.extend(
            measure_diff(
                paths[0],
                paths[1],
                repeat=args.repeat,
                limit_functions=args.limit_functions,
                warnings=warnings,
            )
        )

    ordered = sorted(rows, key=lambda row: (row.benchmark, row.path))
    for warning in warnings:
        print(f"bench: warning: {warning}", file=sys.stderr)
    if args.json:
        payload = build_payload(ordered, args, paths, warnings)
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_table(ordered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
