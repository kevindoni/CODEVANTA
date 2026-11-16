#!/usr/bin/env python3
"""Run the committed-sample benchmark and render a side-by-side report.

Every task is one in-process call into :mod:`codevanta.mcp_server.tools`, so the
run needs no server, no subprocess and no API key. Results are written to
``bench/results/codevanta.json`` (machine-readable) and
``bench/results/report.md`` (human-readable). Optional ``--rea`` merges numbers
produced by an external REA agent session into both outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

DEFAULT_TASKS = REPO_ROOT / "bench" / "tasks.json"
DEFAULT_OUT_DIR = REPO_ROOT / "bench" / "results"
DEFAULT_SAMPLE_DIR = REPO_ROOT / "samples"
SAMPLE_PLACEHOLDER = "{sample_dir}"
RESULTS_FORMAT = "codevanta-bench-results"
RESULTS_VERSION = 1

_TOOLS_MODULE: Any = None


def get_tools() -> Any:
    """Import the in-process MCP tool module once, on first use."""
    global _TOOLS_MODULE
    if _TOOLS_MODULE is None:
        from codevanta.mcp_server import tools as mcp_tools

        _TOOLS_MODULE = mcp_tools
    return _TOOLS_MODULE


def estimate_tokens(chars: int) -> int:
    """Return the project-wide token estimate: one token per four characters."""
    return math.ceil(chars / 4)


def canonical_json(value: Any) -> str:
    """Return stable compact JSON used for both hashing and size accounting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load_benchmark(path: str | Path) -> dict[str, Any]:
    """Load and validate a benchmark definition such as ``bench/tasks.json``."""
    source = Path(path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
        raise ValueError(f"{source}: expected an object with a 'tasks' list")
    seen: set[str] = set()
    for index, task in enumerate(data["tasks"]):
        if not isinstance(task, dict):
            raise ValueError(f"{source}: task {index} is not an object")
        for field in ("id", "tool", "question"):
            value = task.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{source}: task {index} needs a non-empty {field!r}")
        if task["id"] in seen:
            raise ValueError(f"{source}: duplicate task id {task['id']!r}")
        seen.add(task["id"])
        if not isinstance(task.get("args", {}), dict):
            raise ValueError(f"{source}: task {task['id']!r} has non-object args")
        for field in ("required_keys", "min_list"):
            if not isinstance(task.get(field, {}), (list, dict)):
                raise ValueError(f"{source}: task {task['id']!r} has invalid {field!r}")
    return data


def load_tasks(path: str | Path) -> list[dict[str, Any]]:
    """Return just the task list from a benchmark definition."""
    return load_benchmark(path)["tasks"]


def default_sample_dir(tasks_path: str | Path, config: dict[str, Any]) -> Path:
    """Resolve ``sample_dir`` from the definition against the repository root."""
    configured = config.get("sample_dir", "samples")
    return (Path(tasks_path).resolve().parent.parent / str(configured)).resolve()


def expand_args(args: dict[str, Any], sample_dir: str | Path) -> dict[str, Any]:
    """Replace the ``{sample_dir}`` placeholder in string arguments."""
    prefix = Path(sample_dir).as_posix()
    expanded: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, str):
            expanded[key] = value.replace(SAMPLE_PLACEHOLDER, prefix)
        else:
            expanded[key] = value
    return expanded


def _normalize_text(text: str, sample_dir: str | Path) -> str:
    """Make sample paths machine-independent so output hashes are portable."""
    normalized = text.replace("\\", "/")
    prefix = Path(sample_dir).as_posix().rstrip("/")
    if normalized == prefix:
        return SAMPLE_PLACEHOLDER
    if normalized.startswith(prefix + "/"):
        return SAMPLE_PLACEHOLDER + normalized[len(prefix) :]
    return normalized


def normalize_output(value: Any, sample_dir: str | Path) -> Any:
    """Recursively normalize paths and separators in a tool result."""
    if isinstance(value, dict):
        return {
            key: normalize_output(item, sample_dir)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_output(item, sample_dir) for item in value]
    if isinstance(value, str):
        return _normalize_text(value, sample_dir)
    return value


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def check_criteria(result: Any, task: dict[str, Any]) -> list[str]:
    """Return human-readable failures; an empty list means the task succeeded."""
    if not isinstance(result, dict):
        return [f"output is {type(result).__name__}, expected an object"]
    failures: list[str] = []
    for key in task.get("required_keys", []):
        if key not in result:
            failures.append(f"missing key: {key}")
        elif _is_empty(result[key]):
            failures.append(f"empty value: {key}")
    for key, minimum in task.get("min_list", {}).items():
        value = result.get(key)
        if not isinstance(value, list):
            failures.append(f"{key} is not a list")
        elif len(value) < int(minimum):
            failures.append(f"{key} has {len(value)} item(s), needs {minimum}")
    return failures


def run_task(task: dict[str, Any], sample_dir: str | Path) -> dict[str, Any]:
    """Execute one task, recording cost and quality; never raises for tool errors."""
    args = expand_args(task.get("args", {}), sample_dir)
    started = time.perf_counter()
    result: Any = None
    error: str | None = None
    try:
        tool = getattr(get_tools(), str(task["tool"]))
        result = tool(**args)
    except Exception as exc:  # noqa: BLE001 - a failed task must not abort the run
        error = f"{type(exc).__name__}: {exc}"
    wall_ms = round((time.perf_counter() - started) * 1000.0, 3)

    failures = [] if error else check_criteria(result, task)
    ok = error is None and not failures
    criteria_error = "; ".join(failures) or None
    normalized = normalize_output(result, sample_dir) if error is None else None
    encoded = canonical_json(normalized) if normalized is not None else ""
    return {
        "id": task["id"],
        "sample": task.get("sample", ""),
        "question": task.get("question", ""),
        "tool": task["tool"],
        "args": task.get("args", {}),
        "ok": ok,
        "wall_ms": wall_ms,
        "output_chars": len(encoded),
        "approx_tokens": estimate_tokens(len(encoded)),
        "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest() if encoded else None,
        "error": error or criteria_error,
    }


def run_tasks(tasks: list[dict[str, Any]], sample_dir: str | Path) -> list[dict[str, Any]]:
    """Run every task in file order; the caller decides the output order."""
    get_tools()  # pay the one-time import outside every task's timer
    return [run_task(task, sample_dir) for task in tasks]


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate the four headline metrics from per-task records."""
    total = len(results)
    ok = sum(1 for result in results if result["ok"])
    total_tokens = sum(int(result["approx_tokens"]) for result in results)
    total_ms = round(sum(float(result["wall_ms"]) for result in results), 3)
    return {
        "tasks": total,
        "ok": ok,
        "failed": total - ok,
        "success_rate": round(ok / total, 6) if total else 0.0,
        "total_output_chars": sum(int(result["output_chars"]) for result in results),
        "total_approx_tokens": total_tokens,
        "mean_approx_tokens": round(total_tokens / total, 3) if total else 0.0,
        "total_wall_ms": total_ms,
        "mean_wall_ms": round(total_ms / total, 3) if total else 0.0,
        "max_wall_ms": max((float(result["wall_ms"]) for result in results), default=0.0),
        "hashed_outputs": sum(1 for result in results if result["sha256"]),
    }


def load_rea(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load ``{"task_id": {"ok": bool, "tokens": int, "ms": int}}`` strictly."""
    source = Path(path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected a mapping of task id to numbers")
    rea: dict[str, dict[str, Any]] = {}
    for task_id, entry in data.items():
        if not isinstance(entry, dict):
            raise ValueError(f"{source}: entry {task_id!r} is not an object")
        missing = [key for key in ("ok", "tokens", "ms") if key not in entry]
        if missing:
            raise ValueError(f"{source}: entry {task_id!r} misses {', '.join(missing)}")
        if not isinstance(entry["ok"], bool):
            raise ValueError(f"{source}: {task_id!r}.ok must be a boolean")
        for field in ("tokens", "ms"):
            value = entry[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"{source}: {task_id!r}.{field} must be a non-negative integer"
                )
        rea[task_id] = {"ok": entry["ok"], "tokens": entry["tokens"], "ms": entry["ms"]}
    return rea


def _display_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def build_payload(
    results: list[dict[str, Any]],
    tasks_path: str | Path,
    sample_dir: str | Path,
    rea: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the JSON document written to ``codevanta.json``."""
    sorted_results = sorted(results, key=lambda result: str(result["id"]))
    payload: dict[str, Any] = {
        "format": RESULTS_FORMAT,
        "version": RESULTS_VERSION,
        "tasks_file": _display_path(tasks_path),
        "sample_dir": _display_path(sample_dir),
        "environment": {
            "python": platform.python_version(),
            "os": platform.system(),
        },
        "summary": summarize(sorted_results),
        "tasks": sorted_results,
    }
    if rea is not None:
        payload["rea"] = {task_id: rea[task_id] for task_id in sorted(rea)}
    return payload


def _format_number(value: float) -> str:
    return f"{value:,.2f}"


def _ratio(numerator: float, denominator: float) -> str:
    if not denominator:
        return "-"
    ratio = numerator / denominator
    if 0 < ratio < 0.01:
        return "<0.01x"
    return f"{ratio:.2f}x"


def _mean(total: float, count: int) -> str:
    return f"{total / count:,.2f}" if count else "-"


def render_report(payload: dict[str, Any], rea: dict[str, dict[str, Any]] | None) -> str:
    """Render the Markdown report, including the REA comparison when supplied."""
    results = payload["tasks"]
    summary = payload["summary"]
    environment = payload["environment"]
    total = int(summary["tasks"])
    ok = int(summary["ok"])
    merge = rea if rea is not None else payload.get("rea", {})
    lines = [
        "# CODEVANTA sample benchmark",
        "",
        "Per-task cost and quality for the committed samples in `samples/`, run "
        "in-process through `codevanta.mcp_server.tools`.",
        "Generated by `bench/run_codevanta.py` from `bench/tasks.json`; the file "
        "carries no timestamp, so repeat runs differ only in timing.",
        "",
        "## Headline metrics",
        "",
        f"- **Success rate:** {ok}/{total} ({summary['success_rate']:.1%})",
        f"- **Tokens/task (approx):** {summary['mean_approx_tokens']:,.1f} "
        f"(total {summary['total_approx_tokens']:,}; `ceil(chars / 4)`)",
        f"- **Wall-clock:** {_format_number(summary['total_wall_ms'])} ms total, "
        f"{_format_number(summary['max_wall_ms'])} ms slowest task",
        f"- **Reproducible output:** {summary['hashed_outputs']}/{total} "
        "SHA-256 hashes recorded",
        "",
        f"Environment: Python {environment['python']} on {environment['os']}.",
        "",
        "## Per-task results",
        "",
    ]
    header = "| Task | Tool | OK | ms | Chars | ~Tokens | SHA-256 |"
    divider = "| --- | --- | :---: | ---: | ---: | ---: | --- |"
    if merge:
        header += " REA ok | REA tokens | REA ms |"
        divider += " :---: | ---: | ---: |"
    lines.extend([header, divider])
    for result in results:
        digest = f"`{result['sha256'][:12]}`" if result["sha256"] else "-"
        row = (
            f"| `{result['id']}` | `{result['tool']}` | {'yes' if result['ok'] else 'no'} "
            f"| {_format_number(result['wall_ms'])} | {result['output_chars']:,} "
            f"| {result['approx_tokens']:,} | {digest} |"
        )
        if merge:
            external = merge.get(result["id"])
            if external is None:
                row += " - | - | - |"
            else:
                row += (
                    f" {'yes' if external['ok'] else 'no'} | {external['tokens']:,} "
                    f"| {external['ms']:,} |"
                )
        lines.append(row)
    total_row = (
        f"| **Total** | | {ok}/{total} | {_format_number(summary['total_wall_ms'])} "
        f"| {summary['total_output_chars']:,} | {summary['total_approx_tokens']:,} | |"
    )
    if merge:
        covered = [result for result in results if result["id"] in merge]
        total_row += (
            f" {sum(1 for result in covered if merge[result['id']]['ok'])}/{len(covered)}"
            f" | {sum(merge[result['id']]['tokens'] for result in covered):,}"
            f" | {sum(merge[result['id']]['ms'] for result in covered):,} |"
        )
    lines.append(total_row)
    lines.append("")

    if merge:
        covered = [result for result in results if result["id"] in merge]
        codevanta_ok = sum(1 for result in covered if result["ok"])
        rea_ok = sum(1 for result in covered if merge[result["id"]]["ok"])
        codevanta_tokens = sum(int(result["approx_tokens"]) for result in covered)
        rea_tokens = sum(int(merge[result["id"]]["tokens"]) for result in covered)
        codevanta_ms = round(sum(float(result["wall_ms"]) for result in covered), 3)
        rea_ms = sum(int(merge[result["id"]]["ms"]) for result in covered)
        lines.extend(
            [
                "## External REA comparison",
                "",
                "REA numbers were merged from `--rea`; they come from an external agent "
                "session, not from this harness.",
                "",
                "| Metric | CODEVANTA | REA | Ratio |",
                "| --- | ---: | ---: | ---: |",
                f"| Tasks covered | {len(covered)} | {len(covered)} | - |",
                f"| Success rate | {codevanta_ok}/{len(covered)} "
                f"| {rea_ok}/{len(covered)} | - |",
                f"| Total tokens | {codevanta_tokens:,} | {rea_tokens:,} "
                f"| {_ratio(codevanta_tokens, rea_tokens)} |",
                f"| Tokens/task | {_mean(codevanta_tokens, len(covered))} "
                f"| {_mean(rea_tokens, len(covered))} "
                f"| {_ratio(codevanta_tokens, rea_tokens)} |",
                f"| Total wall-clock (ms) | {_format_number(codevanta_ms)} "
                f"| {rea_ms:,} | {_ratio(codevanta_ms, rea_ms)} |",
                "",
            ]
        )

    lines.extend(
        [
            "## Reproducibility",
            "",
            "Each SHA-256 covers the canonical JSON (`sort_keys=True`, compact "
            "separators) of the tool result after sample paths are normalized to "
            "`{sample_dir}`. Re-run the harness and diff `bench/results/codevanta.json`: "
            "timings change, hashes must not.",
            "",
            "Decompilation runs with `backend=\"auto\"`, so `*-decompile` hashes depend "
            "on which optional decompilers (Ghidra/angr) are installed in the environment.",
            "",
        ]
    )
    failures = [result for result in results if not result["ok"]]
    if failures:
        lines.extend(["## Failures", ""])
        for result in failures:
            lines.append(f"- `{result['id']}`: {result['error']}")
        lines.append("")
    return "\n".join(lines)


def write_outputs(
    payload: dict[str, Any],
    out_dir: str | Path,
    rea: dict[str, dict[str, Any]] | None = None,
) -> tuple[Path, Path]:
    """Write ``codevanta.json`` and ``report.md``; return both paths."""
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "codevanta.json"
    report_path = destination / "report.md"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report_path.write_text(render_report(payload, rea), encoding="utf-8")
    return json_path, report_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tasks",
        type=Path,
        default=DEFAULT_TASKS,
        help=f"benchmark definition (default: {_display_path(DEFAULT_TASKS)})",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"directory for codevanta.json and report.md (default: "
        f"{_display_path(DEFAULT_OUT_DIR)})",
    )
    parser.add_argument(
        "--sample-dir",
        type=Path,
        default=None,
        help="sample directory; overrides 'sample_dir' in the task definition",
    )
    parser.add_argument(
        "--rea",
        type=Path,
        default=None,
        help='external REA numbers: {"task_id": {"ok": bool, "tokens": int, "ms": int}}',
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when any task fails or misses its success criteria",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_benchmark(args.tasks)
        tasks = config["tasks"]
        sample_dir = (
            Path(args.sample_dir) if args.sample_dir is not None
            else default_sample_dir(args.tasks, config)
        )
        rea = load_rea(args.rea) if args.rea is not None else None
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if rea is not None:
        known = {task["id"] for task in tasks}
        unknown = sorted(set(rea) - known)
        if unknown:
            print(
                f"warning: ignoring REA rows for unknown task ids: {', '.join(unknown)}",
                file=sys.stderr,
            )
    results = run_tasks(tasks, sample_dir)
    payload = build_payload(results, args.tasks, sample_dir, rea)
    json_path, report_path = write_outputs(payload, args.out_dir, rea)
    summary = payload["summary"]
    print(
        f"{summary['ok']}/{summary['tasks']} tasks ok, "
        f"{summary['total_approx_tokens']:,} approx tokens, "
        f"{summary['total_wall_ms']:.2f} ms"
    )
    print(f"wrote {json_path}")
    print(f"wrote {report_path}")
    if args.check and summary["failed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
