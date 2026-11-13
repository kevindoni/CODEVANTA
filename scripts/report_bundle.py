#!/usr/bin/env python3
"""Build and verify a tamper-evident CODEVANTA evidence bundle.

The script ties together the two halves of an analysis hand-off: the static
report produced by :func:`codevanta.core.report.build_report` and -- when one
is available -- the dynamic trace parsed by
:mod:`codevanta.analysis.trace`.  Both go into one
:class:`~codevanta.analysis.evidence_bundle.Bundle` next to the digest of the
analysed binary, so the receiver can check with a single command that nothing
was edited on the way:

Build (report + optional trace, always verified digests)::

    python scripts/report_bundle.py BIN --output OUT.json [--trace FILE] [--notes TEXT]

Verify::

    python scripts/report_bundle.py --verify OUT.json

The build always embeds ``xrefs``, ``cfg`` and ``callgraph`` sections and
prints the resulting manifest as JSON on stdout (progress goes to stderr).
With ``--trace`` the file is parsed with automatic provider detection
(``gdb`` session output or Frida JSON-lines) and stored as the ``trace``
entry; without it, the trace entry is omitted and the manifest metadata
carries a note saying so.  ``--notes`` text is stored verbatim in the
``metadata`` entry.

Exit codes: ``0`` success (bundle written / bundle verified), ``1`` the
bundle failed verification, ``2`` usage errors -- missing files, an output
path that would overwrite or live inside the input, or an analysis failure.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

_SRC_DIR = REPO_ROOT / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from codevanta.analysis.evidence_bundle import (  # noqa: E402
    TOOL_VERSION,
    build_bundle,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from codevanta.analysis.trace import parse_frida_trace, parse_gdb_trace  # noqa: E402
from codevanta.core.functions import discover_functions  # noqa: E402
from codevanta.core.loader import BinaryLoadError  # noqa: E402
from codevanta.core.report import AnalysisError, build_report, load_binary  # noqa: E402

#: Exit code for a completed build or a passed verification.
EXIT_OK = 0
#: Exit code when ``--verify`` found problems (or the bundle is unreadable).
EXIT_VERIFY_FAILED = 1
#: Exit code for usage errors and analysis failures.
EXIT_USAGE = 2

#: Label recorded in ``manifest.subject`` when a trace is embedded.
LABEL_WITH_TRACE = "analyze+trace"
#: Label recorded in ``manifest.subject`` when no trace was supplied.
LABEL_NO_TRACE = "analyze"

#: Note written into ``metadata`` when ``--trace`` is not given.
NO_TRACE_NOTE = "trace omitted: no --trace file given"


def codevanta_version() -> str:
    """Return the installed CODEVANTA version, falling back to the pinned one."""
    try:
        return _package_version("codevanta")
    except PackageNotFoundError:
        return TOOL_VERSION


def detect_trace_provider(text: str) -> str:
    """Return ``"gdb"`` or ``"frida"`` for the parsed trace ``text``.

    A ``HIT 0x...`` line is the gdb session marker; a JSON object line with a
    ``hit`` or ``event`` key is a Frida message.  Anything else is refused:
    bundling a trace we could not identify would pin a payload nobody can
    interpret later.

    Raises:
        AnalysisError: When no line matches either format.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("HIT ") or stripped.startswith("BACKTRACE"):
            return "gdb"
        if stripped.startswith("{"):
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and ("hit" in message or "event" in message):
                return "frida"
    raise AnalysisError(
        "cannot detect trace provider: no gdb 'HIT' line and no Frida JSON message found"
    )


def parse_trace_file(path: Path, subject: Path) -> tuple[str, dict[str, Any]]:
    """Read and parse the trace at ``path``, returning ``(provider, payload)``.

    The analysed binary's metadata and function candidates are attached so
    hits are attributed to functions, exactly like the CLI trace command.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AnalysisError(f"cannot read trace {path}: {exc}") from exc

    provider = detect_trace_provider(text)
    info = load_binary(subject)
    functions = discover_functions(info)
    if provider == "gdb":
        report = parse_gdb_trace(text, info=info, functions=functions)
    else:
        report = parse_frida_trace(text, info=info, functions=functions)
    return provider, report.to_dict()


def build_metadata_payload(notes: str | None, provider: str | None) -> dict[str, Any]:
    """Assemble the ``metadata`` entry: notes, versions and the trace note."""
    note_bits: list[str] = []
    if notes:
        note_bits.append(notes)
    if provider is None:
        note_bits.append(NO_TRACE_NOTE)
    return {
        "notes": "; ".join(note_bits) if note_bits else "no operator notes",
        "python_version": platform.python_version(),
        "codevanta_version": codevanta_version(),
        "trace_provider": provider,
    }


def output_conflicts_with_input(subject: Path, output: Path) -> str | None:
    """Return a refusal reason when ``output`` would clobber the input.

    The bundle must never overwrite the analysed file, and never land inside
    it when the input is a directory.  Same-directory output (the usual
    ``samples/report_bundle.json`` case) is fine.
    """
    subject_real = subject.resolve()
    output_real = output.resolve()
    if output_real == subject_real:
        return f"output path {output} is the same file as the input {subject}"
    if subject_real.is_dir() and output_real.is_relative_to(subject_real):
        return f"output path {output} is inside the input directory {subject}"
    return None


def cmd_build(args: argparse.Namespace) -> int:
    """Handle the build mode: analyze, parse trace, bundle, write, report."""
    subject = Path(args.subject)
    output = Path(args.output)

    conflict = output_conflicts_with_input(subject, output)
    if conflict is not None:
        print(f"error: {conflict}", file=sys.stderr)
        return EXIT_USAGE

    provider: str | None = None
    trace_payload: dict[str, Any] | None = None
    if args.trace:
        trace_path = Path(args.trace)
        if not trace_path.is_file():
            print(f"error: trace file not found: {trace_path}", file=sys.stderr)
            return EXIT_USAGE

    try:
        report = build_report(
            subject,
            include_xrefs=True,
            include_cfg=True,
            include_callgraph=True,
        )
        if args.trace:
            provider, trace_payload = parse_trace_file(Path(args.trace), subject)
    except (AnalysisError, BinaryLoadError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    payloads: dict[str, Any] = {"report": report}
    if trace_payload is not None:
        payloads["trace"] = trace_payload
    payloads["metadata"] = build_metadata_payload(args.notes, provider)

    label = LABEL_WITH_TRACE if provider is not None else LABEL_NO_TRACE
    try:
        bundle = build_bundle(subject, payloads, label=label)
        write_bundle(bundle, output)
    except AnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(json.dumps(bundle.manifest.to_dict(), indent=2, sort_keys=True))
    print(f"wrote bundle to {output}", file=sys.stderr)
    return EXIT_OK


def cmd_verify(bundle_path: Path) -> int:
    """Handle ``--verify``: read the bundle back and recompute every digest."""
    if not bundle_path.is_file():
        print(f"error: bundle file not found: {bundle_path}", file=sys.stderr)
        return EXIT_USAGE
    try:
        bundle = read_bundle(bundle_path)
    except AnalysisError as exc:
        print(f"verify FAILED: {exc}", file=sys.stderr)
        return EXIT_VERIFY_FAILED

    verification = verify_bundle(bundle)
    if verification.passed:
        manifest = verification.manifest
        print(
            f"OK: {bundle_path} verified "
            f"({manifest.entry_count} entries, subject sha256 {manifest.subject_sha256})"
        )
        return EXIT_OK
    for problem in verification.problems:
        print(problem)
    return EXIT_VERIFY_FAILED


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI."""
    parser = argparse.ArgumentParser(
        prog="report_bundle",
        description=(
            "Build a verifiable evidence bundle from an analyze report plus an "
            "optional dynamic trace, or verify an existing bundle."
        ),
    )
    parser.add_argument(
        "subject",
        help="binary to analyse (with --verify: the bundle file to check)",
    )
    parser.add_argument(
        "--output",
        metavar="OUT.json",
        help="bundle destination; parent directory must exist",
    )
    parser.add_argument(
        "--trace",
        metavar="FILE",
        help="gdb session log or Frida JSON-lines file to embed",
    )
    parser.add_argument(
        "--notes",
        metavar="TEXT",
        help="free-form operator notes stored in the metadata entry",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify the bundle given as SUBJECT instead of building one",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verify:
        return cmd_verify(Path(args.subject))
    if not args.output:
        parser.error("--output is required unless --verify is given")
    return cmd_build(args)


if __name__ == "__main__":
    raise SystemExit(main())
