"""CODEVANTA obligations commands: the obligation ledger sub-app.

One Typer app exported as :data:`app`, registered by :mod:`codevanta.cli.main`
with a single ``add_typer`` line as ``codevanta obligations``:

* ``add <ledger> --question ... [--authority ...] [--confidence ...]
  [--environment ...] [--probe ...] [--evidence ...] [--json]``
* ``list <ledger> [--status ...] [--json]``
* ``get <ledger> <id> [--json]``
* ``verify <ledger> <bundle> [--json]`` -- coverage evaluation
* ``waive <ledger> <id> --note ... [--expected-revision N] [--json]``
* ``discharge <ledger> <id> [--note ...] [--expected-revision N] [--json]``
* ``remove <ledger> <id> [--expected-revision N] [--json]``

Every command maps the lane's typed
:class:`~codevanta.core.report.AnalysisError` /
:class:`~codevanta.core.unknowns.LedgerConflictError` to ``exit 2`` and
``--json`` prints the unchanged ledger payload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.compare import is_bundle_document, load_document
from codevanta.core.coverage import COVERAGE_VERDICTS, evaluate
from codevanta.core.obligations import (
    DEFAULT_OBLIGATION_AUTHORITY,
    DEFAULT_OBLIGATION_CONFIDENCE,
    DEFAULT_OBLIGATION_ENVIRONMENT,
    OBLIGATIONS_ENTRY_NAME,
    ObligationRecord,
    discharge_obligation,
    get_obligation,
    list_obligations,
    make_open_obligation,
    obligations_from_payload,
    obligations_to_payload,
    remove_obligation,
    waive_obligation,
)
from codevanta.core.report import AnalysisError

app = typer.Typer(
    help="Obligation ledger: typed evidence debts with revision-controlled CAS mutations",
    no_args_is_help=True,
)
console = Console()

ObligationAuthority = Literal["parsed", "computed", "verified"]
ObligationConfidence = Literal["low", "medium", "high"]
ObligationEnvironment = Literal["host", "device", "network"]
ObligationStatus = Literal["open", "discharged", "waived"]
ObligationFormat = Literal["text", "json"]


def _fail(message: str) -> NoReturn:
    """Print an error and exit with code 2 (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=2) from None


def _load_obligations_ledger(path: Path) -> dict[str, Any]:
    """Load an obligations ledger payload, unwrapping a bundle if needed."""
    document = load_document(path)
    if is_bundle_document(document):
        entry = document["entries"].get(OBLIGATIONS_ENTRY_NAME)
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), dict):
            raise AnalysisError(
                f"{path} is a bundle without an '{OBLIGATIONS_ENTRY_NAME}' entry"
            )
        document = entry["payload"]
    return document


def _write_obligations_ledger(path: Path, payload: dict[str, Any]) -> None:
    """Write a ledger payload as canonical JSON (sorted keys, trailing newline)."""
    try:
        path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        _fail(f"cannot write ledger {path}: {exc}")


def _print_records(records: tuple[ObligationRecord, ...]) -> None:
    """Render the obligation records as one bounded rich table."""
    table = Table(title=f"Obligations ({len(records)} records)")
    table.add_column("Id")
    table.add_column("Status")
    table.add_column("Authority", justify="center")
    table.add_column("Confidence", justify="center")
    table.add_column("Environment", justify="center")
    table.add_column("Question")
    table.add_column("Refs", justify="right")
    for record in records:
        table.add_row(
            escape(record.id),
            escape(record.status),
            escape(record.required_authority),
            escape(record.required_confidence),
            escape(record.required_environment),
            escape(record.question),
            str(len(record.evidence_refs)),
        )
    console.print(table)
    open_count = sum(1 for record in records if record.status == "open")
    console.print(f"[dim]records: {len(records)} · open: {open_count}[/]")


# ---- end of helpers; commands follow -----------------------------------------


@app.command("add")
def add(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file (created when missing)")],
    question: Annotated[str, typer.Option("--question", help="What must be decided")],
    authority: Annotated[
        ObligationAuthority, typer.Option("--authority", help="Authority that may close it")
    ] = DEFAULT_OBLIGATION_AUTHORITY,
    confidence: Annotated[
        ObligationConfidence, typer.Option("--confidence", help="Required confidence")
    ] = DEFAULT_OBLIGATION_CONFIDENCE,
    environment: Annotated[
        ObligationEnvironment, typer.Option("--environment", help="Required environment")
    ] = DEFAULT_OBLIGATION_ENVIRONMENT,
    probe: Annotated[
        list[str] | None,
        typer.Option("--probe", help="Recommended probe; repeatable (max 8)"),
    ] = None,
    evidence: Annotated[
        list[str] | None,
        typer.Option("--evidence", help="Evidence reference; repeatable (max 16)"),
    ] = None,
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Add one open obligation to the ledger (deterministic content id)."""
    existing: list[Any] = []
    if ledger.exists():
        try:
            existing = list(obligations_from_payload(_load_obligations_ledger(ledger)))
        except AnalysisError as exc:
            _fail(str(exc))
    try:
        record = make_open_obligation(
            question=question,
            required_authority=authority,
            required_confidence=confidence,
            required_environment=environment,
            recommended_probes=tuple(probe or ()),
            evidence_refs=tuple(evidence or ()),
        )
        payload = obligations_to_payload([*existing, record])
    except AnalysisError as exc:
        _fail(str(exc))
    _write_obligations_ledger(ledger, payload)
    if output_format == "json":
        console.print_json(json.dumps({"action": "add", "record": record.to_dict()}))
    else:
        console.print(
            f"[green]obligation added:[/] {escape(record.id)} · "
            f"authority: {record.required_authority} · "
            f"confidence: {record.required_confidence} · "
            f"environment: {record.required_environment} · "
            f"revision: {record.revisions[-1].revision}"
        )


@app.command("list")
def list_cmd(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file")],
    status: Annotated[
        ObligationStatus | None, typer.Option("--status", help="Filter by status")
    ] = None,
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """List the ledger's obligations (optionally status-filtered)."""
    try:
        records = list_obligations(_load_obligations_ledger(ledger), status=status)
    except AnalysisError as exc:
        _fail(str(exc))
    if output_format == "json":
        console.print_json(json.dumps(obligations_to_payload(list(records))))
        return
    _print_records(records)


@app.command("get")
def get(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file")],
    obligation_id: Annotated[str, typer.Argument(help="Obligation id")],
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Print one obligation record, including its revision trail."""
    try:
        record = get_obligation(_load_obligations_ledger(ledger), obligation_id)
    except AnalysisError as exc:
        _fail(str(exc))
    if output_format == "json":
        console.print_json(json.dumps(record.to_dict()))
        return
    current = record.revisions[-1].revision if record.revisions else 0
    console.print(f"[bold]{escape(record.id)}[/] · {escape(record.status)}")
    console.print(f"question: {escape(record.question)}")
    console.print(
        f"requires: {escape(record.required_authority)} / "
        f"{escape(record.required_confidence)} / "
        f"{escape(record.required_environment)}"
    )
    console.print(
        f"probes: {len(record.recommended_probes)} · refs: {len(record.evidence_refs)}"
    )
    console.print(f"[dim]revisions: {len(record.revisions)} · current: {current}[/]")


# ---- end of read commands; verify and mutations follow -----------------------


@app.command("verify")
def verify(
    ledger: Annotated[Path, typer.Argument(help="Obligations ledger JSON file")],
    bundle: Annotated[Path, typer.Argument(help="Evidence bundle JSON file")],
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Evaluate coverage: which obligations does the bundle's evidence pay?"""
    try:
        payload = evaluate(_load_obligations_ledger(ledger), bundle)
    except AnalysisError as exc:
        _fail(str(exc))
    if output_format == "json":
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"Coverage ({payload['total']} obligations)")
    table.add_column("Id")
    table.add_column("Verdict")
    table.add_column("Matched", justify="right")
    for verdict in payload["obligations"]:
        table.add_row(
            escape(str(verdict["id"])),
            escape(str(verdict["verdict"])),
            str(len(verdict["matched_evidence_ids"])),
        )
    console.print(table)
    console.print(
        f"[dim]total: {payload['total']} · complete: {payload['complete']} · "
        f"partial: {payload['partial']} · uncovered: {payload['uncovered']} · "
        f"verdicts: {', '.join(COVERAGE_VERDICTS)}[/]"
    )


def _mutate(
    ledger: Path,
    obligation_id: str,
    mutate: Any,
    note: str,
    expected_revision: int | None,
    action: str,
    output_format: str,
) -> None:
    """Shared CAS mutation path: load, guard+mutate, write back, report."""
    try:
        payload = mutate(
            _load_obligations_ledger(ledger),
            obligation_id,
            note=note,
            expected_revision=expected_revision,
        )
    except AnalysisError as exc:
        _fail(str(exc))
    _write_obligations_ledger(ledger, payload)
    if output_format == "json":
        console.print_json(
            json.dumps(
                {"action": action, "obligation": obligation_id, "count": payload["count"]}
            )
        )
    else:
        console.print(f"[green]obligation {action}:[/] {escape(obligation_id)}")


@app.command("waive")
def waive(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file")],
    obligation_id: Annotated[str, typer.Argument(help="Obligation id")],
    note: Annotated[str, typer.Option("--note", help="Why the obligation is waived")],
    expected_revision: Annotated[
        int | None,
        typer.Option(
            "--expected-revision",
            help="CAS guard: fail unless the record is at this revision",
        ),
    ] = None,
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Waive one open obligation (consciously given up; requires --note)."""
    _mutate(
        ledger,
        obligation_id,
        waive_obligation,
        note,
        expected_revision,
        "waived",
        output_format,
    )


@app.command("discharge")
def discharge(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file")],
    obligation_id: Annotated[str, typer.Argument(help="Obligation id")],
    note: Annotated[str, typer.Option("--note", help="How the obligation was met")] = "",
    expected_revision: Annotated[
        int | None,
        typer.Option(
            "--expected-revision",
            help="CAS guard: fail unless the record is at this revision",
        ),
    ] = None,
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Discharge one open obligation (the evidence obligation was met)."""
    _mutate(
        ledger,
        obligation_id,
        discharge_obligation,
        note,
        expected_revision,
        "discharged",
        output_format,
    )


@app.command("remove")
def remove(
    ledger: Annotated[Path, typer.Argument(help="Ledger JSON file")],
    obligation_id: Annotated[str, typer.Argument(help="Obligation id")],
    expected_revision: Annotated[
        int | None,
        typer.Option(
            "--expected-revision",
            help="CAS guard: fail unless the record is at this revision",
        ),
    ] = None,
    output_format: Annotated[
        ObligationFormat, typer.Option("--format", "-f", help="Output format")
    ] = "text",
) -> None:
    """Remove one obligation from the ledger (for mistaken entries)."""
    try:
        payload = remove_obligation(
            _load_obligations_ledger(ledger),
            obligation_id,
            expected_revision=expected_revision,
        )
    except AnalysisError as exc:
        _fail(str(exc))
    _write_obligations_ledger(ledger, payload)
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "action": "removed",
                    "obligation": obligation_id,
                    "count": payload["count"],
                }
            )
        )
    else:
        console.print(f"[green]obligation removed:[/] {escape(obligation_id)}")


