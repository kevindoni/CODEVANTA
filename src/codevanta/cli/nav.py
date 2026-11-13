"""``codevanta nav`` -- navigation state for persisted sessions (sub-app).

Eight commands over :mod:`codevanta.analysis.nav` and
:mod:`codevanta.analysis.nav_providers`: ``mark`` pins a bookmark, ``comment``
attaches a note, ``goto`` moves the session cursor and records the visit,
``cursor`` reads the cursor back, ``bookmarks`` / ``comments`` / ``history``
list the bounded navigation state and ``providers`` reports which external
GUI bridges *could* attach on this machine. ``--json`` prints the unchanged
payloads; every surprise (unknown session, bad address) is the typed
:class:`~codevanta.core.report.AnalysisError` rendered as ``error:`` with
exit code 2.

Registered in :mod:`codevanta.cli.main` with exactly one ``add_typer`` line.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.nav import NavStore, nav_evidence
from codevanta.analysis.nav_providers import providers_report
from codevanta.core.report import AnalysisError

app = typer.Typer(
    help="Navigation state for persisted sessions (bookmarks, comments, cursor)"
)
console = Console()

#: Evidence source of the provider probe report (probes are not session data).
PROVIDERS_EVIDENCE_SOURCE = "nav.providers"


def _fail(message: str) -> NoReturn:
    """Print an error and exit with code 2 (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=2) from None


def _run(store_op):
    """Run one store operation, mapping every typed failure to ``exit 2``."""
    try:
        return store_op()
    except AnalysisError as exc:
        _fail(str(exc))


def _resolve_db(db: Path | None) -> Path:
    """Return ``db``, else ``$CODEVANTA_DB``, else ``~/.codevanta/sessions.db``.

    Mirrors the session commands so both layers read and write the same
    database by default.
    """
    if db is not None:
        return db
    configured = os.environ.get("CODEVANTA_DB")
    if configured and configured.strip():
        return Path(configured)
    return Path.home() / ".codevanta" / "sessions.db"


def _parse_address(text: str) -> int:
    """Parse ``0x``-prefixed hex or decimal into a non-negative integer."""
    cleaned = text.strip()
    try:
        value = int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned, 10)
    except ValueError:
        _fail(f"invalid address {text!r}; expected decimal or 0x-prefixed hex")
    if value < 0:
        _fail(f"invalid address {text!r}; addresses must not be negative")
    return value


def _evidence_footer(source: str, method: str) -> None:
    """Print the shared ``evidence:`` footer line."""
    console.print(f"[dim]evidence: {escape(source)} via {escape(method)}[/]")


@app.command("mark")
def mark(
    session_id: str,
    address: str,
    name: str | None = typer.Argument(None),
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Pin ADDRESS inside SESSION as a bookmark, optionally labeled NAME."""
    parsed = _parse_address(address)
    label = name if name is not None else f"0x{parsed:x}"
    with NavStore(_resolve_db(db)) as store:
        bookmark = _run(lambda: store.bookmark(session_id, parsed, label))
    console.print(f"[green]bookmark saved:[/] {bookmark.id} · 0x{bookmark.address:x}")
    console.print(f"[dim]{escape(bookmark.name)}[/]")
    _evidence_footer("nav.session", "nav.bookmark")


@app.command("comment")
def comment(
    session_id: str,
    address: str,
    text: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Attach TEXT to ADDRESS inside SESSION (replaces any existing note)."""
    parsed = _parse_address(address)
    with NavStore(_resolve_db(db)) as store:
        note = _run(lambda: store.comment(session_id, parsed, text))
    console.print(f"[green]comment saved:[/] {note.id} · 0x{note.address:x}")
    console.print(f"[dim]{escape(note.text)}[/]")
    _evidence_footer("nav.session", "nav.comment")


@app.command("goto")
def goto(
    session_id: str,
    address: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Move SESSION's cursor to ADDRESS and record the visit in the history."""
    parsed = _parse_address(address)
    with NavStore(_resolve_db(db)) as store:
        position = _run(lambda: store.goto(session_id, parsed))
    console.print(f"[green]goto:[/] 0x{position.address:x} · {escape(position.updated_at)}")
    _evidence_footer("nav.session", "nav.goto")


@app.command("cursor")
def cursor(
    session_id: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """Show where SESSION's reading cursor currently points."""
    with NavStore(_resolve_db(db)) as store:
        position = _run(lambda: store.cursor(session_id))
    if position is None:
        console.print(f"[yellow]no cursor set for session {escape(session_id)}[/]")
        _evidence_footer("nav.session", "nav.cursor")
        return
    console.print(f"cursor: 0x{position.address:x} · {escape(position.updated_at)}")
    _evidence_footer("nav.session", "nav.cursor")


@app.command("bookmarks")
def bookmarks(
    session_id: str,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON payload")] = False,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """List SESSION's bookmarks, newest first (bounded at 128)."""
    with NavStore(_resolve_db(db)) as store:
        rows = _run(lambda: store.bookmarks(session_id))
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "session_id": session_id,
                    "count": len(rows),
                    "bookmarks": [row.to_dict() for row in rows],
                    "evidence": nav_evidence("nav.bookmarks").to_dict(),
                }
            )
        )
        return
    if not rows:
        console.print(f"[yellow]no bookmarks for session {escape(session_id)}[/]")
        return
    table = Table(title=escape(f"Bookmarks ({len(rows)})"))
    table.add_column("Id")
    table.add_column("Address", justify="right")
    table.add_column("Name")
    for row in rows:
        table.add_row(escape(row.id), f"0x{row.address:x}", escape(row.name))
    console.print(table)
    _evidence_footer("nav.session", "nav.bookmarks")


@app.command("comments")
def comments(
    session_id: str,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON payload")] = False,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """List SESSION's comments, newest first (bounded at 128)."""
    with NavStore(_resolve_db(db)) as store:
        rows = _run(lambda: store.comments(session_id))
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "session_id": session_id,
                    "count": len(rows),
                    "comments": [row.to_dict() for row in rows],
                    "evidence": nav_evidence("nav.comments").to_dict(),
                }
            )
        )
        return
    if not rows:
        console.print(f"[yellow]no comments for session {escape(session_id)}[/]")
        return
    table = Table(title=escape(f"Comments ({len(rows)})"))
    table.add_column("Id")
    table.add_column("Address", justify="right")
    table.add_column("Text")
    for row in rows:
        table.add_row(escape(row.id), f"0x{row.address:x}", escape(row.text))
    console.print(table)
    _evidence_footer("nav.session", "nav.comments")


@app.command("history")
def history(
    session_id: str,
    db: Annotated[Path | None, typer.Option("--db", help="Session database file")] = None,
) -> None:
    """List SESSION's goto history, newest first (bounded at 64)."""
    with NavStore(_resolve_db(db)) as store:
        rows = _run(lambda: store.history(session_id))
    if not rows:
        console.print(f"[yellow]no goto history for session {escape(session_id)}[/]")
        return
    table = Table(title=escape(f"Goto history ({len(rows)})"))
    table.add_column("Address", justify="right")
    table.add_column("Visited")
    for row in rows:
        table.add_row(f"0x{row.address:x}", escape(row.visited_at))
    console.print(table)
    _evidence_footer("nav.session", "nav.history")


@app.command("providers")
def providers(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON payload")] = False,
) -> None:
    """Report which external GUI providers could attach on this machine."""
    report = providers_report()
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "count": len(report),
                    "providers": [capability.to_dict() for capability in report],
                    "evidence": {
                        "source": PROVIDERS_EVIDENCE_SOURCE,
                        "method": "nav.providers",
                    },
                }
            )
        )
        return
    table = Table(title=f"GUI providers ({len(report)})")
    table.add_column("Provider")
    table.add_column("Available", justify="center")
    table.add_column("Reason")
    for capability in report:
        table.add_row(
            escape(capability.name),
            "yes" if capability.available else "no",
            escape(capability.reason),
        )
    console.print(table)
    _evidence_footer(PROVIDERS_EVIDENCE_SOURCE, "nav.providers")
