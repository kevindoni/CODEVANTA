"""MCP tools: ``codevanta_nav`` and ``codevanta_nav_providers``.

``codevanta_nav`` is one action-dispatching tool over CODEVANTA's own
navigation lane (:mod:`codevanta.analysis.nav`): ``action="mark"`` pins a
bookmark, ``"comment"`` attaches a note, ``"goto"`` moves the session cursor
and records the visit, ``"cursor"`` reads the cursor back and
``"bookmarks"`` / ``"comments"`` / ``"history"`` list the bounded state.
``codevanta_nav_providers`` reports which external GUI bridges *could* attach
on this machine (:mod:`codevanta.analysis.nav_providers`) -- CODEVANTA's own
navigation works regardless.

Like every entry in :mod:`codevanta.mcp_server.tools` these are plain
``dict``-returning functions; a missing session surfaces as the typed
:class:`~codevanta.core.report.AnalysisError` with the ``codevanta session
save`` hint rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.nav import NavStore, nav_evidence
from codevanta.analysis.nav_providers import providers_report
from codevanta.core.report import AnalysisError

__all__ = ["NAV_ACTIONS", "codevanta_nav", "codevanta_nav_providers"]

#: Actions ``codevanta_nav`` accepts.
NAV_ACTIONS: tuple[str, ...] = (
    "mark",
    "comment",
    "goto",
    "cursor",
    "bookmarks",
    "comments",
    "history",
)

#: Actions that operate on one address.
_ADDRESS_ACTIONS: frozenset[str] = frozenset({"mark", "comment", "goto"})


def _resolve_db(db: str | None) -> Path:
    """Turn the optional ``db`` argument into a usable path."""
    if db is None or not db.strip():
        raise AnalysisError("db must be a path to the session database")
    return Path(db.strip()).expanduser()


def _parse_address(address: int | str | None, action: str) -> int:
    """Validate the address argument of an address-taking action.

    MCP clients send integers, but a quoted ``"0x401000"`` is accepted too --
    both parse to the same non-negative address.
    """
    if isinstance(address, bool) or address is None:
        raise AnalysisError(f"action {action!r} requires an integer address")
    if isinstance(address, str):
        parsed = _parse_address_text(address)
        if parsed is None:
            raise AnalysisError(
                f"address must be an integer or 0x-prefixed hex string, not {address!r}"
            )
        return parsed
    if not isinstance(address, int):
        raise AnalysisError(f"address must be an integer, not {type(address).__name__}")
    return address


def _parse_address_text(text: str) -> int | None:
    """Parse ``0x``-prefixed hex or decimal text, or return ``None``."""
    cleaned = text.strip()
    try:
        return int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned, 10)
    except ValueError:
        return None


def codevanta_nav(
    action: str,
    session: str | None = None,
    address: int | str | None = None,
    name: str | None = None,
    text: str | None = None,
    db: str | None = None,
) -> dict[str, Any]:
    """Read or write one session's navigation state.

    Args:
        action: One of ``mark``, ``comment``, ``goto``, ``cursor``,
            ``bookmarks``, ``comments``, ``history``.
        session: Session identifier (required by every action).
        address: Virtual address; required by ``mark``, ``comment`` and
            ``goto``, accepted as ``int`` or ``0x``-prefixed string.
        name: Bookmark label for ``mark`` (optional; defaults to the hex
            address).
        text: Comment body for ``comment``.
        db: Path to the session database (the store that ``codevanta session
            save`` writes).

    Returns:
        A JSON-safe payload with ``action``, ``session_id``, the operation
        result (or bounded lists) and the ``nav.session`` evidence record.

    Raises:
        AnalysisError: On an unknown action, a missing ``session`` or ``db``,
            a missing/invalid ``address`` where one is required, an unknown
            session, or invalid navigation arguments.
    """
    if action not in NAV_ACTIONS:
        raise AnalysisError(
            f"unknown action {action!r}; expected one of {', '.join(NAV_ACTIONS)}"
        )
    if not session or not session.strip():
        raise AnalysisError(f"action {action!r} requires a session identifier")
    if db is None or not db.strip():
        raise AnalysisError(
            f"action {action!r} requires the session database path (db)"
        )
    with NavStore(_resolve_db(db)) as store:
        if action in _ADDRESS_ACTIONS:
            return _run_address_action(store, action, session, address, name, text)
        if action == "cursor":
            position = store.cursor(session)
            return {
                "action": action,
                "session_id": session,
                "cursor": None if position is None else position.to_dict(),
                "evidence": nav_evidence("nav.cursor").to_dict(),
            }
        if action == "bookmarks":
            pinned = store.bookmarks(session)
            return {
                "action": action,
                "session_id": session,
                "count": len(pinned),
                "bookmarks": [row.to_dict() for row in pinned],
                "evidence": nav_evidence("nav.bookmarks").to_dict(),
            }
        if action == "comments":
            noted = store.comments(session)
            return {
                "action": action,
                "session_id": session,
                "count": len(noted),
                "comments": [row.to_dict() for row in noted],
                "evidence": nav_evidence("nav.comments").to_dict(),
            }
        visits = store.history(session)
        return {
            "action": action,
            "session_id": session,
            "count": len(visits),
            "history": [row.to_dict() for row in visits],
            "evidence": nav_evidence("nav.history").to_dict(),
        }


def _run_address_action(
    store: NavStore,
    action: str,
    session: str,
    address: int | str | None,
    name: str | None,
    text: str | None,
) -> dict[str, Any]:
    """Dispatch one address-taking ``codevanta_nav`` action."""
    parsed = _parse_address(address, action)
    if action == "mark":
        pinned = store.bookmark(session, parsed, name if name else f"0x{parsed:x}")
        return {
            "action": action,
            "session_id": session,
            "bookmark": pinned.to_dict(),
            "evidence": nav_evidence("nav.bookmark").to_dict(),
        }
    if action == "comment":
        if not text or not text.strip():
            raise AnalysisError("action 'comment' requires text")
        noted = store.comment(session, parsed, text)
        return {
            "action": action,
            "session_id": session,
            "comment": noted.to_dict(),
            "evidence": nav_evidence("nav.comment").to_dict(),
        }
    moved = store.goto(session, parsed)
    return {
        "action": action,
        "session_id": session,
        "cursor": moved.to_dict(),
        "evidence": nav_evidence("nav.goto").to_dict(),
    }


def codevanta_nav_providers() -> dict[str, Any]:
    """Report which external GUI providers could attach on this machine.

    Returns:
        A JSON-safe payload with the typed capability reports (``name``,
        ``available``, ``reason`` for Hopper, Cutter and Ghidra) and the
        ``nav.providers`` evidence record. The probes never launch anything
        and never raise.
    """
    report = providers_report()
    return {
        "count": len(report),
        "providers": [capability.to_dict() for capability in report],
        "evidence": {
            "source": "nav.providers",
            "method": "nav.providers",
        },
    }
