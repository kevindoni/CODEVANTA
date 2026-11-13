"""Navigation state for persisted analysis sessions: bookmarks, notes, cursor.

CODEVANTA's disassembler output is static and read-only, so analysts mark up
their findings *around* it: a bookmark pins a noteworthy address, a comment
records what was found there, and the cursor remembers where the analyst
stopped reading. Everything lives in the same SQLite database as the analysis
sessions (see :mod:`codevanta.storage.session`), in additive ``nav_*`` tables
that follow the session store's migration style: ``CREATE TABLE IF NOT
EXISTS`` only, so pre-existing session databases upgrade transparently and no
existing schema changes.

Every navigation write is verified by a read-back in the same call -- the
returned record is rebuilt from the stored row, not from the arguments. A
missing session is a typed :class:`~codevanta.core.report.AnalysisError`
whose message points at ``codevanta session save``; CODEVANTA's own
navigation never depends on an external GUI being installed (see
:mod:`codevanta.analysis.nav_providers` for the probe that reports which
live-GUI bridges *could* attach).

The module uses the standard library only (``sqlite3``, ``hashlib``,
``datetime``, ``pathlib``) and issues parameterized SQL exclusively.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "BOOKMARK_LIST_LIMIT",
    "COMMENT_LIST_LIMIT",
    "HISTORY_LIMIT",
    "MAX_COMMENT_LENGTH",
    "MAX_NAME_LENGTH",
    "NAV_ID_LENGTH",
    "SESSION_MISSING_HINT",
    "NavBookmark",
    "NavComment",
    "NavCursor",
    "NavGoto",
    "NavStore",
    "nav_evidence",
]

#: Maximum number of bookmarks returned by :meth:`NavStore.bookmarks`.
BOOKMARK_LIST_LIMIT = 128

#: Maximum number of comments returned by :meth:`NavStore.comments`.
COMMENT_LIST_LIMIT = 128

#: Maximum number of goto entries kept per session (newest first).
HISTORY_LIMIT = 64

#: Maximum accepted length of a bookmark name, in characters.
MAX_NAME_LENGTH = 256

#: Maximum accepted length of a comment text, in characters (mirrors the
#: annotation note bound in :mod:`codevanta.storage.session`).
MAX_COMMENT_LENGTH = 4000

#: Number of hex characters used for generated bookmark/comment identifiers.
NAV_ID_LENGTH = 12

#: Hint appended to every unknown-session error.
SESSION_MISSING_HINT = "save a session first with `codevanta session save`"

_EVIDENCE_SOURCE = "nav.session"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nav_bookmarks (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    address     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nav_bookmarks_session ON nav_bookmarks (session_id);

CREATE TABLE IF NOT EXISTS nav_comments (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    address     INTEGER NOT NULL,
    text        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (session_id, address)
);

CREATE INDEX IF NOT EXISTS idx_nav_comments_session ON nav_comments (session_id);

CREATE TABLE IF NOT EXISTS nav_cursor (
    session_id  TEXT PRIMARY KEY,
    address     INTEGER NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nav_history (
    visit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    address     INTEGER NOT NULL,
    visited_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nav_history_session ON nav_history (session_id);
"""

_BOOKMARK_UPSERT = (
    "INSERT INTO nav_bookmarks (id, session_id, address, name, created_at) "
    "VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT (id) DO UPDATE SET "
    "address = excluded.address, name = excluded.name, created_at = excluded.created_at"
)

_COMMENT_UPSERT = (
    "INSERT INTO nav_comments (id, session_id, address, text, created_at) "
    "VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT (session_id, address) DO UPDATE SET "
    "id = excluded.id, text = excluded.text, created_at = excluded.created_at"
)

_CURSOR_UPSERT = (
    "INSERT INTO nav_cursor (session_id, address, updated_at) "
    "VALUES (?, ?, ?) "
    "ON CONFLICT (session_id) DO UPDATE SET "
    "address = excluded.address, updated_at = excluded.updated_at"
)

_TRIM_HISTORY = (
    "DELETE FROM nav_history WHERE session_id = ? AND visit_id NOT IN ("
    "SELECT visit_id FROM nav_history WHERE session_id = ? "
    "ORDER BY visit_id DESC LIMIT ?)"
)


@dataclass(frozen=True)
class NavBookmark:
    """One pinned address inside a session, with the analyst's label."""

    id: str
    address: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the bookmark, rendering the address as hex."""
        return {
            "id": self.id,
            "address": f"0x{self.address:x}",
            "name": self.name,
        }


@dataclass(frozen=True)
class NavComment:
    """One free-text note attached to one address inside a session."""

    id: str
    address: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the comment, rendering the address as hex."""
        return {
            "id": self.id,
            "address": f"0x{self.address:x}",
            "text": self.text,
        }


@dataclass(frozen=True)
class NavCursor:
    """The address a session's reading cursor currently points at."""

    address: int
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the cursor, rendering the address as hex."""
        return {
            "address": f"0x{self.address:x}",
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class NavGoto:
    """One visited address in a session's bounded goto history."""

    address: int
    visited_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the history entry, rendering the address as hex."""
        return {
            "address": f"0x{self.address:x}",
            "visited_at": self.visited_at,
        }


def nav_evidence(method: str, *, detail: str | None = None) -> Evidence:
    """Build the evidence record for one navigation operation.

    The ``source`` id is ``nav.session`` for every operation: the finding came
    from CODEVANTA's own SQLite session store, never from an external GUI.
    """
    return Evidence(
        source=_EVIDENCE_SOURCE,
        method=method,
        confidence=Confidence.HIGH,
        detail=detail,
    )


class NavStore:
    """Read and write navigation state for sessions in one SQLite database.

    The database file (and any missing parent directories) is created on
    construction; the ``nav_*`` tables are added without touching the session
    tables. Use the store as a context manager to close it on exit.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = _resolve_db_path(db_path)
        self._closed = False
        try:
            self._conn = sqlite3.connect(str(self._db_path), timeout=5.0)
        except sqlite3.Error as exc:  # pragma: no cover - environment dependent
            raise AnalysisError(
                f"cannot open navigation database {self._db_path}: {exc}"
            ) from exc
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.close()
            self._closed = True
            raise AnalysisError(
                f"cannot initialize navigation tables in {self._db_path}: {exc}"
            ) from exc

    # ---- lifecycle ----------------------------------------------------

    def __enter__(self) -> NavStore:
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the database connection. Calling it twice is harmless."""
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.close()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(f"cannot close navigation database: {exc}") from exc

    # ---- bookmarks ----------------------------------------------------

    def bookmark(self, session_id: str, address: int, name: str) -> NavBookmark:
        """Pin ``address`` under ``name`` and return the stored bookmark.

        The identifier is derived from ``(session_id, address, name)`` with
        SHA-256, so marking the same address with the same name again replaces
        the stored bookmark (and refreshes its timestamp) instead of adding a
        duplicate row. Different names at the same address coexist.
        """
        self._require_open()
        sid = _require_session_id(session_id)
        addr = _require_address(address)
        label = _require_name(name)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))

        nav_id = _deterministic_id(sid, addr, label)
        created_at = _utc_now()
        try:
            self._conn.execute(_BOOKMARK_UPSERT, (nav_id, sid, addr, label, created_at))
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise AnalysisError(
                f"cannot bookmark 0x{addr:x} in session {sid}: {exc}"
            ) from exc
        return self._read_back_bookmark(nav_id, addr, label)

    def bookmarks(self, session_id: str) -> list[NavBookmark]:
        """Return up to :data:`BOOKMARK_LIST_LIMIT` bookmarks, newest first."""
        self._require_open()
        sid = _require_session_id(session_id)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))
        try:
            rows = self._conn.execute(
                "SELECT id, address, name FROM nav_bookmarks "
                "WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (sid, BOOKMARK_LIST_LIMIT),
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot list bookmarks for session {sid}: {exc}"
            ) from exc
        return [_row_to_bookmark(row) for row in rows]

    def delete_bookmark(self, session_id: str, bookmark_id: str) -> bool:
        """Drop one bookmark and return ``True`` when a row was removed.

        Unknown sessions and unknown identifiers simply report ``False`` so
        the call stays idempotent.
        """
        self._require_open()
        if not _is_usable_id(session_id) or not _is_usable_id(bookmark_id):
            return False
        try:
            deleted = self._conn.execute(
                "DELETE FROM nav_bookmarks WHERE session_id = ? AND id = ?",
                (session_id, bookmark_id),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise AnalysisError(
                f"cannot delete bookmark {bookmark_id} in session {session_id}: {exc}"
            ) from exc
        return deleted.rowcount > 0

    # ---- comments -----------------------------------------------------

    def comment(self, session_id: str, address: int, text: str) -> NavComment:
        """Attach ``text`` to ``address`` and return the stored comment.

        Comments are unique per ``(session_id, address)`` pair: commenting an
        address a second time replaces the stored text (and its timestamp)
        instead of adding another row.
        """
        self._require_open()
        sid = _require_session_id(session_id)
        addr = _require_address(address)
        note = _require_text(text)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))

        nav_id = _deterministic_id(sid, addr)
        created_at = _utc_now()
        try:
            self._conn.execute(_COMMENT_UPSERT, (nav_id, sid, addr, note, created_at))
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise AnalysisError(
                f"cannot comment on 0x{addr:x} in session {sid}: {exc}"
            ) from exc
        return self._read_back_comment(sid, addr, note)

    def comments(self, session_id: str) -> list[NavComment]:
        """Return up to :data:`COMMENT_LIST_LIMIT` comments, newest first."""
        self._require_open()
        sid = _require_session_id(session_id)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))
        try:
            rows = self._conn.execute(
                "SELECT id, address, text FROM nav_comments "
                "WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (sid, COMMENT_LIST_LIMIT),
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot list comments for session {sid}: {exc}"
            ) from exc
        return [_row_to_comment(row) for row in rows]

    def delete_comment(self, session_id: str, comment_id: str) -> bool:
        """Drop one comment and return ``True`` when a row was removed.

        Unknown sessions and unknown identifiers simply report ``False`` so
        the call stays idempotent.
        """
        self._require_open()
        if not _is_usable_id(session_id) or not _is_usable_id(comment_id):
            return False
        try:
            deleted = self._conn.execute(
                "DELETE FROM nav_comments WHERE session_id = ? AND id = ?",
                (session_id, comment_id),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise AnalysisError(
                f"cannot delete comment {comment_id} in session {session_id}: {exc}"
            ) from exc
        return deleted.rowcount > 0

    # ---- cursor and goto history ---------------------------------------

    def goto(self, session_id: str, address: int) -> NavCursor:
        """Move the session cursor to ``address`` and record the visit.

        One cursor per session: ``goto`` replaces the previous position. Every
        visit is appended to the goto history, which is trimmed to
        :data:`HISTORY_LIMIT` newest entries per session.
        """
        self._require_open()
        sid = _require_session_id(session_id)
        addr = _require_address(address)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))

        updated_at = _utc_now()
        try:
            self._conn.execute(_CURSOR_UPSERT, (sid, addr, updated_at))
            self._conn.execute(
                "INSERT INTO nav_history (session_id, address, visited_at) "
                "VALUES (?, ?, ?)",
                (sid, addr, updated_at),
            )
            self._conn.execute(_TRIM_HISTORY, (sid, sid, HISTORY_LIMIT))
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise AnalysisError(
                f"cannot move cursor of session {sid} to 0x{addr:x}: {exc}"
            ) from exc
        stored = self._read_back_cursor(sid, addr)
        self._verify_history_head(sid, addr)
        return stored

    def cursor(self, session_id: str) -> NavCursor | None:
        """Return the session cursor, or ``None`` when it was never moved."""
        self._require_open()
        sid = _require_session_id(session_id)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))
        try:
            row = self._conn.execute(
                "SELECT address, updated_at FROM nav_cursor WHERE session_id = ? LIMIT 1",
                (sid,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot read cursor for session {sid}: {exc}"
            ) from exc
        return None if row is None else _row_to_cursor(row)

    def history(self, session_id: str) -> list[NavGoto]:
        """Return the goto history, newest first, at most 64 entries."""
        self._require_open()
        sid = _require_session_id(session_id)
        if not self._session_exists(sid):
            raise AnalysisError(_missing_session_message(sid))
        try:
            rows = self._conn.execute(
                "SELECT address, visited_at FROM nav_history "
                "WHERE session_id = ? ORDER BY visit_id DESC LIMIT ?",
                (sid, HISTORY_LIMIT),
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot list goto history for session {sid}: {exc}"
            ) from exc
        return [_row_to_goto(row) for row in rows]

    # ---- helpers -------------------------------------------------------

    def _session_exists(self, session_id: str) -> bool:
        """Return ``True`` when a session row with ``session_id`` is stored."""
        try:
            row = self._conn.execute(
                "SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        except sqlite3.OperationalError as exc:
            # A database without any saved sessions has no ``sessions`` table
            # yet; treat that as "session absent" rather than crashing.
            if "no such table" in str(exc):
                return False
            raise AnalysisError(f"cannot read session {session_id}: {exc}") from exc
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(f"cannot read session {session_id}: {exc}") from exc
        return row is not None

    def _read_back_bookmark(self, nav_id: str, address: int, name: str) -> NavBookmark:
        """Reload the bookmark row and verify it matches the intended write."""
        try:
            row = self._conn.execute(
                "SELECT id, address, name FROM nav_bookmarks WHERE id = ? LIMIT 1",
                (nav_id,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(f"cannot read back bookmark {nav_id}: {exc}") from exc
        if row is None:
            raise AnalysisError(f"bookmark {nav_id} vanished after write")
        stored = _row_to_bookmark(row)
        if stored.address != address or stored.name != name:
            raise AnalysisError(
                f"bookmark {nav_id} read-back mismatch: expected 0x{address:x} "
                f"{name!r}, got 0x{stored.address:x} {stored.name!r}"
            )
        return stored

    def _read_back_comment(self, session_id: str, address: int, text: str) -> NavComment:
        """Reload the comment row and verify it matches the intended write."""
        try:
            row = self._conn.execute(
                "SELECT id, address, text FROM nav_comments "
                "WHERE session_id = ? AND address = ? LIMIT 1",
                (session_id, address),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot read back comment at 0x{address:x}: {exc}"
            ) from exc
        if row is None:
            raise AnalysisError(f"comment at 0x{address:x} vanished after write")
        stored = _row_to_comment(row)
        if stored.address != address or stored.text != text:
            raise AnalysisError(
                f"comment at 0x{address:x} read-back mismatch: expected {text!r}, "
                f"got {stored.text!r}"
            )
        return stored

    def _read_back_cursor(self, session_id: str, address: int) -> NavCursor:
        """Reload the cursor row and verify it matches the intended write."""
        try:
            row = self._conn.execute(
                "SELECT address, updated_at FROM nav_cursor WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot read back cursor of session {session_id}: {exc}"
            ) from exc
        if row is None:
            raise AnalysisError(
                f"cursor of session {session_id} vanished after write"
            )
        stored = _row_to_cursor(row)
        if stored.address != address:
            raise AnalysisError(
                f"cursor of session {session_id} read-back mismatch: expected "
                f"0x{address:x}, got 0x{stored.address:x}"
            )
        return stored

    def _verify_history_head(self, session_id: str, address: int) -> None:
        """Confirm the newest history entry is the goto just recorded."""
        try:
            row = self._conn.execute(
                "SELECT address FROM nav_history WHERE session_id = ? "
                "ORDER BY visit_id DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise AnalysisError(
                f"cannot read back goto history of session {session_id}: {exc}"
            ) from exc
        if row is None or int(row["address"]) != address:
            raise AnalysisError(
                f"goto history of session {session_id} did not record 0x{address:x}"
            )

    def _require_open(self) -> None:
        if self._closed:
            raise AnalysisError("navigation store is closed")


def _missing_session_message(session_id: str) -> str:
    """Unknown-session error text, pointing at the fix."""
    return f"unknown session {session_id}; {SESSION_MISSING_HINT}"


def _resolve_db_path(db_path: str | Path) -> str | Path:
    """Validate ``db_path`` and create its missing parent directories.

    Mirrors the session store's path handling so both layers accept the same
    shapes: ``str``, :class:`~pathlib.Path` and ``":memory:"``.
    """
    if isinstance(db_path, Path):
        path = db_path
    elif isinstance(db_path, str):
        text = db_path.strip()
        if not text:
            raise AnalysisError("database path must not be empty")
        path = Path(text)
    else:
        raise AnalysisError(
            f"database path must be str or Path, not {type(db_path).__name__}"
        )

    if str(path) == ":memory:":  # pragma: no cover - in-memory store
        return ":memory:"

    try:
        if path.exists() and path.is_dir():
            raise AnalysisError(f"database path is a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    except AnalysisError:
        raise
    except OSError as exc:
        raise AnalysisError(
            f"cannot create directory for database {path}: {exc}"
        ) from exc
    return path


def _is_usable_id(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_session_id(session_id: Any) -> str:
    if not _is_usable_id(session_id):
        raise AnalysisError("session_id must be a non-empty string")
    return session_id


def _require_address(address: Any) -> int:
    """Validate a navigation address, which must be a non-negative integer."""
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError("address must be an integer")
    if address < 0:
        raise AnalysisError("address must not be negative")
    return address


def _require_name(name: Any) -> str:
    """Validate a bookmark name: a non-blank string of bounded length."""
    if not isinstance(name, str):
        raise AnalysisError("name must be a string")
    if not name.strip():
        raise AnalysisError("name must not be empty")
    if len(name) > MAX_NAME_LENGTH:
        raise AnalysisError(f"name must be at most {MAX_NAME_LENGTH} characters long")
    return name


def _require_text(text: Any) -> str:
    """Validate a comment text: a non-blank string of bounded length."""
    if not isinstance(text, str):
        raise AnalysisError("text must be a string")
    if not text.strip():
        raise AnalysisError("text must not be empty")
    if len(text) > MAX_COMMENT_LENGTH:
        raise AnalysisError(
            f"text must be at most {MAX_COMMENT_LENGTH} characters long"
        )
    return text


def _deterministic_id(session_id: str, address: int, name: str | None = None) -> str:
    """Derive a stable identifier from the navigation key.

    Same key in, same id out -- replacing an entry therefore reuses its row
    instead of duplicating it.
    """
    key = f"{session_id}|0x{address:x}"
    if name is not None:
        key = f"{key}|{name}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:NAV_ID_LENGTH]


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string with a numeric offset."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _row_to_bookmark(row: sqlite3.Row) -> NavBookmark:
    return NavBookmark(
        id=str(row["id"]),
        address=int(row["address"]),
        name=str(row["name"]),
    )


def _row_to_comment(row: sqlite3.Row) -> NavComment:
    return NavComment(
        id=str(row["id"]),
        address=int(row["address"]),
        text=str(row["text"]),
    )


def _row_to_cursor(row: sqlite3.Row) -> NavCursor:
    return NavCursor(address=int(row["address"]), updated_at=str(row["updated_at"]))


def _row_to_goto(row: sqlite3.Row) -> NavGoto:
    return NavGoto(address=int(row["address"]), visited_at=str(row["visited_at"]))
