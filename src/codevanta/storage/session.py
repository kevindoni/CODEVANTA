"""SQLite-backed session storage for CODEVANTA analyses.

A *session* is a persisted snapshot of one analysis run: the normalized
fingerprint produced by :mod:`codevanta.core.loader` plus the function and
string counts gathered by later phases. Sessions are additive — saving the
same binary twice creates two rows with distinct identifiers, which keeps an
audit trail of repeated analyses.

Sessions can also carry *annotations*: one free-text note per address, kept
in the ``annotations`` table and keyed by ``(session_id, address)`` so that
re-annotating an address replaces the previous note instead of appending a
duplicate row.

The module uses the standard library only (``sqlite3``, ``uuid``,
``datetime``, ``pathlib``) and issues parameterized SQL exclusively.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_NOTE_LENGTH",
    "SESSION_ID_LENGTH",
    "Annotation",
    "SessionError",
    "SessionRecord",
    "SessionStore",
]

#: Default number of rows returned by :meth:`SessionStore.list`.
DEFAULT_LIMIT = 50

#: Hard ceiling applied by :meth:`SessionStore.list` so one call cannot
#: exhaust memory on a very large database.
MAX_LIMIT = 10_000

#: Number of hex characters used for generated session identifiers.
SESSION_ID_LENGTH = 12

#: Maximum accepted length of a single annotation note, in characters.
MAX_NOTE_LENGTH = 4000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    binary_path   TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    format        TEXT NOT NULL,
    architecture  TEXT NOT NULL,
    bitness       INTEGER NOT NULL,
    entry_point   INTEGER,
    functions     INTEGER NOT NULL,
    strings       INTEGER NOT NULL,
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions (created_at);

CREATE TABLE IF NOT EXISTS annotations (
    session_id    TEXT NOT NULL,
    address       INTEGER NOT NULL,
    note          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (session_id, address)
);

CREATE INDEX IF NOT EXISTS idx_annotations_session ON annotations (session_id);
"""

_COLUMNS = (
    "session_id, created_at, binary_path, sha256, format, architecture, "
    "bitness, entry_point, functions, strings, notes"
)

_INSERT = (
    "INSERT INTO sessions (session_id, created_at, binary_path, sha256, format, "
    "architecture, bitness, entry_point, functions, strings, notes) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_ANNOTATION_COLUMNS = "session_id, address, note, created_at"

_ANNOTATION_UPSERT = (
    "INSERT INTO annotations (session_id, address, note, created_at) "
    "VALUES (?, ?, ?, ?) "
    "ON CONFLICT (session_id, address) DO UPDATE SET "
    "note = excluded.note, created_at = excluded.created_at"
)


class SessionError(Exception):
    """Raised when a session store cannot be opened, written or queried."""


@dataclass(frozen=True)
class SessionRecord:
    """A single persisted analysis session."""

    session_id: str
    created_at: str
    binary_path: str
    sha256: str
    format: str
    architecture: str
    bitness: int
    entry_point: int | None
    functions: int
    strings: int
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record, rendering the entry point as hex."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "binary_path": self.binary_path,
            "sha256": self.sha256,
            "format": self.format,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "entry_point": f"0x{self.entry_point:x}" if self.entry_point is not None else None,
            "functions": self.functions,
            "strings": self.strings,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Annotation:
    """A free-text note attached to one address inside a session."""

    session_id: str
    address: int
    note: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the annotation, rendering the address as hex."""
        return {
            "session_id": self.session_id,
            "address": f"0x{self.address:x}",
            "note": self.note,
            "created_at": self.created_at,
        }


class SessionStore:
    """Create, read, list and delete analysis sessions in SQLite.

    The database file (and any missing parent directories) is created on
    construction. Use the store as a context manager to close it on exit.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = _resolve_db_path(db_path)
        self._closed = False
        try:
            self._conn = sqlite3.connect(str(self._db_path), timeout=5.0)
        except sqlite3.Error as exc:  # pragma: no cover - environment dependent
            raise SessionError(f"cannot open session database {self._db_path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.close()
            self._closed = True
            raise SessionError(
                f"cannot initialize session database {self._db_path}: {exc}"
            ) from exc

    # ---- lifecycle ----------------------------------------------------

    def __enter__(self) -> SessionStore:
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
            raise SessionError(f"cannot close session database: {exc}") from exc

    # ---- CRUD ---------------------------------------------------------

    def save(
        self,
        info: BinaryInfo,
        functions_count: int,
        strings_count: int,
        notes: str | None = None,
        session_id: str | None = None,
    ) -> SessionRecord:
        """Persist ``info`` as a new session and return the stored record."""
        self._require_open()
        if info is None:
            raise SessionError("binary info is required")
        functions = _require_count(functions_count, "functions_count")
        strings = _require_count(strings_count, "strings_count")
        if notes is not None and not isinstance(notes, str):
            raise SessionError("notes must be a string or None")
        sid = _require_session_id(session_id)

        record = SessionRecord(
            session_id=sid,
            created_at=_utc_now(),
            binary_path=str(info.path),
            sha256=str(info.sha256),
            format=str(info.format),
            architecture=str(info.architecture),
            bitness=int(info.bitness),
            entry_point=None if info.entry_point is None else int(info.entry_point),
            functions=functions,
            strings=strings,
            notes=notes,
        )
        try:
            self._conn.execute(
                _INSERT,
                (
                    record.session_id,
                    record.created_at,
                    record.binary_path,
                    record.sha256,
                    record.format,
                    record.architecture,
                    record.bitness,
                    record.entry_point,
                    record.functions,
                    record.strings,
                    record.notes,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise SessionError(f"cannot save session {sid}: {exc}") from exc
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        """Return the session with ``session_id``, or ``None`` when absent."""
        self._require_open()
        if not _is_usable_id(session_id):
            return None
        try:
            row = self._conn.execute(
                f"SELECT {_COLUMNS} FROM sessions WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise SessionError(f"cannot read session {session_id}: {exc}") from exc
        return None if row is None else _row_to_record(row)

    def list(self, limit: int = DEFAULT_LIMIT) -> list[SessionRecord]:
        """Return up to ``limit`` sessions, newest first.

        Ordering falls back to insertion order (``rowid``) when two sessions
        share a timestamp, which happens on platforms with coarse clocks.
        """
        self._require_open()
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise SessionError("limit must be an integer")
        if limit <= 0:
            raise SessionError("limit must be a positive integer")
        capped = min(limit, MAX_LIMIT)
        try:
            rows = self._conn.execute(
                f"SELECT {_COLUMNS} FROM sessions "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (capped,),
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise SessionError(f"cannot list sessions: {exc}") from exc
        return [_row_to_record(row) for row in rows]

    def delete(self, session_id: str) -> bool:
        """Delete a session and return ``True`` when a row was removed."""
        self._require_open()
        if not _is_usable_id(session_id):
            return False
        try:
            cursor = self._conn.execute(
                "DELETE FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise SessionError(f"cannot delete session {session_id}: {exc}") from exc
        return cursor.rowcount > 0

    # ---- annotations --------------------------------------------------

    def annotate(self, session_id: str, address: int, note: str) -> Annotation:
        """Attach ``note`` to ``address`` inside ``session_id``.

        Notes are unique per ``(session_id, address)`` pair: annotating an
        address a second time replaces the stored note (and its timestamp)
        instead of adding another row.
        """
        self._require_open()
        sid = _require_session_id(session_id)
        addr = _require_address(address)
        text = _require_note(note)
        if not self._session_exists(sid):
            raise SessionError(f"unknown session {sid}")

        annotation = Annotation(
            session_id=sid,
            address=addr,
            note=text,
            created_at=_utc_now(),
        )
        try:
            self._conn.execute(
                _ANNOTATION_UPSERT,
                (
                    annotation.session_id,
                    annotation.address,
                    annotation.note,
                    annotation.created_at,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise SessionError(
                f"cannot annotate address 0x{addr:x} in session {sid}: {exc}"
            ) from exc
        return annotation

    def annotations(self, session_id: str) -> list[Annotation]:
        """Return every annotation of ``session_id``, lowest address first."""
        self._require_open()
        sid = _require_session_id(session_id)
        if not self._session_exists(sid):
            raise SessionError(f"unknown session {sid}")
        try:
            rows = self._conn.execute(
                f"SELECT {_ANNOTATION_COLUMNS} FROM annotations "
                "WHERE session_id = ? ORDER BY address ASC",
                (sid,),
            ).fetchall()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise SessionError(f"cannot list annotations for session {sid}: {exc}") from exc
        return [_row_to_annotation(row) for row in rows]

    def remove_annotation(self, session_id: str, address: int) -> bool:
        """Drop the note at ``address`` and return ``True`` when one existed.

        Unknown sessions and unknown addresses simply report ``False`` so the
        call stays idempotent.
        """
        self._require_open()
        if not _is_usable_id(session_id):
            return False
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            return False
        try:
            cursor = self._conn.execute(
                "DELETE FROM annotations WHERE session_id = ? AND address = ?",
                (session_id, address),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise SessionError(
                f"cannot remove annotation at 0x{address:x} in session {session_id}: {exc}"
            ) from exc
        return cursor.rowcount > 0

    # ---- helpers ------------------------------------------------------

    def _session_exists(self, session_id: str) -> bool:
        """Return ``True`` when a row with ``session_id`` is stored."""
        try:
            row = self._conn.execute(
                "SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise SessionError(f"cannot read session {session_id}: {exc}") from exc
        return row is not None

    def _require_open(self) -> None:
        if self._closed:
            raise SessionError("session store is closed")


def _resolve_db_path(db_path: str | Path) -> str | Path:
    """Validate ``db_path`` and create its missing parent directories."""
    if isinstance(db_path, Path):
        path = db_path
    elif isinstance(db_path, str):
        text = db_path.strip()
        if not text:
            raise SessionError("database path must not be empty")
        path = Path(text)
    else:
        raise SessionError(f"database path must be str or Path, not {type(db_path).__name__}")

    if str(path) == ":memory:":  # pragma: no cover - in-memory store
        return ":memory:"

    try:
        if path.exists() and path.is_dir():
            raise SessionError(f"database path is a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    except SessionError:
        raise
    except OSError as exc:
        raise SessionError(f"cannot create directory for database {path}: {exc}") from exc
    return path


def _is_usable_id(session_id: Any) -> bool:
    return isinstance(session_id, str) and bool(session_id.strip())


def _require_session_id(session_id: str | None) -> str:
    if session_id is None:
        return uuid.uuid4().hex[:SESSION_ID_LENGTH]
    if not _is_usable_id(session_id):
        raise SessionError("session_id must be a non-empty string")
    return session_id


def _require_count(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SessionError(f"{name} must be an integer")
    if value < 0:
        raise SessionError(f"{name} must not be negative")
    return value


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string with a numeric offset."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _require_address(address: Any) -> int:
    """Validate an annotation address, which must be a non-negative integer."""
    if isinstance(address, bool) or not isinstance(address, int):
        raise SessionError("address must be an integer")
    if address < 0:
        raise SessionError("address must not be negative")
    return address


def _require_note(note: Any) -> str:
    """Validate an annotation note: a non-blank string of bounded length."""
    if not isinstance(note, str):
        raise SessionError("note must be a string")
    if not note.strip():
        raise SessionError("note must not be empty")
    if len(note) > MAX_NOTE_LENGTH:
        raise SessionError(
            f"note must be at most {MAX_NOTE_LENGTH} characters long"
        )
    return note


def _row_to_annotation(row: sqlite3.Row) -> Annotation:
    return Annotation(
        session_id=row["session_id"],
        address=int(row["address"]),
        note=row["note"],
        created_at=row["created_at"],
    )


def _row_to_record(row: sqlite3.Row) -> SessionRecord:
    entry_point = row["entry_point"]
    return SessionRecord(
        session_id=row["session_id"],
        created_at=row["created_at"],
        binary_path=row["binary_path"],
        sha256=row["sha256"],
        format=row["format"],
        architecture=row["architecture"],
        bitness=int(row["bitness"]),
        entry_point=None if entry_point is None else int(entry_point),
        functions=int(row["functions"]),
        strings=int(row["strings"]),
        notes=row["notes"],
    )
