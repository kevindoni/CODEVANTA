"""Read-only SQLite introspection (``file:...?mode=ro&immutable=1``).

A database file is opened through SQLite's immutable read-only URI mode, so
the introspection cannot write, cannot create journals and never replays a
WAL: the main file is read exactly as it lies on disk. What comes back is a
bounded summary -- up to :data:`MAX_TABLES` table names with row counts, and
for one requested table its column list (``PRAGMA table_info``) plus up to
:data:`MAX_SAMPLE_ROWS` sample rows with JSON-safe values. Nothing else is
executed: every statement is a ``SELECT``/``PRAGMA`` against a
``mode=ro&immutable=1`` connection, and any ``sqlite3.Error`` becomes a typed
:class:`~codevanta.core.report.AnalysisError`.

Bounds and errors
-----------------
A database is refused above :data:`MAX_DB_BYTES` rather than page-walked
forever (``COUNT(*)`` on a hostile table is SQLite's problem, ours is only
opening the file at all). Table lists are capped at :data:`MAX_TABLES` and
samples at :data:`MAX_SAMPLE_ROWS` with a ``truncated`` flag. A file without
the ``SQLite format 3\\0`` magic, a missing file, or a corrupt database is a
typed error, never a traceback.
"""

from __future__ import annotations

import sqlite3
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "MAX_DB_BYTES",
    "MAX_SAMPLE_ROWS",
    "MAX_TABLES",
    "SQLITE_MAGIC",
    "SqliteColumn",
    "SqliteSummary",
    "SqliteTable",
    "inspect_sqlite",
]

#: Hard ceiling on the database file size one introspection will open.
MAX_DB_BYTES = 256 * 1024 * 1024

#: Tables kept in the summary before the rest are counted but not listed.
MAX_TABLES = 32

#: Sample rows kept per requested table.
MAX_SAMPLE_ROWS = 10

#: The 16-byte header every SQLite 3 database starts with.
SQLITE_MAGIC = b"SQLite format 3\x00"

#: Evidence ``source`` for every finding extracted from a database file.
EVIDENCE_SOURCE = "bin.sqlite"

#: Evidence ``method``: the introspection runs through immutable read-only URIs.
EVIDENCE_METHOD = "sqlite_ro_immutable"


@dataclass(frozen=True)
class SqliteColumn:
    """One column of a requested table: name, declared type, nullability, pk."""

    name: str
    type: str
    not_null: bool
    primary_key: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "not_null": self.not_null,
            "primary_key": self.primary_key,
        }


@dataclass(frozen=True)
class SqliteTable:
    """One table: name, row count, and (when requested) schema + samples."""

    name: str
    row_count: int
    columns: tuple[SqliteColumn, ...] = ()
    sample_rows: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "row_count": self.row_count}
        if self.columns:
            data["columns"] = [c.to_dict() for c in self.columns]
        if self.sample_rows:
            data["sample_rows"] = list(self.sample_rows)
        return data


@dataclass(frozen=True)
class SqliteSummary:
    """Bounded read-only introspection result for one database file."""

    path: str
    size_bytes: int
    table_count: int
    tables: tuple[SqliteTable, ...]
    truncated: bool
    requested_table: str | None
    wal_present: bool
    shm_present: bool
    immutable_mode: bool = True
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "table_count": self.table_count,
            "tables": [t.to_dict() for t in self.tables],
            "truncated": self.truncated,
            "requested_table": self.requested_table,
            "wal_present": self.wal_present,
            "shm_present": self.shm_present,
            "immutable_mode": self.immutable_mode,
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def _quote_ident(name: str) -> str:
    """Quote an identifier for SQL (internal quotes doubled, per SQLite)."""
    return '"' + name.replace('"', '""') + '"'


def _json_safe(value: Any) -> Any:
    """Map one cell value to something ``json.dumps`` accepts unchanged."""
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes>"
    if isinstance(value, (str, int, float)) or value is None:
        return value
    return str(value)


def _open_readonly(candidate: Path) -> sqlite3.Connection:
    """Open the database through the ``mode=ro&immutable=1`` URI."""
    # pathname2url yields /D:/... on Windows and /home/... elsewhere; the
    # query string stays literal so SQLite parses mode and immutable itself.
    uri = f"file:{urllib.request.pathname2url(str(candidate))}?mode=ro&immutable=1"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise AnalysisError(f"cannot open database {str(candidate)!r}: {exc}") from exc


def inspect_sqlite(path: Path, table: str | None = None) -> SqliteSummary:
    """Introspect one SQLite file read-only; ``table`` adds schema + samples.

    The file must exist, be regular, carry the SQLite 3 magic and pass the
    size ceiling. Tables are listed with row counts (bounded at
    :data:`MAX_TABLES`); a requested table gets its column list and up to
    :data:`MAX_SAMPLE_ROWS` sample rows. A ``-wal``/``-shm`` sibling file is
    reported as present-but-ignored: immutable mode never replays it, so with
    hot un-checkpointed WAL the visible rows can lag the last writer -- that
    caveat is stated in ``warnings``, not hidden.
    """
    if not path.exists():
        raise AnalysisError(f"file not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_DB_BYTES:
        raise AnalysisError(
            f"database too large for introspection: {size} bytes (limit {MAX_DB_BYTES})"
        )
    try:
        with path.open("rb") as handle:
            magic = handle.read(16)
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc
    if magic != SQLITE_MAGIC:
        raise AnalysisError(f"not a SQLite 3 database: {path}")
    wal_present = path.with_name(path.name + "-wal").exists()
    shm_present = path.with_name(path.name + "-shm").exists()
    warnings: list[str] = []
    if wal_present:
        warnings.append("WAL file present; immutable mode reads the main file without replaying it")
    connection = _open_readonly(path)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    except sqlite3.Error as exc:
        connection.close()
        raise AnalysisError(f"cannot read schema of {str(path)!r}: {exc}") from exc
    names = [str(row[0]) for row in rows]
    truncated = len(names) > MAX_TABLES
    if truncated:
        warnings.append(f"tables: kept {MAX_TABLES} of {len(names)}")
    listed = names[:MAX_TABLES]
    tables: list[SqliteTable] = []
    for name in listed:
        try:
            count_row = connection.execute(
                f"SELECT COUNT(*) FROM {_quote_ident(name)}"
            ).fetchone()
        except sqlite3.Error as exc:
            connection.close()
            raise AnalysisError(
                f"cannot count rows of table {name!r} in {str(path)!r}: {exc}"
            ) from exc
        tables.append(SqliteTable(name=name, row_count=int(count_row[0] if count_row else 0)))
    requested: str | None = None
    if table is not None:
        wanted = table.strip()
        if wanted not in names:
            connection.close()
            known = ", ".join(names[:MAX_TABLES]) or "(none)"
            raise AnalysisError(f"table not found: {table!r} (tables: {known})")
        requested = wanted
        tables = [_describe_table(connection, wanted, path)]
    connection.close()
    return SqliteSummary(
        path=str(path),
        size_bytes=size,
        table_count=len(names),
        tables=tuple(tables),
        truncated=truncated,
        requested_table=requested,
        wal_present=wal_present,
        shm_present=shm_present,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method=EVIDENCE_METHOD,
            confidence=Confidence.HIGH,
            detail=f"{len(names)} tables, mode=ro&immutable=1, writes: none",
        ),
    )


def _describe_table(
    connection: sqlite3.Connection, name: str, path: Path
) -> SqliteTable:
    """Schema plus bounded sample rows for one table (typed errors on failure)."""
    try:
        info = connection.execute(f"PRAGMA table_info({_quote_ident(name)})").fetchall()
        columns = tuple(
            SqliteColumn(
                name=str(row[1]),
                type=str(row[2] or ""),
                not_null=bool(row[3]),
                primary_key=bool(row[5]),
            )
            for row in info
        )
        count_row = connection.execute(
            f"SELECT COUNT(*) FROM {_quote_ident(name)}"
        ).fetchone()
        count = int(count_row[0] if count_row else 0)
        cursor = connection.execute(
            f"SELECT * FROM {_quote_ident(name)} LIMIT {MAX_SAMPLE_ROWS}"
        )
        column_names = [str(row[1]) for row in info]
        sample_rows = tuple(
            {key: _json_safe(value) for key, value in zip(column_names, record, strict=False)}
            for record in cursor.fetchall()
        )
    except sqlite3.Error as exc:
        raise AnalysisError(
            f"cannot read table {name!r} in {str(path)!r}: {exc}"
        ) from exc
    return SqliteTable(name=name, row_count=count, columns=columns, sample_rows=sample_rows)
