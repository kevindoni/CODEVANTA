"""Tests for the SQLite-backed session store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codevanta.core.loader import BinaryInfo
from codevanta.storage.session import (
    SESSION_ID_LENGTH,
    SessionError,
    SessionRecord,
    SessionStore,
)


def make_info(
    path: Path,
    *,
    sha256: str = "a" * 64,
    entry_point: int | None = 0x401000,
) -> BinaryInfo:
    return BinaryInfo(
        path=path,
        format="ELF",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=entry_point,
        image_base=0x400000,
        sha256=sha256,
        file_size=4096,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "sessions.db"


@pytest.fixture
def sample_info(tmp_path: Path) -> BinaryInfo:
    return make_info(tmp_path / "sample.bin")


@pytest.fixture
def store(db_path: Path) -> Iterator[SessionStore]:
    session_store = SessionStore(db_path)
    try:
        yield session_store
    finally:
        session_store.close()


def test_save_get_roundtrip(store: SessionStore, sample_info: BinaryInfo) -> None:
    saved = store.save(sample_info, 12, 34, notes="initial triage")

    assert isinstance(saved, SessionRecord)
    assert len(saved.session_id) == SESSION_ID_LENGTH
    assert saved.binary_path == str(sample_info.path)
    assert saved.sha256 == sample_info.sha256
    assert saved.format == "ELF"
    assert saved.architecture == "x86_64"
    assert saved.bitness == 64
    assert saved.entry_point == 0x401000
    assert saved.functions == 12
    assert saved.strings == 34
    assert saved.notes == "initial triage"

    loaded = store.get(saved.session_id)
    assert loaded is not None
    assert loaded == saved
    payload = loaded.to_dict()
    assert payload["entry_point"] == "0x401000"
    assert payload["functions"] == 12
    assert payload["strings"] == 34
    assert payload["notes"] == "initial triage"
    assert payload["session_id"] == saved.session_id

    created = datetime.fromisoformat(saved.created_at)
    assert created.tzinfo is not None
    assert created.utcoffset() == timezone.utc.utcoffset(created)


def test_entry_point_none_roundtrip(store: SessionStore, tmp_path: Path) -> None:
    info = make_info(tmp_path / "noentry.bin", entry_point=None)
    saved = store.save(info, 0, 0)

    assert saved.entry_point is None
    loaded = store.get(saved.session_id)
    assert loaded is not None
    assert loaded.entry_point is None
    assert loaded.notes is None
    assert loaded.to_dict()["entry_point"] is None


def test_same_sha256_creates_distinct_sessions(
    store: SessionStore, sample_info: BinaryInfo
) -> None:
    first = store.save(sample_info, 1, 2)
    second = store.save(sample_info, 3, 4)

    assert first.session_id != second.session_id
    assert first.sha256 == second.sha256 == sample_info.sha256
    assert store.get(first.session_id) == first
    assert store.get(second.session_id) == second
    assert len(store.list(limit=10)) == 2


def test_list_respects_limit_and_newest_first(
    store: SessionStore, sample_info: BinaryInfo
) -> None:
    saved = [
        store.save(sample_info, index, index, session_id=f"session{index:03d}")
        for index in range(3)
    ]

    everything = store.list(limit=10)
    assert [record.session_id for record in everything] == [
        saved[2].session_id,
        saved[1].session_id,
        saved[0].session_id,
    ]
    assert store.list(limit=2) == [saved[2], saved[1]]
    assert store.list(limit=1) == [saved[2]]
    assert store.list() == everything


def test_empty_list(store: SessionStore) -> None:
    assert store.list() == []


@pytest.mark.parametrize("limit", [0, -1, -50])
def test_list_rejects_non_positive_limit(store: SessionStore, limit: int) -> None:
    with pytest.raises(SessionError):
        store.list(limit=limit)


def test_delete_returns_true_then_false(
    store: SessionStore, sample_info: BinaryInfo
) -> None:
    saved = store.save(sample_info, 5, 6)

    assert store.delete(saved.session_id) is True
    assert store.delete(saved.session_id) is False
    assert store.get(saved.session_id) is None
    assert store.list() == []


def test_unknown_session_id_returns_none(store: SessionStore) -> None:
    assert store.get("missing-session") is None
    assert store.delete("missing-session") is False
    assert store.list() == []


def test_nested_database_directory_is_created(
    tmp_path: Path, sample_info: BinaryInfo
) -> None:
    db_path = tmp_path / "nested" / "deeper" / "sessions.db"
    assert not db_path.parent.exists()

    with SessionStore(db_path) as nested_store:
        saved = nested_store.save(sample_info, 2, 3)
        assert db_path.is_file()
        assert nested_store.get(saved.session_id) == saved


def test_schema_creates_table_and_created_at_index(
    db_path: Path, sample_info: BinaryInfo
) -> None:
    with SessionStore(db_path) as schema_store:
        schema_store.save(sample_info, 1, 1)

    connection = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        indexes = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    finally:
        connection.close()

    assert "sessions" in tables
    assert any("created_at" in name for name in indexes)


def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(SessionError):
        SessionStore(tmp_path)


def test_empty_path_raises() -> None:
    with pytest.raises(SessionError):
        SessionStore("   ")


def test_unsupported_path_type_raises() -> None:
    with pytest.raises(SessionError):
        SessionStore(1234)  # type: ignore[arg-type]


def test_context_manager_closes_store(
    db_path: Path, sample_info: BinaryInfo
) -> None:
    with SessionStore(db_path) as managed:
        saved = managed.save(sample_info, 1, 1)

    with pytest.raises(SessionError):
        managed.get(saved.session_id)
    managed.close()  # idempotent


def test_custom_session_id(store: SessionStore, sample_info: BinaryInfo) -> None:
    saved = store.save(sample_info, 0, 0, session_id="custom-id")

    assert saved.session_id == "custom-id"
    assert store.get("custom-id") == saved


def test_negative_counts_rejected(store: SessionStore, sample_info: BinaryInfo) -> None:
    with pytest.raises(SessionError):
        store.save(sample_info, -1, 0)
    with pytest.raises(SessionError):
        store.save(sample_info, 0, -2)


def test_notes_none_roundtrip(store: SessionStore, sample_info: BinaryInfo) -> None:
    saved = store.save(sample_info, 1, 1, notes=None)

    loaded = store.get(saved.session_id)
    assert loaded is not None
    assert loaded.notes is None


def test_duplicate_session_id_raises_and_store_stays_usable(
    store: SessionStore, sample_info: BinaryInfo
) -> None:
    store.save(sample_info, 1, 1, session_id="duplicate")

    with pytest.raises(SessionError):
        store.save(sample_info, 2, 2, session_id="duplicate")

    assert len(store.list()) == 1
    assert store.save(sample_info, 3, 3).session_id != "duplicate"


def test_sessions_persist_across_instances(
    db_path: Path, sample_info: BinaryInfo
) -> None:
    with SessionStore(db_path) as first_store:
        saved = first_store.save(sample_info, 7, 8, notes="persisted")

    with SessionStore(db_path) as second_store:
        assert second_store.get(saved.session_id) == saved


def test_in_memory_store_supported(sample_info: BinaryInfo) -> None:
    with SessionStore(":memory:") as memory_store:
        saved = memory_store.save(sample_info, 1, 2)
        assert memory_store.get(saved.session_id) == saved
