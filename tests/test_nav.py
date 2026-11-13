"""Tests for the navigation lane: store, provider probes, CLI and MCP tools.

Everything here is offline: sessions are created through the existing
:class:`~codevanta.storage.session.SessionStore` API against a temporary
database, the provider probes are pure presence checks, and the GUI bridges
are only ever *reported*, never launched.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis import nav as nav_module
from codevanta.analysis import nav_providers
from codevanta.analysis.nav import (
    BOOKMARK_LIST_LIMIT,
    COMMENT_LIST_LIMIT,
    HISTORY_LIMIT,
    SESSION_MISSING_HINT,
    NavBookmark,
    NavComment,
    NavCursor,
    NavGoto,
    NavStore,
    nav_evidence,
)
from codevanta.cli.nav import app as nav_app
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_nav
from codevanta.storage.session import SessionStore

# ``codevanta.cli.main`` and ``codevanta.mcp_server.tools`` pull in the whole
# analysis stack (lief, capstone, z3, ...). They are imported inside the two
# tests that need them -- the full-app registration smoke and the
# tools-module wiring check -- to keep this module's import graph small.

runner = CliRunner()

BASE = 0x401000


def make_info(path: Path) -> BinaryInfo:
    """Build the minimal metadata a session row needs."""
    return BinaryInfo(
        path=path,
        format="ELF",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=BASE,
        image_base=0x400000,
        sha256="a" * 64,
        file_size=4096,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "sessions.db"


@pytest.fixture
def session_id(db_path: Path) -> Iterator[str]:
    """Create one persisted session via the existing SessionStore API."""
    store = SessionStore(db_path)
    try:
        record = store.save(make_info(db_path.with_suffix(".bin")), 12, 34)
        yield record.session_id
    finally:
        store.close()


@pytest.fixture
def nav(db_path: Path) -> Iterator[NavStore]:
    store = NavStore(db_path)
    try:
        yield store
    finally:
        store.close()


def _payload(result) -> dict:
    """Parse the JSON object a ``--json`` command printed."""
    return json.loads(result.output)


class TestBookmarks:
    """``NavStore.bookmark`` round-trips, upserts and bounds."""

    def test_roundtrip_returns_stored_record(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            marked = store.bookmark(session_id, BASE, "entry stub")
            assert isinstance(marked, NavBookmark)
            assert marked.address == BASE
            assert marked.name == "entry stub"
            assert len(marked.id) == 12
            listed = store.bookmarks(session_id)
        assert listed == [marked]

    def test_same_address_and_name_is_replaced_not_duplicated(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            first = store.bookmark(session_id, BASE, "entry stub")
            second = store.bookmark(session_id, BASE, "entry stub")
            assert second.id == first.id
            assert len(store.bookmarks(session_id)) == 1

    def test_same_address_with_different_names_coexists(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            store.bookmark(session_id, BASE, "one")
            store.bookmark(session_id, BASE, "two")
            names = {bookmark.name for bookmark in store.bookmarks(session_id)}
        assert names == {"one", "two"}

    def test_ids_are_deterministic(self, db_path: Path, session_id: str) -> None:
        with NavStore(db_path) as store:
            direct = store.bookmark(session_id, BASE, "entry stub")
        with NavStore(db_path) as reopened:
            again = reopened.bookmark(session_id, BASE, "entry stub")
        assert direct.id == again.id

    def test_listing_is_bounded_at_128(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            for index in range(BOOKMARK_LIST_LIMIT + 2):
                store.bookmark(session_id, BASE + index, f"spot-{index}")
            listed = store.bookmarks(session_id)
        assert len(listed) == BOOKMARK_LIST_LIMIT
        # Newest first: the last two marks survive, the first two were cut.
        assert listed[0].name == f"spot-{BOOKMARK_LIST_LIMIT + 1}"
        assert listed[-1].name == "spot-2"

    def test_delete_bookmark_is_idempotent(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            marked = store.bookmark(session_id, BASE, "entry stub")
            assert store.delete_bookmark(session_id, marked.id) is True
            assert store.delete_bookmark(session_id, marked.id) is False
            assert store.delete_bookmark("no-such-session", marked.id) is False
            assert store.delete_bookmark(session_id, "") is False
            assert store.bookmarks(session_id) == []

    def test_bookmarks_of_empty_session_is_empty_list(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            assert store.bookmarks(session_id) == []


class TestComments:
    """``NavStore.comment`` round-trips, replaces and bounds."""

    def test_roundtrip_returns_stored_record(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            noted = store.comment(session_id, BASE, "string table starts here")
            assert isinstance(noted, NavComment)
            assert noted.address == BASE
            assert noted.text == "string table starts here"
            assert store.comments(session_id) == [noted]

    def test_same_address_is_replaced_not_duplicated(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            store.comment(session_id, BASE, "first look")
            second = store.comment(session_id, BASE, "second look")
            listed = store.comments(session_id)
        assert len(listed) == 1
        assert listed[0].text == "second look"
        assert listed[0].id == second.id

    def test_listing_is_bounded_at_128(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            for index in range(COMMENT_LIST_LIMIT + 2):
                store.comment(session_id, BASE + index, f"note-{index}")
            listed = store.comments(session_id)
        assert len(listed) == COMMENT_LIST_LIMIT
        assert listed[0].text == f"note-{COMMENT_LIST_LIMIT + 1}"
        assert listed[-1].text == "note-2"

    def test_delete_comment_is_idempotent(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            noted = store.comment(session_id, BASE, "first look")
            assert store.delete_comment(session_id, noted.id) is True
            assert store.delete_comment(session_id, noted.id) is False
            assert store.delete_comment("no-such-session", noted.id) is False
            assert store.comments(session_id) == []


class TestCursorAndHistory:
    """One cursor per session plus the bounded goto history."""

    def test_goto_sets_and_updates_the_cursor(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            assert store.cursor(session_id) is None
            moved = store.goto(session_id, BASE)
            assert isinstance(moved, NavCursor)
            assert moved.address == BASE
            assert store.cursor(session_id) == moved
            again = store.goto(session_id, BASE + 0x20)
            assert again.address == BASE + 0x20
            assert store.cursor(session_id) == again

    def test_history_is_newest_first_and_bounded_at_64(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            for index in range(HISTORY_LIMIT + 6):
                store.goto(session_id, BASE + index)
            history = store.history(session_id)
        assert len(history) == HISTORY_LIMIT
        assert all(isinstance(entry, NavGoto) for entry in history)
        assert history[0].address == BASE + HISTORY_LIMIT + 5
        assert history[-1].address == BASE + 6

    def test_history_is_scoped_per_session(
        self, db_path: Path, session_id: str
    ) -> None:
        store = SessionStore(db_path)
        try:
            other = store.save(make_info(db_path.with_suffix(".elf")), 1, 2)
        finally:
            store.close()
        with NavStore(db_path) as nav:
            nav.goto(session_id, BASE)
            nav.goto(other.session_id, BASE + 0x40)
            mine = nav.history(session_id)
            assert len(mine) == 1
            assert mine[0].address == BASE
            assert nav.history(other.session_id)[0].address == BASE + 0x40


class TestMissingSessionAndValidation:
    """Typed errors, never crashes."""

    @pytest.mark.parametrize(
        ("operation", "args"),
        [
            ("bookmark", (BASE, "name")),
            ("comment", (BASE, "text")),
            ("goto", (BASE,)),
            ("cursor", ()),
            ("bookmarks", ()),
            ("comments", ()),
            ("history", ()),
        ],
    )
    def test_unknown_session_is_a_typed_error_with_hint(
        self, db_path: Path, operation: str, args: tuple
    ) -> None:
        with NavStore(db_path) as store:
            method = getattr(store, operation)
            with pytest.raises(AnalysisError) as excinfo:
                method("does-not-exist", *args)
        assert "codevanta session save" in str(excinfo.value)
        assert SESSION_MISSING_HINT in str(excinfo.value)

    def test_nav_tables_do_not_require_existing_sessions(self, tmp_path: Path) -> None:
        """A fresh database has no ``sessions`` table yet; reads stay typed."""
        with NavStore(tmp_path / "fresh.db") as store:
            with pytest.raises(AnalysisError) as excinfo:
                store.bookmarks("anything")
        assert "unknown session" in str(excinfo.value)

    @pytest.mark.parametrize(
        "args",
        [
            ("", BASE, "name"),
            ("   ", BASE, "name"),
            (None, BASE, "name"),
            (123, BASE, "name"),
        ],
    )
    def test_bad_session_ids_raise(self, db_path: Path, args: tuple) -> None:
        with NavStore(db_path) as store:
            with pytest.raises(AnalysisError):
                store.bookmark(*args)

    @pytest.mark.parametrize("address", [-1, "0x10", True, None, 1.5])
    def test_bad_addresses_raise(self, db_path: Path, session_id: str, address) -> None:
        with NavStore(db_path) as store:
            with pytest.raises(AnalysisError):
                store.bookmark(session_id, address, "name")

    def test_bad_names_and_texts_raise(self, db_path: Path, session_id: str) -> None:
        with NavStore(db_path) as store:
            with pytest.raises(AnalysisError):
                store.bookmark(session_id, BASE, "   ")
            with pytest.raises(AnalysisError):
                store.bookmark(session_id, BASE, "x" * 257)
            with pytest.raises(AnalysisError):
                store.comment(session_id, BASE, "")
            with pytest.raises(AnalysisError):
                store.comment(session_id, BASE, "y" * 4001)

    def test_closed_store_raises_typed_error(
        self, db_path: Path, session_id: str
    ) -> None:
        store = NavStore(db_path)
        store.close()
        store.close()  # harmless
        with pytest.raises(AnalysisError):
            store.bookmarks(session_id)

    def test_bad_db_paths_raise(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError):
            NavStore("")
        with pytest.raises(AnalysisError):
            NavStore(123)  # type: ignore[arg-type]
        with pytest.raises(AnalysisError):
            NavStore(tmp_path)  # a directory

    def test_records_are_frozen(self) -> None:
        import dataclasses

        bookmark = NavBookmark(id="abc", address=1, name="n")
        comment = NavComment(id="abc", address=1, text="t")
        cursor = NavCursor(address=1, updated_at="now")
        goto = NavGoto(address=1, visited_at="now")
        for record in (bookmark, comment, cursor, goto):
            with pytest.raises(dataclasses.FrozenInstanceError):
                record.address = 2  # type: ignore[misc]

    def test_to_dict_is_json_safe(self, db_path: Path, session_id: str) -> None:
        with NavStore(db_path) as store:
            bookmark = store.bookmark(session_id, BASE, "entry stub")
            comment = store.comment(session_id, BASE, "note")
            cursor = store.goto(session_id, BASE + 4)
            history = store.history(session_id)
        payload = {
            "bookmark": bookmark.to_dict(),
            "comment": comment.to_dict(),
            "cursor": cursor.to_dict(),
            "history": [entry.to_dict() for entry in history],
        }
        encoded = json.dumps(payload)
        assert f"0x{BASE:x}" in encoded
        assert payload["bookmark"]["address"] == f"0x{BASE:x}"
        assert payload["cursor"]["address"] == f"0x{BASE + 4:x}"

    def test_evidence_source_is_nav_session(self) -> None:
        evidence = nav_evidence("nav.bookmark")
        assert evidence.source == "nav.session"
        assert evidence.method == "nav.bookmark"
        assert evidence.to_dict()["source"] == "nav.session"


class TestProviderProbes:
    """Typed capability reports; Hopper is unavailable on this Windows box."""

    def test_hopper_is_unavailable_on_this_machine(self) -> None:
        capability = nav_providers.probe_hopper()
        assert isinstance(capability, nav_providers.TypedProviderCapability)
        assert capability.name == "hopper"
        if sys.platform != "darwin":
            assert capability.available is False
            assert "macOS" in capability.reason
        assert json.dumps(capability.to_dict())

    def test_hopper_on_darwin_without_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nav_providers.sys, "platform", "darwin")
        monkeypatch.setattr(nav_providers.glob, "glob", lambda pattern: [])
        capability = nav_providers.probe_hopper()
        assert capability.available is False
        assert "/Applications" in capability.reason

    def test_hopper_on_darwin_with_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nav_providers.sys, "platform", "darwin")
        monkeypatch.setattr(
            nav_providers.glob, "glob", lambda pattern: ["/Applications/Hopper.app"]
        )
        capability = nav_providers.probe_hopper()
        assert capability.available is True
        assert "Hopper.app" in capability.reason

    def test_cutter_missing_and_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nav_providers.shutil, "which", lambda name: None)
        assert nav_providers.probe_cutter().available is False
        monkeypatch.setattr(
            nav_providers.shutil, "which", lambda name: "C:/tools/cutter.exe"
        )
        present = nav_providers.probe_cutter()
        assert present.available is True
        assert "cutter.exe" in present.reason

    def test_ghidra_via_install_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = (
            "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        )
        install = tmp_path / "ghidra"
        install.mkdir()
        (install / script).write_bytes(b"rem headless")
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
        monkeypatch.setattr(nav_providers.shutil, "which", lambda name: None)
        capability = nav_providers.probe_ghidra()
        assert capability.available is True
        assert "GHIDRA_INSTALL_DIR" in capability.reason

    def test_ghidra_via_path_when_env_dir_is_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))  # no script inside
        monkeypatch.setattr(
            nav_providers.shutil, "which", lambda name: "gh:/analyzeHeadless"
        )
        capability = nav_providers.probe_ghidra()
        assert capability.available is True
        assert "PATH" in capability.reason

    def test_ghidra_unavailable_reports_the_env_gap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
        monkeypatch.setattr(nav_providers.shutil, "which", lambda name: None)
        capability = nav_providers.probe_ghidra()
        assert capability.available is False
        assert "GHIDRA_INSTALL_DIR" in capability.reason

    def test_ghidra_unavailable_when_nothing_is_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        monkeypatch.setattr(nav_providers.shutil, "which", lambda name: None)
        assert nav_providers.probe_ghidra().available is False

    def test_report_never_crashes_and_lists_every_provider(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode() -> nav_providers.TypedProviderCapability:
            raise RuntimeError("hostile environment")

        monkeypatch.setattr(nav_providers, "probe_hopper", explode)
        report = nav_providers.providers_report()
        assert [entry.name for entry in report] == ["hopper", "cutter", "ghidra"]
        assert report[0].available is False
        assert "probe failed" in report[0].reason
        assert json.dumps([entry.to_dict() for entry in report])


class TestCli:
    """The ``codevanta nav`` sub-app, exercised through CliRunner."""

    def _invoke(self, *args: str, db: Path):
        return runner.invoke(nav_app, [*args, "--db", str(db)])

    def test_mark_goto_cursor_roundtrip(self, db_path: Path, session_id: str) -> None:
        marked = self._invoke("mark", session_id, "0x401000", "entry stub", db=db_path)
        assert marked.exit_code == 0, marked.output
        assert "bookmark saved:" in marked.output
        assert "entry stub" in marked.output
        assert "evidence: nav.session via nav.bookmark" in marked.output

        moved = self._invoke("goto", session_id, "0x401008", db=db_path)
        assert moved.exit_code == 0, moved.output
        assert "goto: 0x401008" in moved.output

        cursor = self._invoke("cursor", session_id, db=db_path)
        assert cursor.exit_code == 0, cursor.output
        assert "cursor: 0x401008" in cursor.output

        history = self._invoke("history", session_id, db=db_path)
        assert history.exit_code == 0, history.output
        assert "Goto history (1)" in history.output
        assert "0x401008" in history.output

    def test_comment_roundtrip_and_listing(
        self, db_path: Path, session_id: str
    ) -> None:
        noted = self._invoke(
            "comment", session_id, "0x401000", "string table starts here", db=db_path
        )
        assert noted.exit_code == 0, noted.output
        assert "comment saved:" in noted.output
        assert "evidence: nav.session via nav.comment" in noted.output

        table = self._invoke("comments", session_id, db=db_path)
        assert table.exit_code == 0, table.output
        assert "string table starts here" in table.output

        payload = _payload(
            self._invoke("comments", session_id, "--json", db=db_path)
        )
        assert payload["count"] == 1
        assert payload["comments"][0]["text"] == "string table starts here"
        assert payload["evidence"]["source"] == "nav.session"

    def test_bookmarks_json_and_table(self, db_path: Path, session_id: str) -> None:
        self._invoke("mark", session_id, "0x401000", "entry", db=db_path)
        self._invoke("mark", session_id, "0x401010", db=db_path)
        payload = _payload(
            self._invoke("bookmarks", session_id, "--json", db=db_path)
        )
        assert payload["count"] == 2
        assert payload["bookmarks"][0]["name"] == "0x401010"  # newest first
        assert payload["evidence"]["source"] == "nav.session"

        table = self._invoke("bookmarks", session_id, db=db_path)
        assert table.exit_code == 0, table.output
        assert "entry" in table.output
        assert "evidence: nav.session via nav.bookmarks" in table.output

    def test_cursor_before_any_goto(self, db_path: Path, session_id: str) -> None:
        cursor = self._invoke("cursor", session_id, db=db_path)
        assert cursor.exit_code == 0, cursor.output
        assert "no cursor set" in cursor.output

    def test_empty_lists_say_so(self, db_path: Path, session_id: str) -> None:
        assert "no bookmarks" in self._invoke("bookmarks", session_id, db=db_path).output
        assert "no comments" in self._invoke("comments", session_id, db=db_path).output
        assert "no goto history" in self._invoke("history", session_id, db=db_path).output

    def test_unknown_session_exits_two_with_hint(
        self, db_path: Path
    ) -> None:
        result = self._invoke("bookmarks", "ghost-session", db=db_path)
        assert result.exit_code == 2
        flattened = " ".join(result.output.split())
        assert "unknown session ghost-session" in flattened
        assert "codevanta session save" in flattened

    def test_bad_address_exits_two(self, db_path: Path, session_id: str) -> None:
        result = self._invoke("mark", session_id, "not-an-address", db=db_path)
        assert result.exit_code == 2
        assert "invalid address" in result.output
        negative = self._invoke("goto", session_id, "-5", db=db_path)
        assert negative.exit_code == 2

    def test_providers_json_and_table(self) -> None:
        payload = _payload(runner.invoke(nav_app, ["providers", "--json"]))
        assert payload["count"] == 3
        assert payload["evidence"]["source"] == "nav.providers"
        assert {entry["name"] for entry in payload["providers"]} == {
            "hopper",
            "cutter",
            "ghidra",
        }
        table = runner.invoke(nav_app, ["providers"])
        assert table.exit_code == 0, table.output
        assert "GUI providers (3)" in table.output
        assert "evidence: nav.providers via nav.providers" in table.output

    def test_registered_in_main_app_as_nav(self) -> None:
        from codevanta.cli.main import app as main_app

        result = runner.invoke(main_app, ["nav", "providers", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["count"] == 3


class TestMcpTools:
    """``codevanta_nav`` and ``codevanta_nav_providers`` through tools.py."""

    def test_tools_module_registers_both_tools(self) -> None:
        from codevanta.mcp_server import tools

        # tools.py re-exports the ext_nav functions: that one import line is
        # the whole MCP registration of the lane.
        assert tools.codevanta_nav is ext_nav.codevanta_nav
        assert tools.codevanta_nav_providers is ext_nav.codevanta_nav_providers
        assert ext_nav.NAV_ACTIONS == (
            "mark",
            "comment",
            "goto",
            "cursor",
            "bookmarks",
            "comments",
            "history",
        )

    def test_mark_and_cursor_actions(self, db_path: Path, session_id: str) -> None:
        marked = ext_nav.codevanta_nav(
            "mark", session=session_id, address=BASE, name="entry stub", db=str(db_path)
        )
        assert marked["action"] == "mark"
        assert marked["bookmark"] == {"id": marked["bookmark"]["id"], "address": f"0x{BASE:x}", "name": "entry stub"}
        assert marked["evidence"]["source"] == "nav.session"

        moved = ext_nav.codevanta_nav(
            "goto", session=session_id, address="0x401010", db=str(db_path)
        )
        assert moved["cursor"]["address"] == "0x401010"

        cursor = ext_nav.codevanta_nav("cursor", session=session_id, db=str(db_path))
        assert cursor["cursor"]["address"] == "0x401010"
        assert cursor["evidence"]["method"] == "nav.cursor"

    def test_comment_action_and_listing(self, db_path: Path, session_id: str) -> None:
        noted = ext_nav.codevanta_nav(
            "comment", session=session_id, address=BASE, text="first look", db=str(db_path)
        )
        assert noted["comment"]["text"] == "first look"
        listed = ext_nav.codevanta_nav("comments", session=session_id, db=str(db_path))
        assert listed["count"] == 1
        assert listed["comments"][0]["id"] == noted["comment"]["id"]
        assert listed["evidence"]["source"] == "nav.session"

    def test_bookmarks_and_history_actions(self, db_path: Path, session_id: str) -> None:
        ext_nav.codevanta_nav("mark", session=session_id, address=BASE, db=str(db_path))
        bookmarks = ext_nav.codevanta_nav("bookmarks", session=session_id, db=str(db_path))
        assert bookmarks["count"] == 1
        assert bookmarks["bookmarks"][0]["name"] == f"0x{BASE:x}"  # default label
        history = ext_nav.codevanta_nav("history", session=session_id, db=str(db_path))
        assert history["count"] == 0
        assert history["history"] == []

    def test_hex_string_address_is_accepted(self, db_path: Path, session_id: str) -> None:
        payload = ext_nav.codevanta_nav(
            "goto", session=session_id, address="4198408", db=str(db_path)
        )
        assert payload["cursor"]["address"] == "0x401008"

    def test_unknown_action_raises_typed_error(self, db_path: Path) -> None:
        with pytest.raises(AnalysisError) as excinfo:
            ext_nav.codevanta_nav("teleport", session="s", db=str(db_path))
        assert "unknown action" in str(excinfo.value)

    def test_missing_session_argument_raises(self, db_path: Path) -> None:
        with pytest.raises(AnalysisError):
            ext_nav.codevanta_nav("cursor", db=str(db_path))

    def test_missing_db_argument_raises(self) -> None:
        with pytest.raises(AnalysisError):
            ext_nav.codevanta_nav("cursor", session="whatever")

    def test_missing_address_for_mark_raises(self, db_path: Path, session_id: str) -> None:
        with pytest.raises(AnalysisError) as excinfo:
            ext_nav.codevanta_nav("mark", session=session_id, db=str(db_path))
        assert "requires an integer address" in str(excinfo.value)

    def test_bad_address_text_raises(self, db_path: Path, session_id: str) -> None:
        with pytest.raises(AnalysisError):
            ext_nav.codevanta_nav(
                "goto", session=session_id, address="nonsense", db=str(db_path)
            )

    def test_unknown_session_raises_with_hint(self, db_path: Path) -> None:
        with pytest.raises(AnalysisError) as excinfo:
            ext_nav.codevanta_nav(
                "mark", session="ghost", address=1, name="x", db=str(db_path)
            )
        assert "codevanta session save" in str(excinfo.value)

    def test_comment_without_text_raises(self, db_path: Path, session_id: str) -> None:
        with pytest.raises(AnalysisError):
            ext_nav.codevanta_nav(
                "comment", session=session_id, address=BASE, db=str(db_path)
            )

    def test_providers_tool(self) -> None:
        payload = ext_nav.codevanta_nav_providers()
        assert payload["count"] == 3
        assert payload["providers"][0]["name"] == "hopper"
        assert all("reason" in entry for entry in payload["providers"])
        assert payload["evidence"]["source"] == "nav.providers"

    def test_blank_db_is_rejected(self) -> None:
        with pytest.raises(AnalysisError):
            ext_nav._resolve_db(None)
        with pytest.raises(AnalysisError):
            ext_nav._resolve_db("   ")

    def test_non_integer_address_type_is_rejected(
        self, db_path: Path, session_id: str
    ) -> None:
        with pytest.raises(AnalysisError) as excinfo:
            ext_nav.codevanta_nav(
                "mark", session=session_id, address=1.5, db=str(db_path)
            )
        assert "must be an integer, not float" in str(excinfo.value)


class TestDefensivePaths:
    """Crash and race guards that only fire when SQLite or the host misbehaves."""

    class _ConnProxy:
        """Swap-in connection wrapper used to force SQLite-level failures."""

        def __init__(self, real: sqlite3.Connection, guard) -> None:
            self._real = real
            self._guard = guard

        def execute(self, sql: str, *args: object):
            return self._guard(sql, *args)

        def __getattr__(self, name: str):  # noqa: D105 - delegate the rest
            return getattr(self._real, name)

    class _EmptyCursor:
        @staticmethod
        def fetchone() -> None:
            return None

        @staticmethod
        def fetchall() -> list:
            return []

    class _RowCursor:
        def __init__(self, row: dict) -> None:
            self._row = row

        def fetchone(self) -> dict:
            return self._row

    def test_schema_failure_is_typed(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BrokenConnection:
            row_factory = None

            def executescript(self, script: str) -> None:
                raise sqlite3.OperationalError("disk I/O error")

            def close(self) -> None:
                pass

        monkeypatch.setattr(nav_module.sqlite3, "connect", lambda *a, **k: BrokenConnection())
        with pytest.raises(AnalysisError) as excinfo:
            NavStore(db_path)
        assert "cannot initialize navigation tables" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("operation", "sql_marker", "message"),
        [
            ("bookmark", "INSERT INTO nav_bookmarks", "cannot bookmark"),
            ("comment", "INSERT INTO nav_comments", "cannot comment"),
            ("goto", "INSERT INTO nav_cursor", "cannot move cursor"),
            ("delete_bookmark", "DELETE FROM nav_bookmarks", "cannot delete bookmark"),
            ("delete_comment", "DELETE FROM nav_comments", "cannot delete comment"),
        ],
    )
    def test_write_failures_are_typed(
        self,
        db_path: Path,
        session_id: str,
        operation: str,
        sql_marker: str,
        message: str,
    ) -> None:
        def failing(sql: str, *args: object):
            if sql_marker in sql:
                raise sqlite3.OperationalError("disk I/O error")
            return real.execute(sql, *args)

        with NavStore(db_path) as store:
            real = store._conn
            store._conn = self._ConnProxy(real, failing)
            with pytest.raises(AnalysisError) as excinfo:
                if operation == "delete_bookmark":
                    store.delete_bookmark(session_id, "some-id")
                elif operation == "delete_comment":
                    store.delete_comment(session_id, "some-id")
                elif operation == "goto":
                    store.goto(session_id, BASE)
                elif operation == "comment":
                    store.comment(session_id, BASE, "note")
                else:
                    store.bookmark(session_id, BASE, "name")
        assert message in str(excinfo.value)

    def test_read_back_mismatches_are_typed(
        self, db_path: Path, session_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with NavStore(db_path) as store:
            monkeypatch.setattr(
                nav_module,
                "_row_to_bookmark",
                lambda row: NavBookmark(id="x", address=999, name="wrong"),
            )
            with pytest.raises(AnalysisError) as bookmark_error:
                store.bookmark(session_id, BASE, "entry stub")
            assert "read-back mismatch" in str(bookmark_error.value)
            monkeypatch.setattr(
                nav_module,
                "_row_to_comment",
                lambda row: NavComment(id="x", address=999, text="wrong"),
            )
            with pytest.raises(AnalysisError) as comment_error:
                store.comment(session_id, BASE, "note")
            assert "read-back mismatch" in str(comment_error.value)
            monkeypatch.setattr(
                nav_module,
                "_row_to_cursor",
                lambda row: NavCursor(address=999, updated_at="wrong"),
            )
            with pytest.raises(AnalysisError) as cursor_error:
                store.goto(session_id, BASE)
        assert "read-back mismatch" in str(cursor_error.value)

    def test_vanished_rows_are_typed(
        self, db_path: Path, session_id: str
    ) -> None:
        def empty_reads(sql: str, *args: object):
            if (
                "FROM nav_bookmarks WHERE id" in sql
                or "FROM nav_comments" in sql
                or "FROM nav_cursor" in sql
            ):
                return self._EmptyCursor()
            return real.execute(sql, *args)

        with NavStore(db_path) as store:
            real = store._conn
            store._conn = self._ConnProxy(real, empty_reads)
            with pytest.raises(AnalysisError) as bookmark_error:
                store.bookmark(session_id, BASE, "entry stub")
            assert "vanished after write" in str(bookmark_error.value)
            with pytest.raises(AnalysisError) as comment_error:
                store.comment(session_id, BASE, "note")
            assert "vanished after write" in str(comment_error.value)
            with pytest.raises(AnalysisError) as cursor_error:
                store.goto(session_id, BASE)
        assert "vanished after write" in str(cursor_error.value)

    def test_history_head_mismatch_is_typed(
        self, db_path: Path, session_id: str
    ) -> None:
        def wrong_head(sql: str, *args: object):
            if "FROM nav_history" in sql and "ORDER BY" in sql:
                return self._RowCursor({"address": 123})
            return real.execute(sql, *args)

        with NavStore(db_path) as store:
            real = store._conn
            store._conn = self._ConnProxy(real, wrong_head)
            with pytest.raises(AnalysisError) as excinfo:
                store.goto(session_id, BASE)
        assert "did not record" in str(excinfo.value)

    def test_locked_session_table_is_typed(
        self, db_path: Path, session_id: str
    ) -> None:
        def locked(sql: str, *args: object) -> sqlite3.Cursor:
            if "FROM sessions" in sql:
                raise sqlite3.OperationalError("database is locked")
            return real.execute(sql, *args)

        with NavStore(db_path) as store:
            real = store._conn
            store._conn = self._ConnProxy(real, locked)
            with pytest.raises(AnalysisError) as excinfo:
                store.bookmarks(session_id)
        assert "cannot read session" in str(excinfo.value)

    def test_in_memory_store_rejects_unknown_sessions(self) -> None:
        with NavStore(":memory:") as store:
            with pytest.raises(AnalysisError) as excinfo:
                store.bookmarks("anything")
        assert "unknown session" in str(excinfo.value)

    def test_unwritable_parent_directory_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refusing(self: Path, *args: object, **kwargs: object) -> None:
            raise OSError("no space left on device")

        monkeypatch.setattr(Path, "mkdir", refusing)
        with pytest.raises(AnalysisError) as excinfo:
            NavStore(tmp_path / "nested" / "nav.db")
        assert "cannot create directory" in str(excinfo.value)

    def test_non_string_names_and_texts_are_typed(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            with pytest.raises(AnalysisError) as name_error:
                store.bookmark(session_id, BASE, 123)  # type: ignore[arg-type]
            assert "name must be a string" in str(name_error.value)
            with pytest.raises(AnalysisError) as text_error:
                store.comment(session_id, BASE, 456)  # type: ignore[arg-type]
            assert "text must be a string" in str(text_error.value)

    def test_delete_comment_rejects_blank_ids(
        self, db_path: Path, session_id: str
    ) -> None:
        with NavStore(db_path) as store:
            assert store.delete_comment(session_id, "   ") is False
            assert store.delete_comment("   ", "some-id") is False
