"""fs lane tests: filesystem snapshot + diff.

Every fixture is a real ``tmp_path`` tree assembled in this module -- text
and binary files, nested and empty subdirs, an optional symlink -- so the
tests stay offline and self-contained. What is asserted is the manifest
fields (entries, hashes, counts, evidence), the diff classification contract
(created/modified/deleted + verdict), the size-only fallback for oversize
files, byte-identical determinism, the typed ``AnalysisError`` for missing
roots and malformed snapshot files, the bounded-work guards (entry cap,
diff list cap), JSON safety, and the MCP tool wiring only.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from codevanta.analysis.fs_diff import (
    FsSnapshot,
    diff_snapshots,
    load_snapshot,
    snapshot_tree,
)
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

# --- 8< --- helpers: small tmp_path trees ------------------------------------


def _make_tree(root) -> dict[str, bytes]:
    """Text file + binary file + nested subdir + empty subdir."""
    contents = {
        "readme.txt": b"hello snapshot\n",
        "blob.bin": bytes(range(256)),
        "nested/deep.txt": b"buried payload",
    }
    (root / "nested").mkdir(parents=True)
    (root / "empty").mkdir()
    for rel, data in contents.items():
        (root / rel).write_bytes(data)
    return contents


def _entry_map(snapshot: FsSnapshot) -> dict:
    return {entry.path: entry for entry in snapshot.entries}


# --- 8< --- snapshot: shapes, hashes, counts ---------------------------------


def test_snapshot_captures_tree_shapes_hashes_and_counts(tmp_path) -> None:
    """Files (hashed), dirs and the empty subdir all land in the manifest."""
    contents = _make_tree(tmp_path)
    snapshot = snapshot_tree(tmp_path)
    entries = _entry_map(snapshot)
    assert set(entries) == {
        "blob.bin",
        "empty",
        "nested",
        "nested/deep.txt",
        "readme.txt",
    }
    readme = entries["readme.txt"]
    assert readme.kind == "file"
    assert readme.size == len(contents["readme.txt"])
    assert readme.sha256 == hashlib.sha256(contents["readme.txt"]).hexdigest()
    assert readme.hashed is True
    assert entries["blob.bin"].sha256 == hashlib.sha256(contents["blob.bin"]).hexdigest()
    assert entries["nested"].kind == "dir"
    assert entries["empty"].kind == "dir"
    assert snapshot.root == str(tmp_path)
    assert snapshot.file_count == 3
    assert snapshot.dir_count == 2
    assert snapshot.symlink_count == 0
    assert snapshot.hashed_count == 3
    assert snapshot.entries_truncated is False
    assert snapshot.bytes_truncated is False
    assert snapshot.warnings == ()
    manifest = snapshot.to_dict()
    assert manifest["counts"] == {"files": 3, "dirs": 2, "symlinks": 0}
    assert manifest["evidence"]["source"] == "fs.snapshot"
    assert manifest["evidence"]["method"] == "walk-sha256"
    assert manifest["evidence"]["confidence"] == "high"


def test_snapshot_is_deterministic(tmp_path) -> None:
    """Two snapshots of the same tree dump to byte-identical JSON."""
    _make_tree(tmp_path)
    first = json.dumps(snapshot_tree(tmp_path).to_dict(), sort_keys=True)
    second = json.dumps(snapshot_tree(tmp_path).to_dict(), sort_keys=True)
    assert first == second


def test_snapshot_missing_root_is_typed_error(tmp_path) -> None:
    """A missing root raises AnalysisError with the 'file not found' text."""
    with pytest.raises(AnalysisError, match="file not found"):
        snapshot_tree(tmp_path / "nope")


def test_snapshot_file_root_is_typed_error(tmp_path) -> None:
    """A plain file root raises AnalysisError (root must be a directory)."""
    target = tmp_path / "plain.txt"
    target.write_bytes(b"not a directory")
    with pytest.raises(AnalysisError, match="not a directory"):
        snapshot_tree(target)


def test_snapshot_symlink_is_recorded_never_followed(tmp_path) -> None:
    """Symlinks become entries with clipped target text; content untouched."""
    target = tmp_path / "real.txt"
    target.write_bytes(b"pointed at")
    link = tmp_path / "alias.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")
    snapshot = snapshot_tree(tmp_path)
    entries = _entry_map(snapshot)
    assert entries["alias.txt"].kind == "symlink"
    # Windows readlink may surface the \\?\-prefixed form: assert the tail.
    assert entries["alias.txt"].target.endswith("real.txt")
    assert entries["alias.txt"].sha256 is None
    assert snapshot.symlink_count == 1


# --- 8< --- diff: created / modified / deleted / identical --------------------


def test_diff_detects_exactly_one_created_modified_deleted(tmp_path) -> None:
    """Same-size rewrite is caught by the hash; add + delete round it out."""
    _make_tree(tmp_path)
    before = snapshot_tree(tmp_path)
    (tmp_path / "readme.txt").write_bytes(b"jello snapshot\n")  # same size!
    (tmp_path / "added.log").write_bytes(b"new file")
    (tmp_path / "blob.bin").unlink()
    after = snapshot_tree(tmp_path)
    diff = diff_snapshots(before, after)
    assert diff.verdict == "changed"
    assert diff.created_total == 1
    assert [entry.path for entry in diff.created] == ["added.log"]
    assert diff.deleted_total == 1
    assert [entry.path for entry in diff.deleted] == ["blob.bin"]
    assert diff.modified_total == 1
    record = diff.modified[0]
    assert record.path == "readme.txt"
    assert record.size_only is False  # hash caught the same-size rewrite
    assert record.before_sha256 != record.after_sha256
    assert record.before_size == record.after_size
    assert diff.unchanged_count == 3  # nested/deep.txt + the two dirs
    manifest = diff.to_dict()
    assert manifest["evidence"]["source"] == "fs.diff"
    assert manifest["evidence"]["method"] == "hash-set-compare"


def test_diff_of_identical_snapshots_is_identical(tmp_path) -> None:
    """Same tree twice: verdict identical, all lists empty."""
    _make_tree(tmp_path)
    before = snapshot_tree(tmp_path)
    after = snapshot_tree(tmp_path)
    diff = diff_snapshots(before, after)
    assert diff.verdict == "identical"
    assert diff.created == ()
    assert diff.deleted == ()
    assert diff.modified == ()
    assert diff.unchanged_count == 5


def test_diff_accepts_json_manifest_dicts(tmp_path) -> None:
    """The diff coerces plain JSON dicts through from_dict."""
    _make_tree(tmp_path)
    before = snapshot_tree(tmp_path).to_dict()
    (tmp_path / "late.txt").write_bytes(b"latecomer")
    after = snapshot_tree(tmp_path).to_dict()
    diff = diff_snapshots(before, after)
    assert diff.verdict == "changed"
    assert diff.created_total == 1


def test_oversize_file_is_size_only_and_size_compare_detects_change(tmp_path) -> None:
    """Files above max_hash_bytes are hashed=false; size compare finds edits."""
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 64)
    before = snapshot_tree(tmp_path, max_hash_bytes=16)
    entry = _entry_map(before)["big.bin"]
    assert entry.hashed is False
    assert entry.sha256 is None
    assert entry.size == 64
    target.write_bytes(b"A" * 96)  # different content, different size
    after = snapshot_tree(tmp_path, max_hash_bytes=16)
    diff = diff_snapshots(before, after)
    assert diff.verdict == "changed"
    assert diff.modified_total == 1
    record = diff.modified[0]
    assert record.path == "big.bin"
    assert record.size_only is True
    assert record.before_size == 64
    assert record.after_size == 96


# --- 8< --- bounds, errors, JSON safety ---------------------------------------


def test_entry_cap_sets_truncated_flag_and_warning(tmp_path) -> None:
    """More files than the (small) cap -> truncated flag plus warning."""
    for index in range(6):
        (tmp_path / f"file{index}.txt").write_bytes(b"x")
    snapshot = snapshot_tree(tmp_path, max_entries=4)
    assert snapshot.entries_truncated is True
    assert any("entry cap" in warning for warning in snapshot.warnings)
    assert len(snapshot.entries) == 4
    assert snapshot.file_count == 4


def test_diff_list_cap_truncates_honestly(tmp_path) -> None:
    """Created lists beyond max_lists are cut, counts stay true."""
    before = snapshot_tree(tmp_path)
    for index in range(4):
        (tmp_path / f"n{index}.txt").write_bytes(b"new")
    after = snapshot_tree(tmp_path)
    diff = diff_snapshots(before, after, max_lists=2)
    assert diff.created_total == 4
    assert len(diff.created) == 2
    assert diff.created_truncated is True


def test_load_snapshot_typed_errors(tmp_path) -> None:
    """Missing files, garbage JSON and manifests without entries all raise."""
    with pytest.raises(AnalysisError, match="file not found"):
        load_snapshot(str(tmp_path / "missing.json"))
    garbage = tmp_path / "garbage.json"
    garbage.write_bytes(b"{not json at all")
    with pytest.raises(AnalysisError, match="not valid JSON"):
        load_snapshot(str(garbage))
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(json.dumps({"root": "x"}).encode("utf-8"))
    with pytest.raises(AnalysisError, match="malformed snapshot"):
        load_snapshot(str(malformed))


def test_diff_with_malformed_dict_is_typed_error(tmp_path) -> None:
    """A dict without an 'entries' key is a malformed snapshot."""
    snapshot = snapshot_tree(tmp_path)
    with pytest.raises(AnalysisError, match="malformed snapshot"):
        diff_snapshots(snapshot.to_dict(), {"root": "x"})


def test_snapshot_and_diff_are_json_safe(tmp_path) -> None:
    """Both manifests survive json.dumps round trips untouched."""
    _make_tree(tmp_path)
    before = snapshot_tree(tmp_path)
    (tmp_path / "created.txt").write_bytes(b"c")
    after = snapshot_tree(tmp_path)
    dump_before = json.dumps(before.to_dict())
    dump_after = json.dumps(after.to_dict())
    dump_diff = json.dumps(diff_snapshots(before, after).to_dict())
    assert "readme.txt" in dump_before
    assert json.loads(dump_after)["counts"]["files"] == 4
    assert json.loads(dump_diff)["verdict"] == "changed"


# --- 8< --- MCP tool layer -----------------------------------------------------


def test_mcp_fs_snapshot_writes_manifest(tmp_path) -> None:
    """The snapshot tool writes fs_snapshot.json and reports its hash."""
    _make_tree(tmp_path / "tree")
    out_dir = tmp_path / "out"
    payload = tools.codevanta_fs_snapshot(str(tmp_path / "tree"), str(out_dir))
    written = payload["written"]
    artifact = out_dir / "fs_snapshot.json"
    assert written["path"] == str(artifact)
    raw = artifact.read_bytes()
    assert written["bytes"] == len(raw)
    assert written["sha256"] == hashlib.sha256(raw).hexdigest()
    reloaded = json.loads(raw)
    assert reloaded["counts"]["files"] == 3
    assert reloaded["evidence"]["method"] == "walk-sha256"
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_fs_snapshot(str(tmp_path / "gone"), str(out_dir))


def test_mcp_fs_diff_reads_snapshot_files(tmp_path) -> None:
    """The diff tool loads both snapshot files and returns the diff dict."""
    _make_tree(tmp_path / "before_tree")
    before_json = tmp_path / "b" / "fs_snapshot.json"
    tools.codevanta_fs_snapshot(str(tmp_path / "before_tree"), str(tmp_path / "b"))
    (tmp_path / "before_tree" / "readme.txt").write_bytes(b"rewritten")
    (tmp_path / "before_tree" / "extra.txt").write_bytes(b"extra")
    (tmp_path / "before_tree" / "blob.bin").unlink()
    after_json = tmp_path / "a" / "fs_snapshot.json"
    tools.codevanta_fs_snapshot(str(tmp_path / "before_tree"), str(tmp_path / "a"))
    payload = tools.codevanta_fs_diff(str(before_json), str(after_json))
    assert payload["verdict"] == "changed"
    assert payload["counts"]["created"] == 1
    assert payload["counts"]["modified"] == 1
    assert payload["counts"]["deleted"] == 1
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_fs_diff(str(tmp_path / "nope.json"), str(before_json))
    broken = tmp_path / "broken.json"
    broken.write_bytes(b"[[[")
    with pytest.raises(AnalysisError, match="not valid JSON"):
        tools.codevanta_fs_diff(str(broken), str(before_json))


def test_server_registers_both_fs_tools() -> None:
    """Both lane tools are registered on the built MCP server."""
    import asyncio

    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert "codevanta_fs_snapshot" in names
    assert "codevanta_fs_diff" in names
