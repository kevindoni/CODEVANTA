"""webfw lane tests: source-map tracer and recursive unpack manifest.

Every fixture is assembled in this module -- source maps with a hand-written
base64-VLQ encoder, archives built through :mod:`zipfile` / :mod:`tarfile` /
:mod:`gzip` in memory, and a cpio newc image packed byte by byte -- so the
tests stay offline and self-contained. What is asserted is the decoded
fields, the trace hit/miss contract, the typed ``AnalysisError`` for
malformed maps and unknown archive formats, the bounded-work guards (depth,
segment cap, bomb ratio, byte budget), and the MCP tool wiring only.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from codevanta.analysis.sourcemap import MAX_SEGMENTS, decode_source_map, trace_position
from codevanta.analysis.unpack import build_unpack_manifest, detect_format
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

# --- 8< --- helpers: hand-rolled base64-VLQ encoding for source maps ---------


_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _vlq(value: int) -> str:
    """Encode one signed integer as base64 VLQ (the inverse of the parser)."""
    encoded = ((-value) << 1) | 1 if value < 0 else value << 1
    chars: list[str] = []
    while True:
        digit = encoded & 0x1F
        encoded >>= 5
        if encoded:
            digit |= 0x20
        chars.append(_B64_ALPHABET[digit])
        if not encoded:
            return "".join(chars)


def _segment(*fields: int) -> str:
    """Encode one mapping segment from its field deltas."""
    return "".join(_vlq(field) for field in fields)


def _map_bytes(
    mappings: str,
    *,
    sources: list[str] | None = None,
    names: list[str] | None = None,
    source_root: str | None = None,
    version: int = 3,
) -> bytes:
    """Build a source map JSON document (fixture shorthand)."""
    payload: dict[str, object] = {
        "version": version,
        "sources": sources if sources is not None else ["src/app.ts", "vendor/lib.js"],
        "names": names if names is not None else ["emitFoo"],
        "mappings": mappings,
    }
    if source_root is not None:
        payload["sourceRoot"] = source_root
    return json.dumps(payload).encode("utf-8")


#: line 0: col 0 -> src 0 line 0 col 0; col 4 -> src 0 line 1 col 0
#: line 1: col 1 -> src 1 line 1 col 0; col 6 -> src 1 line 1 col 0 name 0
FIXTURE_MAPPINGS = (
    ",".join([_segment(0, 0, 0, 0), _segment(4, 0, 1, 0)])
    + ";"
    + ",".join([_segment(1, 1, 0, 0), _segment(5, 0, 0, 0, 0)])
)


# --- 8< --- sourcemap: decode ------------------------------------------------


def test_decode_round_trips_hand_encoded_vlq() -> None:
    """The hand-encoded segments decode to the exact expected mapping table."""
    summary = decode_source_map(_map_bytes(FIXTURE_MAPPINGS))
    assert summary.version == 3
    assert summary.sources == ("src/app.ts", "vendor/lib.js")
    assert summary.source_count == 2
    assert summary.names == ("emitFoo",)
    assert summary.name_count == 1
    assert summary.segment_count == 4
    assert summary.generated_line_count == 2
    assert summary.segments_truncated is False
    assert summary.sources_truncated is False
    assert summary.names_truncated is False
    assert summary.warnings == ()
    assert summary.evidence.source == "web.sourcemap"
    payload = summary.to_dict()
    assert payload["segment_count"] == 4
    assert payload["truncated"] == {
        "segments": False,
        "sources": False,
        "names": False,
    }


def test_decode_segment_cap_is_a_truncation_flag_not_an_error() -> None:
    """More segments than the cap decode up to the cap with honest flags."""
    mappings = ",".join(_segment(1) for _ in range(MAX_SEGMENTS + 25))
    summary = decode_source_map(_map_bytes(mappings))
    assert summary.segment_count == MAX_SEGMENTS
    assert summary.segments_truncated is True
    assert any("bounded at 20000" in warning for warning in summary.warnings)


def test_decode_rejects_bad_json_version_and_shapes() -> None:
    """Malformed maps raise typed errors naming the exact problem."""
    with pytest.raises(AnalysisError, match="not valid JSON"):
        decode_source_map(b"{not json at all")
    with pytest.raises(AnalysisError, match="version 2"):
        decode_source_map(_map_bytes(FIXTURE_MAPPINGS, version=2))
    with pytest.raises(AnalysisError, match="version"):
        decode_source_map(json.dumps({"sources": [], "mappings": ""}).encode())
    with pytest.raises(AnalysisError, match="'sources' must be a list"):
        decode_source_map(
            json.dumps({"version": 3, "sources": "nope", "mappings": ""}).encode()
        )


def test_decode_rejects_invalid_vlq_and_bad_indexes() -> None:
    """Invalid VLQ characters, bad field counts and indexes are typed errors."""
    with pytest.raises(AnalysisError, match="invalid base64 VLQ character"):
        decode_source_map(_map_bytes("AA*A"))
    with pytest.raises(AnalysisError, match="ends mid-value"):
        decode_source_map(_map_bytes("Ag"))
    with pytest.raises(AnalysisError, match="too many continuation digits"):
        decode_source_map(_map_bytes("g" * 9))
    with pytest.raises(AnalysisError, match="expected 1, 4 or 5"):
        decode_source_map(_map_bytes("AA"))
    with pytest.raises(AnalysisError, match="has 1 sources"):
        decode_source_map(_map_bytes(_segment(0, 1, 0, 0), sources=["src/app.ts"]))
    with pytest.raises(AnalysisError, match="has 0 sources"):
        decode_source_map(_map_bytes(_segment(0, 0, 0, 0), sources=[]))
    with pytest.raises(AnalysisError, match="name index 3"):
        decode_source_map(_map_bytes(_segment(0, 0, 0, 0, 3), names=["one"]))
    with pytest.raises(AnalysisError, match="generated column negative"):
        decode_source_map(_map_bytes(_segment(-1)))


# --- 8< --- sourcemap: trace -------------------------------------------------


def test_trace_hits_nearest_segment_at_or_before_column() -> None:
    """Exact and mid-span columns land on the segment that starts before them."""
    hit = trace_position(_map_bytes(FIXTURE_MAPPINGS), 0, 4)
    assert hit["hit"] is True
    assert hit["source"] == "src/app.ts"
    assert hit["source_index"] == 0
    assert hit["source_line"] == 1
    assert hit["source_column"] == 0
    assert hit["name"] is None
    assert hit["segment"]["generated_column"] == 4
    assert hit["evidence"]["confidence"] == "high"
    mid_span = trace_position(_map_bytes(FIXTURE_MAPPINGS), 0, 7)
    assert mid_span["hit"] is True
    assert mid_span["segment"]["generated_column"] == 4
    first = trace_position(_map_bytes(FIXTURE_MAPPINGS), 0, 0)
    assert first["source_line"] == 0


def test_trace_resolves_name_and_source_root() -> None:
    """A five-field segment carries its name; sourceRoot joins the source."""
    hit = trace_position(_map_bytes(FIXTURE_MAPPINGS, source_root="app"), 1, 6)
    assert hit["hit"] is True
    assert hit["source"] == "app/vendor/lib.js"
    assert hit["name"] == "emitFoo"
    assert hit["source_index"] == 1
    assert hit["source_line"] == 1


def test_trace_misses_are_normal_results() -> None:
    """Columns before the first mapping and lines beyond the map miss honestly."""
    before = trace_position(_map_bytes(FIXTURE_MAPPINGS), 1, 0)
    assert before["hit"] is False
    assert "before the first mapping" in before["reason"]
    assert before["evidence"]["detail"] == before["reason"]
    beyond = trace_position(_map_bytes(FIXTURE_MAPPINGS), 9, 0)
    assert beyond["hit"] is False
    assert "beyond the map" in beyond["reason"]
    gap = trace_position(
        _map_bytes(_segment(0, 0, 0, 0) + ";;" + _segment(0, 0, 0, 0)), 1, 0
    )
    assert gap["hit"] is False
    assert "no mappings" in gap["reason"]


def test_trace_rejects_bad_arguments() -> None:
    """Non-integer or negative positions are typed errors, never misses."""
    data = _map_bytes(FIXTURE_MAPPINGS)
    with pytest.raises(AnalysisError, match="line must be an integer"):
        trace_position(data, "0", 0)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="column must be non-negative"):
        trace_position(data, 0, -1)


# --- 8< --- unpack: fixtures -------------------------------------------------


def _zip_bytes(*entries: tuple[str, bytes]) -> bytes:
    """Build a deflate zip archive in memory (fixture shorthand)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in entries:
            archive.writestr(name, blob)
    return buffer.getvalue()


def _tar_gz_bytes(*entries: tuple[str, bytes]) -> bytes:
    """Build a gzip-compressed tar archive in memory (fixture shorthand)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, blob in entries:
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            archive.addfile(info, io.BytesIO(blob))
    return buffer.getvalue()


def _cpio_newc_bytes() -> bytes:
    """Hand-pack a tiny newc cpio: one file, one directory and the trailer."""

    def header(ino: int, mode: int, filesize: int, namesize: int) -> bytes:
        fields = (ino, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0)
        return b"070701" + b"".join(f"{field:08X}".encode("ascii") for field in fields)

    image = bytearray()
    name = b"hello.txt\x00"
    image += header(1, 0o100644, 5, len(name))
    image += name
    image += b"world"
    image += b"\x00" * ((-(110 + len(name) + 5)) % 4)
    name = b"d\x00"
    image += header(2, 0o040755, 0, len(name))
    image += name
    image += b"\x00" * ((-(110 + len(name))) % 4)
    name = b"TRAILER!!!\x00"
    image += header(0, 0, 0, len(name))
    image += name
    return bytes(image)


def _iter_nodes(node):
    """Yield ``node`` and every descendant (manifest tree helper)."""
    yield node
    for child in node.children or ():
        yield from _iter_nodes(child)


def _find(manifest, path: str):
    """Return the node at ``path`` or fail the test naming the miss."""
    for node in _iter_nodes(manifest.root):
        if node.path == path:
            return node
    raise AssertionError(f"no node at {path!r} in the manifest tree")


# --- 8< --- unpack: zip, tar.gz, gzip, cpio ----------------------------------


def test_detect_format_and_unknown_input() -> None:
    """Magic detection gates every walker; unknown bytes are a typed error."""
    assert detect_format(_zip_bytes()) == "zip"
    assert detect_format(gzip.compress(b"x")) == "gzip"
    assert detect_format(_cpio_newc_bytes()) == "cpio-newc"
    assert detect_format(b"just some text") is None
    with pytest.raises(AnalysisError, match="known archive format"):
        build_unpack_manifest(b"just some text")


def test_zip_manifest_lists_entries_and_hashes_small_leaves() -> None:
    """A tiny zip lists dirs/files with sizes and sha256 for small leaves."""
    data = _zip_bytes(
        ("docs/", b""), ("docs/readme.txt", b"hello"), ("app.js", b"export default 1;")
    )
    manifest = build_unpack_manifest(data)
    assert manifest.root_format == "zip"
    assert manifest.root.kind == "archive"
    assert manifest.entry_count == 3
    assert manifest.truncated is False
    assert manifest.warnings == ()
    assert manifest.total_bytes == 5 + len(b"export default 1;")
    readme = _find(manifest, "archive/docs/readme.txt")
    assert readme.kind == "file"
    assert readme.size == 5
    assert readme.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert _find(manifest, "archive/docs").kind == "dir"
    assert _find(manifest, "archive/app.js").kind == "file"
    assert manifest.evidence.source == "web.unpack"


def test_tar_gz_manifest_descends_into_the_inner_tar() -> None:
    """A gzipped tar unpacks as stream -> tar -> entries with hashes."""
    data = _tar_gz_bytes(("a.txt", b"alpha"), ("lib/b.bin", b"\x7fELF-fake"))
    manifest = build_unpack_manifest(data)
    assert manifest.root_format == "gzip"
    assert manifest.root.kind == "stream"
    assert manifest.root.format == "gzip"
    inner_tar = manifest.root.children[0]
    assert inner_tar.kind == "archive"
    assert inner_tar.format == "tar"
    assert manifest.entry_count == 2
    leaf = _find(manifest, "archive!gunzip/a.txt")
    assert leaf.kind == "file"
    assert leaf.size == 5
    assert leaf.sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert _find(manifest, "archive!gunzip/lib/b.bin").size == 9


def test_gzip_single_stream_expands_to_a_hashed_leaf() -> None:
    """A plain gzip payload is a stream node whose child is the expansion."""
    payload = b"hello world"
    compressed = gzip.compress(payload)
    manifest = build_unpack_manifest(compressed)
    assert manifest.root_format == "gzip"
    assert manifest.root.kind == "stream"
    assert manifest.root.size == len(compressed)
    leaf = _find(manifest, "archive!gunzip")
    assert leaf.kind == "file"
    assert leaf.size == 11
    assert leaf.sha256 == hashlib.sha256(payload).hexdigest()


def test_cpio_newc_headers_are_detected_and_listed() -> None:
    """A hand-packed newc cpio lists entries from headers only (no content)."""
    manifest = build_unpack_manifest(_cpio_newc_bytes())
    assert manifest.root_format == "cpio-newc"
    assert manifest.root.format == "cpio-newc"
    assert manifest.entry_count == 2
    hello = _find(manifest, "archive/hello.txt")
    assert hello.kind == "file"
    assert hello.size == 5
    assert hello.sha256 is None  # headers only: no content is read for cpio
    assert _find(manifest, "archive/d").kind == "dir"
    assert manifest.truncated is False


# --- 8< --- unpack: bounded-work guards --------------------------------------


def test_nested_zip_depth_guard_stops_at_max_depth() -> None:
    """Zip-in-zip-in-... descends to depth 4 and marks deeper levels truncated."""
    blob = _zip_bytes(("core.txt", b"core"))
    for layer in range(5):
        blob = _zip_bytes((f"layer{layer}.zip", blob))
    manifest = build_unpack_manifest(blob)
    assert manifest.root_format == "zip"
    assert manifest.truncated is True
    assert manifest.depth_reached == 5
    assert any("descent bounded at depth 4" in w for w in manifest.warnings)
    deepest = _find(
        manifest, "archive/layer4.zip/layer3.zip/layer2.zip/layer1.zip/layer0.zip"
    )
    assert deepest.kind == "archive"
    assert deepest.truncated is True
    assert not deepest.children  # nothing below depth 4 was unpacked
    reachable = _find(manifest, "archive/layer4.zip/layer3.zip/layer2.zip/layer1.zip")
    assert reachable.format == "zip"  # depth 4 itself was fully unpacked


def test_zip_bomb_suspect_is_flagged_and_never_read() -> None:
    """A high declared/compressed ratio is reported as a bomb, content skipped."""
    blob = _zip_bytes(("bomb.bin", b"\x00" * (8 * 1024 * 1024)))
    manifest = build_unpack_manifest(blob)
    bomb = _find(manifest, "archive/bomb.bin")
    assert bomb.size == 8 * 1024 * 1024
    assert bomb.truncated is True
    assert bomb.sha256 is None
    assert any("bomb suspect" in warning for warning in manifest.warnings)
    assert manifest.truncated is True


def test_gzip_budget_overflow_is_truncated_not_slurped() -> None:
    """A stream expanding past the 64 MiB budget stops at the budget."""
    blob = gzip.compress(b"\x00" * (68 * 1024 * 1024))
    manifest = build_unpack_manifest(blob)
    assert manifest.root_format == "gzip"
    assert manifest.truncated is True
    assert manifest.total_bytes <= 64 * 1024 * 1024
    assert any("exceeds the remaining" in warning for warning in manifest.warnings)


def test_corrupt_zip_magic_is_a_typed_error() -> None:
    """Bytes matching the zip magic but failing to parse raise AnalysisError."""
    with pytest.raises(AnalysisError, match="readable zip archive"):
        build_unpack_manifest(b"PK\x03\x04" + b"\x00" * 32)


# --- 8< --- MCP tool layer (`codevanta_sourcemap` / `codevanta_unpack`) ------


def test_mcp_sourcemap_summary_trace_and_argument_errors(tmp_path) -> None:
    """The tool layer decodes and traces through the plain-function API."""
    target = tmp_path / "bundle.js.map"
    target.write_bytes(_map_bytes(FIXTURE_MAPPINGS, source_root="app"))
    payload = tools.codevanta_sourcemap(str(target))
    assert payload["version"] == 3
    assert payload["segment_count"] == 4
    assert payload["source_root"] == "app"
    traced = tools.codevanta_sourcemap(str(target), line=1, column=6)
    assert traced["hit"] is True
    assert traced["source"] == "app/vendor/lib.js"
    assert traced["name"] == "emitFoo"
    with pytest.raises(AnalysisError, match="together"):
        tools.codevanta_sourcemap(str(target), line=1)
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_sourcemap(str(tmp_path / "missing.js.map"))


def test_mcp_unpack_manifest_and_argument_errors(tmp_path) -> None:
    """The tool layer builds manifests from files and rejects non-archives."""
    target = tmp_path / "bundle.zip"
    target.write_bytes(_zip_bytes(("docs/readme.txt", b"hello")))
    payload = tools.codevanta_unpack(str(target))
    assert payload["root_format"] == "zip"
    assert payload["entry_count"] == 1
    assert payload["root"]["children"][0]["path"] == "archive/docs/readme.txt"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"not an archive at all")
    with pytest.raises(AnalysisError, match="known archive format"):
        tools.codevanta_unpack(str(plain))
    with pytest.raises(AnalysisError, match="not a regular file"):
        tools.codevanta_unpack(str(tmp_path))


def test_server_registers_both_webfw_tools() -> None:
    """Both lane tools are registered on the built MCP server."""
    import asyncio

    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert "codevanta_sourcemap" in names
    assert "codevanta_unpack" in names
