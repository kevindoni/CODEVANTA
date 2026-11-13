"""Evidence bundle tests: manifests, tamper detection, bounds and round-trips.

The digests asserted here are recomputed with ``hashlib``/``json`` directly
rather than through the module under test, so the tests pin the *recipe* a
third party would follow when verifying a bundle by hand.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import evidence_bundle
from codevanta.analysis.evidence_bundle import (
    DEFAULT_ALGORITHM,
    MAX_ENTRIES,
    MAX_PAYLOAD_BYTES,
    MEDIA_TYPE_JSON,
    TOOL_VERSION,
    Bundle,
    BundleManifest,
    build_bundle,
    canonical_json,
    dumps_bundle,
    entries_digest,
    hash_subject,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from codevanta.core.report import AnalysisError

FIXED_NOW = "2026-01-02T03:04:05+00:00"


def _independent_digest(payload: Any) -> tuple[str, int]:
    """Recompute (sha256, byte length) the way a third party would."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    data = text.encode("utf-8")
    return hashlib.sha256(data).hexdigest(), len(data)


@pytest.fixture()
def subject(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(bytes(range(256)) * 8)
    return path


@pytest.fixture()
def payloads() -> dict[str, Any]:
    return {
        "cfg": {"blocks": [{"address": 4096, "successors": [4100]}]},
        "strings": ["libc.so.6", "printf"],
    }


@pytest.fixture()
def bundle(subject: Path, payloads: dict[str, Any]) -> Bundle:
    return build_bundle(subject, payloads)


@pytest.fixture()
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(evidence_bundle, "_utc_now_iso", lambda: FIXED_NOW)
    return FIXED_NOW


# --------------------------------------------------------------------------- build


def test_build_records_manifest_fields(
    subject: Path, payloads: dict[str, Any], fixed_clock: str
) -> None:
    built = build_bundle(subject, payloads)

    assert built.manifest.created_at == fixed_clock
    assert built.manifest.tool_version == TOOL_VERSION
    assert built.manifest.subject == "sample.bin"
    assert built.manifest.subject_sha256 == hashlib.sha256(subject.read_bytes()).hexdigest()
    assert built.manifest.entry_count == 2
    assert built.manifest.algorithm == DEFAULT_ALGORITHM


def test_entries_are_hashed_canonical_payloads_sorted_by_name(bundle: Bundle) -> None:
    assert bundle.names == ("cfg", "strings")
    for name in bundle.names:
        expected_sha, expected_bytes = _independent_digest(bundle.payload(name))
        record = bundle.entries[name]
        assert record["sha256"] == expected_sha
        assert record["bytes"] == expected_bytes
        assert record["media_type"] == MEDIA_TYPE_JSON


def test_payload_accessor_returns_the_built_payload(bundle: Bundle, payloads: dict[str, Any]) -> None:
    assert bundle.payload("cfg") == payloads["cfg"]
    assert bundle.payload("strings") == payloads["strings"]


def test_payload_accessor_rejects_unknown_name(bundle: Bundle) -> None:
    with pytest.raises(AnalysisError, match="no entry"):
        bundle.payload("callgraph")


def test_label_overrides_the_subject_name(subject: Path) -> None:
    built = build_bundle(subject, {"cfg": {}}, label="notepad.exe")

    assert built.manifest.subject == "notepad.exe"
    assert built.manifest.subject_sha256 == hash_subject(subject)


def test_blank_label_is_rejected(subject: Path) -> None:
    with pytest.raises(AnalysisError, match="label"):
        build_bundle(subject, {"cfg": {}}, label="   ")


def test_hash_subject_matches_hashlib(subject: Path) -> None:
    assert hash_subject(subject) == hashlib.sha256(subject.read_bytes()).hexdigest()


def test_bundle_is_immutable(bundle: Bundle) -> None:
    with pytest.raises(FrozenInstanceError):
        bundle.manifest = bundle.manifest  # type: ignore[misc]
    with pytest.raises(TypeError):
        bundle.entries["cfg"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        bundle.entries["cfg"]["sha256"] = "0" * 64  # type: ignore[index]


def test_to_dict_is_json_safe_and_inlines_payloads(
    bundle: Bundle, payloads: dict[str, Any]
) -> None:
    document = bundle.to_dict()
    text = json.dumps(document, sort_keys=True)

    assert set(document) == {"manifest", "entries"}
    assert document["manifest"] == bundle.manifest.to_dict()
    assert list(document["entries"]) == ["cfg", "strings"]
    assert document["entries"]["cfg"]["payload"] == payloads["cfg"]
    assert document["entries"]["cfg"]["media_type"] == MEDIA_TYPE_JSON
    assert isinstance(document["entries"]["cfg"]["bytes"], int)
    assert json.loads(text) == document


def test_entries_digest_matches_the_documented_recipe(bundle: Bundle) -> None:
    rows = [
        [name, record["sha256"], record["bytes"], record["media_type"]]
        for name, record in sorted(bundle.entries.items())
    ]
    expected = hashlib.sha256(canonical_json(rows).encode("utf-8")).hexdigest()

    assert bundle.manifest.entries_sha256 == expected
    assert entries_digest(bundle.entries) == expected
    assert entries_digest(dict(reversed(list(bundle.entries.items())))) == expected


def test_canonical_json_ignores_key_order_and_spacing() -> None:
    left = canonical_json({"b": 1, "a": [1, 2]})
    right = canonical_json({"a": [1, 2], "b": 1})

    assert left == right == '{"a":[1,2],"b":1}'


def test_canonical_json_escapes_non_ascii() -> None:
    assert canonical_json({"name": "caf\u00e9"}) == '{"name":"caf\\u00e9"}'


# ---------------------------------------------------------------------- round-trip


def test_round_trip_write_read_verify(
    bundle: Bundle, subject: Path, tmp_path: Path, payloads: dict[str, Any]
) -> None:
    path = write_bundle(bundle, tmp_path / "bundle.json")

    assert path == tmp_path / "bundle.json"
    assert path.read_text(encoding="utf-8") == dumps_bundle(bundle)
    assert path.read_text(encoding="utf-8").endswith("}\n")
    assert json.loads(path.read_text(encoding="utf-8")) == bundle.to_dict()

    loaded = read_bundle(path)

    assert loaded == bundle
    assert loaded.manifest == bundle.manifest
    assert loaded.names == bundle.names
    assert loaded.payload("cfg") == payloads["cfg"]
    assert verify_bundle(loaded).passed
    assert verify_bundle(loaded, subject_path=subject).passed


def test_verify_accepts_bundle_and_plain_dict(bundle: Bundle) -> None:
    from_bundle = verify_bundle(bundle)
    from_dict = verify_bundle(bundle.to_dict())

    assert from_bundle.passed and from_dict.passed
    assert from_bundle.problems == from_dict.problems == ()
    assert from_bundle.manifest == from_dict.manifest == bundle.manifest


def test_verification_result_is_json_safe(bundle: Bundle, subject: Path) -> None:
    result = verify_bundle(bundle, subject_path=subject)
    document = result.to_dict()

    assert set(document) == {"passed", "problems", "manifest"}
    assert json.loads(json.dumps(document)) == document


def test_verify_rejects_objects_that_are_not_bundles() -> None:
    with pytest.raises(AnalysisError, match="Bundle or a mapping"):
        verify_bundle(["not", "a", "bundle"])  # type: ignore[arg-type]


def test_verify_checks_the_subject_binary(
    bundle: Bundle, subject: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.bin"
    other.write_bytes(subject.read_bytes() + b"x")

    assert verify_bundle(bundle, subject_path=subject).passed

    failed = verify_bundle(bundle, subject_path=other)

    assert not failed.passed
    assert len(failed.problems) == 1
    assert "sha256 mismatch" in failed.problems[0]
    assert bundle.manifest.subject_sha256 in failed.problems[0]
    assert hash_subject(other) in failed.problems[0]



# ------------------------------------------------------------------------ tampering


def test_flipping_one_byte_of_a_payload_on_disk_fails_naming_that_entry(
    bundle: Bundle, tmp_path: Path
) -> None:
    path = write_bundle(bundle, tmp_path / "bundle.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    original = document["entries"]["cfg"]["payload"]
    document["entries"]["cfg"]["payload"] = {"blocks": [{"address": 4096, "successors": [4104]}]}
    path.write_text(json.dumps(document, sort_keys=True, indent=2), encoding="utf-8")

    from_disk = verify_bundle(json.loads(path.read_text(encoding="utf-8")))
    # The file is still structurally valid, so it also loads; verification is
    # what reports the edit.
    from_loaded = verify_bundle(read_bundle(path))

    assert from_disk.passed is False
    assert from_loaded.passed is False
    assert any(
        "'cfg'" in problem and "sha256 mismatch" in problem for problem in from_disk.problems
    )
    assert not any("'strings'" in problem for problem in from_disk.problems)
    expected_sha, _ = _independent_digest(original)
    assert any(expected_sha in problem for problem in from_disk.problems)


def test_editing_a_recorded_entry_digest_fails(bundle: Bundle) -> None:
    document = bundle.to_dict()
    document["entries"]["cfg"]["sha256"] = "0" * 64

    result = verify_bundle(document)

    assert not result.passed
    assert any("'cfg'" in problem and "sha256 mismatch" in problem for problem in result.problems)
    assert any("0" * 64 in problem for problem in result.problems)
    # The entry table changed too, so the combined digest no longer matches.
    assert any("entries_sha256 mismatch" in problem for problem in result.problems)


def test_editing_a_recorded_size_fails(bundle: Bundle) -> None:
    document = bundle.to_dict()
    document["entries"]["strings"]["bytes"] += 1

    result = verify_bundle(document)

    assert not result.passed
    assert any("'strings'" in problem and "size mismatch" in problem for problem in result.problems)
    assert any("entries_sha256 mismatch" in problem for problem in result.problems)


def test_editing_the_manifest_entries_sha256_fails(bundle: Bundle) -> None:
    document = bundle.to_dict()
    document["manifest"]["entries_sha256"] = "f" * 64

    result = verify_bundle(document)

    assert not result.passed
    assert len(result.problems) == 1
    assert result.problems[0].startswith("manifest: entries_sha256 mismatch")
    assert "f" * 64 in result.problems[0]
    assert bundle.manifest.entries_sha256 in result.problems[0]
    assert result.manifest.entries_sha256 == "f" * 64


def test_dropping_an_entry_is_detected(bundle: Bundle) -> None:
    document = bundle.to_dict()
    del document["entries"]["strings"]

    result = verify_bundle(document)

    assert not result.passed
    assert any("entry_count mismatch (expected 2, actual 1)" in p for p in result.problems)
    assert any("entries_sha256 mismatch" in p for p in result.problems)


def test_missing_payload_is_reported(bundle: Bundle) -> None:
    document = bundle.to_dict()
    del document["entries"]["cfg"]["payload"]

    result = verify_bundle(document)

    assert not result.passed
    assert any("'cfg'" in p and "payload is missing" in p for p in result.problems)


def test_malformed_entry_metadata_is_reported(bundle: Bundle) -> None:
    document = bundle.to_dict()
    document["entries"]["cfg"]["sha256"] = "not-a-digest"

    result = verify_bundle(document)

    assert not result.passed
    assert any("'cfg'" in problem and "malformed" in problem for problem in result.problems)


def test_unsupported_algorithm_is_reported(bundle: Bundle) -> None:
    document = bundle.to_dict()
    document["manifest"]["algorithm"] = "md5"

    result = verify_bundle(document)

    assert not result.passed
    assert any("unsupported algorithm" in problem for problem in result.problems)


def test_missing_manifest_is_reported(bundle: Bundle) -> None:
    document = bundle.to_dict()
    del document["manifest"]

    result = verify_bundle(document)

    assert not result.passed
    assert any("manifest: missing" in problem for problem in result.problems)
    assert result.manifest.entries_sha256 == ""



# -------------------------------------------------------------------- determinism


def test_two_builds_serialise_to_identical_bytes(
    subject: Path, payloads: dict[str, Any], fixed_clock: str, tmp_path: Path
) -> None:
    first = write_bundle(build_bundle(subject, payloads), tmp_path / "one.json")
    second = write_bundle(build_bundle(subject, payloads), tmp_path / "two.json")

    assert first.read_bytes() == second.read_bytes()
    assert read_bundle(first).manifest == read_bundle(second).manifest


def test_entry_order_does_not_change_the_bytes(
    subject: Path, payloads: dict[str, Any], fixed_clock: str, tmp_path: Path
) -> None:
    reordered = {"strings": payloads["strings"], "cfg": payloads["cfg"]}

    first = write_bundle(build_bundle(subject, payloads), tmp_path / "one.json")
    second = write_bundle(build_bundle(subject, reordered), tmp_path / "two.json")

    assert first.read_bytes() == second.read_bytes()


def test_identical_payloads_hash_identically_regardless_of_insertion_order(
    subject: Path,
) -> None:
    left = build_bundle(subject, {"cfg": {"b": [2, 1], "a": 1}})
    right = build_bundle(subject, {"cfg": {"a": 1, "b": [2, 1]}})

    assert left.entries["cfg"] == right.entries["cfg"]
    assert left.manifest.entries_sha256 == right.manifest.entries_sha256


# ------------------------------------------------------------------------- bounds


def test_entry_cap_is_enforced_at_the_boundary(subject: Path) -> None:
    at_cap = {f"entry-{index:03d}": index for index in range(MAX_ENTRIES)}
    built = build_bundle(subject, at_cap)

    assert built.manifest.entry_count == MAX_ENTRIES
    assert verify_bundle(built).passed

    with pytest.raises(AnalysisError, match="too many entries"):
        build_bundle(subject, {**at_cap, "one-too-many": 0})


def test_payload_size_cap_is_enforced(subject: Path) -> None:
    oversized = {"blob": "a" * MAX_PAYLOAD_BYTES}

    with pytest.raises(AnalysisError, match="too large"):
        build_bundle(subject, oversized)


def test_payload_size_cap_boundary_is_exact(
    subject: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence_bundle, "MAX_PAYLOAD_BYTES", 32)

    # The payload here is a JSON string, so its canonical form is n + 2 bytes:
    # 30 characters land exactly on the cap, 31 go over by one.
    assert build_bundle(subject, {"blob": "a" * 30}).entries["blob"]["bytes"] == 32
    with pytest.raises(AnalysisError, match="too large"):
        build_bundle(subject, {"blob": "a" * 31})


def test_missing_subject_binary_raises(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not found"):
        build_bundle(tmp_path / "absent.bin", {"cfg": {}})


def test_directory_as_subject_raises(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not a regular file"):
        build_bundle(tmp_path, {"cfg": {}})


def test_non_json_payload_raises(subject: Path) -> None:
    with pytest.raises(AnalysisError, match="not canonical JSON"):
        build_bundle(subject, {"cfg": {object()}})


def test_nan_payload_raises(subject: Path) -> None:
    with pytest.raises(AnalysisError, match="not canonical JSON"):
        build_bundle(subject, {"cfg": {"score": float("nan")}})


def test_payloads_must_be_a_mapping(subject: Path) -> None:
    with pytest.raises(AnalysisError, match="payloads must be a mapping"):
        build_bundle(subject, [("cfg", {})])  # type: ignore[arg-type]


def test_blank_entry_name_raises(subject: Path) -> None:
    with pytest.raises(AnalysisError, match="entry name"):
        build_bundle(subject, {"  ": {}})



# ----------------------------------------------------------------------- reading


def test_read_bundle_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot read bundle"):
        read_bundle(tmp_path / "absent.json")


def test_read_bundle_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(AnalysisError, match="not valid JSON"):
        read_bundle(path)


def test_read_bundle_rejects_a_json_array(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text("[1, 2]", encoding="utf-8")

    with pytest.raises(AnalysisError, match="not a JSON object"):
        read_bundle(path)


def test_read_bundle_rejects_a_structurally_broken_document(
    bundle: Bundle, tmp_path: Path
) -> None:
    document = bundle.to_dict()
    del document["entries"]["cfg"]["payload"]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AnalysisError, match="payload is missing"):
        read_bundle(path)


def test_read_bundle_rejects_malformed_manifest_metadata(
    bundle: Bundle, tmp_path: Path
) -> None:
    document = bundle.to_dict()
    document["manifest"]["entry_count"] = "two"
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AnalysisError, match="entry_count"):
        read_bundle(path)


def test_written_file_has_a_stable_key_order(bundle: Bundle, tmp_path: Path) -> None:
    path = write_bundle(bundle, tmp_path / "bundle.json")
    document = json.loads(path.read_text(encoding="utf-8"))

    assert list(document) == ["entries", "manifest"]
    assert list(document["manifest"]) == [
        "algorithm",
        "created_at",
        "entries_sha256",
        "entry_count",
        "subject",
        "subject_sha256",
        "tool_version",
    ]
    assert list(document["entries"]["strings"]) == [
        "bytes",
        "media_type",
        "payload",
        "sha256",
    ]
    # Two-space indent, sorted keys, LF endings only.
    assert '\n  "entries": {' in path.read_text(encoding="utf-8")
    assert "\r" not in path.read_text(encoding="utf-8")


def test_bundle_manifest_to_dict_is_json_safe() -> None:
    manifest = BundleManifest(
        created_at=FIXED_NOW,
        tool_version=TOOL_VERSION,
        subject="sample.bin",
        subject_sha256="a" * 64,
        entry_count=1,
        entries_sha256="b" * 64,
    )

    document = manifest.to_dict()

    assert document["algorithm"] == DEFAULT_ALGORITHM
    assert json.loads(json.dumps(document)) == document


def test_non_ascii_payload_round_trips(subject: Path, tmp_path: Path) -> None:
    built = build_bundle(subject, {"strings": ["caf\u00e9", "na\u00efve", "\u4e2d\u6587"]})
    path = write_bundle(built, tmp_path / "bundle.json")

    # The file stays pure ASCII; unescaping happens on the way back in.
    assert "caf\u00e9" not in path.read_text(encoding="utf-8")
    assert read_bundle(path).payload("strings") == ["caf\u00e9", "na\u00efve", "\u4e2d\u6587"]
    assert verify_bundle(read_bundle(path)).passed

