"""The linked-digest chain on evidence bundles.

``entries_digest`` says *that* the entry table changed; the chain also pins
the row order and names the first entry where the links diverge, which is the
tamper-evidence the bundle format is for.
"""

from __future__ import annotations

import json
from pathlib import Path

from codevanta.analysis.evidence_bundle import (
    CHAIN_ALGORITHM,
    build_bundle,
    chain_entries,
    read_bundle,
    verify_bundle,
    write_bundle,
)


def _subject(tmp_path: Path) -> Path:
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"\x90" * 64)
    return subject


def test_built_bundle_carries_a_chain(tmp_path: Path) -> None:
    bundle = build_bundle(_subject(tmp_path), {"a": {"x": 1}, "b": {"y": 2}})

    assert bundle.manifest.chain_algorithm == CHAIN_ALGORITHM
    assert bundle.manifest.chain_head == chain_entries(dict(bundle.entries))["b"]
    links = chain_entries(dict(bundle.entries))
    for name, link in links.items():
        assert bundle.entries[name]["chain_sha256"] == link
    # Verification passes on the untouched bundle.
    assert verify_bundle(bundle).passed


def test_written_bundle_round_trips_the_chain(tmp_path: Path) -> None:
    path = write_bundle(
        build_bundle(_subject(tmp_path), {"alpha": {"n": 1}}), tmp_path / "b.json"
    )

    loaded = read_bundle(path)

    assert loaded.manifest.chain_head is not None
    assert verify_bundle(loaded).passed


def test_tampered_payload_breaks_verification(tmp_path: Path) -> None:
    path = write_bundle(
        build_bundle(_subject(tmp_path), {"alpha": {"n": 1}}), tmp_path / "b.json"
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"]["alpha"]["payload"] = {"n": 999}
    path.write_text(json.dumps(document), encoding="utf-8")

    problems = verify_bundle(read_bundle(path)).problems

    assert any("alpha" in problem for problem in problems)


def test_metadata_edit_breaks_the_chain_link(tmp_path: Path) -> None:
    """Forging an entry's sha256 without relinking is named by the chain."""
    path = write_bundle(
        build_bundle(_subject(tmp_path), {"alpha": {"n": 1}, "beta": {"m": 2}}),
        tmp_path / "b.json",
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    forged = "f" * 64
    document["entries"]["alpha"]["sha256"] = forged
    path.write_text(json.dumps(document), encoding="utf-8")

    problems = verify_bundle(read_bundle(path)).problems

    assert any("chain link mismatch" in problem for problem in problems)
    assert any("alpha" in problem for problem in problems)


def test_legacy_bundle_without_a_chain_still_verifies(tmp_path: Path) -> None:
    path = write_bundle(
        build_bundle(_subject(tmp_path), {"alpha": {"n": 1}}), tmp_path / "b.json"
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["manifest"].pop("chain_head", None)
    document["manifest"].pop("chain_algorithm", None)
    for record in document["entries"].values():
        record.pop("chain_sha256", None)
    path.write_text(json.dumps(document), encoding="utf-8")

    loaded = read_bundle(path)
    verification = verify_bundle(loaded)

    assert loaded.manifest.chain_head is None
    assert verification.passed, verification.problems
