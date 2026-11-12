"""Unit tests for the evidence layer."""

from __future__ import annotations

from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.evidence.provenance import Provenance


def test_confidence_scores_are_ordered() -> None:
    assert Confidence.CERTAIN.score > Confidence.HIGH.score
    assert Confidence.HIGH.score > Confidence.MEDIUM.score
    assert Confidence.MEDIUM.score > Confidence.LOW.score
    assert Confidence.LOW.score >= Confidence.UNKNOWN.score


def test_confidence_is_string_compatible() -> None:
    assert Confidence.HIGH == "high"
    assert str(Confidence.MEDIUM) == "medium"


def test_evidence_to_dict_includes_core_fields() -> None:
    evidence = Evidence(
        source="test",
        method="unit",
        confidence=Confidence.HIGH,
        address=0x1000,
        detail="ok",
    )
    data = evidence.to_dict()
    assert data == {
        "source": "test",
        "method": "unit",
        "confidence": "high",
        "address": "0x1000",
        "detail": "ok",
    }


def test_evidence_omits_empty_optional_fields() -> None:
    data = Evidence(source="s", method="m").to_dict()
    assert "address" not in data
    assert "detail" not in data
    assert "extra" not in data


def test_provenance_records_steps_in_order() -> None:
    provenance = Provenance().add_step("load").add_step("analyze")
    data = provenance.to_dict()
    assert data["tool"] == "codevanta"
    assert data["steps"] == ["load", "analyze"]
    assert data["created_at"]
