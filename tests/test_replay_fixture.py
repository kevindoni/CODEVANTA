"""Replay fixture tests: HAR in, deterministic bounded fixture document out.

Everything here is offline: the HAR captures are built in-memory and dumped
to ``tmp_path``, no network is touched, and every assertion runs against
the pure :func:`codevanta.analysis.replay_fixture.build_replay_fixture`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.replay_fixture import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_MAX_ENTRIES,
    build_replay_fixture,
)
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence

_T1 = "2026-01-01T00:00:01.000Z"
_T2 = "2026-01-01T00:00:02.000Z"
_T3 = "2026-01-01T00:00:03.000Z"
_T4 = "2026-01-01T00:00:04.000Z"
_HOST = "api.example.test"

#: 160 chars: the first 128 become the preview, the tail must never leak.
_BODY_A = '{"prefix":"' + "A" * 128 + 'TAILMARKER918273645"}'
_BODY_B = '{"error":"not found"}'
_BODY_C = '{"id": 42}'


def _entry(
    started: str,
    method: str,
    url: str,
    *,
    status: int = 200,
    status_text: str = "OK",
    body: str = "",
    mime: str = "application/json",
    headers: list[dict[str, str]] | None = None,
    query: list[dict[str, str]] | None = None,
    time_ms: float | None = None,
    wait_ms: float | None = None,
) -> dict[str, Any]:
    """Build one minimal-but-valid HAR entry dict."""
    request: dict[str, Any] = {"method": method, "url": url, "headers": headers or []}
    if query is not None:
        request["queryString"] = query
    return {
        "startedDateTime": started,
        "time": time_ms,
        "timings": {"wait": wait_ms},
        "request": request,
        "response": {
            "status": status,
            "statusText": status_text,
            "headers": [
                {"name": "Content-Type", "value": mime},
                {"name": "Content-Length", "value": str(len(body))},
            ],
            "content": {"mimeType": mime, "text": body},
        },
    }


def _base_entries() -> list[dict[str, Any]]:
    """Two GETs to numeric item paths (200 + 404) and one POST with a body."""
    return [
        _entry(
            _T1,
            "GET",
            f"https://{_HOST}/api/items/42?a=1&b=2",
            status=200,
            status_text="OK",
            body=_BODY_A,
            headers=[
                {"name": "Accept", "value": "application/json"},
                {"name": "User-Agent", "value": "codevanta-test"},
            ],
            time_ms=40.5,
            wait_ms=10.25,
        ),
        _entry(
            _T2,
            "GET",
            f"https://{_HOST}/api/items/17",
            status=404,
            status_text="Not Found",
            body=_BODY_B,
            time_ms=20.0,
            wait_ms=5.0,
        ),
        _entry(
            _T3,
            "POST",
            f"https://{_HOST}/api/items",
            status=201,
            status_text="Created",
            body=_BODY_C,
            headers=[{"name": "X-Api-Key", "value": "secret-redacted"}],
            query=[{"name": "beta", "value": "1"}],
            time_ms=120.5,
            wait_ms=5.0,
        ),
    ]


def _write_har(
    tmp_path: Path, entries: list[dict[str, Any]], name: str = "capture.har"
) -> Path:
    """Dump one in-memory HAR dict to a real file under ``tmp_path``."""
    path = tmp_path / name
    path.write_text(
        json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8"
    )
    return path


def test_defaults_match_documented_bounds() -> None:
    """The shipped defaults are the documented 500 / 262144 caps."""
    assert DEFAULT_MAX_ENTRIES == 500
    assert DEFAULT_MAX_BODY_BYTES == 262_144


def test_normalises_entries_and_session_summary(tmp_path: Path) -> None:
    """Three entries normalise with parsed URL parts, timings and summary."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()))
    assert not report.truncated
    assert report.warnings == ()
    assert report.total_entries == 3
    assert report.har_entry_count == 3
    assert report.unique_hosts == (_HOST,)
    assert report.host_count == 1
    assert report.method_counts == {"GET": 2, "POST": 1}
    assert report.status_classes == {"2xx": 2, "4xx": 1}
    assert report.total_body_bytes == len(_BODY_A) + len(_BODY_B) + len(_BODY_C)

    first, second, third = report.entries
    assert (first.method, first.scheme, first.host) == ("GET", "https", _HOST)
    assert first.path == "/api/items/42"
    assert first.query == (("a", "1"), ("b", "2"))
    assert (first.status, first.status_text) == (200, "OK")
    assert (first.time_ms, first.wait_ms) == (40.5, 10.25)
    assert ("Accept", "application/json") in first.request_headers
    assert first.content_type == "application/json"
    assert first.content_length == str(len(_BODY_A))
    assert (second.status, second.status_text) == (404, "Not Found")
    assert third.method == "POST"
    assert third.query == (("beta", "1"),)
    assert third.status == 201

    assert report.evidence.source == "replay.fixture"
    assert report.evidence.method == "har_normalization"
    assert report.evidence.confidence is Confidence.MEDIUM


def test_endpoint_collapse_digits_with_status_distribution(tmp_path: Path) -> None:
    """``/api/items/42`` and ``/api/items/17`` collapse with per-status counts."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()))
    by_key = {(ep.method, ep.host, ep.path_template): ep for ep in report.endpoints}
    collapsed = by_key[("GET", _HOST, "/api/items/{n}")]
    assert collapsed.count == 2
    assert collapsed.statuses == {"200": 1, "404": 1}
    assert by_key[("POST", _HOST, "/api/items")].count == 1
    assert report.endpoint_count == 2


def test_path_template_collapses_long_hex_runs(tmp_path: Path) -> None:
    """Long hex segments collapse to ``{hex}``; version segments stay."""
    entries = [
        _entry(_T1, "GET", f"https://{_HOST}/api/commits/0123456789abcdef0123456789abcdef01234567"),
        _entry(
            _T2,
            "GET",
            f"https://{_HOST}/api/commits/89abcdef0123456789abcdef0123456789abcdef01",
        ),
        _entry(_T3, "GET", f"https://{_HOST}/api/v2/status"),
    ]
    report = build_replay_fixture(_write_har(tmp_path, entries))
    templates = {(ep.host, ep.path_template): ep.count for ep in report.endpoints}
    assert templates[(_HOST, "/api/commits/{hex}")] == 2
    assert templates[(_HOST, "/api/v2/status")] == 1


def test_body_stored_as_sha256_and_bounded_preview_only(tmp_path: Path) -> None:
    """Bodies land as size + sha256 + first-128-byte preview; never inlined."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()))
    first = report.entries[0]
    raw = _BODY_A.encode("utf-8")
    assert first.body.has_body
    assert first.body.size == len(raw)
    assert first.body.sha256 == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(first.body.preview_b64 or "") == raw[:128]
    full = report.entries[1].body
    assert base64.b64decode(full.preview_b64 or "") == _BODY_B.encode("utf-8")
    assert "TAILMARKER918273645" not in report.to_fixture_json()
    assert "TAILMARKER918273645" not in json.dumps(report.to_dict())


def test_oversized_body_not_inlined_with_warning(tmp_path: Path) -> None:
    """A body past ``max_body_bytes`` keeps size+sha256, loses the preview."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()), max_body_bytes=64)
    first = report.entries[0]
    assert first.body.size == len(_BODY_A.encode("utf-8"))
    assert len(first.body.sha256) == 64
    assert first.body.preview_b64 is None
    assert first.body.preview_omitted
    assert report.truncated
    assert any("preview omitted" in warning for warning in report.warnings)
    assert "TAILMARKER918273645" not in report.to_fixture_json()
    small = report.entries[1].body
    assert small.preview_b64 is not None


def test_header_value_cap_cuts_with_warning(tmp_path: Path) -> None:
    """A 600-char header value is cut at 512 and reported."""
    entry = _entry(
        _T1,
        "GET",
        f"https://{_HOST}/api/items/42",
        headers=[{"name": "X-Long", "value": "v" * 600}],
    )
    report = build_replay_fixture(_write_har(tmp_path, [entry]))
    record = report.entries[0]
    assert record.request_headers == (("X-Long", "v" * 512),)
    assert record.header_values_truncated
    assert report.truncated
    assert any("header names/values cut at 512" in w for w in report.warnings)


def test_header_count_cap_truncates_with_warning(tmp_path: Path) -> None:
    """130 request headers are capped at 128 with an honest flag."""
    headers = [{"name": f"X-H{i:03d}", "value": str(i)} for i in range(130)]
    entry = _entry(_T1, "GET", f"https://{_HOST}/api/items/42", headers=headers)
    report = build_replay_fixture(_write_har(tmp_path, [entry]))
    record = report.entries[0]
    assert len(record.request_headers) == 128
    assert record.headers_truncated
    assert any("request headers capped at 128" in w for w in report.warnings)


def test_query_pair_cap_truncates_with_warning(tmp_path: Path) -> None:
    """70 query pairs are capped at 64 with an honest flag."""
    query = [{"name": f"p{i:02d}", "value": str(i)} for i in range(70)]
    entry = _entry(_T1, "GET", f"https://{_HOST}/search", query=query)
    report = build_replay_fixture(_write_har(tmp_path, [entry]))
    record = report.entries[0]
    assert len(record.query) == 64
    assert record.query[0] == ("p00", "0")
    assert record.query_truncated
    assert any("query pairs capped at 64" in w for w in report.warnings)


def test_max_entries_truncates_honestly(tmp_path: Path) -> None:
    """``max_entries=2`` keeps two entries and says so."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()), max_entries=2)
    assert report.total_entries == 2
    assert report.har_entry_count == 3
    assert report.truncated
    assert any("truncated to 2 of 3" in w for w in report.warnings)
    assert [entry.method for entry in report.entries] == ["GET", "GET"]
    assert all(endpoint.method == "GET" for endpoint in report.endpoints)


def test_deterministic_output_for_same_input(tmp_path: Path) -> None:
    """Same capture, two builds: byte-identical fixture documents."""
    path = _write_har(tmp_path, _base_entries())
    first = build_replay_fixture(path)
    second = build_replay_fixture(path)
    assert first.to_fixture_json() == second.to_fixture_json()
    assert first.to_dict() == second.to_dict()


def test_har_digest_and_path_recorded(tmp_path: Path) -> None:
    """The report cites its source file and its sha256."""
    path = _write_har(tmp_path, _base_entries())
    report = build_replay_fixture(path)
    assert report.har_path == str(path)
    assert report.har_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_to_dict_and_fixture_json_are_json_safe(tmp_path: Path) -> None:
    """Both serialisations round-trip through json cleanly."""
    report = build_replay_fixture(_write_har(tmp_path, _base_entries()))
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["summary"]["total_entries"] == 3
    assert payload["summary"]["method_counts"] == {"GET": 2, "POST": 1}
    document = json.loads(report.to_fixture_json())
    assert set(document) == {"fixture", "manifest"}
    assert document["manifest"]["endpoint_count"] == len(document["manifest"]["endpoints"])
    assert document["manifest"]["truncated"] is False
    assert document["fixture"]["summary"]["status_classes"] == {"2xx": 2, "4xx": 1}


def test_entries_sorted_by_started_datetime(tmp_path: Path) -> None:
    """Out-of-order captures are re-sorted by ``startedDateTime``."""
    shuffled = [_base_entries()[2], _base_entries()[0], _base_entries()[1]]
    report = build_replay_fixture(_write_har(tmp_path, shuffled))
    assert [entry.started for entry in report.entries] == [_T1, _T2, _T3]
    assert [entry.index for entry in report.entries] == [1, 2, 0]


def test_missing_file_raises_typed_error(tmp_path: Path) -> None:
    """A missing path is a typed AnalysisError."""
    with pytest.raises(AnalysisError, match="file not found"):
        build_replay_fixture(tmp_path / "missing.har")


def test_invalid_json_raises_typed_error(tmp_path: Path) -> None:
    """Non-JSON bytes are a typed AnalysisError."""
    path = tmp_path / "broken.har"
    path.write_text("{not json at all", encoding="utf-8")
    with pytest.raises(AnalysisError, match="not valid JSON"):
        build_replay_fixture(path)


def test_not_a_har_document_raises_typed_error(tmp_path: Path) -> None:
    """JSON without a ``log.entries`` list is refused."""
    path = tmp_path / "nohar.json"
    path.write_text(json.dumps({"log": {"version": "1.2"}}), encoding="utf-8")
    with pytest.raises(AnalysisError, match="log.entries"):
        build_replay_fixture(path)
    path.write_text(json.dumps({"nothing": "here"}), encoding="utf-8")
    with pytest.raises(AnalysisError, match="not a HAR document"):
        build_replay_fixture(path)


def test_empty_entries_raises_typed_error(tmp_path: Path) -> None:
    """An empty capture has nothing to replay."""
    path = tmp_path / "empty.har"
    path.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
    with pytest.raises(AnalysisError, match="nothing to replay"):
        build_replay_fixture(path)


def test_no_replayable_entries_raises_typed_error(tmp_path: Path) -> None:
    """Entries that all lack a request URL leave nothing to replay."""
    entries = [{"startedDateTime": _T1, "response": {"status": 200}}]
    path = _write_har(tmp_path, entries)
    with pytest.raises(AnalysisError, match="no replayable entries"):
        build_replay_fixture(path)


def test_out_of_range_caps_raise_typed_errors(tmp_path: Path) -> None:
    """Both cap arguments are validated against their bounds."""
    path = _write_har(tmp_path, _base_entries())
    with pytest.raises(AnalysisError, match="max_entries"):
        build_replay_fixture(path, max_entries=0)
    with pytest.raises(AnalysisError, match="max_entries"):
        build_replay_fixture(path, max_entries=10_000)
    with pytest.raises(AnalysisError, match="max_body_bytes"):
        build_replay_fixture(path, max_body_bytes=0)
    with pytest.raises(AnalysisError, match="max_body_bytes"):
        build_replay_fixture(path, max_body_bytes=10**9)


def test_base64_body_decoded_before_digest(tmp_path: Path) -> None:
    """A base64-encoded HAR body is decoded before hashing and preview."""
    raw = b"\x00\x01binary-tail-marker"
    entry = {
        "startedDateTime": _T4,
        "time": 1.0,
        "timings": {"wait": 0.5},
        "request": {"method": "GET", "url": f"https://{_HOST}/bin", "headers": []},
        "response": {
            "status": 200,
            "statusText": "OK",
            "headers": [],
            "content": {
                "mimeType": "application/octet-stream",
                "encoding": "base64",
                "text": base64.b64encode(raw).decode("ascii"),
            },
        },
    }
    report = build_replay_fixture(_write_har(tmp_path, [entry]))
    body = report.entries[0].body
    assert body.size == len(raw)
    assert body.sha256 == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(body.preview_b64 or "") == raw[:128]


# ---- CLI ------------------------------------------------------------------------


def test_cli_replay_fixture_table_and_output(tmp_path: Path) -> None:
    """`codevanta replay-fixture` renders endpoints and -o writes the fixture."""
    import json as _json

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    har = tmp_path / "cap.har"
    har.write_text(
        _json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "startedDateTime": "2026-01-01T00:00:00Z",
                            "request": {
                                "method": "get",
                                "url": "https://api.test/items/42",
                                "headers": [],
                            },
                            "response": {"status": 200, "headers": []},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["replay-fixture", str(har)])
    assert result.exit_code == 0, result.output
    assert "/items/{n}" in result.output

    out = tmp_path / "fixture.json"
    result = runner.invoke(cli, ["replay-fixture", str(har), "-o", str(out)])
    assert result.exit_code == 0, result.output
    document = _json.loads(out.read_text(encoding="utf-8"))
    assert "fixture" in document and "manifest" in document


def test_cli_replay_fixture_error_exit(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["replay-fixture", str(tmp_path / "missing.har")])
    assert result.exit_code == 2
