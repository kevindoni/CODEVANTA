# HAR replay fixtures

`codevanta.analysis.replay_fixture.build_replay_fixture` turns a recorded
HTTP Archive (HAR) capture into a deterministic, bounded **replay
fixture**: normalised request/response rows plus an endpoint manifest that
another tool — or an agent harness — can replay or train against. It is
pure Python, stdlib only: no server, no sockets, nothing executed.

## Why: the REA RL-environment idea, honestly scoped

REA ([rea.tools](https://rea.tools)) popularised treating a recorded
application surface as a *reinforcement-learning environment*: a bounded,
deterministic description of the endpoints an application actually
exchanged, so an agent can train against it offline. CODEVANTA builds the
**offline half** of that idea — the fixture *document*. The honest
difference: CODEVANTA never serves traffic, never replays requests, and
never executes anything; consuming the fixture is another tool's job.

## The fixture document

`build_replay_fixture(har_path, *, max_entries=500, max_body_bytes=262_144)`
returns a `ReplayFixtureReport`; `report.to_fixture_json()` emits the
standalone document:

```json
{
  "fixture": {
    "har_path": "...", "har_sha256": "...",
    "summary": {"total_entries": 3, "har_entry_count": 3, "unique_hosts": ["..."],
                 "host_count": 1, "total_body_bytes": 198,
                 "method_counts": {"GET": 2, "POST": 1},
                 "status_classes": {"2xx": 2, "4xx": 1}},
    "entries": ["...normalised rows, sorted by startedDateTime..."],
    "truncated": false, "warnings": [], "evidence": {"...": "..."}
  },
  "manifest": {
    "endpoints": [{"method": "GET", "host": "api.example.test",
                    "path_template": "/api/items/{n}", "count": 2,
                    "statuses": {"200": 1, "404": 1}}],
    "endpoint_count": 2, "truncated": false
  }
}
```

The manifest is the "environment surface": one row per unique
`(method, host, path-template)` with hit counts and the distribution of
response statuses actually observed.

## Normalisation rules

The fixture is derived data — these choices are fixed and documented:

| Input | Rule |
|-------|------|
| Entry order | sorted by `startedDateTime` (stable; ties keep capture order) |
| Method | upper-cased |
| URL | split into `scheme` + `host` + `path` + parsed query pairs |
| Query | `queryString` wins when present, else percent-decoded from the URL |
| Path template | all-digit segments → `{n}`; hex-only segments ≥ 8 chars → `{hex}` |
| Request headers | every name kept, values cut at 512 chars, at most 128 pairs |
| Response headers | only `Content-Type` and `Content-Length` are kept |
| Response body | **never inlined** — only `size`, `sha256`, `mimeType`, `has_body`, and a base64 preview of the first 128 bytes when the body is within `max_body_bytes` |
| Timing | `time` and `timings.wait` as floats when present, else `null` |
| Bodies encoded `base64` | decoded before hashing/previewing (shared HAR bounds reused from the capture lane) |

Determinism: entries, endpoints, hosts and every summary map are emitted
in sorted order and `to_fixture_json` serialises with sorted keys — the
same input file always yields a byte-identical document.

## Bounds

Every bound that fires sets `truncated` / a per-entry flag and adds a
warning — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Entries kept (`max_entries`) | 500 (max 4096) | `truncated: true` + warning; entries past the cap are not walked |
| Body preview eligibility (`max_body_bytes`) | 262144 (max 16 MiB) | larger bodies keep size + sha256, no preview, warning |
| Preview bytes | 128 | first bytes only, base64 |
| Query pairs per entry | 64 | `query_truncated: true` + warning |
| Request headers per entry | 128 | `headers_truncated: true` + warning |
| Header name / value chars | 128 / 512 | `header_values_truncated: true` + warning |
| Endpoints in manifest | 256 | honest `endpoint_count` kept, list capped, warning |
| Unique hosts listed | 32 | honest `host_count` kept, list capped, warning |
| Warnings kept | 32 | further warnings dropped |

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| Fixture rows (method/host/path/status/size/sha256) | `medium` | literal capture data, but normalised — the derived shape is a documented choice, not raw fact |
| Endpoint manifest rows | `medium` | collapse rules (`{n}`, `{hex}`) group paths by heuristic shape |
| Truncation / bounds accounting | `certain` | counted by the walk itself |

The evidence record (`source: "replay.fixture"`, `method:
"har_normalization"`, confidence `medium`) carries the caps that produced
the fixture, so a consumer can judge how lossy the document is.

## Python usage

```python
from pathlib import Path

from codevanta.analysis.replay_fixture import build_replay_fixture

report = build_replay_fixture(Path("capture.har"))
print(report.total_entries, report.endpoint_count, report.status_classes)
document = report.to_fixture_json()   # standalone {"fixture": ..., "manifest": ...}
payload = report.to_dict()            # full JSON-safe record
```

A missing file, invalid JSON, a document without `log.entries`, an empty
capture, or an out-of-range `max_entries` / `max_body_bytes` raises the
typed `AnalysisError`. This engine is Python-only for now — it is not
wired into the CLI, MCP server or GUI.
