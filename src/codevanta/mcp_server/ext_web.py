"""MCP tools: ``codevanta_web_inspect`` (skip-gated) and ``codevanta_asar``.

Two plain ``dict``-returning helpers like every other entry in
:mod:`codevanta.mcp_server.tools`. ``codevanta_web_inspect`` inspects a live
Electron/Chromium *passively* through CDP -- and is skip-gated: an unreachable
debugger comes back as a typed ``{"available": false, "reason": ...}`` result
with evidence instead of an error, so MCP clients can degrade gracefully.
Nothing is ever executed in the target; ``Runtime.evaluate`` is not part of
the lane's vocabulary. ``codevanta_asar`` is offline and always works: it
lists an Electron ASAR archive (bounded 512 files) or extracts one entry
(bounded 8 MiB), purely by parsing bytes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from codevanta.analysis import cdp_client
from codevanta.analysis.asar import (
    DEFAULT_EXTRACT_BYTES,
    extract_file,
    list_archive,
)
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_asar", "codevanta_web_inspect"]


def _validate_container_path(path: str) -> Path:
    """Return ``path`` as an existing regular file, or raise naming the problem."""
    if not isinstance(path, str):
        raise AnalysisError(f"path must be a string, got {type(path).__name__}")
    text = path.strip()
    if not text:
        raise AnalysisError("path must not be empty")
    candidate = Path(text).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def _unavailable(endpoint: str, reason: str) -> dict[str, Any]:
    """Typed skip-gate result for a web inspection that cannot run."""
    return {
        "available": False,
        "endpoint": endpoint,
        "reason": reason,
        "evidence": {
            "source": "cdp.inspect",
            "method": "cdp_ws_passive",
            "confidence": "low",
            "extra": {"reason": reason},
        },
    }


def codevanta_web_inspect(
    endpoint: str = cdp_client.DEFAULT_ENDPOINT,
    target_id: str | None = None,
    observe_ms: int = cdp_client.DEFAULT_OBSERVE_MS,
) -> dict[str, Any]:
    """Passively inspect one live page; skip-gated on endpoint reachability.

    Lists the endpoint's debug targets, picks ``target_id`` (or the first
    ``page`` target), and returns title, url, bounded resource list and
    console traffic overheard during ``observe_ms``. Any failure -- endpoint
    down, no page target, debugger socket refused -- becomes
    ``{"available": false, "reason": ...}`` with evidence, never an
    exception. Read-only: only domain enables and navigation/resource
    queries are sent, never ``Runtime.evaluate``.
    """
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise AnalysisError("endpoint must be a non-empty string")
    try:
        targets = cdp_client.list_targets(endpoint)
    except AnalysisError as exc:
        return _unavailable(endpoint, str(exc))
    target: cdp_client.CdpTarget | None = None
    if target_id is not None:
        for candidate in targets.targets:
            if candidate.target_id == target_id:
                target = candidate
                break
        if target is None:
            return _unavailable(
                endpoint,
                f"target {target_id!r} not found; use codevanta_web_inspect with "
                "no target_id to list targets",
            )
    else:
        for candidate in targets.targets:
            if candidate.type == "page" and candidate.ws_url:
                target = candidate
                break
    if target is None:
        return _unavailable(endpoint, "no inspectable page target on this endpoint")
    if not target.ws_url:
        return _unavailable(
            endpoint, f"target {target.target_id!r} exposes no debugger websocket"
        )
    try:
        result = cdp_client.inspect_page(target.ws_url, observe_ms=observe_ms)
    except AnalysisError as exc:
        return _unavailable(endpoint, str(exc))
    payload = result.to_dict()
    payload["available"] = True
    payload["endpoint"] = targets.endpoint
    payload["target_id"] = target.target_id
    return payload


def codevanta_asar(path: str, extract: str | None = None) -> dict[str, Any]:
    """List an Electron ASAR archive offline; ``extract`` adds one entry.

    The listing is bounded at 512 file entries with honest totals, and
    carries ``evidence`` with ``source``/``method``/``confidence``. With
    ``extract`` naming an in-archive entry, the entry is read into memory
    (bounded 8 MiB, range-verified) and reported with its size and SHA-256
    -- the bytes themselves stay out of the JSON payload.
    """
    if extract is not None and not isinstance(extract, str):
        raise AnalysisError(f"extract must be a string, got {type(extract).__name__}")
    target = _validate_container_path(path)
    listing = list_archive(target)
    payload: dict[str, Any] = listing.to_dict()
    if extract is not None:
        result = extract_file(target, extract, max_bytes=DEFAULT_EXTRACT_BYTES)
        payload["extract"] = {
            "path": result.path,
            "size": len(result.data),
            "sha256": hashlib.sha256(result.data).hexdigest(),
            "evidence": result.evidence.to_dict(),
        }
    return payload
