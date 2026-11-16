"""Token-efficient meta-tool gateway over the CODEVANTA MCP registry.

An MCP client normally loads every registered tool schema at connect time. The
CODEVANTA server registers 126 tools, so that handshake costs roughly 26k input
tokens before the agent does any work. This module keeps the same registry but
publishes only five small meta-tools instead: ``search``, ``schema``, ``call``,
``result_read`` and ``result_grep``.

The source server returned by :func:`codevanta.mcp_server.server.build_server`
is unchanged and remains available for clients that want the flat tool list.
The gateway is a facade: ``call`` invokes the underlying registry entry through
the SDK's own validation and execution path, then serializes the result as JSON.
Oversized replies are written under ``~/.codevanta/mcp_results`` and replaced by
a preview plus a ``result_id``, so the agent can page or search the full payload
with :func:`result_read` and :func:`result_grep`.

Approximate token counts use ``len(text) // 4`` and are deliberately cheap; the
budget is a guardrail against dumping a multi-megabyte report into context, not
a billing meter.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, cast

from mcp.server.mcpserver import Context, MCPServer

from codevanta.core.report import AnalysisError

from .server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SERVER_NAME,
    SERVER_VERSION,
    SUPPORTED_TRANSPORTS,
    HttpTransport,
    build_server,
    transport_security,
)

#: Default reply budget for ``call`` and window size for ``result_read``.
DEFAULT_MAX_TOKENS = 1500

#: The budget is clamped to this range; a zero or negative budget would hide
#: the payload entirely, and an unbounded one defeats the gateway.
MIN_MAX_TOKENS = 100
MAX_MAX_TOKENS = 50_000

#: Pagination defaults for ``search`` and ``result_grep``.
DEFAULT_SEARCH_LIMIT = 20
MAX_SEARCH_LIMIT = 100
DEFAULT_MAX_MATCHES = 20
MAX_MAX_MATCHES = 100
MAX_CONTEXT_LINES = 5

#: Descriptions in compact views are cut to their first sentence, then to this
#: many characters so one verbose tool cannot dominate a search page.
MAX_SEARCH_DESCRIPTION = 160
MAX_SCHEMA_DESCRIPTION = 240
MAX_PROPERTY_DESCRIPTION = 120

#: Environment override for the result store (tests and sandboxes use it);
#: the default is ``%USERPROFILE%\.codevanta\mcp_results`` on Windows and
#: ``~/.codevanta/mcp_results`` elsewhere.
RESULTS_DIR_ENV = "CODEVANTA_MCP_RESULTS_DIR"

#: Only these characters are accepted as a result id. This is the first of two
#: checks; the resolved path is also required to stay directly inside the
#: result directory, so ``..``, separators and absolute paths cannot escape.
_RESULT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: ``path`` grammar for :func:`result_read`: dotted keys with optional integer
#: indices, e.g. ``normalized_result.functions`` or ``settings[3].name``.
_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")

GATEWAY_INSTRUCTIONS = (
    "This is the token-efficient CODEVANTA gateway. Do not assume any analysis "
    "tool exists: start with search(query=...) to list tools compactly, then "
    "schema(tool=...) for one input schema, then call(tool=..., arguments={...}) "
    "to run it. Results over max_tokens (default 1500) are stored and return a "
    "result_id; page them with result_read or search them with result_grep. "
    "Every analysis result carries evidence: check 'source', 'method' and "
    "'confidence' before relying on a finding."
)


def _json_text(payload: Any) -> str:
    """Serialize ``payload`` as readable, UTF-8-preserving JSON."""
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def estimate_tokens(text: str) -> int:
    """Return a cheap token estimate for ``text`` (about four chars per token)."""
    return len(text) // 4


def clamp_max_tokens(value: Any) -> int:
    """Clamp a caller-supplied reply budget to :data:`MIN_MAX_TOKENS`..:data:`MAX_MAX_TOKENS`.

    Invalid values (including booleans, which ``isinstance(True, int)`` would
    otherwise accept) fall back to :data:`DEFAULT_MAX_TOKENS`.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return DEFAULT_MAX_TOKENS
    return max(MIN_MAX_TOKENS, min(MAX_MAX_TOKENS, value))


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    """Clamp an optional integer argument, falling back to ``default``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(low, min(high, value))


def _first_sentence(text: str | None, limit: int) -> str:
    """Return the first sentence of ``text``, whitespace-normalized and capped."""
    cleaned = " ".join((text or "").split())
    if not cleaned:
        return ""
    sentence = re.split(r"(?<=[.!?])\s", cleaned, maxsplit=1)[0]
    if len(sentence) > limit:
        sentence = sentence[: limit - 3].rstrip() + "..."
    return sentence


def results_dir() -> Path:
    """Return (and create) the directory that stores oversized tool results."""
    override = os.environ.get(RESULTS_DIR_ENV, "").strip()
    root = (
        Path(override).expanduser()
        if override
        else Path.home() / ".codevanta" / "mcp_results"
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def _result_path(result_id: str) -> Path:
    """Map ``result_id`` to a file path, rejecting any path-traversal attempt.

    Raises:
        ValueError: ``result_id`` is not a bare identifier or the resolved path
            is not directly inside :func:`results_dir`.
    """
    if not isinstance(result_id, str) or not _RESULT_ID_RE.fullmatch(result_id):
        raise ValueError(
            f"invalid result_id {result_id!r}: expected 1-64 characters from "
            "[A-Za-z0-9_-]"
        )
    root = results_dir().resolve()
    path = (root / f"{result_id}.json").resolve()
    if path.parent != root:
        raise ValueError(f"invalid result_id {result_id!r}: path escapes the result store")
    return path


def _load_result(result_id: str) -> str:
    """Read the full stored JSON text for ``result_id``."""
    return _result_path(result_id).read_text(encoding="utf-8")


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    """Build a typed, non-raising error payload."""
    payload: dict[str, Any] = {"error": message, "code": code}
    payload.update(extra)
    return payload


def _unknown_tool(tool: str) -> dict[str, Any]:
    """Build the typed error returned for an unknown tool name."""
    return _error(
        "unknown_tool",
        f"unknown tool {tool!r}",
        hint="Call search(query=...) to list tools, then schema(tool=...) before call().",
    )


def _tool_error(tool: str, exc: Exception) -> dict[str, Any]:
    """Wrap a tool exception as a typed error payload instead of raising."""
    message = str(exc).strip() or exc.__class__.__name__
    return _error(
        "tool_error",
        message,
        tool=tool,
        exception=exc.__class__.__name__,
    )


def _compact_schema(spec: Any) -> Any:
    """Keep the useful parts of one JSON-schema property.

    Kept: ``type``, ``enum``, ``default``, bounds, ``format``, array ``items``
    and union branches. Free-text descriptions are reduced to their first
    sentence and capped. Titles and other presentation metadata are dropped.
    """
    if not isinstance(spec, dict):
        return spec
    compact: dict[str, Any] = {}
    for key in ("type", "enum", "default", "format", "minimum", "maximum"):
        if key in spec:
            compact[key] = spec[key]
    description = spec.get("description")
    if description:
        compact["description"] = _first_sentence(description, MAX_PROPERTY_DESCRIPTION)
    for key in ("anyOf", "oneOf"):
        branches = spec.get(key)
        if isinstance(branches, list):
            compact[key] = [_compact_schema(branch) for branch in branches]
    if "items" in spec:
        compact["items"] = _compact_schema(spec["items"])
    return compact


def _json_path(data: Any, path: str) -> Any:
    """Resolve a ``a.b[0].c`` style path against parsed JSON.

    Raises:
        ValueError: ``path`` is empty or contains no path tokens.
        KeyError, IndexError, TypeError: the path does not exist in ``data``.
    """
    tokens: list[str | int] = []
    for match in _PATH_TOKEN_RE.finditer(path or ""):
        key, index = match.groups()
        tokens.append(int(index) if index is not None else key)
    if not tokens:
        raise ValueError("path is empty")
    current = data
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(current, list):
                raise TypeError(f"cannot index non-array with [{token}]")
            current = current[token]
        else:
            if not isinstance(current, dict):
                raise TypeError(f"cannot read key {token!r} from a non-object")
            current = current[token]
    return current


class McpGateway:
    """Facade over an existing ``MCPServer`` registry.

    The registry is snapshotted at construction: tools added to the source
    server afterwards are not visible through the gateway. Invocation still
    goes through the SDK's ``Tool.run`` so argument validation, defaults and
    asynchronous tools behave exactly as they do on the flat server.
    """

    def __init__(self, source: MCPServer) -> None:
        self._source = source
        # ``_tool_manager`` is the SDK's registry; ``list_tools`` on it is the
        # synchronous equivalent of ``MCPServer.list_tools`` and returns the
        # raw Tool objects (fn, description, parameters) we need here.
        self._tools = {tool.name: tool for tool in source._tool_manager.list_tools()}

    @property
    def tool_names(self) -> list[str]:
        """Return the names of the wrapped tools, sorted."""
        return sorted(self._tools)

    def search(
        self,
        query: str | None = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Return compact tool rows filtered by a case-insensitive substring."""
        needle = (query or "").strip().lower()
        rows: list[dict[str, Any]] = []
        for name in sorted(self._tools):
            tool = self._tools[name]
            description = tool.description or ""
            if needle and needle not in name.lower() and needle not in description.lower():
                continue
            rows.append(
                {
                    "name": name,
                    "required": list(tool.parameters.get("required") or []),
                    "description": _first_sentence(description, MAX_SEARCH_DESCRIPTION),
                }
            )
        page_limit = _clamp_int(limit, 1, MAX_SEARCH_LIMIT, DEFAULT_SEARCH_LIMIT)
        page_offset = _clamp_int(offset, 0, 10**9, 0)
        page = rows[page_offset : page_offset + page_limit]
        return {
            "total": len(rows),
            "offset": page_offset,
            "limit": page_limit,
            "count": len(page),
            "tools": page,
        }

    def schema(self, tool: str) -> dict[str, Any]:
        """Return one tool's compact input schema, or a typed unknown-tool error."""
        tool_info = self._tools.get(tool)
        if tool_info is None:
            return _unknown_tool(tool)
        parameters = tool_info.parameters or {}
        properties = parameters.get("properties")
        compact_properties = (
            {name: _compact_schema(spec) for name, spec in properties.items()}
            if isinstance(properties, dict)
            else {}
        )
        return {
            "name": tool,
            "description": _first_sentence(tool_info.description, MAX_SCHEMA_DESCRIPTION),
            "required": list(parameters.get("required") or []),
            "properties": compact_properties,
        }

    async def call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> dict[str, Any]:
        """Run one underlying tool and cap its JSON reply.

        A result that fits the budget is returned directly (a non-object result
        is wrapped in ``{"result": ...}``). A larger result is stored under
        :func:`results_dir` and replaced by a preview, its ``result_id``, the
        full token count and a next-step hint.
        """
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, dict):
            return _error(
                "invalid_arguments",
                "arguments must be a JSON object (tool, arguments=...)",
                tool=tool,
            )
        tool_info = self._tools.get(tool)
        if tool_info is None:
            return _unknown_tool(tool)
        budget = clamp_max_tokens(max_tokens)

        try:
            context = Context(
                mcp_server=self._source,
                subscriptions=getattr(self._source, "_subscriptions", None),
            )
            result = await tool_info.run(dict(arguments), context, convert_result=False)
        except Exception as exc:  # noqa: BLE001 - the gateway must never crash a call
            return _tool_error(tool, exc)

        try:
            text = _json_text(result)
        except Exception as exc:  # noqa: BLE001 - unusual non-JSON return values
            return _error(
                "serialization_error",
                f"tool {tool!r} returned a value that could not be serialized: {exc}",
                tool=tool,
            )

        total_tokens = estimate_tokens(text)
        if total_tokens <= budget:
            return result if isinstance(result, dict) else {"result": result}
        return self._store_oversized(tool, text, total_tokens, budget)

    def _store_oversized(
        self,
        tool: str,
        text: str,
        total_tokens: int,
        budget: int,
    ) -> dict[str, Any]:
        """Persist an oversized result and return its paged-preview envelope."""
        result_id = uuid.uuid4().hex
        try:
            _result_path(result_id).write_text(text, encoding="utf-8")
        except OSError as exc:
            return _error(
                "storage_error",
                f"could not store the full result: {exc}",
                tool=tool,
                total_tokens=total_tokens,
                preview=text[: budget * 3],
                hint="Retry call() with a larger max_tokens if the payload is needed.",
            )

        response: dict[str, Any] = {
            "result_id": result_id,
            "tool": tool,
            "total_tokens": total_tokens,
            "preview": text[: budget * 3],
            "next": (
                f'result_read(result_id="{result_id}") or '
                f'result_grep(result_id="{result_id}", pattern="...")'
            ),
            "hint": "Truncated preview (not evidence); the full JSON is stored.",
        }
        # Keep the whole envelope inside the same budget the caller set.
        while estimate_tokens(_json_text(response)) > budget and response["preview"]:
            response["preview"] = response["preview"][: len(response["preview"]) // 2]
        return response

    def result_read(
        self,
        result_id: str,
        offset_tokens: int = 0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        path: str | None = None,
    ) -> dict[str, Any]:
        """Read a stored result, optionally one JSON subtree, in token windows."""
        try:
            full_text = _load_result(result_id)
        except ValueError as exc:
            return _error("invalid_result_id", str(exc))
        except FileNotFoundError:
            return _error(
                "result_not_found",
                f"no stored result {result_id!r}",
                hint="Result ids are ephemeral; re-run call() to get a fresh one.",
            )
        except OSError as exc:
            return _error("storage_error", f"could not read result: {exc}")

        if path:
            try:
                full_text = _json_text(_json_path(json.loads(full_text), path))
            except json.JSONDecodeError as exc:
                return _error("corrupt_result", f"stored result is not valid JSON: {exc}")
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                return _error("invalid_path", f"path {path!r} was not found: {exc}")

        budget = clamp_max_tokens(max_tokens)
        offset = _clamp_int(offset_tokens, 0, 10**9, 0)
        start = offset * 4
        end = start + budget * 4
        window = full_text[start:end]
        response: dict[str, Any] = {
            "result_id": result_id,
            "total_tokens": estimate_tokens(full_text),
            "offset_tokens": offset,
            "max_tokens": budget,
            "next_offset_tokens": end // 4 if end < len(full_text) else None,
            "text": window,
        }
        if path:
            response["path"] = path
        return response

    def result_grep(
        self,
        result_id: str,
        pattern: str,
        regex: bool = False,
        context_lines: int = 1,
        max_matches: int = DEFAULT_MAX_MATCHES,
    ) -> dict[str, Any]:
        """Search a stored result line by line, with bounded context."""
        try:
            text = _load_result(result_id)
        except ValueError as exc:
            return _error("invalid_result_id", str(exc))
        except FileNotFoundError:
            return _error(
                "result_not_found",
                f"no stored result {result_id!r}",
                hint="Result ids are ephemeral; re-run call() to get a fresh one.",
            )
        except OSError as exc:
            return _error("storage_error", f"could not read result: {exc}")

        if not isinstance(pattern, str) or not pattern:
            return _error("invalid_pattern", "pattern must be a non-empty string")
        compiled: re.Pattern[str] | None = None
        if regex:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                return _error("invalid_pattern", f"invalid regular expression: {exc}")

        context = _clamp_int(context_lines, 0, MAX_CONTEXT_LINES, 1)
        limit = _clamp_int(max_matches, 1, MAX_MAX_MATCHES, DEFAULT_MAX_MATCHES)
        lines = text.splitlines()
        matches: list[dict[str, Any]] = []
        truncated = False
        for index, line in enumerate(lines):
            hit = compiled.search(line) if compiled is not None else pattern in line
            if not hit:
                continue
            if len(matches) >= limit:
                truncated = True
                break
            lo = max(0, index - context)
            hi = min(len(lines), index + 1 + context)
            matches.append(
                {
                    "line": index + 1,
                    "text": line,
                    "before": lines[lo:index],
                    "after": lines[index + 1 : hi],
                }
            )
        return {
            "result_id": result_id,
            "pattern": pattern,
            "regex": bool(regex),
            "context_lines": context,
            "match_count": len(matches),
            "truncated": truncated,
            "matches": matches,
        }


def build_gateway_server(source: MCPServer | None = None) -> MCPServer:
    """Create an MCP server that exposes only the gateway meta-tools.

    Args:
        source: Registry to wrap. Defaults to the full CODEVANTA server from
            :func:`codevanta.mcp_server.server.build_server`; tests may pass a
            small server with synthetic tools. The source server is not
            modified.

    Returns:
        A server registering ``search``, ``schema``, ``call``, ``result_read``
        and ``result_grep`` and nothing else.
    """
    underlying = source if source is not None else build_server()
    gateway = McpGateway(underlying)
    server = MCPServer(
        name=f"{SERVER_NAME}-Gateway",
        version=SERVER_VERSION,
        instructions=GATEWAY_INSTRUCTIONS,
    )

    @server.tool(
        description=(
            "List CODEVANTA tools compactly: name, required parameters and the "
            "first sentence of the description. Filter with a case-insensitive "
            "query and page with limit (1-100, default 20) and offset. No full "
            "schemas are returned; call schema(tool=...) for one."
        )
    )
    def search(
        query: str | None = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        return gateway.search(query=query, limit=limit, offset=offset)

    @server.tool(
        description=(
            "Return one tool's compact input schema: required names plus each "
            "property's type, enum, default and a truncated description. Use "
            "search(query=...) first if the tool name is unknown."
        )
    )
    def schema(tool: str) -> dict[str, Any]:
        return gateway.schema(tool)

    @server.tool(
        description=(
            "Run one CODEVANTA tool by name with a JSON arguments object and "
            "return its JSON result. Replies over max_tokens (default 1500, "
            "clamped to 100-50000) are stored under ~/.codevanta/mcp_results "
            "and replaced by a result_id, a truncated preview and the full "
            "token count; page with result_read or search with result_grep."
        )
    )
    async def call(
        tool: str,
        arguments: dict[str, Any] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> dict[str, Any]:
        return await gateway.call(tool, arguments=arguments, max_tokens=max_tokens)

    @server.tool(
        description=(
            "Read a stored result by result_id in token windows: offset_tokens "
            "(default 0) and max_tokens (default 1500, clamped to 100-50000). "
            "Pass path (for example 'items[0].name' or 'settings[3]') to read "
            "one JSON subtree instead of the raw text."
        )
    )
    def result_read(
        result_id: str,
        offset_tokens: int = 0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        path: str | None = None,
    ) -> dict[str, Any]:
        return gateway.result_read(
            result_id,
            offset_tokens=offset_tokens,
            max_tokens=max_tokens,
            path=path,
        )

    @server.tool(
        description=(
            "Search a stored result line by line. The pattern is a plain "
            "substring unless regex=true. Returns matching lines with up to "
            "context_lines (0-5, default 1) before/after and at most "
            "max_matches (1-100, default 20) hits."
        )
    )
    def result_grep(
        result_id: str,
        pattern: str,
        regex: bool = False,
        context_lines: int = 1,
        max_matches: int = DEFAULT_MAX_MATCHES,
    ) -> dict[str, Any]:
        return gateway.result_grep(
            result_id,
            pattern,
            regex=regex,
            context_lines=context_lines,
            max_matches=max_matches,
        )

    return server


def serve_gateway(transport: str = "stdio", port: int | None = None) -> None:
    """Serve the gateway meta-tools.

    ``stdio`` is the default and the same transport existing MCP clients use.
    ``sse`` and ``streamable-http`` bind loopback on ``port`` (default
    :data:`codevanta.mcp_server.server.DEFAULT_PORT`); there is deliberately no
    host/``allow_remote`` parameter because the gateway exposes the same
    file-reading tools and should stay local.

    Args:
        transport: One of :data:`SUPPORTED_TRANSPORTS`.
        port: Bind port for HTTP transports; ``None`` uses the default, ``0``
            picks a free port.

    Raises:
        AnalysisError: Unknown transport or an invalid port.
    """
    if transport not in SUPPORTED_TRANSPORTS:
        supported = ", ".join(SUPPORTED_TRANSPORTS)
        raise AnalysisError(
            f"unknown MCP transport {transport!r}; supported transports: {supported}"
        )
    server = build_gateway_server()
    if transport == "stdio":
        server.run(transport="stdio")
        return

    bind_port = DEFAULT_PORT if port is None else port
    if isinstance(bind_port, bool) or not isinstance(bind_port, int) or not 0 <= bind_port <= 65535:
        raise AnalysisError(
            f"invalid MCP port {bind_port!r}; expected an integer in 0..65535"
        )
    server.run(
        transport=cast(HttpTransport, transport),
        host=DEFAULT_HOST,
        port=bind_port,
        transport_security=transport_security(DEFAULT_HOST),
    )
