"""Optional bearer-token auth (``CODEVANTA_MCP_TOKEN``) for the HTTP MCP transports.

Lane contract: with ``CODEVANTA_MCP_TOKEN`` set, every request an
``sse``/``streamable-http`` app receives must carry the token in
``X-MCP-Token`` or ``Authorization: Bearer``; anything else gets ``401
unauthorized`` from the ASGI middleware before the SDK's app runs. With the
variable unset the behaviour is unchanged, and ``stdio`` never requires a
token.

The tests drive the same app-construction path :func:`run` uses (real
``build_server()`` plus ``_apply_token_auth``) over Starlette's in-process
ASGI test client, so no socket is bound.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from starlette.testclient import TestClient

from codevanta.mcp_server import server as mcp_server
from codevanta.mcp_server.server import TokenAuthMiddleware, build_server

TOKEN = "correct-horse-battery-staple"
HTTP_TRANSPORTS = ("sse", "streamable-http")


def _http_app(transport: str, *, token: str | None = None) -> Any:
    """Build the HTTP app exactly the way :func:`codevanta.mcp_server.server.run` does."""
    instance = build_server()
    if token is not None:
        mcp_server._apply_token_auth(instance, token)
    builder = instance.sse_app if transport == "sse" else instance.streamable_http_app
    return builder(host="127.0.0.1", transport_security=mcp_server.transport_security("127.0.0.1"))


def _client(app: Any) -> TestClient:
    """Test client pinned to a ``Host`` the transport-security allow-list accepts."""
    return TestClient(app, base_url="http://127.0.0.1")


def _probe(client: TestClient, transport: str, headers: Any = None) -> Any:
    """POST at the transport's message endpoint; a 4xx from the SDK proves pass-through."""
    if transport == "sse":
        # No live SSE session, so the SDK answers 404 "Could not find session".
        return client.post("/messages/?session_id=probe", headers=headers)
    # No MCP session id, so the SDK answers 400 "Missing session ID".
    accept = [("Accept", "application/json, text/event-stream")]
    extra = list(headers) if isinstance(headers, list) else list((headers or {}).items())
    return client.post(
        "/mcp",
        headers=accept + extra,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )


def _capture_sdk_run(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, str, dict]]:
    """Replace ``MCPServer.run`` with a recorder so no transport ever serves."""
    seen: list[tuple[Any, str, dict]] = []

    def fake_run(self: Any, transport: str = "stdio", **kwargs: Any) -> None:
        seen.append((self, transport, kwargs))

    monkeypatch.setattr(MCPServer, "run", fake_run)
    return seen


# --- the env var itself ------------------------------------------------------


@pytest.mark.parametrize(
    ("env_value", "expected"),
    [(None, None), ("", None), ("   ", None), (" tok ", "tok")],
)
def test_remote_token_parses_the_env_var(
    monkeypatch: pytest.MonkeyPatch, env_value: str | None, expected: str | None
) -> None:
    monkeypatch.delenv(mcp_server.MCP_TOKEN_ENV, raising=False)
    if env_value is not None:
        monkeypatch.setenv(mcp_server.MCP_TOKEN_ENV, env_value)
    assert mcp_server.remote_token() == expected


# --- (a) correct credentials pass -------------------------------------------


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
def test_correct_header_token_passes_through(transport: str) -> None:
    with _client(_http_app(transport, token=TOKEN)) as client:
        response = _probe(client, transport, {"X-MCP-Token": TOKEN})
    assert response.status_code != 401


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
def test_correct_bearer_credential_passes_through(transport: str) -> None:
    with _client(_http_app(transport, token=TOKEN)) as client:
        response = _probe(client, transport, {"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code != 401


# --- (b)/(c) missing or wrong credentials fail ------------------------------


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
def test_missing_header_is_401_unauthorized(transport: str) -> None:
    with _client(_http_app(transport, token=TOKEN)) as client:
        response = _probe(client, transport)
    assert response.status_code == 401
    assert response.text == "unauthorized"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
@pytest.mark.parametrize(
    ("header_name", "header_value"),
    [
        ("X-MCP-Token", "wrong-token"),
        ("Authorization", "Bearer wrong-token"),
        ("Authorization", "bearer wrong-token"),
        ("Authorization", f"Basic {TOKEN}"),
    ],
)
def test_wrong_credential_is_401_unauthorized(
    transport: str, header_name: str, header_value: str
) -> None:
    with _client(_http_app(transport, token=TOKEN)) as client:
        response = _probe(client, transport, {header_name: header_value})
    assert response.status_code == 401
    assert response.text == "unauthorized"


def test_split_secret_across_headers_is_rejected() -> None:
    """One matching and one mismatching credential must fail closed."""
    app = _http_app("streamable-http", token=TOKEN)
    headers = [("X-MCP-Token", TOKEN), ("Authorization", "Bearer wrong-token")]
    with _client(app) as client:
        response = _probe(client, "streamable-http", headers)
    assert response.status_code == 401
    assert response.text == "unauthorized"


def test_repeated_identical_headers_pass_through() -> None:
    app = _http_app("streamable-http", token=TOKEN)
    duplicates = [("X-MCP-Token", TOKEN), ("X-MCP-Token", TOKEN)]
    with _client(app) as client:
        response = _probe(client, "streamable-http", duplicates)
    assert response.status_code != 401


# --- (d) env unset -> no auth layer -----------------------------------------


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
def test_token_env_unset_keeps_plain_sdk_behaviour(
    monkeypatch: pytest.MonkeyPatch, transport: str
) -> None:
    monkeypatch.delenv(mcp_server.MCP_TOKEN_ENV, raising=False)
    with _client(_http_app(transport)) as client:
        response = _probe(client, transport)
    assert response.status_code != 401
    assert response.text != "unauthorized"


# --- (e) stdio and the run() wiring -----------------------------------------


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
def test_run_guards_http_transports_when_token_set(
    monkeypatch: pytest.MonkeyPatch, transport: str
) -> None:
    monkeypatch.setenv(mcp_server.MCP_TOKEN_ENV, TOKEN)
    seen = _capture_sdk_run(monkeypatch)

    mcp_server.run(transport=transport)

    instance, seen_transport, kwargs = seen[0]
    assert seen_transport == transport
    assert "sse_app" in instance.__dict__
    assert "streamable_http_app" in instance.__dict__
    wrapped = instance.sse_app(transport_security=None, host="127.0.0.1")
    assert isinstance(wrapped, TokenAuthMiddleware)
    assert kwargs["transport_security"] is not None


def test_run_does_not_guard_when_token_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(mcp_server.MCP_TOKEN_ENV, raising=False)
    seen = _capture_sdk_run(monkeypatch)

    mcp_server.run(transport="streamable-http")

    instance, _, _ = seen[0]
    assert "sse_app" not in instance.__dict__
    assert "streamable_http_app" not in instance.__dict__


def test_stdio_run_never_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with the env var set, the stdio branch must stay auth-free."""
    monkeypatch.setenv(mcp_server.MCP_TOKEN_ENV, TOKEN)
    seen = _capture_sdk_run(monkeypatch)

    mcp_server.run(transport="stdio")

    instance, seen_transport, kwargs = seen[0]
    assert seen_transport == "stdio"
    assert kwargs == {}
    assert "sse_app" not in instance.__dict__
    assert "streamable_http_app" not in instance.__dict__


# --- middleware units --------------------------------------------------------


def test_middleware_passes_non_http_scopes_through() -> None:
    """lifespan must reach the wrapped app so the SDK app can still start up."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    async def exercise() -> None:
        await TokenAuthMiddleware(inner, TOKEN)({"type": "lifespan"}, None, None)

    asyncio.run(exercise())
    assert seen == ["lifespan"]

