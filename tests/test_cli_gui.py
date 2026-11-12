"""CLI tests for the v0.1.0 completion surface: ``codevanta gui`` and ``mcp serve``.

Both commands bind sockets, so most tests only exercise the parts that must not
need one: the help text, input validation (port range, loopback-only bind
addresses, unknown MCP transport) and the exit codes the rest of the CLI already
uses. The two bind-failure tests do hold a port open, but only to prove that the
failure is reported as exit ``2`` instead of a traceback or uvicorn's exit ``3``.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner, Result

from codevanta.cli.main import app

runner = CliRunner()

#: ANSI escape sequences Rich emits when the captured console reports a TTY.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _output(result: Result) -> str:
    """Return stdout and stderr, so an assertion sees everything the CLI printed."""
    return result.output + (result.stderr or "")


def _squeeze(text: str) -> str:
    """Return ``text`` without ANSI escapes or whitespace.

    Rich wraps its option table at the terminal width, which differs between a
    local Windows console and the narrow Linux runners, so help-text assertions
    compare the squeezed form instead of a layout-dependent one.
    """
    return re.sub(r"\s+", "", _ANSI.sub("", text))


@contextmanager
def _taken_port() -> Iterator[int]:
    """Hold a listening socket open and yield its port, so a bind must fail."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        yield taken.getsockname()[1]


def test_gui_is_listed_in_the_top_level_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    flat = _squeeze(result.stdout)
    assert "gui" in flat
    assert "webdashboard" in flat


def test_gui_rejects_a_port_outside_the_tcp_range() -> None:
    result = runner.invoke(app, ["gui", "--port", "70000"])

    assert result.exit_code == 2
    assert "port must be within 0 .. 65535" in _output(result)


def test_gui_rejects_a_non_loopback_host() -> None:
    result = runner.invoke(app, ["gui", "--host", "8.8.8.8", "--no-browser"])

    assert result.exit_code == 2
    assert "loopback" in _output(result).lower()


def test_mcp_serve_exposes_the_transport_flags() -> None:
    result = runner.invoke(app, ["mcp", "serve", "--help"])

    assert result.exit_code == 0
    # Rich wraps the options table at the terminal width, so compare against the
    # help text with ANSI escapes and all whitespace removed: "--transport" may be
    # split across lines or padded on a narrow CI terminal.
    flat = _squeeze(result.stdout)
    for option in (
        "--transport",
        "--host",
        "--port",
        "--allow-remote",
        "streamable-http",
    ):
        assert option in flat, flat


@pytest.mark.parametrize("transport", ["bogus", "http", ""])
def test_mcp_serve_rejects_an_unknown_transport(transport: str) -> None:
    result = runner.invoke(app, ["mcp", "serve", "--transport", transport])

    assert result.exit_code == 2
    output = _output(result)
    assert "stdio" in output and "streamable-http" in output


def test_mcp_serve_rejects_a_non_loopback_host_without_allow_remote() -> None:
    result = runner.invoke(app, ["mcp", "serve", "--transport", "sse", "--host", "8.8.8.8"])

    assert result.exit_code == 2
    assert "allow_remote" in _output(result)


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_mcp_serve_maps_a_taken_port_to_exit_code_2(transport: str) -> None:
    """uvicorn reports a bind failure with ``sys.exit``; the CLI must exit 2."""
    with _taken_port() as port:
        result = runner.invoke(
            app,
            [
                "mcp",
                "serve",
                "--transport",
                transport,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
        )

    assert result.exit_code == 2
    assert f"could not bind 127.0.0.1:{port}" in _output(result)


def test_gui_maps_a_taken_port_to_exit_code_2() -> None:
    with _taken_port() as port:
        result = runner.invoke(app, ["gui", "--port", str(port), "--no-browser"])

    assert result.exit_code == 2
    assert f"could not bind 127.0.0.1:{port}" in _output(result)

