"""The persistent interactive gdb MI session lane (MCP layer)."""

from __future__ import annotations

from typing import Any

import pytest

from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_misession as mi


class _FakeTransport:
    """MI transport double: canned result chunks per read, prompt-delimited."""

    def __init__(self, chunks: list[list[str]] | None = None) -> None:
        self.sent: list[str] = []
        self.shutdown_calls = 0
        self.shutdown_result: tuple[int | None, bool] = (0, True)
        self._handshake_done = False
        self._chunks: list[list[str]] = [list(chunk) for chunk in (chunks or [])]

    def send(self, command: str) -> None:
        self.sent.append(command)

    def read_until_prompt(self, timeout: float) -> list[str]:
        if not self._handshake_done:
            self._handshake_done = True
            return ["=thread-group-added,id=\"i1\"", "(gdb)"]
        if self._chunks:
            return self._chunks.pop(0)
        return ["(gdb)"]  # a bare prompt: no result record

    def shutdown(self, timeout: float) -> tuple[int | None, bool]:
        self.shutdown_calls += 1
        return self.shutdown_result


@pytest.fixture()
def registry():
    """Give every test an empty session registry."""
    mi._REGISTRY.sessions.clear()
    mi._REGISTRY.next_number = 1
    yield mi._REGISTRY
    mi._REGISTRY.sessions.clear()


def _start(transport: _FakeTransport, target: str | None = None) -> dict[str, Any]:
    return mi.codevanta_mi_start(target, timeout=5.0, transport=transport)


def test_start_registers_a_ready_session(registry) -> None:
    payload = _start(_FakeTransport(), target="app.exe")

    assert payload["session_id"] == "mi-001"
    assert payload["state"] == "ready"
    assert payload["target"] == "app.exe"
    assert payload["timeout"] == 5.0
    assert "disposition_reason" in payload


def test_start_without_target_launches_a_bare_session(registry) -> None:
    payload = _start(_FakeTransport())

    assert payload["target"] is None
    assert payload["state"] == "ready"


def test_console_returns_the_transcript(registry) -> None:
    transport = _FakeTransport(chunks=[['^done,files=["app.exe"]', "(gdb)"]])
    _start(transport)
    payload = mi.codevanta_mi_console("mi-001", "-file-list-exec-source-files")

    assert payload["result_class"] == "done"
    assert payload["records"]
    assert "-file-list-exec-source-files" in transport.sent[-1]


def test_console_returns_mi_errors_as_data(registry) -> None:
    transport = _FakeTransport(chunks=[['^error,msg="No symbol table is loaded"', "(gdb)"]])
    _start(transport)

    payload = mi.codevanta_mi_console("mi-001", "-exec-run")

    assert payload["result_class"] == "error"
    entry = mi.codevanta_mi_status("mi-001")["recent_commands"][-1]
    assert entry["ok"] is True and entry["result_class"] == "error"


def test_console_refuses_gdb_exit_and_kill(registry) -> None:
    _start(_FakeTransport())

    for command in ("-gdb-exit", " -gdb-exit", "kill"):
        with pytest.raises(AnalysisError, match="codevanta_mi_close"):
            mi.codevanta_mi_console("mi-001", command)


def test_console_rejects_newlines_and_empty(registry) -> None:
    _start(_FakeTransport())

    with pytest.raises(AnalysisError):
        mi.codevanta_mi_console("mi-001", "run\nquit")
    with pytest.raises(AnalysisError):
        mi.codevanta_mi_console("mi-001", "   ")


def test_close_reports_a_verified_shutdown(registry) -> None:
    transport = _FakeTransport()
    _start(transport)

    payload = mi.codevanta_mi_close("mi-001")

    assert payload["clean"] is True
    assert payload["exit_code"] == 0
    assert payload["state"] == "closed"
    assert transport.shutdown_calls == 1
    assert any("-gdb-exit" in sent for sent in transport.sent)


def test_close_reports_an_unclean_shutdown_without_lying(registry) -> None:
    transport = _FakeTransport()
    transport.shutdown_result = (1, False)
    _start(transport)

    payload = mi.codevanta_mi_close("mi-001")

    assert payload["clean"] is False
    assert payload["warnings"]


def test_double_close_and_unknown_ids_are_typed_errors(registry) -> None:
    _start(_FakeTransport())
    mi.codevanta_mi_close("mi-001")

    with pytest.raises(AnalysisError, match="already closed"):
        mi.codevanta_mi_close("mi-001")
    with pytest.raises(AnalysisError, match="unknown session id"):
        mi.codevanta_mi_status("mi-999")
    with pytest.raises(AnalysisError, match="closed"):
        mi.codevanta_mi_console("mi-001", "-exec-run")


def test_status_lists_bounded_history(registry) -> None:
    transport = _FakeTransport(
        chunks=[["^done", "(gdb)"], ['^error,msg="no"', "(gdb)"]]
    )
    _start(transport)
    mi.codevanta_mi_console("mi-001", "-break-info")
    mi.codevanta_mi_console("mi-001", "-exec-run")

    status = mi.codevanta_mi_status("mi-001")

    assert status["session_id"] == "mi-001"
    assert [entry["command"] for entry in status["recent_commands"]] == [
        "-break-info",
        "-exec-run",
    ]


def test_sessions_lists_records(registry) -> None:
    _start(_FakeTransport())
    _start(_FakeTransport(), target="b.exe")

    listing = mi.codevanta_mi_sessions()

    assert listing["count"] == 2
    assert listing["max_sessions"] == mi.MAX_SESSIONS
    assert [row["session_id"] for row in listing["sessions"]] == ["mi-001", "mi-002"]


def test_full_registry_evicts_the_oldest_live_session_with_a_quit(registry) -> None:
    transports = []
    for _ in range(mi.MAX_SESSIONS):
        transport = _FakeTransport()
        transports.append(transport)
        _start(transport)

    _start(_FakeTransport())  # one over the bound

    assert transports[0].shutdown_calls == 1  # the oldest got a verified quit
    listing = mi.codevanta_mi_sessions()
    assert listing["count"] == mi.MAX_SESSIONS
    assert "mi-001" not in {row["session_id"] for row in listing["sessions"]}
