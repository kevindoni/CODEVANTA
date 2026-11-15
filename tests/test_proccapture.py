"""Tests for the owned process capture lane (fake runners, plus one real run).

``codevanta.mcp_server.ext_proccapture`` never spawns a real process in the
offline tests: every run goes through an injected ``runner`` returning a canned
``CompletedProcess``-shaped outcome (the same double pattern as
``tests/test_livesessions.py``), so the reserve-id -> run -> register pipeline
is driven deterministically. Exactly one test performs a real execution --
``python -c "print('hello')"`` via ``sys.executable`` -- because a pipe capture
is the one thing a fake cannot prove. Everything else, including the timeout
path (the double raises ``subprocess.TimeoutExpired``) and the comparator, is
pure.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

import pytest

from codevanta.analysis.proc_capture import (
    MAX_ARGS,
    MAX_ENV_ENTRIES,
    MAX_OUTPUT_BYTES,
    MAX_TIMEOUT,
    capture_process,
    compare_captures,
)
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_proccapture
from codevanta.mcp_server.ext_proccapture import (
    MAX_PROC_SESSIONS,
    codevanta_proc_compare,
    codevanta_proc_run,
    codevanta_proc_sessions,
    codevanta_proc_status,
)


class _FakeOutcome:
    """``subprocess.CompletedProcess``-shaped stand-in."""

    def __init__(self, returncode: int, stdout: Any = b"", stderr: Any = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _RecordingRunner:
    """Runner double: returns a canned outcome and records what it was given."""

    def __init__(self, outcome: _FakeOutcome) -> None:
        self.outcome = outcome
        self.commands: list[list[str]] = []
        self.kwargs: list[dict[str, Any]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> _FakeOutcome:
        self.commands.append(list(command))
        self.kwargs.append(dict(kwargs))
        return self.outcome


class _TimeoutRunner:
    """Runner double that models the wall-clock budget ending the run."""

    def __init__(self, partial_stdout: bytes = b"") -> None:
        self.partial_stdout = partial_stdout
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> _FakeOutcome:
        self.commands.append(list(command))
        raise subprocess.TimeoutExpired(
            cmd=command[0], timeout=5.0, output=self.partial_stdout
        )


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the module-level registry around every test."""
    yield
    ext_proccapture._REGISTRY.sessions.clear()
    ext_proccapture._REGISTRY.next_number = 1


def _run_once(runner: Any, command: str = "fake-tool") -> dict[str, Any]:
    """Register one capture through the ext layer with ``runner``."""
    return codevanta_proc_run(command, ["--flag", "1"], runner=runner)
def test_fake_runner_capture_registers_a_bounded_session() -> None:
    """The happy path: one bounded capture, registered as proc-001/captured."""
    runner = _RecordingRunner(_FakeOutcome(0, b"hello out\n", b"warn\n"))

    payload = _run_once(runner)

    assert payload["session_id"] == "proc-001"
    assert payload["state"] == "captured"
    capture = payload["capture"]
    assert capture["command"] == ["fake-tool", "--flag", "1"]
    assert capture["exit_code"] == 0
    assert capture["stdout"] == "hello out\n"
    assert capture["stderr"] == "warn\n"
    assert capture["timed_out"] is False
    assert capture["stdout_truncated"] is False
    assert capture["stdout_sha256"] == hashlib.sha256(b"hello out\n").hexdigest()
    assert capture["stdout_bytes"] == len(b"hello out\n")
    assert capture["started_at"] <= capture["finished_at"]
    assert capture["duration_ms"] >= 0.0
    evidence = capture["evidence"]
    assert evidence["source"] == "proc.capture"
    assert evidence["method"] == "owned-subprocess"
    assert evidence["confidence"] == "high"
    # The runner receives the full argv and the bounded invocation contract.
    assert runner.commands == [["fake-tool", "--flag", "1"]]
    assert runner.kwargs[0]["capture_output"] is True
    assert runner.kwargs[0]["timeout"] <= MAX_TIMEOUT
    listing = codevanta_proc_sessions()
    assert listing["count"] == 1
    assert listing["sessions"][0]["state"] == "captured"


def test_real_python_capture_reports_hello(tmp_path: Any) -> None:
    """The one real execution: ``python -c print('hello')`` via pipes."""
    capture = capture_process(
        sys.executable,
        ["-c", "print('hello')"],
        working_directory=str(tmp_path),
        timeout=30,
    )
    assert capture.exit_code == 0
    assert "hello" in capture.stdout
    assert capture.timed_out is False
    assert capture.stdout_truncated is False
    assert capture.stdout_sha256 == hashlib.sha256(
        capture.stdout.encode("utf-8")
    ).hexdigest()
    assert capture.evidence.source == "proc.capture"


def test_output_truncation_flags_and_keeps_the_full_digest() -> None:
    """Over the byte cap the head is kept, the digest covers everything."""
    raw = b"x" * 5000
    runner = _RecordingRunner(_FakeOutcome(0, raw, b""))

    capture = capture_process("flood", runner=runner, max_output_bytes=64)

    assert capture.stdout_truncated is True
    assert len(capture.stdout) == 64
    assert capture.stdout_bytes == 5000
    assert capture.stdout_sha256 == hashlib.sha256(raw).hexdigest()
    assert any("5000" in warning for warning in capture.warnings)


def test_timeout_expired_is_an_honest_timed_out_capture() -> None:
    """A budget expiry keeps the partial output and reports ``timed_out``."""
    runner = _TimeoutRunner(partial_stdout=b"partial out")

    capture = capture_process("slow-worker", timeout=5, runner=runner)

    assert capture.timed_out is True
    assert capture.exit_code is None
    assert capture.stdout == "partial out"
    assert any("timeout" in warning for warning in capture.warnings)
    assert capture.evidence.extra["timed_out"] is True


def test_input_bounds_are_typed_errors() -> None:
    """Every bound fires a typed error before the runner is ever called."""

    def boom(command: Sequence[str], **kwargs: Any) -> _FakeOutcome:
        raise AssertionError("runner must not run on invalid input")

    with pytest.raises(AnalysisError, match="33 given"):
        capture_process("x", [str(i) for i in range(MAX_ARGS + 1)], runner=boom)
    with pytest.raises(AnalysisError, match="17 given"):
        capture_process(
            "x", env={f"K{i}": "v" for i in range(MAX_ENV_ENTRIES + 1)}, runner=boom
        )
    with pytest.raises(AnalysisError, match="max_output_bytes"):
        capture_process("x", max_output_bytes=MAX_OUTPUT_BYTES + 1, runner=boom)
    with pytest.raises(AnalysisError, match="out of range"):
        capture_process("x", timeout=MAX_TIMEOUT + 1, runner=boom)
    with pytest.raises(AnalysisError, match="command must be a non-empty string"):
        capture_process("   ", runner=boom)
    with pytest.raises(AnalysisError, match="working_directory"):
        capture_process("x", working_directory="Z:\\definitely-missing-dir", runner=boom)
    # A runner that breaks the injection contract is a typed error, too.
    with pytest.raises(AnalysisError, match="injection contract"):
        capture_process("x", runner=_RecordingRunner(_FakeOutcome(None)))  # type: ignore[arg-type]
    assert codevanta_proc_sessions()["count"] == 0


def test_timeout_above_ceiling_is_a_typed_error() -> None:
    """The ext layer forwards the wall-clock ceiling as a typed error."""
    runner = _RecordingRunner(_FakeOutcome(0))
    with pytest.raises(AnalysisError, match="1 .. 120"):
        codevanta_proc_run("x", timeout=MAX_TIMEOUT + 5, runner=runner)
    assert runner.commands == []
    assert codevanta_proc_sessions()["count"] == 0


def test_unknown_session_id_names_the_id() -> None:
    """status/compare on an unknown id fail, naming the id and what is known."""
    _run_once(_RecordingRunner(_FakeOutcome(0)))

    with pytest.raises(AnalysisError) as status_error:
        codevanta_proc_status("proc-999")
    assert "proc-999" in str(status_error.value)
    assert "proc-001" in str(status_error.value)

def test_compare_covers_all_four_verdicts() -> None:
    """identical / exit-mismatch / output-mismatch / divergent, and the diff."""
    a = _capture("same", 0, b"out\n")
    b = _capture("same", 0, b"out\n")

    twin = compare_captures(a, b)
    assert twin.verdict == "identical"
    assert twin.exit_match is True
    assert twin.stdout_digest_match is True
    assert twin.stdout_diff == ()

    exit_only = compare_captures(a, _capture("same", 3, b"out\n"))
    assert exit_only.verdict == "exit-mismatch"
    assert exit_only.stdout_digest_match is True

    output_only = compare_captures(a, _capture("same", 0, b"different\n"))
    assert output_only.verdict == "output-mismatch"
    assert output_only.stdout_digest_match is False
    assert output_only.stdout_diff
    assert any("-out" in line for line in output_only.stdout_diff)
    assert any("+different" in line for line in output_only.stdout_diff)

    divergent = compare_captures(a, _capture("same", 7, b"else\n"))
    assert divergent.verdict == "divergent"
    assert divergent.exit_match is False
    assert divergent.duration_delta_ms >= 0.0
    assert divergent.evidence.source == "proc.compare"
    assert divergent.evidence.confidence.value == "high"

    # The MCP layer wires the same comparator over registered ids.
    left = codevanta_proc_run("same", runner=_RecordingRunner(_FakeOutcome(0, b"out\n")))
    right = codevanta_proc_run("same", runner=_RecordingRunner(_FakeOutcome(0, b"out\n")))
    payload = codevanta_proc_compare(left["session_id"], right["session_id"])
    assert payload["left_session_id"] == "proc-001"
    assert payload["right_session_id"] == "proc-002"
    assert payload["verdict"] == "identical"

    with pytest.raises(AnalysisError, match="must be a ProcCapture"):
        compare_captures(None, a)  # type: ignore[arg-type]


def test_max_sessions_rejects_the_ninth_run() -> None:
    """The registry caps at MAX_PROC_SESSIONS records; the 9th run is refused."""

    def quick_run() -> dict[str, Any]:
        return codevanta_proc_run("fake-tool", runner=_RecordingRunner(_FakeOutcome(0)))

    for _ in range(MAX_PROC_SESSIONS):
        assert quick_run()["state"] == "captured"
    assert codevanta_proc_sessions()["count"] == MAX_PROC_SESSIONS

    with pytest.raises(AnalysisError) as excinfo:
        quick_run()
    message = str(excinfo.value)
    assert str(MAX_PROC_SESSIONS) in message
    assert "registry is full" in message


def test_sessions_listing_is_bounded() -> None:
    """The listing mirrors the registry: every record, at most the cap."""
    for index in range(3):
        codevanta_proc_run("fake-tool", runner=_RecordingRunner(_FakeOutcome(index)))
    listing = codevanta_proc_sessions()
    assert listing["count"] == 3
    assert listing["max_sessions"] == MAX_PROC_SESSIONS
    assert [record["session_id"] for record in listing["sessions"]] == [
        "proc-001",
        "proc-002",
        "proc-003",
    ]
    assert listing["sessions"][0]["command"] == ["fake-tool"]

    # A rejected run (out-of-range timeout) registers nothing; ids stay monotonic.
    with pytest.raises(AnalysisError):
        codevanta_proc_run("x", timeout=0.5, runner=_RecordingRunner(_FakeOutcome(0)))
    assert codevanta_proc_sessions()["count"] == 3
    payload = codevanta_proc_run("fake-tool", runner=_RecordingRunner(_FakeOutcome(0)))
    assert payload["session_id"] == "proc-004"
    assert codevanta_proc_status("proc-004")["capture"]["exit_code"] == 0

    with pytest.raises(AnalysisError) as compare_error:
        codevanta_proc_compare("proc-999", "proc-001")
    assert "proc-999" in str(compare_error.value)


def _capture(command: str, code: int, out: bytes) -> Any:
    """Build one capture through the fake runner (no registry involvement)."""
    return capture_process(command, runner=_RecordingRunner(_FakeOutcome(code, out, b"")))
