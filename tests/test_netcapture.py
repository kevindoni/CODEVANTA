"""Tests for the network-capture lane (fake runners only; never real tshark).

``codevanta.analysis.net_capture`` never spawns a real tshark in the offline
tests: the background recorder goes through an injected ``capture_runner``
(a Popen-shaped starter returning a ``_FakeProcess`` that also writes the
canned pcap at the ``-w`` path), the target through the proc lane's
``proc_runner`` contract, and the offline summary through a ``summary_runner``
returning canned ``tshark -T fields`` TSV. The canned pcap bytes are built
exactly in the test (24-byte libpcap global header plus one 4-byte packet
record), so the recorded size and sha256 are provable without any packet
tooling.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import net_capture
from codevanta.analysis.net_capture import (
    MAX_ARGS,
    MAX_CAPTURE_SECONDS,
    capture_around,
    list_interfaces,
)
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_netcapture
from codevanta.mcp_server.ext_netcapture import (
    codevanta_net_capture,
    codevanta_net_interfaces,
)


class _FakeOutcome:
    """``subprocess.CompletedProcess``-shaped stand-in (run-shaped runners)."""

    def __init__(self, returncode: int, stdout: Any = b"", stderr: Any = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _RunShapedRunner:
    """Runner double for ``subprocess.run``-shaped seams; records commands."""

    def __init__(self, outcome: _FakeOutcome) -> None:
        self.outcome = outcome
        self.commands: list[list[str]] = []
        self.kwargs: list[dict[str, Any]] = []

    def __call__(self, command: Any, **kwargs: Any) -> _FakeOutcome:
        self.commands.append([str(part) for part in command])
        self.kwargs.append(dict(kwargs))
        return self.outcome


class _FakeProcess:
    """Popen-shaped handle: records the bounded join and the kill."""

    def __init__(self, returncode: int = 0) -> None:
        self.returncode: int | None = None
        self._code = returncode
        self.wait_calls = 0
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        self.wait_calls += 1
        self.returncode = self._code
        return self._code

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class _JoinTimeoutProcess(_FakeProcess):
    """A handle whose wait always raises: the bounded join must kill it."""

    def wait(self, timeout: float | None = None) -> int | None:
        self.wait_calls += 1
        raise subprocess.TimeoutExpired(cmd="tshark", timeout=timeout or 0.0)


class _SpawnRunner:
    """Popen-shaped starter double: writes the canned pcap at the -w path."""

    def __init__(self, pcap_bytes: bytes, process: _FakeProcess) -> None:
        self.pcap_bytes = pcap_bytes
        self.process = process
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> _FakeProcess:
        self.commands.append(list(command))
        pcap_path = Path(command[command.index("-w") + 1])
        pcap_path.write_bytes(self.pcap_bytes)
        return self.process


class _SpawnBoom:
    """Starter double that models tshark vanishing between probe and spawn."""

    def __call__(self, command: list[str], **kwargs: Any) -> _FakeProcess:
        raise FileNotFoundError("no such file: tshark")


def _minimal_pcap() -> bytes:
    """Exact bytes: libpcap global header (24) + one 4-byte packet record."""
    global_header = (
        (0xA1B2C3D4).to_bytes(4, "little")
        + (2).to_bytes(2, "little")  # major version
        + (4).to_bytes(2, "little")  # minor version
        + (0).to_bytes(4, "little")  # thiszone
        + (0).to_bytes(4, "little")  # sigfigs
        + (65535).to_bytes(4, "little")  # snaplen
        + (1).to_bytes(4, "little")  # network = Ethernet
    )
    packet_header = (
        (111).to_bytes(4, "little")  # ts_sec
        + (222).to_bytes(4, "little")  # ts_usec
        + (4).to_bytes(4, "little")  # incl_len
        + (4).to_bytes(4, "little")  # orig_len
    )
    return global_header + packet_header + b"\x00\x01\x02\x03"


_TSV = (
    "frame.number\tframe.len\tip.src\tip.dst\r\n"
    '"1"\t"60"\t"10.0.0.1"\t"93.184.216.34"\r\n'
)


@pytest.fixture(autouse=True)
def _reset_pcap_counter():
    """Reset the module-level pcap sequence counter around every test."""
    yield
    net_capture._PCAP_COUNTER = 0

def test_list_interfaces_parses_the_numbered_list() -> None:
    """Canned ``tshark -D`` output parses into bounded numbered records."""
    stdout = (
        "1. \\Device\\NPF_{GUID-1} (Ethernet 0)\n"
        "2. \\Device\\NPF_Loopback\n"
        "junk line without a number\n"
    )
    runner = _RunShapedRunner(_FakeOutcome(0, stdout, b""))

    payload = list_interfaces(capture_runner=runner)

    assert payload["available"] is True
    assert payload["count"] == 2
    assert payload["truncated"] is False
    assert payload["interfaces"][0] == {
        "number": 1,
        "device": "\\Device\\NPF_{GUID-1}",
        "description": "Ethernet 0",
    }
    assert payload["interfaces"][1] == {
        "number": 2,
        "device": "\\Device\\NPF_Loopback",
        "description": None,
    }
    assert any("junk line" in warning for warning in payload["warnings"])
    assert runner.commands == [["tshark", "-D"]]
    assert payload["evidence"]["source"] == "net.capture"
    assert payload["evidence"]["confidence"] == "high"
    assert json.loads(json.dumps(payload)) == payload


def test_list_interfaces_is_honest_when_tshark_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Probe false, a vanished executable and a nonzero exit: honest, no crash."""
    monkeypatch.setattr(net_capture, "tshark_available", lambda: False)

    payload = list_interfaces()
    assert payload["available"] is False
    assert payload["count"] == 0
    assert payload["interfaces"] == []
    assert "tshark" in payload["message"]
    assert "Npcap" in payload["message"] and "administrator" in payload["message"]
    assert payload["evidence"]["confidence"] == "low"

    class _Boom:
        """Runner that models tshark vanishing between probe and call."""

        def __call__(self, command: Any, **kwargs: Any) -> _FakeOutcome:
            raise FileNotFoundError("tshark")

    vanished = list_interfaces(capture_runner=_Boom())
    assert vanished["available"] is False
    assert any("vanished" in warning for warning in vanished["warnings"])

    failing = list_interfaces(capture_runner=_RunShapedRunner(_FakeOutcome(2, b"", b"err")))
    assert failing["available"] is False
    assert "code 2" in failing["message"]


def test_capture_around_happy_path_records_and_summarises(tmp_path: Path) -> None:
    """Fake spawn writes the canned pcap, fake target exits 0, summary reads it."""
    pcap_bytes = _minimal_pcap()
    process = _FakeProcess(returncode=0)
    spawn = _SpawnRunner(pcap_bytes, process)
    proc_runner = _RunShapedRunner(_FakeOutcome(0, b"hello\n", b""))
    summary = _RunShapedRunner(_FakeOutcome(0, _TSV, b""))

    payload = capture_around(
        "fake-tool",
        ["--get", "x"],
        2,
        "1",
        tmp_path,
        proc_runner=proc_runner,
        capture_runner=spawn,
        summary_runner=summary,
    ).to_dict()

    assert payload["available"] is True
    pcap_path = Path(payload["pcap_path"] or "")
    assert re.match(r"net_capture_\d+\.pcap$", pcap_path.name)
    assert pcap_path.is_file() and pcap_path.parent == tmp_path
    assert payload["pcap_bytes"] == len(pcap_bytes)
    assert payload["pcap_sha256"] == hashlib.sha256(pcap_bytes).hexdigest()
    assert payload["target_argv"] == ["fake-tool", "--get", "x"]
    assert payload["target_exit_code"] == 0
    assert payload["target_stdout"] == "hello\n"
    assert payload["target_timed_out"] is False
    # The recorder got the exact bounded auto-stop argv and the bounded join.
    assert spawn.commands == [
        [
            "tshark",
            "-i",
            "1",
            "-a",
            "duration:2",
            "-w",
            str(pcap_path),
            "-q",
        ]
    ]
    assert process.wait_calls == 1 and process.killed is False
    # The offline summary stage was invoked on the pcap path.
    assert summary.commands[0][:2] == ["tshark", "-r"]
    assert str(pcap_path) in summary.commands[0]
    assert payload["pcap_summary"]["count"] == 1
    assert payload["pcap_summary"]["fields"][0] == "frame.number"
    assert payload["evidence"]["source"] == "net.capture"
    assert payload["evidence"]["method"] == "tshark-around-run"
    assert payload["evidence"]["confidence"] == "high"
    assert json.loads(json.dumps(payload)) == payload

def test_capture_around_rejects_out_of_range_capture_seconds(tmp_path: Path) -> None:
    """Below 1, above MAX_CAPTURE_SECONDS, and non-ints are typed errors."""
    for bad in (0, -5, MAX_CAPTURE_SECONDS + 1, True, 2.5):
        with pytest.raises(AnalysisError, match="capture_seconds"):
            capture_around("fake-tool", [], bad, "1", tmp_path)  # type: ignore[arg-type]


def test_capture_around_enforces_the_argument_cap(tmp_path: Path) -> None:
    """More than MAX_ARGS target arguments is a typed error naming the cap."""
    args = [f"--arg{index}" for index in range(MAX_ARGS + 1)]
    with pytest.raises(AnalysisError, match=f"at most {MAX_ARGS}"):
        capture_around("fake-tool", args, 2, "1", tmp_path)


def test_capture_around_unavailable_runs_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No tshark on PATH: honest result, no pcap, and the target is NOT run."""
    monkeypatch.setattr(net_capture, "tshark_available", lambda: False)

    payload = capture_around("fake-tool", [], 2, "1", tmp_path).to_dict()

    assert payload["available"] is False
    assert payload["pcap_path"] is None
    assert payload["pcap_bytes"] is None
    assert payload["target_exit_code"] is None
    assert payload["target_argv"] == []
    assert "tshark" in payload["message"] and "Npcap" in payload["message"]
    assert payload["evidence"]["method"] == "availability-probe"
    assert payload["evidence"]["confidence"] == "low"
    assert list(tmp_path.iterdir()) == []  # nothing was written or run
    assert json.loads(json.dumps(payload)) == payload


def test_capture_around_tshark_start_failure_is_typed(tmp_path: Path) -> None:
    """A spawn failure surfaces as a typed error naming the tshark-start stage."""
    with pytest.raises(AnalysisError, match="tshark-start"):
        capture_around(
            "fake-tool",
            [],
            2,
            "1",
            tmp_path,
            capture_runner=_SpawnBoom(),
            summary_runner=_RunShapedRunner(_FakeOutcome(0, _TSV, b"")),
        )


def test_capture_around_bounded_join_kills_a_stuck_tshark(tmp_path: Path) -> None:
    """A tshark that never exits is killed by the bounded join, with a warning."""
    process = _JoinTimeoutProcess()
    spawn = _SpawnRunner(_minimal_pcap(), process)

    payload = capture_around(
        "fake-tool",
        [],
        2,
        "1",
        tmp_path,
        proc_runner=_RunShapedRunner(_FakeOutcome(0, b"", b"")),
        capture_runner=spawn,
        summary_runner=_RunShapedRunner(_FakeOutcome(0, _TSV, b"")),
    ).to_dict()

    assert process.killed is True
    assert any("tshark-join stage" in warning for warning in payload["warnings"])
    assert payload["pcap_summary"] is not None  # the pcap was written before the join


def test_ext_layer_wrappers_stay_honest_and_json_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The MCP-facing functions return the same honest payloads (no registry)."""
    monkeypatch.setattr(net_capture, "tshark_available", lambda: False)

    listing = codevanta_net_interfaces()
    assert listing["available"] is False
    assert json.loads(json.dumps(listing)) == listing

    result = codevanta_net_capture("fake-tool", [], 2, "1", tmp_path)
    assert result["available"] is False
    assert json.loads(json.dumps(result)) == result

    for description in (
        ext_netcapture.TOOL_DESCRIPTION_NET_INTERFACES,
        ext_netcapture.TOOL_DESCRIPTION_NET_CAPTURE,
    ):
        lowered = description.lower()
        assert "administrator" in lowered and "npcap" in lowered


