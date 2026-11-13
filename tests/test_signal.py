"""Signal-lane tests: sigrok .sr archives, UART decoder-lite, sigrok-cli wrap.

All offline: the ``.sr`` archive is built in-test, the UART capture is a
synthetic sample buffer, and the sigrok-cli wrapper is exercised through an
injected fake runner, never a real process.
"""

from __future__ import annotations

import json
import re
import subprocess
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import sigrok_cli_wrap, sigrok_sr, uart_decode
from codevanta.analysis.sigrok_cli_wrap import (
    SIGROK_MISSING_MESSAGE,
    decode_with_sigrok,
    parse_sigrok_output,
    sigrok_available,
)
from codevanta.analysis.sigrok_sr import summarize_session
from codevanta.analysis.uart_decode import decode_uart, decode_uart_file
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.mcp_server import ext_signal

runner_cli = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(result: Result) -> dict:
    text = _plain(result.stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


# --------------------------------------------------------------------------
# shared synthetic-capture helpers
# --------------------------------------------------------------------------

SPB = 10  # samples per bit used by the synthetic UART captures


def expand(bits: list[int], spb: int = SPB) -> list[int]:
    """Expand one logic level per bit into ``spb`` samples per bit."""
    return [bit for bit in bits for _ in range(spb)]


def uart_frame(
    value: int,
    *,
    data_bits: int = 8,
    parity_bit: int | None = None,
    stop_bits: int = 1,
    spb: int = SPB,
) -> list[int]:
    """One UART frame starting at a falling edge (caller adds idle around it)."""
    seq = [0]  # start bit
    for k in range(data_bits):
        seq.append((value >> k) & 1)  # LSB first
    if parity_bit is not None:
        seq.append(parity_bit)
    seq.extend([1] * stop_bits)
    return expand(seq, spb)


def make_sr_zip(
    path: Path,
    *,
    version: str | None = "2",
    metadata: str = (
        "device=DSLogic Plus\n"
        "samplerate=1 MHz\n"
        "capturefile=logic-1\n"
        "unitsize=2\n"
        "numchannels=4\n"
    ),
    channels: dict[int, str] | None = None,
    logic_sizes: dict[str, int] | None = None,
    annotations: str | None = "3-10: start\n11-20: data\n",
) -> Path:
    """Build one synthetic sigrok session archive for the tests."""
    if channels is None:
        channels = {0: "D0", 1: "D1", 2: "D2", 3: "D3"}
    if logic_sizes is None:
        logic_sizes = {"logic-1.1": 2048}
    with zipfile.ZipFile(path, "w") as zf:
        if version is not None:
            zf.writestr("version", version)
        zf.writestr("metadata", metadata)
        for index, name in channels.items():
            zf.writestr(f"channels/{index}", name)
        for name, size in logic_sizes.items():
            zf.writestr(name, bytes(size))
        if annotations is not None:
            zf.writestr("annotations", annotations)
    return path


class TestSrSummary:
    """``.sr`` archive summarization."""

    def test_happy_path(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "session.sr")
        result = summarize_session(path)
        assert result.version == "2"
        assert result.samplerate_hz == 1_000_000
        assert result.device == "DSLogic Plus"
        assert result.numchannels == 4
        assert [(c.index, c.name) for c in result.channels] == [
            (0, "D0"),
            (1, "D1"),
            (2, "D2"),
            (3, "D3"),
        ]
        assert [f.name for f in result.logic_files] == ["logic-1.1"]
        assert result.logic_files[0].size_bytes == 2048
        assert result.annotations_count == 2
        assert result.truncated is False
        assert result.warnings == []
        assert result.evidence.source == "sig.sr"
        assert result.evidence.confidence is Confidence.HIGH

    def test_khz_and_plain_samplerate(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr", metadata="samplerate=100 kHz\n")
        assert summarize_session(path).samplerate_hz == 100_000
        path = make_sr_zip(tmp_path / "b.sr", metadata="samplerate=9600\n")
        assert summarize_session(path).samplerate_hz == 9600

    def test_unparsable_samplerate_warns(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr", metadata="samplerate=very fast\n")
        result = summarize_session(path)
        assert result.samplerate_hz is None
        assert any("unparsable samplerate" in w for w in result.warnings)

    def test_unparsable_numchannels_warns(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr", metadata="numchannels=lots\n")
        result = summarize_session(path)
        assert result.numchannels is None
        assert any("unparsable numchannels" in w for w in result.warnings)

    def test_numchannels_mismatch_warns(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr", metadata="numchannels=16\n")
        result = summarize_session(path)
        assert result.numchannels == 16
        assert any("numchannels metadata says 16" in w for w in result.warnings)

    def test_no_channel_info_warns(self, tmp_path: Path) -> None:
        path = make_sr_zip(
            tmp_path / "a.sr", metadata="device=x\n", channels={}, annotations=None
        )
        result = summarize_session(path)
        assert result.channels == ()
        assert result.annotations_count is None
        assert any("no channels/ directory" in w for w in result.warnings)

    def test_channel_cap_truncates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_sr, "MAX_CHANNELS", 2)
        path = make_sr_zip(tmp_path / "a.sr", channels={i: f"D{i}" for i in range(4)})
        result = summarize_session(path)
        assert len(result.channels) == 2
        assert result.truncated is True

    def test_logic_cap_truncates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_sr, "MAX_LOGIC_FILES", 1)
        path = make_sr_zip(
            tmp_path / "a.sr", logic_sizes={"logic-1.1": 8, "logic-1-2.1": 16}
        )
        result = summarize_session(path)
        assert len(result.logic_files) == 1
        assert result.truncated is True

    def test_oversized_annotations_partial_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_sr, "MAX_MEMBER_BYTES", 64)
        big = "\n".join(f"{i}-{i + 1}: note" for i in range(50))
        path = make_sr_zip(tmp_path / "a.sr", annotations=big)
        result = summarize_session(path)
        assert result.annotations_count is not None
        assert result.annotations_count < 50
        assert result.truncated is True
        assert any("annotations member larger" in w for w in result.warnings)

    def test_empty_version_warns_and_drops_confidence(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr", version="   ")
        result = summarize_session(path)
        assert result.version is None
        assert result.evidence.confidence is Confidence.MEDIUM

    def test_not_a_zip_is_typed(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.sr"
        path.write_bytes(b"definitely not a zip archive")
        with pytest.raises(AnalysisError, match="not a readable ZIP archive"):
            summarize_session(path)

    def test_missing_members_is_typed(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.sr"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("version", "2")
        with pytest.raises(AnalysisError, match="missing required member\\(s\\): metadata"):
            summarize_session(path)

    def test_missing_file_is_typed(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError, match="not found"):
            summarize_session(tmp_path / "absent.sr")

    def test_wrong_path_type_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="path must be a str or Path"):
            summarize_session(123)  # type: ignore[arg-type]

    def test_entry_bomb_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_sr, "MAX_ENTRIES", 2)
        path = tmp_path / "many.sr"
        with zipfile.ZipFile(path, "w") as zf:
            for i in range(5):
                zf.writestr(f"channels/{i}", "x")
        with pytest.raises(AnalysisError, match="ZIP-bomb ceiling"):
            summarize_session(path)

    def test_size_bomb_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_sr, "MAX_TOTAL_UNCOMPRESSED", 16)
        path = make_sr_zip(tmp_path / "fat.sr")
        with pytest.raises(AnalysisError, match="ZIP-bomb ceiling"):
            summarize_session(path)

    def test_to_dict_is_json_safe(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "a.sr")
        payload = summarize_session(path).to_dict()
        roundtrip = json.loads(json.dumps(payload))
        assert roundtrip["version"] == "2"
        assert roundtrip["evidence"]["source"] == "sig.sr"


class TestUartDecode:
    """UART decoder-lite: frames, markers, garbage tolerance, typed params."""

    def test_8n1_two_bytes(self) -> None:
        samples = (
            expand([1] * 10) + uart_frame(0x41) + uart_frame(0x7A) + expand([1] * 10)
        )
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert [item.value for item in result.bytes] == [0x41, 0x7A]
        assert all(item.ok for item in result.bytes)
        assert result.frames_found == 2
        assert result.ok_count == 2
        assert result.parity_errors == 0
        assert result.framing_errors == 0
        assert result.truncated is False
        assert result.scan_truncated is False
        assert result.config.to_dict() == {
            "samplerate_hz": 9600,
            "baud": 960,
            "data_bits": 8,
            "parity": "none",
            "stop_bits": 1,
        }
        assert result.evidence.source == "sig.uart"
        assert result.evidence.confidence is Confidence.MEDIUM

    def test_7e2_even_ok(self) -> None:
        # 'C' = 0x43 has three data-bit ones; even parity bit is 1.
        samples = expand([1] * 10) + uart_frame(0x43, data_bits=7, parity_bit=1, stop_bits=2)
        result = decode_uart(
            bytes(samples),
            samplerate_hz=9600,
            baud=960,
            data_bits=7,
            parity="even",
            stop_bits=2,
        )
        assert [item.value for item in result.bytes] == [0x43]
        assert result.ok_count == 1

    def test_7o1_odd_ok(self) -> None:
        # 'C' has three ones; odd parity bit is 0.
        samples = expand([1] * 10) + uart_frame(0x43, data_bits=7, parity_bit=0)
        result = decode_uart(
            bytes(samples), samplerate_hz=9600, baud=960, data_bits=7, parity="odd"
        )
        assert [item.value for item in result.bytes] == [0x43]
        assert result.parity_errors == 0

    def test_parity_error_marks_the_byte(self) -> None:
        # Even parity expected, wrong parity bit sent.
        samples = expand([1] * 10) + uart_frame(0x43, data_bits=7, parity_bit=0, stop_bits=2)
        result = decode_uart(
            bytes(samples),
            samplerate_hz=9600,
            baud=960,
            data_bits=7,
            parity="even",
            stop_bits=2,
        )
        assert len(result.bytes) == 1
        assert result.bytes[0].value == 0x43
        assert result.bytes[0].ok is False
        assert result.bytes[0].error == "parity"
        assert result.parity_errors == 1
        assert any("parity error" in w for w in result.warnings)

    def test_framing_error_marks_the_byte(self) -> None:
        # Stop bit driven low: framing error, byte still reported.
        frame = uart_frame(0x41)
        broken = frame[: 9 * SPB] + [0] * SPB  # stop-bit position forced low
        samples = expand([1] * 10) + broken + expand([1] * 10)
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert result.bytes[0].ok is False
        assert result.bytes[0].error == "framing"
        assert result.framing_errors == 1
        assert any("framing error" in w for w in result.warnings)

    def test_garbage_text_yields_zero_bytes_not_crash(self) -> None:
        result = decode_uart(b"Hello garbage capture payload", samplerate_hz=9600, baud=960)
        assert result.bytes == ()
        assert result.frames_found == 0

    def test_all_low_buffer_still_decodes_with_framing_errors(self) -> None:
        result = decode_uart(bytes(200), samplerate_hz=9600, baud=960)
        assert result.frames_found >= 1
        assert result.framing_errors == result.frames_found

    def test_single_sample_glitch_is_resynchronised(self) -> None:
        glitch = [1] * 10 + [0] + [1] * (9 * SPB)
        samples = glitch + uart_frame(0x41) + expand([1] * 10)
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert [item.value for item in result.bytes] == [0x41]
        assert result.frames_found == 1

    def test_capture_ending_inside_frame_warns(self) -> None:
        samples = expand([1] * 5) + uart_frame(0x41)[: 5 * SPB]
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert any("ends inside a frame" in w for w in result.warnings)

    def test_decoded_byte_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(uart_decode, "MAX_DECODED", 2)
        samples = expand([1] * 5) + uart_frame(1) + uart_frame(2) + uart_frame(4)
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert len(result.bytes) == 2
        assert result.truncated is True
        assert any("decoded-byte limit" in w for w in result.warnings)

    def test_scan_window_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(uart_decode, "MAX_SCAN_SAMPLES", 50)
        samples = expand([1] * 5) + uart_frame(0x41) + expand([1] * 400)
        result = decode_uart(bytes(samples), samplerate_hz=9600, baud=960)
        assert result.scan_truncated is True
        assert any("scan window capped" in w for w in result.warnings)

    def test_warning_cap_overflows_gracefully(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(uart_decode, "MAX_WARNINGS", 2)
        samples = expand([1] * 5)
        for _ in range(5):  # five parity-broken frames -> more than 2 warnings
            samples += uart_frame(0x43, data_bits=7, parity_bit=0, stop_bits=2)
            samples += expand([1] * 5)
        result = decode_uart(
            bytes(samples), samplerate_hz=9600, baud=960, data_bits=7, parity="even"
        )
        assert result.parity_errors == 5
        assert len(result.warnings) <= 3
        assert result.warnings[-1].endswith("...")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"samplerate_hz": 9600, "baud": 9600},  # 1 sample per bit
            {"samplerate_hz": 0},
            {"samplerate_hz": 9600, "baud": 49},
            {"samplerate_hz": 9600, "baud": 4_000_001},
            {"samplerate_hz": 9600, "parity": "mark"},
            {"samplerate_hz": 9600, "data_bits": 9},
            {"samplerate_hz": 9600, "stop_bits": 3},
            {"samplerate_hz": 9600.0},  # float, not int
            {"samplerate_hz": True},  # bool, not int
            {"samplerate_hz": "9600"},
        ],
    )
    def test_bad_params_are_typed(self, kwargs: dict) -> None:
        with pytest.raises(AnalysisError):
            decode_uart(bytes(400), **kwargs)

    def test_non_bytes_input_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="bytes-like"):
            decode_uart("010101", samplerate_hz=9600, baud=960)  # type: ignore[arg-type]

    def test_buffer_over_ceiling_is_typed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(uart_decode, "MAX_CAPTURE_BYTES", 16)
        with pytest.raises(AnalysisError, match="ceiling"):
            decode_uart(bytes(32), samplerate_hz=9600, baud=960)

    def test_bytearray_and_memoryview_inputs(self) -> None:
        samples = expand([1] * 5) + uart_frame(0x41)
        for wrapper in (bytearray(samples), memoryview(bytes(samples))):
            result = decode_uart(wrapper, samplerate_hz=9600, baud=960)
            assert [item.value for item in result.bytes] == [0x41]

    def test_to_dict_is_json_safe(self) -> None:
        samples = expand([1] * 5) + uart_frame(0x41)
        payload = decode_uart(bytes(samples), samplerate_hz=9600, baud=960).to_dict()
        roundtrip = json.loads(json.dumps(payload))
        assert roundtrip["bytes"][0]["char"] == "A"
        assert roundtrip["evidence"]["method"] == "falling_edge_scan"

    def test_decode_uart_file_happy_and_typed(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(expand([1] * 5) + uart_frame(0x41)))
        result = decode_uart_file(path, samplerate_hz=9600, baud=960)
        assert [item.value for item in result.bytes] == [0x41]
        with pytest.raises(AnalysisError, match="not found"):
            decode_uart_file(tmp_path / "absent.raw", samplerate_hz=9600)
        with pytest.raises(AnalysisError, match="path must be"):
            decode_uart_file(3, samplerate_hz=9600)  # type: ignore[arg-type]

    def test_decode_uart_file_over_ceiling_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(uart_decode, "MAX_CAPTURE_BYTES", 16)
        big = tmp_path / "big.raw"
        big.write_bytes(bytes(64))
        with pytest.raises(AnalysisError, match="ceiling"):
            decode_uart_file(big, samplerate_hz=9600)


# --------------------------------------------------------------------------
# sigrok-cli wrapper: canned parser + skip gate + fake runner
# --------------------------------------------------------------------------

CANNED_SIGROK_OUTPUT = """\
uart: 115200 baud, 8N1
uart: 100-110: TX DATA: 41 'A'
uart: 200-210: TX DATA: 7A 'z'
sample noise without a decoder prefix
* device closed
"""


class FakeOutcome:
    """A ``subprocess.CompletedProcess`` stand-in with plain attributes."""

    def __init__(self, returncode: int, stdout: object, stderr: object) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Record the command it is given and replay one canned outcome."""

    def __init__(self, outcome: FakeOutcome) -> None:
        self.outcome = outcome
        self.calls: list[tuple[tuple[str, ...], dict]] = []

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        self.calls.append((command, dict(kwargs)))
        return self.outcome


class TimeoutRunner:
    """A runner that always exceeds its budget, like a hung sigrok-cli."""

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        raise subprocess.TimeoutExpired(cmd="sigrok-cli", timeout=float(kwargs.get("timeout", 0)))


class MissingRunner:
    """A runner whose executable vanished between probe and call."""

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        raise FileNotFoundError("sigrok-cli")


class TestParseSigrokOutput:
    """Canned-transcript parsing of sigrok-cli decoder output."""

    def test_canned_output(self) -> None:
        result = parse_sigrok_output(CANNED_SIGROK_OUTPUT)
        assert [r.text for r in result.records] == [
            "115200 baud, 8N1",
            "TX DATA: 41 'A'",
            "TX DATA: 7A 'z'",
        ]
        assert result.records[0].start_sample is None  # plain form
        assert result.records[1].start_sample == 100
        assert result.records[1].end_sample == 110
        assert result.records[1].decoder == "uart"
        assert result.truncated is False
        assert any("unrecognised line skipped" in w for w in result.warnings)
        assert result.evidence.source == "sig.cli"
        assert result.evidence.confidence is Confidence.MEDIUM

    def test_empty_transcript_warns(self) -> None:
        result = parse_sigrok_output("")
        assert result.records == ()
        assert any("no decoder output lines" in w for w in result.warnings)

    def test_record_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sigrok_cli_wrap, "MAX_RECORDS", 2)
        result = parse_sigrok_output(CANNED_SIGROK_OUTPUT)
        assert len(result.records) == 2
        assert result.truncated is True
        assert any("record limit" in w for w in result.warnings)

    def test_non_string_transcript_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="transcript must be a string"):
            parse_sigrok_output(None)  # type: ignore[arg-type]

    def test_to_dict_is_json_safe(self) -> None:
        payload = parse_sigrok_output(CANNED_SIGROK_OUTPUT).to_dict()
        roundtrip = json.loads(json.dumps(payload))
        assert roundtrip["count"] == 3
        assert roundtrip["records"][1]["start_sample"] == 100


class TestSigrokSkipGate:
    """The wrapper never spawns anything when sigrok-cli is absent."""

    def test_available_false_when_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sigrok_cli_wrap.shutil, "which", lambda name: None)
        assert sigrok_available() is False

    def test_available_true_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sigrok_cli_wrap.shutil, "which", lambda name: "/usr/bin/sigrok-cli")
        assert sigrok_available() is True

    def test_decode_without_sigrok_is_typed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_cli_wrap.shutil, "which", lambda name: None)
        capture = tmp_path / "capture.sr"
        capture.write_bytes(b"zip")
        with pytest.raises(AnalysisError, match=re.escape(SIGROK_MISSING_MESSAGE)):
            decode_with_sigrok(capture, "uart")
        assert "https://sigrok.org" in SIGROK_MISSING_MESSAGE  # install hint present


class TestDecodeWithSigrok:
    """Runner-injected execution against canned sigrok-cli output."""

    def _capture(self, tmp_path: Path) -> Path:
        capture = tmp_path / "capture.sr"
        capture.write_bytes(b"zip")
        return capture

    def test_happy_run(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(0, CANNED_SIGROK_OUTPUT, ""))
        result = decode_with_sigrok(capture, "uart", runner=fake)
        assert len(result.records) == 3
        assert fake.calls[0][0] == ("sigrok-cli", "-i", str(capture), "-P", "uart")
        assert fake.calls[0][1]["timeout"] == 30.0
        assert result.transcript_path is None

    def test_out_dir_preserves_transcript(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        out_dir = tmp_path / "out"
        fake = FakeRunner(FakeOutcome(0, CANNED_SIGROK_OUTPUT, ""))
        result = decode_with_sigrok(capture, "uart", out_dir=out_dir, runner=fake)
        assert result.transcript_path is not None
        saved = Path(result.transcript_path)
        assert saved.name == "sigrok-uart.txt"
        assert saved.read_text(encoding="utf-8") == CANNED_SIGROK_OUTPUT

    def test_bytes_stdout_is_decoded(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(0, CANNED_SIGROK_OUTPUT.encode(), b""))
        result = decode_with_sigrok(capture, "uart", runner=fake)
        assert len(result.records) == 3

    def test_none_stdout_parses_empty(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(0, None, ""))
        result = decode_with_sigrok(capture, "uart", runner=fake)
        assert result.records == ()
        assert any("no decoder output lines" in w for w in result.warnings)

    def test_nonzero_exit_is_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(3, "", "unknown decoder 'nope'"))
        with pytest.raises(AnalysisError, match="exited with code 3"):
            decode_with_sigrok(capture, "nope", runner=fake)

    def test_timeout_is_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        with pytest.raises(AnalysisError, match="exceeded its timeout"):
            decode_with_sigrok(capture, "uart", timeout=5, runner=TimeoutRunner())

    def test_timeout_out_of_range_is_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(0, "", ""))
        for bad in (0, 0.5, sigrok_cli_wrap.MAX_TIMEOUT + 1, "10", True):
            with pytest.raises(AnalysisError, match="timeout"):
                decode_with_sigrok(capture, "uart", timeout=bad, runner=fake)

    def test_vanished_executable_is_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        with pytest.raises(AnalysisError, match="vanished between the PATH probe"):
            decode_with_sigrok(capture, "uart", runner=MissingRunner())

    def test_runner_contract_violation_is_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome("zero", "", ""))
        with pytest.raises(AnalysisError, match="injection contract"):
            decode_with_sigrok(capture, "uart", runner=fake)

    def test_bad_decoder_names_are_typed(self, tmp_path: Path) -> None:
        capture = self._capture(tmp_path)
        fake = FakeRunner(FakeOutcome(0, "", ""))
        for bad in ("uart; rm -rf", "", "a" * 65, None, 42):
            with pytest.raises(AnalysisError, match="decoder"):
                decode_with_sigrok(capture, bad, runner=fake)  # type: ignore[arg-type]

    def test_missing_capture_is_typed(self, tmp_path: Path) -> None:
        fake = FakeRunner(FakeOutcome(0, "", ""))
        with pytest.raises(AnalysisError, match="capture file not found"):
            decode_with_sigrok(tmp_path / "absent.sr", "uart", runner=fake)

    def test_wrong_path_type_is_typed(self, tmp_path: Path) -> None:
        fake = FakeRunner(FakeOutcome(0, "", ""))
        with pytest.raises(AnalysisError, match="input_path must be"):
            decode_with_sigrok(7, "uart", runner=fake)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# CLI (codevanta signal ...) and MCP tools
# --------------------------------------------------------------------------


class TestSignalCli:
    """``codevanta signal sr|uart|decode`` through the main CLI app."""

    def test_sr_table_and_json(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "session.sr")
        table = runner_cli.invoke(app, ["signal", "sr", str(path)])
        assert table.exit_code == 0
        assert "sigrok session" in _output(table)
        assert "logic-1.1" in _output(table)
        assert "evidence: sig.sr" in _output(table)
        as_json = runner_cli.invoke(app, ["signal", "sr", str(path), "--json"])
        assert as_json.exit_code == 0
        payload = _payload(as_json)
        assert payload["samplerate_hz"] == 1_000_000

    def test_sr_error_exits_two(self, tmp_path: Path) -> None:
        result = runner_cli.invoke(app, ["signal", "sr", str(tmp_path / "absent.sr")])
        assert result.exit_code == 2
        assert "error:" in _output(result)

    def test_uart_table_and_json(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(expand([1] * 5) + uart_frame(0x41) + expand([1] * 5)))
        table = runner_cli.invoke(
            app, ["signal", "uart", str(path), "--samplerate", "9600", "--baud", "960"]
        )
        assert table.exit_code == 0
        assert "1 byte(s) decoded" in _output(table)
        assert "evidence: sig.uart" in _output(table)
        as_json = runner_cli.invoke(
            app,
            ["signal", "uart", str(path), "--samplerate", "9600", "--baud", "960", "--json"],
        )
        assert as_json.exit_code == 0
        assert _payload(as_json)["decoded_count"] == 1

    def test_uart_bad_parity_exits_two(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(400))
        result = runner_cli.invoke(
            app, ["signal", "uart", str(path), "--samplerate", "9600", "--parity", "mark"]
        )
        assert result.exit_code == 2
        assert "invalid parity" in _output(result)

    def test_uart_bad_stopbits_exits_two(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(400))
        result = runner_cli.invoke(
            app, ["signal", "uart", str(path), "--samplerate", "9600", "--stopbits", "3"]
        )
        assert result.exit_code == 2
        assert "invalid stopbits" in _output(result)

    def test_uart_missing_file_exits_two(self, tmp_path: Path) -> None:
        result = runner_cli.invoke(
            app, ["signal", "uart", str(tmp_path / "absent.raw"), "--samplerate", "9600"]
        )
        assert result.exit_code == 2
        assert "error:" in _output(result)

    def test_decode_is_skip_gated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sigrok_cli_wrap.shutil, "which", lambda name: None)
        capture = tmp_path / "capture.sr"
        capture.write_bytes(b"zip")
        result = runner_cli.invoke(app, ["signal", "decode", str(capture), "--decoder", "uart"])
        assert result.exit_code == 2
        assert "sigrok-cli is not on PATH" in _output(result)


class TestSignalMcp:
    """The three ext_signal MCP tools stay plain-dict typed."""

    def test_signal_sr(self, tmp_path: Path) -> None:
        path = make_sr_zip(tmp_path / "session.sr")
        payload = ext_signal.codevanta_signal_sr(str(path))
        assert payload["version"] == "2"
        assert payload["evidence"]["source"] == "sig.sr"

    def test_signal_sr_typed_error(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError):
            ext_signal.codevanta_signal_sr(str(tmp_path / "absent.sr"))
        with pytest.raises(AnalysisError, match="non-empty string"):
            ext_signal.codevanta_signal_sr("   ")

    def test_uart_decode(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(expand([1] * 5) + uart_frame(0x41) + expand([1] * 5)))
        payload = ext_signal.codevanta_uart_decode(str(path), samplerate_hz=9600, baud=960)
        assert payload["decoded_count"] == 1

    def test_uart_decode_typed_errors(self, tmp_path: Path) -> None:
        path = tmp_path / "capture.raw"
        path.write_bytes(bytes(400))
        with pytest.raises(AnalysisError, match="integer"):
            ext_signal.codevanta_uart_decode(str(path), samplerate_hz="9600")  # type: ignore[arg-type]
        with pytest.raises(AnalysisError, match="samples per bit"):
            ext_signal.codevanta_uart_decode(str(path), samplerate_hz=9600, baud=9600)








