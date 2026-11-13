"""UART decoder-lite: pure Python, one wire, no dependencies.

The lane's honest sibling of sigrok's ``uart`` protocol decoder. Input is a
raw buffer of logic-0/1 samples -- one byte per sample, ``0`` low and
anything nonzero high -- plus the capture sample rate. The decoder looks for
idle-high regions, finds falling-edge start-bit candidates inside a bounded
scan window, samples the data bits (LSB first) at their baud mid-points,
optionally checks parity, and validates the stop bit(s).

This is a *decoder-lite*: no baud auto-detection, no glitch filtering beyond
mid-point confirmation, no multi-line capture. Its verdicts carry
:data:`Confidence.MEDIUM` evidence. Garbage input never raises: it yields
few or zero bytes plus warnings. Only malformed *parameters* (bad baud,
parity, data/stop-bit counts, sample rate, or a non-bytes buffer) raise the
typed :class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_BAUD",
    "DEFAULT_DATA_BITS",
    "DEFAULT_PARITY",
    "DEFAULT_STOP_BITS",
    "EVIDENCE_SOURCE",
    "MAX_CAPTURE_BYTES",
    "MAX_DECODED",
    "MAX_SCAN_SAMPLES",
    "MIN_SAMPLES_PER_BIT",
    "PARITIES",
    "STOP_BITS_CHOICES",
    "UartByte",
    "UartConfig",
    "UartResult",
    "decode_uart",
    "decode_uart_file",
]

#: Default line speed when the caller does not know better yet.
DEFAULT_BAUD = 115200

#: Default framing: 8 data bits, no parity, 1 stop bit.
DEFAULT_DATA_BITS = 8
DEFAULT_PARITY = "none"
DEFAULT_STOP_BITS = 1

#: Speeds the decoder accepts (bounded scan work).
MIN_BAUD = 50
MAX_BAUD = 4_000_000

#: Capture rate must give at least this many samples per baud bit.
MIN_SAMPLES_PER_BIT = 2.0

#: Framing choices.
PARITIES: tuple[str, ...] = ("none", "even", "odd")
STOP_BITS_CHOICES: tuple[int, ...] = (1, 2)
DATA_BITS_CHOICES: tuple[int, ...] = (7, 8)

#: Decoded bytes kept before the rest are summarised away.
MAX_DECODED = 256

#: Sample buffer accepted from one call (one byte per sample, 16 MiB).
MAX_CAPTURE_BYTES = 16 * 1024 * 1024

#: Bounded scan window: samples inspected per decode call.
MAX_SCAN_SAMPLES = 4_000_000

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "sig.uart"


@dataclass(frozen=True)
class UartConfig:
    """One validated framing configuration."""

    samplerate_hz: int
    baud: int
    data_bits: int
    parity: str
    stop_bits: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "samplerate_hz": self.samplerate_hz,
            "baud": self.baud,
            "data_bits": self.data_bits,
            "parity": self.parity,
            "stop_bits": self.stop_bits,
        }


@dataclass(frozen=True)
class UartByte:
    """One decoded byte with its per-byte verdict marker."""

    index: int
    value: int
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"index": self.index, "value": self.value}
        if 32 <= self.value < 127:
            data["char"] = chr(self.value)
        data["ok"] = self.ok
        if self.error is not None:
            data["error"] = self.error
        return data


@dataclass(frozen=True)
class UartResult:
    """Bounded decode of one UART capture with per-byte markers and stats."""

    config: UartConfig
    bytes: tuple[UartByte, ...] = ()
    frames_found: int = 0
    ok_count: int = 0
    parity_errors: int = 0
    framing_errors: int = 0
    samples_scanned: int = 0
    scan_truncated: bool = False
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="falling_edge_scan",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "bytes": [item.to_dict() for item in self.bytes],
            "decoded_count": len(self.bytes),
            "frames_found": self.frames_found,
            "ok_count": self.ok_count,
            "parity_errors": self.parity_errors,
            "framing_errors": self.framing_errors,
            "samples_scanned": self.samples_scanned,
            "scan_truncated": self.scan_truncated,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _check_int(name: str, value: Any, minimum: int, maximum: int) -> int:
    """Validate one bounded integer parameter, bools refused."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    if not minimum <= value <= maximum:
        raise AnalysisError(f"{name} {value} is out of range; expected {minimum} .. {maximum}")
    return value


def check_config(
    samplerate_hz: Any,
    baud: Any = DEFAULT_BAUD,
    data_bits: Any = DEFAULT_DATA_BITS,
    parity: Any = DEFAULT_PARITY,
    stop_bits: Any = DEFAULT_STOP_BITS,
) -> UartConfig:
    """Validate the framing parameters; malformed ones are typed errors."""
    rate = _check_int("samplerate", samplerate_hz, 1, 1_000_000_000)
    speed = _check_int("baud", baud, MIN_BAUD, MAX_BAUD)
    bits = _check_int("data_bits", data_bits, DATA_BITS_CHOICES[0], DATA_BITS_CHOICES[-1])
    if bits not in DATA_BITS_CHOICES:
        raise AnalysisError(f"data_bits must be one of {DATA_BITS_CHOICES}, got {bits}")
    if parity not in PARITIES:
        raise AnalysisError(f"parity must be one of {PARITIES}, got {parity!r}")
    stops = _check_int("stop_bits", stop_bits, 1, 2)
    if stops not in STOP_BITS_CHOICES:
        raise AnalysisError(f"stop_bits must be one of {STOP_BITS_CHOICES}, got {stops}")
    samples_per_bit = rate / speed
    if samples_per_bit < MIN_SAMPLES_PER_BIT:
        raise AnalysisError(
            f"samplerate {rate} at baud {speed} gives {samples_per_bit:.2f} samples "
            f"per bit; at least {MIN_SAMPLES_PER_BIT} are needed for mid-point sampling"
        )
    return UartConfig(
        samplerate_hz=rate, baud=speed, data_bits=bits, parity=parity, stop_bits=stops
    )


def _as_samples(buffer: Any) -> bytes:
    """Accept bytes-like buffers; refuse anything else with a typed error."""
    if isinstance(buffer, bytes):
        return buffer
    if isinstance(buffer, (bytearray, memoryview)):
        return bytes(buffer)
    raise AnalysisError(
        f"samples must be a bytes-like buffer of logic-0/1 values, got {type(buffer).__name__}"
    )


def decode_uart(
    samples: Any,
    *,
    samplerate_hz: int,
    baud: int = DEFAULT_BAUD,
    data_bits: int = DEFAULT_DATA_BITS,
    parity: str = DEFAULT_PARITY,
    stop_bits: int = DEFAULT_STOP_BITS,
) -> UartResult:
    """Decode one logic capture as UART frames; garbage in, warnings out."""
    config = check_config(samplerate_hz, baud, data_bits, parity, stop_bits)
    raw = _as_samples(samples)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise AnalysisError(
            f"capture is {len(raw)} samples; the ceiling is {MAX_CAPTURE_BYTES} samples"
        )
    data = memoryview(raw)
    total_bits = config.data_bits + (1 if config.parity != "none" else 0) + config.stop_bits + 1
    samples_per_bit = config.samplerate_hz / config.baud
    half = int(samples_per_bit / 2)
    scan_limit = min(len(data), MAX_SCAN_SAMPLES)
    scan_truncated = len(data) > MAX_SCAN_SAMPLES
    warnings: list[str] = []
    if scan_truncated:
        _note(warnings, f"scan window capped at {MAX_SCAN_SAMPLES} samples")

    decoded: list[UartByte] = []
    frames = 0
    ok_count = 0
    parity_errors = 0
    framing_errors = 0
    truncated = False

    def mid_of(edge: int, bit: int) -> int:
        """Sample index of ``bit``'s mid-point measured from its start edge."""
        return edge + half + int(bit * samples_per_bit)

    i = 0
    while i < scan_limit:
        if len(decoded) >= MAX_DECODED:
            truncated = True
            _note(warnings, f"decoded-byte limit {MAX_DECODED} reached; remainder dropped")
            break
        is_candidate = data[i] == 0 and (i == 0 or data[i - 1] != 0)
        if not is_candidate:
            i += 1  # not a falling edge: keep hunting
            continue
        # Falling edge at ``i`` (or a capture that starts mid-frame).
        start_mid = mid_of(i, 0)
        if start_mid >= scan_limit:
            _note(warnings, "capture ends inside a frame; trailing samples dropped")
            break
        if data[start_mid] != 0:
            i += 1  # glitch, not a start bit: resynchronise one sample later
            continue
        end_mid = mid_of(i, total_bits - 1)
        if end_mid >= scan_limit:
            _note(warnings, "capture ends inside a frame; trailing samples dropped")
            break
        frames += 1
        value = 0
        for bit in range(config.data_bits):
            if data[mid_of(i, bit + 1)] != 0:  # position 0 is the start bit
                value |= 1 << bit
        error: str | None = None
        if config.parity != "none":
            parity_bit = data[mid_of(i, config.data_bits + 1)] != 0
            ones = bin(value).count("1") + (1 if parity_bit else 0)
            good = (ones % 2 == 0) if config.parity == "even" else (ones % 2 == 1)
            if not good:
                error = "parity"
                parity_errors += 1
                _note(warnings, f"parity error on frame {frames}")
        parity_offset = 1 if config.parity != "none" else 0
        for stop in range(config.stop_bits):
            if data[mid_of(i, config.data_bits + parity_offset + 1 + stop)] == 0:

                error = "framing" if error is None else error
                framing_errors += 1
                _note(warnings, f"framing error on frame {frames}")
                break
        if error is None:
            ok_count += 1
        decoded.append(UartByte(index=frames, value=value, ok=error is None, error=error))
        i = end_mid + 1  # resume hunting after this frame's stop bit

    result = UartResult(
        config=config,
        bytes=tuple(decoded),
        frames_found=frames,
        ok_count=ok_count,
        parity_errors=parity_errors,
        framing_errors=framing_errors,
        samples_scanned=scan_limit,
        scan_truncated=scan_truncated,
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="falling_edge_scan",
            confidence=Confidence.MEDIUM,
            detail=(
                f"{config.data_bits}{config.parity[0].upper()}{config.stop_bits} @ "
                f"{config.baud}: {ok_count} ok / {parity_errors} parity / "
                f"{framing_errors} framing of {frames} frames"
            ),
        ),
    )
    return result


def decode_uart_file(
    path: str | Path,
    *,
    samplerate_hz: int,
    baud: int = DEFAULT_BAUD,
    data_bits: int = DEFAULT_DATA_BITS,
    parity: str = DEFAULT_PARITY,
    stop_bits: int = DEFAULT_STOP_BITS,
) -> UartResult:
    """Read one raw capture file (one byte per sample) and decode it."""
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"capture file not found: {target}")
    size = target.stat().st_size
    if size > MAX_CAPTURE_BYTES:
        raise AnalysisError(
            f"capture file is {size} bytes; the ceiling is {MAX_CAPTURE_BYTES} samples"
        )
    return decode_uart(
        target.read_bytes(),
        samplerate_hz=samplerate_hz,
        baud=baud,
        data_bits=data_bits,
        parity=parity,
        stop_bits=stop_bits,
    )


