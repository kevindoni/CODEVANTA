"""Minimal pure-Python PNG decoder and pixel differ for captured screenshots.

CODEVANTA captures screenshots as ordinary 8-bit PNG files. This module is
the read-only counterpart for *those* artifacts: it decodes a PNG well enough
to compare two of them pixel by pixel, entirely offline, with the standard
library only (:mod:`struct` and :mod:`zlib`). No imaging library is used,
nothing is executed, no network is touched.

What is decoded, honestly:

* 8-bit bit depth only, color types 0 (grayscale), 2 (RGB) and 6 (RGBA).
  Anything else -- 1/2/4/16-bit depths, palette (3), or the alpha-only
  color type 4 -- raises a typed :class:`AnalysisError` rather than
  guessing.
* Non-interlaced images only (``interlace method`` 0).
* All five scanline filters (None/Sub/Up/Average/Paeth) are reconstructed.
* Ancillary chunks are skipped; the CRC of every chunk that *is* read is
  verified, and a missing ``IHDR``/``IDAT``/``IEND`` chain is a typed
  error, never a silent fallback.

:func:`pixel_diff` turns two decoded images into a frozen, JSON-safe
:class:`ScreenshotDiff`: a changed-pixel ratio with the verdict thresholds
``identical`` (ratio ``0.0``), ``minor`` (``< 0.01``) and ``major``
(otherwise), plus a per-channel mean absolute delta summary. Images with
different dimensions are ``major`` by definition with an explanatory note,
because no aligned pixel comparison exists.

Bounds
------

An image is refused above :data:`MAX_PNG_PIXELS` pixels before any
decompression work, and the decompressed scanline stream is capped at its
mathematically expected size, so a decompression bomb cannot grow past the
bound.

Evidence discipline
-------------------

Every diff carries an :class:`~codevanta.evidence.models.Evidence` record
with source ``"compare.screenshots"``: exact local pixel metrics, high
confidence, no OCR and no rendering involved.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_PNG_PIXELS",
    "MINOR_RATIO_THRESHOLD",
    "ChannelDelta",
    "PngImage",
    "ScreenshotDiff",
    "decode_png",
    "load_png",
    "pixel_diff",
]

#: Hard pixel ceiling per image (``width * height``). 16 megapixels is the
#: documented bound: screenshots are small, and refusing early keeps a
#: hostile header from triggering expensive work.
MAX_PNG_PIXELS = 16_000_000

#: Verdict thresholds: a ratio strictly below this (and above zero) is minor.
MINOR_RATIO_THRESHOLD = 0.01

#: Magic signature every PNG file must start with (PNG spec 5.2).
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Supported color types -> channel count. Grayscale (0), RGB (2), RGBA (6).
_CHANNELS_BY_COLOR_TYPE: dict[int, int] = {0: 1, 2: 3, 6: 4}

#: Channel names per color type, in byte order, for the delta summary.
_CHANNEL_NAMES: dict[int, tuple[str, ...]] = {
    0: ("gray",),
    2: ("r", "g", "b"),
    6: ("r", "g", "b", "a"),
}

_EVIDENCE_SCREENSHOT_SOURCE = "compare.screenshots"


@dataclass(frozen=True)
class PngImage:
    """One decoded PNG: dimensions, color type and pixels as rows of tuples.

    ``pixels[row][column]`` is a tuple of ``int`` channel values (0..255)
    in the file's channel order -- ``(r, g, b)`` for RGB and so on. The
    structure is deliberately plain (frozen dataclass, tuples throughout)
    so comparisons are deterministic and the projection is JSON-safe.
    """

    width: int
    height: int
    color_type: int
    pixels: tuple[tuple[tuple[int, ...], ...], ...]

    @property
    def channels(self) -> int:
        """Channel count implied by ``color_type`` (1 grayscale, 3 RGB, 4 RGBA)."""
        return _CHANNELS_BY_COLOR_TYPE[self.color_type]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection; ``pixels`` is rows of channel tuples."""
        return {
            "width": self.width,
            "height": self.height,
            "color_type": self.color_type,
            "channels": self.channels,
            "pixels": [[list(pixel) for pixel in row] for row in self.pixels],
        }


@dataclass(frozen=True)
class ChannelDelta:
    """Mean absolute per-channel delta over the compared pixels."""

    name: str
    mean: float

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {"name": self.name, "mean": self.mean}


@dataclass(frozen=True)
class ScreenshotDiff:
    """Outcome of :func:`pixel_diff`; frozen and JSON-safe.

    ``changed_ratio`` is the fraction of compared pixels where at least one
    channel differs; ``verdict`` applies the documented thresholds
    (``identical`` at ``0.0``, ``minor`` below
    :data:`MINOR_RATIO_THRESHOLD`, ``major`` otherwise). Different
    dimensions short-circuit to ``major`` with a note, because no aligned
    pixel comparison exists.
    """

    left_width: int
    left_height: int
    right_width: int
    right_height: int
    changed_pixels: int = 0
    total_pixels: int = 0
    changed_ratio: float = 0.0
    channel_deltas: tuple[ChannelDelta, ...] = ()
    verdict: str = "identical"
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-channel rows."""
        return {
            "left_width": self.left_width,
            "left_height": self.left_height,
            "right_width": self.right_width,
            "right_height": self.right_height,
            "changed_pixels": self.changed_pixels,
            "total_pixels": self.total_pixels,
            "changed_ratio": self.changed_ratio,
            "channel_deltas": [delta.to_dict() for delta in self.channel_deltas],
            "verdict": self.verdict,
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _decode_error(detail: str) -> AnalysisError:
    """Every decode refusal uses one typed error prefix for greppability."""
    return AnalysisError(f"png: {detail}")


def _iter_chunks(data: bytes) -> Any:
    """Yield ``(chunk_type, payload)`` pairs, verifying structure and CRC.

    Raises:
        AnalysisError: On a bad signature, a truncated chunk table, a CRC
            mismatch or a missing ``IEND``. Chunk types are yielded in
            file order; iteration stops after ``IEND``.
    """
    if not data.startswith(_PNG_SIGNATURE):
        raise _decode_error("not a PNG file (bad signature)")
    offset = 8
    while offset + 8 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        raw_type = data[offset + 4 : offset + 8]
        chunk_type = raw_type.decode("ascii", errors="replace")
        payload_end = offset + 8 + length
        if payload_end + 4 > len(data):
            raise _decode_error(f"truncated {chunk_type} chunk")
        payload = data[offset + 8 : payload_end]
        (stored_crc,) = struct.unpack(">I", data[payload_end : payload_end + 4])
        if zlib.crc32(raw_type + payload) & 0xFFFFFFFF != stored_crc:
            raise _decode_error(f"{chunk_type} chunk fails its CRC")
        yield chunk_type, payload
        if chunk_type == "IEND":
            return
        offset = payload_end + 4
    raise _decode_error("missing IEND chunk")


def _parse_header(payload: bytes) -> tuple[int, int, int, int]:
    """Validate IHDR and return ``(width, height, bit_depth, color_type)``."""
    if len(payload) != 13:
        raise _decode_error("IHDR payload is not 13 bytes")
    width, height, bit_depth, color_type, compression, filter_method, interlace = (
        struct.unpack(">IIBBBBB", payload)
    )
    if width < 1 or height < 1:
        raise _decode_error(f"invalid dimensions {width}x{height}")
    if width * height > MAX_PNG_PIXELS:
        raise _decode_error(f"{width}x{height} exceeds the {MAX_PNG_PIXELS}-pixel ceiling")
    if bit_depth != 8:
        raise _decode_error(f"unsupported bit depth {bit_depth} (only 8 is supported)")
    if color_type not in _CHANNELS_BY_COLOR_TYPE:
        raise _decode_error(f"unsupported color type {color_type} (only 0, 2, 6)")
    if compression != 0:
        raise _decode_error(f"unsupported compression method {compression}")
    if filter_method != 0:
        raise _decode_error(f"unsupported filter method {filter_method}")
    if interlace != 0:
        raise _decode_error("interlaced PNG is not supported")
    return width, height, bit_depth, color_type


def _paeth_predictor(left: int, above: int, upper_left: int) -> int:
    """The Paeth predictor from PNG spec 6.3 (filter type 4)."""
    estimate = left + above - upper_left
    dist_left = abs(estimate - left)
    dist_above = abs(estimate - above)
    dist_upper_left = abs(estimate - upper_left)
    if dist_left <= dist_above and dist_left <= dist_upper_left:
        return left
    if dist_above <= dist_upper_left:
        return above
    return upper_left


def _reconstruct_rows(
    raw: bytes, width: int, height: int, channels: int
) -> tuple[tuple[tuple[int, ...], ...], ...]:
    """Undo the five per-scanline filters and group bytes into pixel tuples."""
    stride = width * channels
    if len(raw) != height * (stride + 1):
        raise _decode_error(
            f"scanline data is {len(raw)} bytes, expected {height * (stride + 1)}"
        )
    bpp = channels  # 8-bit depth: one byte per channel per pixel
    rows: list[tuple[tuple[int, ...], ...]] = []
    previous = bytearray(stride)
    position = 0
    for _ in range(height):
        filter_type = raw[position]
        line = bytearray(raw[position + 1 : position + 1 + stride])
        position += 1 + stride
        if filter_type == 0:  # None
            pass
        elif filter_type == 1:  # Sub
            for index in range(bpp, stride):
                line[index] = (line[index] + line[index - bpp]) & 0xFF
        elif filter_type == 2:  # Up
            for index in range(stride):
                line[index] = (line[index] + previous[index]) & 0xFF
        elif filter_type == 3:  # Average
            for index in range(stride):
                left = line[index - bpp] if index >= bpp else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for index in range(stride):
                left = line[index - bpp] if index >= bpp else 0
                upper_left = previous[index - bpp] if index >= bpp else 0
                line[index] = (
                    line[index] + _paeth_predictor(left, previous[index], upper_left)
                ) & 0xFF
        else:
            raise _decode_error(f"unsupported filter type {filter_type}")
        rows.append(
            tuple(
                tuple(line[column * channels : (column + 1) * channels])
                for column in range(width)
            )
        )
        previous = line
    return tuple(rows)


def decode_png(data: bytes) -> PngImage:
    """Decode PNG bytes into a :class:`PngImage`.

    A minimal, honest decoder: exact 8-bit grayscale/RGB/RGBA,
    non-interlaced, all five scanline filters, CRC-verified chunks.

    Raises:
        AnalysisError: On any structural deviation -- bad signature,
            missing/misplaced IHDR, unsupported bit depth or color type,
            interlacing, missing IDAT/IEND, CRC mismatch, corrupted or
            truncated scanline data, or a pixel count above
            :data:`MAX_PNG_PIXELS`.
    """
    ihdr: tuple[int, int, int, int] | None = None
    idat: list[bytes] = []
    for chunk_type, payload in _iter_chunks(data):
        if chunk_type == "IHDR":
            if ihdr is not None:
                raise _decode_error("duplicate IHDR chunk")
            ihdr = _parse_header(payload)
        elif chunk_type == "IDAT":
            if ihdr is None:
                raise _decode_error("IDAT before IHDR")
            idat.append(payload)
        elif chunk_type == "IEND":
            break
        elif chunk_type[0:1].isupper():
            # Critical chunk we do not implement (PLTE and friends): refuse
            # rather than silently mis-decode. Ancillary chunks are skipped.
            raise _decode_error(f"unsupported critical chunk {chunk_type}")
    if ihdr is None:
        raise _decode_error("missing IHDR chunk")
    if not idat:
        raise _decode_error("missing IDAT chunk")
    width, height, _bit_depth, color_type = ihdr
    channels = _CHANNELS_BY_COLOR_TYPE[color_type]
    expected = height * (width * channels + 1)

    # Cap the decompressed stream at its mathematically expected size so a
    # decompression bomb cannot grow past the bound set by IHDR.
    decompressor = zlib.decompressobj()
    raw = bytearray()
    for payload in idat:
        raw.extend(decompressor.decompress(payload, expected - len(raw) + 1))
        if len(raw) > expected:
            break
    if len(raw) > expected:
        raise _decode_error("decompressed scanline data exceeds the expected size")
    if len(raw) < expected:
        raise _decode_error(f"scanline data truncated: {len(raw)} of {expected} bytes")
    if not decompressor.eof:
        raise _decode_error("incomplete zlib stream in IDAT")

    return PngImage(
        width=width,
        height=height,
        color_type=color_type,
        pixels=_reconstruct_rows(bytes(raw), width, height, channels),
    )


def load_png(path: str | Path) -> PngImage:
    """Read and decode the PNG file at ``path``.

    Raises:
        AnalysisError: When the file cannot be read or is not a decodable
            PNG (see :func:`decode_png`).
    """
    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {target}: {exc}") from exc
    return decode_png(data)


def _channel_summary(
    left: PngImage, right: PngImage, changed: int, warnings: list[str]
) -> tuple[ChannelDelta, ...]:
    """Mean absolute per-channel delta over the overlapping pixel grid.

    The summary is naturally bounded: at most one row per channel and at
    most four channels (RGBA). When the sides use different color types,
    only the shared channel prefix is compared and the difference is noted.
    """
    channels = min(left.channels, right.channels)
    if left.color_type != right.color_type:
        warnings.append(
            f"color types differ (left {left.color_type}, right {right.color_type}); "
            f"comparing the shared {channels}-channel prefix"
        )
    if left.color_type == right.color_type:
        names = _CHANNEL_NAMES.get(left.color_type, ())[:channels]
    else:
        names = tuple(f"ch{index}" for index in range(channels))
    if changed == 0:
        return tuple(ChannelDelta(name=name, mean=0.0) for name in names)
    totals = [0 for _ in range(channels)]
    for left_row, right_row in zip(left.pixels, right.pixels, strict=True):
        for left_pixel, right_pixel in zip(left_row, right_row, strict=True):
            for index in range(channels):
                totals[index] += abs(left_pixel[index] - right_pixel[index])
    return tuple(
        ChannelDelta(name=name, mean=round(total / changed, 6))
        for name, total in zip(names, totals, strict=True)
    )


def pixel_diff(
    left_png: str | Path | PngImage, right_png: str | Path | PngImage
) -> ScreenshotDiff:
    """Compare two screenshots pixel by pixel and return a typed verdict.

    Accepts paths (loaded through :func:`load_png`) or already-decoded
    :class:`PngImage` values. When dimensions match, every aligned pixel is
    compared channel-wise; ``changed_ratio`` is the fraction of pixels with
    at least one differing channel, and the per-channel mean absolute delta
    quantifies *how* the screenshot moved. When dimensions differ the
    verdict is ``major`` with a note -- there is no aligned grid to diff --
    and no pixel loop runs.

    Verdicts: ``identical`` when the ratio is exactly ``0.0``, ``minor``
    while it stays below :data:`MINOR_RATIO_THRESHOLD`, ``major`` beyond
    that or for any dimension mismatch.

    Raises:
        AnalysisError: When either side cannot be read or decoded.
    """
    left = left_png if isinstance(left_png, PngImage) else load_png(left_png)
    right = right_png if isinstance(right_png, PngImage) else load_png(right_png)
    warnings: list[str] = []
    if (left.width, left.height) != (right.width, right.height):
        warnings.append(
            f"dimensions differ (left {left.width}x{left.height}, "
            f"right {right.width}x{right.height}); no aligned pixel comparison"
        )
        evidence = Evidence(
            source=_EVIDENCE_SCREENSHOT_SOURCE,
            method="png_pixel_diff",
            confidence=Confidence.HIGH,
            detail=(
                f"dimension mismatch {left.width}x{left.height} vs "
                f"{right.width}x{right.height}; verdict major by definition"
            ),
        )
        return ScreenshotDiff(
            left_width=left.width,
            left_height=left.height,
            right_width=right.width,
            right_height=right.height,
            changed_ratio=1.0,
            verdict="major",
            identical=False,
            warnings=tuple(warnings),
            evidence=evidence.to_dict(),
        )

    total = left.width * left.height
    shared = min(left.channels, right.channels)  # prefix rule, see _channel_summary
    changed = 0
    for left_row, right_row in zip(left.pixels, right.pixels, strict=True):
        for left_pixel, right_pixel in zip(left_row, right_row, strict=True):
            if left_pixel[:shared] != right_pixel[:shared]:
                changed += 1
    ratio = round(changed / total, 6) if total else 0.0
    if ratio == 0.0:
        verdict = "identical"
    elif ratio < MINOR_RATIO_THRESHOLD:
        verdict = "minor"
    else:
        verdict = "major"
    channel_deltas = _channel_summary(left, right, changed, warnings)
    evidence = Evidence(
        source=_EVIDENCE_SCREENSHOT_SOURCE,
        method="png_pixel_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"{changed} of {total} pixels changed ({ratio}); exact 8-bit "
            "channel-wise comparison of decoded scanlines, no OCR"
        ),
    )
    return ScreenshotDiff(
        left_width=left.width,
        left_height=left.height,
        right_width=right.width,
        right_height=right.height,
        changed_pixels=changed,
        total_pixels=total,
        changed_ratio=ratio,
        channel_deltas=channel_deltas,
        verdict=verdict,
        identical=verdict == "identical",
        warnings=tuple(warnings),
        evidence=evidence.to_dict(),
    )
