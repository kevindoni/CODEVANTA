"""sigrok ``.sr`` session archives: bounded, evidence-backed inspection.

A sigrok session file is a ZIP archive: a ``version`` text member, a
``metadata`` member of ``key=value`` lines (``device``, ``samplerate``,
``capturefile``, ``unitsize`` ...), a ``channels/`` directory whose numbered
members carry the channel names, one or more ``logic-...`` data members, and
optionally an ``annotations`` member. :func:`summarize_session` reads the
small members, records the *sizes* of the logic data without decompressing
it, and returns an :class:`SrSessionSummary`.

ZIP-bomb guards run before anything is inflated: at most
:data:`MAX_ENTRIES` members and at most :data:`MAX_TOTAL_UNCOMPRESSED`
uncompressed bytes (computed from the central directory's ``file_size``),
and the file itself must be at most :data:`MAX_FILE_BYTES`. Anything that
is not a readable session archive raises the typed
:class:`~codevanta.core.report.AnalysisError` -- never ``zipfile``'s
bare exceptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile, ZipInfo

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_CHANNELS",
    "MAX_ENTRIES",
    "MAX_FILE_BYTES",
    "MAX_LOGIC_FILES",
    "MAX_MEMBER_BYTES",
    "MAX_TOTAL_UNCOMPRESSED",
    "SrChannel",
    "SrLogicFile",
    "SrSessionSummary",
    "summarize_session",
]

#: Members kept from one archive before the rest are refused (ZIP-bomb guard).
MAX_ENTRIES = 256

#: Total uncompressed bytes one archive may claim (ZIP-bomb guard, 64 MiB).
MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024

#: Hard ceiling on the archive file itself (house rule: never read > 256 MB).
MAX_FILE_BYTES = 64 * 1024 * 1024

#: Channels kept in the summary; anything past the cap sets ``truncated``.
MAX_CHANNELS = 64

#: Logic data members kept in the summary (bounded listing, sizes only).
MAX_LOGIC_FILES = 32

#: Per-member read cap for the small text members (version, metadata, names).
MAX_MEMBER_BYTES = 1024 * 1024

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "sig.sr"

#: ``channels/17`` -- one numbered member per channel.
_CHANNEL_ENTRY = re.compile(r"^channels/(\d+)$")

#: ``logic-1.1`` / ``logic-1-2.1`` -- sigrok's logic data member names.
_LOGIC_ENTRY = re.compile(r"^logic-\d+(?:-\d+)?\.\d+$")

#: Ceiling on warnings kept per summary before the rest are summarised away.
MAX_WARNINGS = 32


@dataclass(frozen=True)
class SrChannel:
    """One named channel from the archive's ``channels/`` directory."""

    index: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name}


@dataclass(frozen=True)
class SrLogicFile:
    """One logic data member, kept by name and size -- never inflated."""

    name: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "size_bytes": self.size_bytes}


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _read_text(info: ZipInfo, zf: ZipFile) -> str:
    """Read one small text member, capped, UTF-8 with replacement."""
    size = min(int(info.file_size), MAX_MEMBER_BYTES)
    with zf.open(info) as handle:
        data = handle.read(size)
    return data.decode("utf-8", errors="replace")


def _parse_samplerate(text: str) -> int | None:
    """Parse a sigrok ``samplerate`` value: ``1 MHz``, ``100 kHz``, ``9600``.

    Returns ``None`` (never raises) for anything unparsable; the caller turns
    that into a warning because a broken sample-rate line must not take the
    whole summary down.
    """
    value = text.strip()
    if not value:
        return None
    parts = value.split()
    if len(parts) > 2:
        return None
    try:
        number = float(parts[0])
    except ValueError:
        return None
    multiplier = 1.0
    if len(parts) == 2:
        unit = parts[1].strip().lower()
        multipliers = {"ghz": 1e9, "mhz": 1e6, "khz": 1e3, "hz": 1.0}
        if unit not in multipliers:
            return None
        multiplier = multipliers[unit]
    rate = number * multiplier
    if rate <= 0:
        return None
    return int(round(rate))


@dataclass(frozen=True)
class SrSessionSummary:
    """Bounded, evidence-backed summary of one ``.sr`` session archive."""

    version: str | None = None
    samplerate_hz: int | None = None
    device: str | None = None
    numchannels: int | None = None
    channels: tuple[SrChannel, ...] = ()
    logic_files: tuple[SrLogicFile, ...] = ()
    annotations_count: int | None = None
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="zip_members",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "samplerate_hz": self.samplerate_hz,
            "device": self.device,
            "numchannels": self.numchannels,
            "channels": [channel.to_dict() for channel in self.channels],
            "logic_files": [logic.to_dict() for logic in self.logic_files],
            "annotations_count": self.annotations_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _check_path(path: str | Path) -> Path:
    """Validate the archive path exists and is within the size ceiling."""
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"session file not found: {target}")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"session file is {size} bytes; the ceiling for one archive is "
            f"{MAX_FILE_BYTES} bytes"
        )
    return target


def _open_archive(target: Path) -> ZipFile:
    """Open the archive after the entry and size bomb-guards have run."""
    try:
        zf = ZipFile(target)
    except BadZipFile as exc:
        raise AnalysisError(f"not a readable ZIP archive: {target} ({exc})") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        zf.close()
        raise AnalysisError(
            f"archive declares {len(infos)} members; the ZIP-bomb ceiling is "
            f"{MAX_ENTRIES} members"
        )
    total = sum(int(info.file_size) for info in infos)
    if total > MAX_TOTAL_UNCOMPRESSED:
        zf.close()
        raise AnalysisError(
            f"archive claims {total} uncompressed bytes; the ZIP-bomb ceiling "
            f"is {MAX_TOTAL_UNCOMPRESSED} bytes"
        )
    return zf


def _annotations_count(
    zf: ZipFile, annotations: ZipInfo | None
) -> tuple[int | None, bool]:
    """Count non-empty lines of the optional ``annotations`` member (capped)."""
    if annotations is None:
        return None, False
    text = _read_text(annotations, zf)
    count = sum(1 for line in text.splitlines() if line.strip())
    return count, int(annotations.file_size) > MAX_MEMBER_BYTES


def summarize_session(path: str | Path) -> SrSessionSummary:
    """Summarize one ``.sr`` session archive into typed, bounded output.

    The ZIP-bomb guards run first; the small text members are read capped and
    the logic data members are only ever stat'ed, never inflated.
    """
    target = _check_path(path)
    zf = _open_archive(target)
    try:
        info_by_name = {info.filename or "": info for info in zf.infolist()}
        warnings: list[str] = []
        truncated = False

        version_info = info_by_name.get("version")
        metadata_info = info_by_name.get("metadata")
        if version_info is None or metadata_info is None:
            missing = [
                name
                for name, info in (("version", version_info), ("metadata", metadata_info))
                if info is None
            ]
            raise AnalysisError(
                "not a sigrok session archive: missing required member(s): "
                + ", ".join(missing)
            )

        version = _read_text(version_info, zf).strip() or None
        if version is None:
            _note(warnings, "version member is empty")

        metadata: dict[str, str] = {}
        for line in _read_text(metadata_info, zf).splitlines():
            stripped = line.strip()
            if not stripped or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            metadata[key.strip()] = value.strip()

        samplerate_hz = None
        raw_rate = metadata.get("samplerate")
        if raw_rate is not None:
            samplerate_hz = _parse_samplerate(raw_rate)
            if samplerate_hz is None:
                _note(warnings, f"unparsable samplerate value {raw_rate!r}")

        device = metadata.get("device") or None
        numchannels: int | None = None
        raw_count = metadata.get("numchannels")
        if raw_count is not None:
            try:
                numchannels = int(raw_count)
            except ValueError:
                _note(warnings, f"unparsable numchannels value {raw_count!r}")

        channels: list[SrChannel] = []
        channel_entries: list[tuple[int, ZipInfo]] = []
        for name, info in info_by_name.items():
            matched = _CHANNEL_ENTRY.match(name)
            if matched is not None:
                channel_entries.append((int(matched.group(1)), info))
        channel_entries.sort(key=lambda item: item[0])
        for index, info in channel_entries:
            if len(channels) >= MAX_CHANNELS:
                truncated = True
                _note(warnings, f"channel limit {MAX_CHANNELS} reached; further channels dropped")
                break
            channels.append(SrChannel(index=index, name=_read_text(info, zf).strip()))

        logic_files: list[SrLogicFile] = []
        logic_names = sorted(name for name in info_by_name if _LOGIC_ENTRY.match(name))
        for name in logic_names:
            if len(logic_files) >= MAX_LOGIC_FILES:
                truncated = True
                _note(warnings, f"logic-file limit {MAX_LOGIC_FILES} reached; further files dropped")
                break
            logic_files.append(
                SrLogicFile(name=name, size_bytes=int(info_by_name[name].file_size))
            )

        if channel_entries and numchannels is not None and numchannels != len(channel_entries):
            _note(
                warnings,
                f"numchannels metadata says {numchannels} but the archive "
                f"carries {len(channel_entries)} channel entries",
            )
        if not channel_entries and numchannels is None:
            _note(warnings, "no channels/ directory and no numchannels metadata")

        annotations_count, annotations_truncated = _annotations_count(
            zf, info_by_name.get("annotations")
        )
        if annotations_truncated:
            truncated = True
            _note(warnings, "annotations member larger than the read cap; count is partial")

        evidence = Evidence(
            source=EVIDENCE_SOURCE,
            method="zip_members",
            confidence=Confidence.HIGH if version is not None else Confidence.MEDIUM,
            detail=(
                f"{len(logic_files)} logic file(s), {len(channels)} channel(s), "
                f"samplerate {samplerate_hz if samplerate_hz is not None else 'unknown'}"
            ),
        )
        return SrSessionSummary(
            version=version,
            samplerate_hz=samplerate_hz,
            device=device,
            numchannels=numchannels,
            channels=tuple(channels),
            logic_files=tuple(logic_files),
            annotations_count=annotations_count,
            truncated=truncated,
            warnings=warnings,
            evidence=evidence,
        )
    finally:
        zf.close()


