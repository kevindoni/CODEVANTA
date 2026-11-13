"""Binary-container inspectors: WASM, EVM bytecode, GGUF, safetensors, pcap.

Five self-describing container families plus one heuristic firmware triage, all
decoded with nothing but :mod:`struct`, :mod:`json` and ``bytes`` -- no external
parser library, no network, no execution. Each inspector takes the raw bytes of
a file and returns either ``None`` (the leading magic says "not mine", so a
caller can hand the file to the next inspector) or a frozen, JSON-safe summary
dataclass whose findings carry :class:`~codevanta.evidence.models.Evidence`.

Inspectors
----------
``inspect_wasm``
    ``\\0asm`` WebAssembly modules: version, the section table (id, known
    name, offset, size) and the import/export vector counts read from the
    section 2 / 7 payload headers -- shallowly, never walking the entries.
``inspect_evm``
    EVM bytecode: a linear ``PUSH``-aware sweep over the documented opcode
    table producing a bounded ``pc``/mnemonic/operand listing, the set of
    instruction-start ``JUMPDEST`` positions and whether the plain
    ``JUMP``/``JUMPI`` targets land on them. Bytecode has no magic, so the
    verdict is a labelled heuristic (low/medium confidence), never a certainty.
``inspect_gguf``
    GGUF 2/3 model files: header fields, the typed key/value block (bounded,
    arrays summarised not materialised) and the 32-byte-aligned data offset
    reached after walking the tensor-info table.
``inspect_safetensors``
    safetensors files: the 8-byte little-endian header length, the JSON
    header's ``dtype``/``shape`` per tensor (bounded) and the total payload
    bytes.
``inspect_pcap``
    classic ``libpcap`` captures (both endiannesses, Âµs and ns) and
    ``pcapng``: global-header fields, a bounded packet/block walk and the
    first packet's timestamp.
``scan_magics``
    Firmware triage: a ``bytes.find`` sweep for known embedded magics (gzip,
    squashfs, uImage, cpio, bzip2, xz, lzma, jffs2, DTB). This is heuristic
    triage over a 3-6 byte signature, so every hit is labelled low or medium
    confidence and the result is evidence, not a verdict.

Bounds and errors
-----------------
A file is read once and refused above :data:`MAX_FILE_BYTES` rather than
slurped. Every list is capped (sections 64, ops 256, kv pairs 64, tensors 64,
packets/blocks 4096, magic hits 64) with a ``truncated`` flag instead of
growing without limit. The only exception raised is
:class:`~codevanta.core.report.AnalysisError` -- a file that cannot be read,
is too big, or (in strict mode) matches no inspector is a typed error, never a
traceback.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_EVM_OPS",
    "MAX_FILE_BYTES",
    "MAX_GGUF_KVS",
    "MAX_GGUF_TENSORS",
    "MAX_MAGIC_HITS",
    "MAX_PCAP_PACKETS",
    "MAX_ST_TENSORS",
    "MAX_WASM_SECTIONS",
    "BinmetaSummary",
    "EvmOp",
    "EvmSummary",
    "GgufSummary",
    "MagicHit",
    "MagicScanSummary",
    "PcapSummary",
    "SafetensorsSummary",
    "WasmSection",
    "WasmSummary",
    "inspect_container",
    "inspect_evm",
    "inspect_gguf",
    "inspect_pcap",
    "inspect_safetensors",
    "inspect_wasm",
    "load_container_bytes",
    "require_evm",
    "scan_magics",
]

#: Hard ceiling on the bytes one inspection will read (files are refused above).
MAX_FILE_BYTES = 256 * 1024 * 1024

#: Sections kept per WASM module before the rest are summarised away.
MAX_WASM_SECTIONS = 64

#: Disassembled ops kept per EVM bytecode blob.
MAX_EVM_OPS = 256

#: Typed key/value pairs kept per GGUF file.
MAX_GGUF_KVS = 64

#: GGUF tensor-info entries walked (to reach the aligned data section) ...
MAX_GGUF_TENSORS = 4096

#: ... and tensor names kept in the summary.
MAX_ST_TENSORS = 64

#: safetensors tensors kept per header.
MAX_ST_TENSORS = 64

#: Packets (pcap) or blocks (pcapng) walked per capture.
MAX_PCAP_PACKETS = 4096

#: Firmware magic-scan hits kept per file.
MAX_MAGIC_HITS = 64

#: Shared evidence ``source`` prefix; every inspector narrows it to its format.
EVIDENCE_SOURCE = "bin"

_WASM_MAGIC = b"\x00asm"

_GGUF_MAGIC = b"GGUF"

_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"
_PCAP_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

#: ``linktype`` names for the DLT values a capture's global header usually
#: carries (full DLT list is hundreds long; these cover every fixture in use).
_LINKTYPE_NAMES: dict[int, str] = {
    0: "NULL",
    1: "EN10MB",
    6: "IEEE802_11",
    101: "RAW",
    113: "LINUX_SLL",
    147: "USER0",
}

class _Reader:
    """Bounds-checked cursor over a bytes buffer (typed errors, never IndexErrors)."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def take(self, count: int) -> bytes:
        """Return the next ``count`` bytes or fail with a short-buffer error."""
        if count < 0 or self.pos + count > len(self.data):
            raise _TruncatedError()
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self, little: bool = True) -> int:
        return int.from_bytes(self.take(2), "little" if little else "big")

    def u32(self, little: bool = True) -> int:
        return int.from_bytes(self.take(4), "little" if little else "big")

    def u64(self, little: bool = True) -> int:
        return int.from_bytes(self.take(8), "little" if little else "big")

    def leb128(self) -> int:
        """Decode one unsigned LEB128 value (WASM vector lengths and sizes)."""
        result = 0
        shift = 0
        while True:
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 42:  # 6 continuation bytes cover every u64; beyond = hostile
                raise AnalysisError("leb128 value over 6 continuation bytes")


class _TruncatedError(Exception):
    """Internal: a structure ran past the end of the buffer."""


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to the next multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _hex(data: bytes) -> str:
    """Render bytes as a JSON-safe ``0x``-prefixed hex string."""
    return f"0x{data.hex()}"


def _warn(truncated: bool, kind: str, kept: int) -> str | None:
    """Build the standard truncation warning, or ``None`` when nothing was cut."""
    if truncated:
        return f"{kind}: output bounded at {kept}, remaining entries skipped"
    return None


# ---------------------------------------------------------------------------
# WASM
# ---------------------------------------------------------------------------

#: Known section ids (WASM spec); anything else stays "unknown".
_WASM_SECTION_NAMES: dict[int, str] = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "datacount",
}


@dataclass(frozen=True)
class WasmSection:
    """One entry of the WASM section table."""

    id: int
    name: str
    offset: int
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
        }


@dataclass(frozen=True)
class WasmSummary:
    """Shallow summary of a WebAssembly module (``\\0asm``)."""

    version: int
    sections: tuple[WasmSection, ...]
    section_count: int
    truncated: bool
    import_count: int | None
    export_count: int | None
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": self.version,
            "sections": [s.to_dict() for s in self.sections],
            "section_count": self.section_count,
            "truncated": self.truncated,
            "import_count": self.import_count,
            "export_count": self.export_count,
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def inspect_wasm(data: bytes) -> WasmSummary | None:
    """Summarise a WASM module, or ``None`` when the leading magic disagrees."""
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        return None
    version = int.from_bytes(data[4:8], "little")
    warnings: list[str] = []
    reader = _Reader(data, 8)
    sections: list[WasmSection] = []
    truncated = False
    import_count: int | None = None
    export_count: int | None = None
    try:
        while reader.pos < len(data):
            offset = reader.pos
            section_id = reader.u8()
            size = reader.leb128()
            payload_start = reader.pos
            if payload_start + size > len(data):
                raise _TruncatedError()
            # Shallow peek at the two vector headers the summary reports: the
            # vector count is the first LEB128 inside the section payload.
            if section_id == 2 and import_count is None:
                try:
                    import_count = _Reader(data, payload_start).leb128()
                except _TruncatedError:
                    import_count = None
                    warnings.append("import section: vector count unreadable")
            elif section_id == 7 and export_count is None:
                try:
                    export_count = _Reader(data, payload_start).leb128()
                except _TruncatedError:
                    export_count = None
                    warnings.append("export section: vector count unreadable")
            if len(sections) < MAX_WASM_SECTIONS:
                sections.append(
                    WasmSection(
                        id=section_id,
                        name=_WASM_SECTION_NAMES.get(section_id, f"unknown({section_id})"),
                        offset=offset,
                        size=size,
                    )
                )
            else:
                truncated = True
            reader.pos = payload_start + size
    except _TruncatedError:
        warnings.append("section table runs past the end of the file")
        truncated = True
    cut_note = _warn(truncated, "sections", MAX_WASM_SECTIONS)
    if cut_note:
        warnings.append(cut_note)
    return WasmSummary(
        version=version,
        sections=tuple(sections),
        section_count=len(sections),
        truncated=truncated,
        import_count=import_count,
        export_count=export_count,
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.wasm",
            method="wasm_section_table",
            confidence=Confidence.HIGH,
            detail=f"{len(sections)} sections in view",
        ),
    )


# ---------------------------------------------------------------------------
# EVM bytecode
# ---------------------------------------------------------------------------

#: The documented EVM opcode table (yellow-paper set plus EIP addenda).
#: A byte not in this table is not a decodable instruction.
_EVM_MNEMONICS: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
    0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE", 0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE",
    0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP",
    0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0x5F: "PUSH0", 0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
_EVM_MNEMONICS.update({0x60 + n: f"PUSH{n + 1}" for n in range(32)})
_EVM_MNEMONICS.update({0x80 + n: f"DUP{n + 1}" for n in range(16)})
_EVM_MNEMONICS.update({0x90 + n: f"SWAP{n + 1}" for n in range(16)})
_EVM_MNEMONICS.update({0xA0 + n: f"LOG{n}" for n in range(5)})

_PUSH_BASE = 0x60
_PUSH_TOP = 0x7F


@dataclass(frozen=True)
class EvmOp:
    """One disassembled EVM instruction: pc, mnemonic and optional immediate."""

    pc: int
    op: str
    operand: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"pc": self.pc, "op": self.op}
        if self.operand is not None:
            data["operand"] = self.operand
        return data


@dataclass(frozen=True)
class EvmSummary:
    """Linear-sweep summary of EVM bytecode (no magic: heuristic verdict)."""

    size_bytes: int
    evm_like: bool
    ops: tuple[EvmOp, ...]
    op_count: int
    truncated: bool
    jumpdest_count: int
    jumpdest_positions: tuple[int, ...]
    jump_targets_total: int
    jump_targets_valid: int
    invalid_at: int | None
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "size_bytes": self.size_bytes,
            "evm_like": self.evm_like,
            "ops": [op.to_dict() for op in self.ops],
            "op_count": self.op_count,
            "truncated": self.truncated,
            "jumpdest_count": self.jumpdest_count,
            "jumpdest_positions": list(self.jumpdest_positions),
            "jump_targets_total": self.jump_targets_total,
            "jump_targets_valid": self.jump_targets_valid,
            "invalid_at": self.invalid_at,
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def inspect_evm(data: bytes) -> EvmSummary | None:
    """Disassemble EVM bytecode with a bounded ``PUSH``-aware linear sweep.

    ``None`` means "no decodable instruction at all" -- not a verdict that the
    file is not EVM, because EVM bytecode carries no magic. ``evm_like`` on the
    summary is the heuristic verdict (every byte decodes and the code has a
    terminator or a landing pad); treat it as low/medium evidence.
    """
    warnings: list[str] = []
    ops: list[EvmOp] = []
    truncated = False
    invalid_at: int | None = None
    total = len(data)
    pc = 0
    while pc < total:
        start = pc
        byte = data[pc]
        mnemonic = _EVM_MNEMONICS.get(byte)
        if mnemonic is None:
            invalid_at = start
            break
        operand: str | None = None
        if _PUSH_BASE <= byte <= _PUSH_TOP:
            width = byte - _PUSH_BASE + 1
            if start + 1 + width > total:
                warnings.append(
                    f"PUSH{width} at pc={start} runs past the end of the code"
                )
                invalid_at = start
                break
            operand = _hex(data[start + 1 : start + 1 + width])
            pc = start + 1 + width
        else:
            pc = start + 1
        if len(ops) < MAX_EVM_OPS:
            ops.append(EvmOp(pc=start, op=mnemonic, operand=operand))
        else:
            truncated = True
    if not ops:
        return None
    # Instruction-start JUMPDESTs are exactly the ones the sweep kept; a 0x5b
    # byte inside PUSH data never becomes an op, so it never lands here.
    jumpdest_pcs = tuple(op.pc for op in ops if op.op == "JUMPDEST")
    jumpdest_set = set(jumpdest_pcs)
    targets_total = 0
    targets_valid = 0
    for index, op in enumerate(ops):
        if op.op not in ("JUMP", "JUMPI"):
            continue
        targets_total += 1
        # Plain (value-stack independent) target: an immediately preceding PUSH.
        if index > 0 and ops[index - 1].op.startswith("PUSH"):
            target = int((ops[index - 1].operand or "0x0")[2:], 16)
            if target in jumpdest_set:
                targets_valid += 1
    if truncated:
        warnings.append(f"ops: output bounded at {MAX_EVM_OPS}, remaining code skipped")
    # Heuristic verdict: fully decodable and at least one terminator or pad.
    terminators = {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}
    has_terminator = any(op.op in terminators for op in ops)
    evm_like = invalid_at is None and (has_terminator or bool(jumpdest_pcs))
    confidence = Confidence.MEDIUM if evm_like and invalid_at is None else Confidence.LOW
    if invalid_at is not None:
        warnings.append(f"undecodable byte at offset {invalid_at}; sweep stopped")
    return EvmSummary(
        size_bytes=total,
        evm_like=evm_like,
        ops=tuple(ops),
        op_count=len(ops),
        truncated=truncated,
        jumpdest_count=len(jumpdest_pcs),
        jumpdest_positions=jumpdest_pcs[:MAX_EVM_OPS],
        jump_targets_total=targets_total,
        jump_targets_valid=targets_valid,
        invalid_at=invalid_at,
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.evm",
            method="evm_linear_sweep",
            confidence=confidence,
            detail=f"{len(ops)} ops, evm_like={evm_like}",
        ),
    )


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------

#: GGUF metadata value types (``gguf`` spec v2/v3).
_GGUF_VALUE_NAMES: dict[int, str] = {
    0: "u8", 1: "i8", 2: "u16", 3: "i16", 4: "u32", 5: "i32",
    6: "f32", 7: "bool", 8: "string", 9: "array", 10: "u64", 11: "i64",
    12: "f64",
}
_GGUF_VALUE_SIZES: dict[int, int] = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}

#: GGML tensor type names (the subset every shipped model uses).
_GGUF_TENSOR_TYPES: dict[int, str] = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1",
    8: "Q8_0", 12: "BF16",
}

#: GGUF data section alignment (the spec's ``GGUF_DEFAULT_ALIGNMENT``).
_GGUF_ALIGNMENT = 32

#: Ceiling on one string/array length before the file is called corrupt.
_GGUF_MAX_LEN = 16 * 1024 * 1024

#: Ceiling on array elements walked while skipping a string array.
_GGUF_MAX_WALK = 1_000_000


@dataclass(frozen=True)
class GgufSummary:
    """Header, typed kv block and aligned data offset of a GGUF 2/3 file."""

    version: int
    tensor_count: int
    kv_count: int
    kv: tuple[dict[str, Any], ...]
    kv_truncated: bool
    data_offset: int | None
    tensors_seen: int
    tensors_truncated: bool
    tensor_names: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": self.version,
            "tensor_count": self.tensor_count,
            "kv_count": self.kv_count,
            "kv": list(self.kv),
            "kv_truncated": self.kv_truncated,
            "data_offset": self.data_offset,
            "tensors_seen": self.tensors_seen,
            "tensors_truncated": self.tensors_truncated,
            "tensor_names": list(self.tensor_names),
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def _gguf_read_string(reader: _Reader) -> str:
    """One GGUF ``string``: u64 length + UTF-8 bytes (corrupt = ``_TruncatedError``)."""
    length = reader.u64()
    if length > _GGUF_MAX_LEN:
        raise _TruncatedError()
    return reader.take(length).decode("utf-8", errors="replace")


def _gguf_scalar(reader: _Reader, value_type: int) -> int | float | bool:
    """Read one scalar metadata value of ``value_type``."""
    if value_type == 6:
        return struct.unpack("<f", reader.take(4))[0]
    if value_type == 12:
        return struct.unpack("<d", reader.take(8))[0]
    if value_type not in _GGUF_VALUE_SIZES:
        raise _TruncatedError()
    size = _GGUF_VALUE_SIZES[value_type]
    raw = reader.take(size)
    signed = value_type in (1, 3, 5, 11)
    value = int.from_bytes(raw, "little", signed=signed)
    if value_type == 7:
        return bool(value)
    return value


def inspect_gguf(data: bytes) -> GgufSummary | None:
    """Summarise a GGUF v2/v3 model file, or ``None`` when magic/version differ.

    The kv block is parsed with typed values (arrays summarised, not
    materialised) and the tensor-info table is walked -- names kept only for a
    bounded sample -- so the 32-byte-aligned data offset can be reported the
    way loaders compute it. Malformed bodies degrade to ``truncated`` flags and
    warnings; only the magic gate decides ``None``.
    """
    if len(data) < 24 or data[:4] != _GGUF_MAGIC:
        return None
    version = int.from_bytes(data[4:8], "little")
    if version not in (2, 3):
        return None
    warnings: list[str] = []
    reader = _Reader(data, 8)
    tensor_count = reader.u64()
    kv_count = reader.u64()
    kv_kept: list[dict[str, Any]] = []
    kv_truncated = False
    tensors_seen = 0
    tensors_truncated = False
    tensor_names: list[str] = []
    data_offset: int | None = None
    try:
        for _ in range(min(kv_count, MAX_GGUF_KVS)):
            key = _gguf_read_string(reader)
            value_type = reader.u32()
            if value_type == 9:
                # Array: header first, then skip the body we summarise away.
                element_type = reader.u32()
                count = reader.u64()
                if element_type == 9 or element_type not in _GGUF_VALUE_NAMES:
                    raise _TruncatedError()
                kv_kept.append(
                    {
                        "key": key,
                        "type": "array",
                        "element_type": _GGUF_VALUE_NAMES[element_type],
                        "count": count,
                    }
                )
                _gguf_skip_array_body(reader, element_type, count)
            elif value_type == 8:
                kv_kept.append(
                    {"key": key, "type": "string", "value": _gguf_read_string(reader)}
                )
            else:
                value = _gguf_scalar(reader, value_type)
                kv_kept.append(
                    {
                        "key": key,
                        "type": _GGUF_VALUE_NAMES[value_type],
                        "value": value,
                    }
                )
        if kv_count > MAX_GGUF_KVS:
            kv_truncated = True
            warnings.append(f"kv: kept {MAX_GGUF_KVS} of {kv_count}")
        # Walk the tensor-info table to reach the aligned data section.
        walked = min(tensor_count, MAX_GGUF_TENSORS)
        for index in range(walked):
            name = _gguf_read_string(reader)
            n_dims = reader.u32()
            if n_dims > 8:
                raise _TruncatedError()
            reader.take(8 * n_dims)
            ggml_type = reader.u32()
            reader.u64()  # tensor data offset within the data section
            tensors_seen = index + 1
            if len(tensor_names) < MAX_ST_TENSORS:
                tensor_names.append(f"{name}:{_GGUF_TENSOR_TYPES.get(ggml_type, ggml_type)}")
        if tensor_count > walked:
            tensors_truncated = True
            warnings.append(
                f"tensor infos: walked {walked} of {tensor_count}; "
                "data offset not computed"
            )
        else:
            data_offset = _align(reader.pos, _GGUF_ALIGNMENT)
    except _TruncatedError:
        warnings.append("GGUF structure runs past the end of the file")
        kv_truncated = kv_truncated or len(kv_kept) < min(kv_count, MAX_GGUF_KVS)
        tensors_truncated = tensors_truncated or tensor_count > tensors_seen
    return GgufSummary(
        version=version,
        tensor_count=tensor_count,
        kv_count=kv_count,
        kv=tuple(kv_kept),
        kv_truncated=kv_truncated,
        data_offset=data_offset,
        tensors_seen=tensors_seen,
        tensors_truncated=tensors_truncated,
        tensor_names=tuple(tensor_names),
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.gguf",
            method="gguf_header_walk",
            confidence=Confidence.HIGH,
            detail=f"GGUF v{version}, {tensor_count} tensors",
        ),
    )


def _gguf_skip_array_body(reader: _Reader, element_type: int, count: int) -> None:
    """Skip the body of one array value after its header was read."""
    if element_type in _GGUF_VALUE_SIZES or element_type in (6, 12):
        size = _GGUF_VALUE_SIZES.get(element_type, 4)
        skip = count * size
        if skip > len(reader.data) - reader.pos:
            raise _TruncatedError()
        reader.pos += skip
        return
    # String array: walk the element lengths (each consumes >= 8 bytes, so the
    # loop terminates; the walk cap keeps a hostile list from burning CPU).
    walked = 0
    while walked < count:
        if walked >= _GGUF_MAX_WALK:
            raise _TruncatedError()
        length = reader.u64()
        if length > len(reader.data) - reader.pos:
            raise _TruncatedError()
        reader.pos += length
        walked += 1


# ---------------------------------------------------------------------------
# safetensors
# ---------------------------------------------------------------------------

#: Ceiling on one safetensors JSON header before the file is refused.
_ST_MAX_HEADER = 100 * 1024 * 1024


@dataclass(frozen=True)
class StTensor:
    """One safetensors header entry: dtype, shape and payload span."""

    name: str
    dtype: str
    shape: tuple[int, ...]
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dtype": self.dtype,
            "shape": list(self.shape),
            "data_offsets": [self.start, self.end],
        }


@dataclass(frozen=True)
class SafetensorsSummary:
    """Header summary of a safetensors file (8-byte length + JSON header)."""

    header_bytes: int
    data_offset: int
    payload_bytes: int
    tensor_count: int
    tensors: tuple[StTensor, ...]
    truncated: bool
    metadata_keys: int
    total_tensor_bytes: int
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "header_bytes": self.header_bytes,
            "data_offset": self.data_offset,
            "payload_bytes": self.payload_bytes,
            "tensor_count": self.tensor_count,
            "tensors": [t.to_dict() for t in self.tensors],
            "truncated": self.truncated,
            "metadata_keys": self.metadata_keys,
            "total_tensor_bytes": self.total_tensor_bytes,
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def inspect_safetensors(data: bytes) -> SafetensorsSummary | None:
    """Summarise a safetensors file, or ``None`` when the header shape differs.

    The format has no magic: detection is the 8-byte little-endian header
    length followed by a JSON object whose values carry ``dtype``/``shape``/
    ``data_offsets``. A header that fails that shape is handed back as
    ``None`` so the next inspector can try.
    """
    if len(data) < 8:
        return None
    header_len = int.from_bytes(data[:8], "little")
    if header_len < 2 or header_len > _ST_MAX_HEADER or 8 + header_len > len(data):
        return None
    try:
        header = json.loads(data[8 : 8 + header_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    metadata = header.get("__metadata__")
    metadata_keys = len(metadata) if isinstance(metadata, dict) else 0
    entries = [kv for kv in header.items() if kv[0] != "__metadata__"]
    tensors: list[StTensor] = []
    total_bytes = 0
    for name, spec in entries:
        if not isinstance(spec, dict) or "dtype" not in spec:
            return None
        shape = spec.get("shape")
        offsets = spec.get("data_offsets")
        if not isinstance(shape, list) or not isinstance(offsets, list) or len(offsets) != 2:
            return None
        start, end = offsets
        if not isinstance(start, int) or not isinstance(end, int) or end < start:
            return None
        total_bytes += end - start
        if len(tensors) < MAX_ST_TENSORS:
            tensors.append(
                StTensor(
                    name=name,
                    dtype=str(spec.get("dtype", "?")),
                    shape=tuple(int(dim) for dim in shape),
                    start=int(start),
                    end=int(end),
                )
            )
    truncated = len(tensors) < len(entries)
    warnings: list[str] = []
    if truncated:
        warnings.append(f"tensors: kept {MAX_ST_TENSORS} of {len(entries)}")
    return SafetensorsSummary(
        header_bytes=header_len,
        data_offset=8 + header_len,
        payload_bytes=len(data) - 8 - header_len,
        tensor_count=len(entries),
        tensors=tuple(tensors),
        truncated=truncated,
        metadata_keys=metadata_keys,
        total_tensor_bytes=total_bytes,
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.safetensors",
            method="safetensors_json_header",
            confidence=Confidence.HIGH,
            detail=f"{len(entries)} tensors, {total_bytes} payload bytes in spans",
        ),
    )


# ---------------------------------------------------------------------------
# pcap / pcapng
# ---------------------------------------------------------------------------

#: pcapng block types the shallow walk names.
_PCAPNG_BLOCK_NAMES: dict[int, str] = {
    0x0A0D0D0A: "SHB",
    0x00000001: "IDB",
    0x00000002: "PBB",
    0x00000003: "SPB",
    0x00000004: "NRB",
    0x00000005: "ISB",
    0x00000006: "EPB",
}

#: Ceiling on one packet/block length before the walk stops (sanity, not spec).
_PCAP_MAX_RECORD = 16 * 1024 * 1024


@dataclass(frozen=True)
class PcapSummary:
    """Global-header plus bounded record walk of a pcap or pcapng capture."""

    format: str
    endian: str
    version_major: int
    version_minor: int
    linktype: int
    linktype_name: str
    snaplen: int
    record_count: int
    truncated: bool
    first_timestamp: float | None
    block_types: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "format": self.format,
            "endian": self.endian,
            "version_major": self.version_major,
            "version_minor": self.version_minor,
            "linktype": self.linktype,
            "linktype_name": self.linktype_name,
            "snaplen": self.snaplen,
            "record_count": self.record_count,
            "truncated": self.truncated,
            "first_timestamp": self.first_timestamp,
            "block_types": list(self.block_types),
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def _pcap_first4(data: bytes) -> str | None:
    """Classify the capture magic: ``pcap``/``pcapng`` endian names or ``None``."""
    if data[:4] == _PCAPNG_MAGIC:
        return "pcapng"
    if data[:4] == _PCAP_MAGIC_LE:
        return "pcap-le"
    if data[:4] == _PCAP_MAGIC_BE:
        return "pcap-be"
    if data[:4] == _PCAP_MAGIC_LE_NS:
        return "pcap-le-ns"
    if data[:4] == _PCAP_MAGIC_BE_NS:
        return "pcap-be-ns"
    return None


def inspect_pcap(data: bytes) -> PcapSummary | None:
    """Summarise a classic pcap or pcapng capture, or ``None`` on magic miss.

    Classic pcap: the 24-byte global header and a bounded per-packet walk with
    the first packet's timestamp. pcapng: a shallow block walk (SHB/IDB/EPB
    named, bounded) with the first enhanced packet's timestamp.
    """
    kind = _pcap_first4(data)
    if kind is None:
        return None
    if kind == "pcapng":
        return _inspect_pcapng(data)
    little = "le" in kind
    warnings: list[str] = []
    endian: Literal["little", "big"] = "little" if little else "big"
    if len(data) < 24:
        return PcapSummary(
            format="pcap",
            endian=endian,
            version_major=0,
            version_minor=0,
            linktype=0,
            linktype_name="unknown",
            snaplen=0,
            record_count=0,
            truncated=True,
            first_timestamp=None,
            block_types=(),
            warnings=("global header truncated",),
            evidence=Evidence(
                source="bin.pcap",
                method="pcap_global_header",
                confidence=Confidence.LOW,
                detail="global header incomplete",
            ),
        )
    version_major = int.from_bytes(data[4:6], endian)
    version_minor = int.from_bytes(data[6:8], endian)
    snaplen = int.from_bytes(data[16:20], endian)
    linktype = int.from_bytes(data[20:24], endian)
    pos = 24
    record_count = 0
    truncated = False
    first_ts: float | None = None
    while pos + 16 <= len(data):
        ts_sec = int.from_bytes(data[pos : pos + 4], endian)
        ts_sub = int.from_bytes(data[pos + 4 : pos + 8], endian)
        incl_len = int.from_bytes(data[pos + 8 : pos + 12], endian)
        if incl_len > _PCAP_MAX_RECORD:
            warnings.append(
                f"packet {record_count}: implausible length {incl_len}; walk stopped"
            )
            truncated = True
            break
        if pos + 16 + incl_len > len(data):
            warnings.append("final packet record is truncated")
            truncated = True
            break
        if record_count == 0:
            divisor = 1e9 if kind.endswith("-ns") else 1e6
            first_ts = ts_sec + ts_sub / divisor
        record_count += 1
        pos += 16 + incl_len
        if record_count >= MAX_PCAP_PACKETS:
            truncated = pos + 16 <= len(data)
            if truncated:
                warnings.append(f"packets: output bounded at {MAX_PCAP_PACKETS}")
            break
    return PcapSummary(
        format="pcap",
        endian=endian,
        version_major=version_major,
        version_minor=version_minor,
        linktype=linktype,
        linktype_name=_LINKTYPE_NAMES.get(linktype, f"DLT_{linktype}"),
        snaplen=snaplen,
        record_count=record_count,
        truncated=truncated,
        first_timestamp=first_ts,
        block_types=(),
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.pcap",
            method="pcap_global_header",
            confidence=Confidence.HIGH,
            detail=f"{record_count} packets in view, linktype {linktype}",
        ),
    )


def _inspect_pcapng(data: bytes) -> PcapSummary:
    """Shallow pcapng walk: name the blocks, count EPB, read first timestamp."""
    warnings: list[str] = []
    if len(data) < 28:
        return PcapSummary(
            format="pcapng",
            endian="little",
            version_major=0,
            version_minor=0,
            linktype=0,
            linktype_name="unknown",
            snaplen=0,
            record_count=0,
            truncated=True,
            first_timestamp=None,
            block_types=(),
            warnings=("SHB truncated",),
            evidence=Evidence(
                source="bin.pcap",
                method="pcapng_block_walk",
                confidence=Confidence.LOW,
                detail="SHB incomplete",
            ),
        )
    bom = int.from_bytes(data[8:12], "little")
    little = bom == 0x1A2B3C4D
    endian: Literal["little", "big"] = "little" if little else "big"
    version_major = int.from_bytes(data[12:14], endian)
    version_minor = int.from_bytes(data[14:16], endian)
    linktype = 0
    snaplen = 0
    blocks: list[str] = []
    record_count = 0
    truncated = False
    first_ts: float | None = None
    pos = 0
    while pos + 12 <= len(data):
        block_type = int.from_bytes(data[pos : pos + 4], endian)
        total_len = int.from_bytes(data[pos + 4 : pos + 8], endian)
        if total_len < 12 or total_len > _PCAP_MAX_RECORD or pos + total_len > len(data):
            warnings.append(f"block at offset {pos}: implausible length; walk stopped")
            truncated = True
            break
        if block_type == 0x0A0D0D0A:
            # SHB carries its own byte-order marker; note a mid-file resync.
            bom_here = int.from_bytes(data[pos + 8 : pos + 12], "little")
            if bom_here != bom:
                warnings.append(f"SHB at offset {pos}: byte order differs from the first")
        elif block_type == 0x00000001 and pos + 16 <= len(data):
            linktype = int.from_bytes(data[pos + 8 : pos + 10], endian)
            snaplen = int.from_bytes(data[pos + 12 : pos + 16], endian)
        elif block_type == 0x00000006 and pos + 28 <= len(data):
            # EPB: interface id, then a 64-bit microsecond timestamp.
            ts_high = int.from_bytes(data[pos + 12 : pos + 16], endian)
            ts_low = int.from_bytes(data[pos + 16 : pos + 20], endian)
            if record_count == 0:
                first_ts = (ts_high << 32 | ts_low) / 1e6
            record_count += 1
        if len(blocks) < MAX_PCAP_PACKETS:
            blocks.append(_PCAPNG_BLOCK_NAMES.get(block_type, f"0x{block_type:08x}"))
        else:
            truncated = True
            warnings.append(f"blocks: output bounded at {MAX_PCAP_PACKETS}")
            break
        pos += total_len
    return PcapSummary(
        format="pcapng",
        endian=endian,
        version_major=version_major,
        version_minor=version_minor,
        linktype=linktype,
        linktype_name=_LINKTYPE_NAMES.get(linktype, f"DLT_{linktype}") if linktype else "unknown",
        snaplen=snaplen,
        record_count=record_count,
        truncated=truncated,
        first_timestamp=first_ts,
        block_types=tuple(blocks),
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.pcap",
            method="pcapng_block_walk",
            confidence=Confidence.MEDIUM,
            detail=f"{record_count} enhanced packets, {len(blocks)} blocks in view",
        ),
    )


# ---------------------------------------------------------------------------
# firmware magic-scan (heuristic triage)
# ---------------------------------------------------------------------------

#: Known embedded/firmware magics. Confidence reflects how unique the byte
#: run is: a 6-byte magic in a fixed position beats a 3-byte run anywhere.
_MAGIC_SIGNATURES: tuple[tuple[str, bytes, Confidence, int], ...] = (
    # kind, magic, confidence, skip step after a hit (dedupe dense repeats)
    ("gzip", b"\x1f\x8b\x08", Confidence.LOW, 1),
    ("squashfs", b"hsqs", Confidence.MEDIUM, 4),
    ("uimage", b"\x27\x19\x19\x56", Confidence.MEDIUM, 4),
    ("cpio-newc", b"070701", Confidence.LOW, 512),
    ("bzip2", b"BZh", Confidence.LOW, 4),
    ("xz", b"\xfd7zXZ\x00", Confidence.MEDIUM, 6),
    ("lzma", b"\x5d\x00\x00", Confidence.LOW, 512),
    ("jffs2", b"\x19\x85\x20\x03", Confidence.MEDIUM, 512),
    ("dtb", b"\xd0\x0d\xfe\xed", Confidence.MEDIUM, 4),
)


@dataclass(frozen=True)
class MagicHit:
    """One firmware-signature match: offset, guessed container kind."""

    offset: int
    kind: str
    aligned: bool
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "kind": self.kind,
            "aligned": self.aligned,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class MagicScanSummary:
    """Bounded firmware-signature sweep over raw bytes (heuristic triage)."""

    size_bytes: int
    hits: tuple[MagicHit, ...]
    hit_count: int
    truncated: bool
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "size_bytes": self.size_bytes,
            "hits": [hit.to_dict() for hit in self.hits],
            "hit_count": self.hit_count,
            "truncated": self.truncated,
        }
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


def scan_magics(data: bytes) -> MagicScanSummary | None:
    """Sweep raw bytes for known firmware magics (``bytes.find``, C speed).

    Reports offset + guessed kind per hit, bounded at :data:`MAX_MAGIC_HITS`.
    This is heuristic triage over 3-6 byte signatures: gzip/lzma/bzip2/cpio
    hits are low confidence (those runs occur inside other data), the rest
    medium. ``None`` when nothing matched.
    """
    candidates: list[MagicHit] = []
    for kind, magic, confidence, skip in _MAGIC_SIGNATURES:
        pos = data.find(magic)
        while pos != -1 and len(candidates) < MAX_MAGIC_HITS * 4:
            candidates.append(
                MagicHit(
                    offset=pos,
                    kind=kind,
                    aligned=pos % 512 == 0,
                    confidence=confidence.value,
                )
            )
            pos = data.find(magic, pos + skip)
    if not candidates:
        return None
    candidates.sort(key=lambda hit: hit.offset)
    truncated = len(candidates) > MAX_MAGIC_HITS
    hits = tuple(candidates[:MAX_MAGIC_HITS])
    warnings: list[str] = []
    if truncated:
        warnings.append(f"hits: kept {MAX_MAGIC_HITS} of {len(candidates)}")
    warnings.append("firmware signature scan is heuristic triage (LOW/MEDIUM confidence)")
    return MagicScanSummary(
        size_bytes=len(data),
        hits=hits,
        hit_count=len(hits),
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=Evidence(
            source="bin.magics",
            method="firmware_magic_scan",
            confidence=Confidence.LOW,
            detail=f"{len(hits)} signature hits (bounded view)",
        ),
    )


# ---------------------------------------------------------------------------
# auto-detecting binmeta summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BinmetaSummary:
    """Whatever the auto-detectors matched in one file (all ``None``-able)."""

    path: str
    size_bytes: int
    detected: tuple[str, ...]
    wasm: WasmSummary | None = None
    evm: EvmSummary | None = None
    gguf: GgufSummary | None = None
    safetensors: SafetensorsSummary | None = None
    pcap: PcapSummary | None = None
    magics: MagicScanSummary | None = None
    warnings: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "detected": list(self.detected),
        }
        if self.wasm is not None:
            data["wasm"] = self.wasm.to_dict()
        if self.evm is not None:
            data["evm"] = self.evm.to_dict()
        if self.gguf is not None:
            data["gguf"] = self.gguf.to_dict()
        if self.safetensors is not None:
            data["safetensors"] = self.safetensors.to_dict()
        if self.pcap is not None:
            data["pcap"] = self.pcap.to_dict()
        if self.magics is not None:
            data["magics"] = self.magics.to_dict()
        if self.warnings:
            data["warnings"] = list(self.warnings)
        data["evidence"] = [item.to_dict() for item in self.evidence]
        return data


def load_container_bytes(path: Path) -> bytes:
    """Read a container file once, refusing missing files and oversize reads."""
    if not path.exists():
        raise AnalysisError(f"file not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"file too large for container inspection: {size} bytes "
            f"(limit {MAX_FILE_BYTES})"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc


def inspect_container(path: Path) -> BinmetaSummary:
    """Auto-detect every container format ``path`` matches and summarise it.

    Runs the WASM, GGUF, safetensors, pcap and EVM inspectors in that order
    (magic-gated formats first; EVM last because it has no magic), then the
    firmware magic sweep over the raw bytes. Inspectors that do not match
    return ``None`` and stay out of the summary; a file matching nothing is a
    valid summary with an empty ``detected`` list, never an error.
    """
    data = load_container_bytes(path)
    detected: list[str] = []
    warnings: list[str] = []
    evidence: list[Evidence] = []
    wasm = inspect_wasm(data)
    if wasm is not None:
        detected.append("wasm")
        warnings.extend(wasm.warnings)
        if wasm.evidence:
            evidence.append(wasm.evidence)
    gguf = inspect_gguf(data)
    if gguf is not None:
        detected.append("gguf")
        warnings.extend(gguf.warnings)
        if gguf.evidence:
            evidence.append(gguf.evidence)
    safetensors = inspect_safetensors(data)
    if safetensors is not None:
        detected.append("safetensors")
        warnings.extend(safetensors.warnings)
        if safetensors.evidence:
            evidence.append(safetensors.evidence)
    pcap = inspect_pcap(data)
    if pcap is not None:
        detected.append("pcap")
        warnings.extend(pcap.warnings)
        if pcap.evidence:
            evidence.append(pcap.evidence)
    evm = None
    if not detected:
        candidate = inspect_evm(data)
        # EVM has no magic; only claim a fully decodable blob as a detection.
        if candidate is not None and candidate.evm_like:
            evm = candidate
            detected.append("evm")
            warnings.extend(candidate.warnings)
            if candidate.evidence:
                evidence.append(candidate.evidence)
    magics = scan_magics(data)
    if magics is not None:
        warnings.extend(magics.warnings)
        if magics.evidence:
            evidence.append(magics.evidence)
    if not detected:
        warnings.append("no container format matched")
    return BinmetaSummary(
        path=str(path),
        size_bytes=len(data),
        detected=tuple(detected),
        wasm=wasm,
        evm=evm,
        gguf=gguf,
        safetensors=safetensors,
        pcap=pcap,
        magics=magics,
        warnings=tuple(warnings),
        evidence=tuple(evidence),
    )


def require_evm(data: bytes) -> EvmSummary:
    """Strict ``evm`` entry point: a typed error when the bytes are not code."""
    summary = inspect_evm(data)
    if summary is None:
        raise AnalysisError("no decodable EVM opcodes in this file")
    if not summary.evm_like:
        raise AnalysisError(
            "file decodes but is not EVM-like "
            f"(undecodable byte at offset {summary.invalid_at})"
            if summary.invalid_at is not None
            else "file decodes but has no terminator or JUMPDEST, so it is not EVM-like"
        )
    return summary

