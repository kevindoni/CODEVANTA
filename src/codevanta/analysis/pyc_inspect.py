"""Pure-Python ``.pyc`` deep inspector (lane-depth2).

Beyond the PEP 552 header this module walks the marshal-like object
structure of the top-level code object *shallowly*: the constants table
(bounded 32), the name tuple (bounded 64) and the nested code objects
(down to depth 8, bounded 64 records) are reported; the bytecode bytes
themselves are skipped, never decoded or unmarshalled.

The marshal walk understands the reference flag, small/normal tuples,
length-prefixed ASCII/unicode strings, bytes, ints (32/64/long), binary and
text floats, complex numbers, dicts, sets, frozensets, singletons and back
references - just enough to step over the tables. Anything else, truncated
data or a non-code top-level object raises the typed
:class:`~codevanta.core.report.AnalysisError`. The field layout follows the
Python minor version implied by the magic number (3.7 without
``posonlyargcount``; 3.11+ with a merged ``localsplus`` tuple).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_CONSTANTS",
    "MAX_NESTED_CODE",
    "MAX_NAMES",
    "NESTED_DEPTH",
    "PycInspectSummary",
    "inspect_pyc_code",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.pyc-deep"

#: Constants described from the top-level constants table (bounded output).
MAX_CONSTANTS = 32

#: Names kept from the top-level names tuple (bounded output).
MAX_NAMES = 64

#: Nested code-object records kept (bounded work).
MAX_NESTED_CODE = 64

#: Maximum recursion depth into nested code objects (bounded work).
NESTED_DEPTH = 8

#: Characters kept from one string constant (bounded output).
MAX_STRING_CHARS = 64

#: Final per-release ``.pyc`` magic numbers (Python 3.7-3.13, PEP 552 era).
_PYC_MAGIC_VERSIONS: dict[int, str] = {
    3390: "3.7",
    3394: "3.7",
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3571: "3.13",
}

#: ``FLAG_REF``: the object is recorded in the reference table.
FLAG_REF = 0x80

#: Marshal type bytes (without ``FLAG_REF``) this walker understands.
T_NULL = 0x30  # '0'
T_NONE = 0x4E  # 'N'
T_FALSE = 0x46  # 'F'
T_TRUE = 0x54  # 'T'
T_STOPITER = 0x53  # 'S'
T_ELLIPSIS = 0x2E  # '.'
T_INT = 0x69  # 'i'
T_INT64 = 0x49  # 'I'
T_FLOAT = 0x66  # 'f'
T_BINARY_FLOAT = 0x67  # 'g'
T_COMPLEX = 0x78  # 'x'
T_BINARY_COMPLEX = 0x79  # 'y'
T_LONG = 0x6C  # 'l'
T_STRING = 0x73  # 's' (bytes)
T_INTERNED = 0x74  # 't'
T_UNICODE = 0x75  # 'u'
T_REF = 0x72  # 'r'
T_TUPLE = 0x28  # '('
T_SMALL_TUPLE = 0x29  # ')'
T_LIST = 0x5B  # '['
T_DICT = 0x7B  # '{'
T_CODE = 0x63  # 'c'
T_ASCII = 0x61  # 'a'
T_ASCII_INTERNED = 0x41  # 'A'
T_SMALL_ASCII = 0x7A  # 'z'
T_SMALL_ASCII_INTERNED = 0x5A  # 'Z'
T_SET = 0x3C  # '<'
T_FROZENSET = 0x3E  # '>'


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class PycInspectSummary:
    """Deep shallow-walk view of one ``.pyc`` file. Bytecode never decoded."""

    path: str
    magic: int
    python_version: str | None
    hash_based: bool
    check_source: bool
    flags: int
    argcount: int
    kwonlyargcount: int
    nlocals: int
    stacksize: int
    code_flags: int
    bytecode_size: int
    constant_count: int
    constants: tuple[dict[str, Any], ...]
    constants_truncated: bool
    name_count: int
    names: tuple[str, ...]
    names_truncated: bool
    nested_code_count: int
    nested_code: tuple[dict[str, Any], ...]
    nested_code_truncated: bool
    nested_depth_max: int
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "python_version": self.python_version,
            "hash_based": self.hash_based,
            "check_source": self.check_source,
            "flags": self.flags,
            "argcount": self.argcount,
            "kwonlyargcount": self.kwonlyargcount,
            "nlocals": self.nlocals,
            "stacksize": self.stacksize,
            "code_flags": self.code_flags,
            "bytecode_size": self.bytecode_size,
            "constant_count": self.constant_count,
            "constants": [dict(entry) for entry in self.constants],
            "constants_truncated": self.constants_truncated,
            "name_count": self.name_count,
            "names": list(self.names),
            "names_truncated": self.names_truncated,
            "nested_code_count": self.nested_code_count,
            "nested_code": [dict(entry) for entry in self.nested_code],
            "nested_code_truncated": self.nested_code_truncated,
            "nested_depth_max": self.nested_depth_max,
        }


# ---- marshal-like shallow reader ----------------------------------------------


class _Reader:
    """Cursor over the marshal body with a reference table (no decoding)."""

    def __init__(self, data: bytes, start: int) -> None:
        self.data = data
        self.pos = start
        self.refs: list[dict[str, Any]] = []

    def byte(self) -> int:
        if self.pos + 1 > len(self.data):
            raise AnalysisError(f"truncated marshal body at 0x{self.pos:x}")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def raw(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise AnalysisError(f"truncated marshal body at 0x{self.pos:x} ({count} bytes)")
        value = self.data[self.pos : self.pos + count]
        self.pos += count
        return value

    def u32(self) -> int:
        return struct.unpack("<I", self.raw(4))[0]

    def remember(self, record: dict[str, Any]) -> dict[str, Any]:
        self.refs.append(record)
        return record


def _string_of(reader: _Reader, length: int) -> str:
    raw = reader.raw(length)
    return raw.decode("utf-8", errors="replace")


def _read_object(
    reader: _Reader,
    depth: int,
    version: tuple[int, int] | None,
    codes: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Read one marshal object shallowly, keeping the ref table aligned.

    Objects tagged ``FLAG_REF`` get their slot in the reference table
    *before* their content is read (marshal semantics), then the slot is
    back-filled with the finished record so later ``T_REF`` entries resolve.
    """
    if depth > NESTED_DEPTH * 2:
        raise AnalysisError("marshal structure deeper than the walk budget")
    type_byte = reader.byte()
    if not type_byte & FLAG_REF:
        return _read_object_inner(reader, type_byte, depth, version, codes)
    slot = len(reader.refs)
    reader.refs.append({})
    record = _read_object_inner(reader, type_byte & ~FLAG_REF, depth, version, codes)
    reader.refs[slot].update(record)
    return record


def _read_object_inner(
    reader: _Reader,
    base: int,
    depth: int,
    version: tuple[int, int] | None,
    codes: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Read one marshal object of type ``base`` (ref bit already stripped).

    Tuples keep every element walked (so the cursor stays correct) but only
    the first ``MAX_NAMES + MAX_CONSTANTS`` element records are kept.
    """
    if base == T_NULL:
        return {"kind": "null"}
    if base == T_NONE:
        return {"kind": "none"}
    if base == T_FALSE:
        return {"kind": "bool", "value": False}
    if base == T_TRUE:
        return {"kind": "bool", "value": True}
    if base == T_STOPITER:
        return {"kind": "stopiteration"}
    if base == T_ELLIPSIS:
        return {"kind": "ellipsis"}
    if base == T_INT:
        return {"kind": "int", "value": struct.unpack("<i", reader.raw(4))[0]}
    if base == T_INT64:
        return {"kind": "int", "value": struct.unpack("<q", reader.raw(8))[0]}
    if base == T_LONG:
        size = struct.unpack("<i", reader.raw(4))[0]
        if size < 0:
            raise AnalysisError("negative marshal long digit count")
        reader.raw(abs(size) * 2)
        return {"kind": "long"}
    if base == T_FLOAT:
        _ = _string_of(reader, reader.u32())
        return {"kind": "float"}
    if base == T_BINARY_FLOAT:
        _ = struct.unpack("<d", reader.raw(8))[0]
        return {"kind": "float"}
    if base == T_COMPLEX:
        _ = _string_of(reader, reader.u32())
        _ = _string_of(reader, reader.u32())
        return {"kind": "complex"}
    if base == T_BINARY_COMPLEX:
        reader.raw(16)
        return {"kind": "complex"}
    if base == T_STRING:
        value = reader.raw(reader.u32())
        return {"kind": "bytes", "size": len(value), "value": value[:MAX_STRING_CHARS].hex()}
    if base in (T_INTERNED, T_UNICODE, T_ASCII, T_ASCII_INTERNED):
        return {"kind": "str", "value": _string_of(reader, reader.u32())[:MAX_STRING_CHARS]}
    if base in (T_SMALL_ASCII, T_SMALL_ASCII_INTERNED):
        return {"kind": "str", "value": _string_of(reader, reader.byte())[:MAX_STRING_CHARS]}
    if base == T_REF:
        index = reader.u32()
        if index >= len(reader.refs):
            raise AnalysisError(f"marshal ref index {index} out of range")
        resolved = reader.refs[index]
        return {"kind": resolved.get("kind", "unresolved"), "value": resolved.get("value")}
    if base == T_CODE:
        if codes is None:
            raise AnalysisError("code object outside the top-level position")
        return _read_code_object(reader, version, depth, codes)
    if base in (T_TUPLE, T_LIST):
        count = reader.u32()
    elif base == T_SMALL_TUPLE:
        count = reader.byte()
    elif base == T_DICT:
        count = reader.u32()  # pair count; the loop reads two objects per pair
    elif base in (T_SET, T_FROZENSET):
        count = reader.u32()
    else:
        raise AnalysisError(f"unsupported marshal type 0x{base:02x} at 0x{reader.pos - 1:x}")
    if base == T_DICT:
        for _ in range(count):
            _read_object(reader, depth + 1, version, codes)
            _read_object(reader, depth + 1, version, codes)
        return {"kind": "dict"}
    kept: list[dict[str, Any]] = []
    for _ in range(count):
        item = _read_object(reader, depth + 1, version, codes)
        if len(kept) < MAX_NAMES + MAX_CONSTANTS:
            kept.append(item)
    if base == T_SET:
        return {"kind": "set"}
    if base == T_FROZENSET:
        return {"kind": "frozenset"}
    return {"kind": "tuple" if base != T_LIST else "list", "count": count, "items": kept}


def _read_code_object(
    reader: _Reader,
    version: tuple[int, int] | None,
    depth: int,
    codes: list[dict[str, Any]],
    *,
    top: bool = False,
) -> dict[str, Any]:
    """Read one code object: scalars, skipped bytecode, bounded tables.

    Field order follows the marshal ``TYPE_CODE`` layout of the implied
    Python minor version (3.7 without ``posonlyargcount``; 3.11+ with
    ``localsplus`` names/kinds plus filename, name and qualname). When
    ``top`` the record additionally carries the bounded names/constant
    tables for the summary.
    """
    argcount = reader.u32()
    posonly = reader.u32() if (version is None or version >= (3, 8)) else 0
    kwonlyargcount = reader.u32()
    nlocals = reader.u32()
    stacksize = reader.u32()
    code_flags = reader.u32()
    bytecode = _read_object(reader, depth + 1, version, None)
    if bytecode.get("kind") != "bytes":
        raise AnalysisError("code object's bytecode field is not a bytes object")
    bytecode_size = int(bytecode.get("size", 0))
    constants = _read_object(reader, depth + 1, version, codes)
    if constants.get("kind") != "tuple":
        raise AnalysisError("code object's constants field is not a tuple")
    names = _read_object(reader, depth + 1, version, codes)
    if names.get("kind") != "tuple":
        raise AnalysisError("code object's names field is not a tuple")
    filename_value = None
    record_name = None
    local_slots = 0
    if version is None or version >= (3, 11):
        localsplus = _read_object(reader, depth + 1, version, codes)
        _ = _read_object(reader, depth + 1, version, codes)  # localspluskinds
        filename = _read_object(reader, depth + 1, version, codes)
        name = _read_object(reader, depth + 1, version, codes)
        qualname = _read_object(reader, depth + 1, version, codes)
        firstlineno = reader.u32()
        _ = _read_object(reader, depth + 1, version, codes)  # linetable
        _ = _read_object(reader, depth + 1, version, codes)  # exceptiontable
        filename_value = (
            filename.get("value") if isinstance(filename.get("value"), str) else None
        )
        record_name = qualname.get("value") or name.get("value")
        local_slots = int(localsplus.get("count", 0))
    else:
        varnames = _read_object(reader, depth + 1, version, codes)
        freevars = _read_object(reader, depth + 1, version, codes)
        cellvars = _read_object(reader, depth + 1, version, codes)
        _ = _read_object(reader, depth + 1, version, codes)  # filename
        name = _read_object(reader, depth + 1, version, codes)
        firstlineno = reader.u32()
        _ = _read_object(reader, depth + 1, version, codes)  # lnotab
        record_name = name.get("value")
        local_slots = sum(
            int(table.get("count", 0))
            for table in (varnames, freevars, cellvars)
            if isinstance(table.get("count"), int)
        )
    record: dict[str, Any] = {
        "kind": "code",
        "name": record_name,
        "filename": filename_value,
        "argcount": argcount,
        "posonlyargcount": posonly,
        "kwonlyargcount": kwonlyargcount,
        "nlocals": nlocals,
        "stacksize": stacksize,
        "flags": code_flags,
        "bytecode_size": bytecode_size,
        "firstlineno": firstlineno,
        "local_slots": local_slots,
        "depth": depth,
    }
    if top:
        record["names"] = [
            str(item.get("value"))
            for item in names.get("items", [])[:MAX_NAMES]
            if isinstance(item.get("value"), str)
        ]
        record["names_count"] = int(names.get("count", 0))
        record["constants"] = [
            _describe_constant(item)
            for item in constants.get("items", [])[:MAX_CONSTANTS]
        ]
        record["constants_count"] = int(constants.get("count", 0))
    codes.append(record)
    return {"kind": "code", "name": record_name}


# ---- header + public entry point ----------------------------------------------


def _version_from_magic(magic: int) -> tuple[int, int] | None:
    """Map the 16-bit ``.pyc`` magic to a ``(major, minor)`` tuple."""
    label = _PYC_MAGIC_VERSIONS.get(magic)
    if label is None:
        return None
    return (int(label.split(".")[0]), int(label.split(".")[1]))


def _describe_constant(record: dict[str, Any]) -> dict[str, Any]:
    """Bounded description of one constant-table entry."""
    if record["kind"] == "code":
        return {"kind": "code", "name": record.get("name")}
    if record["kind"] == "bytes":
        return {"kind": "bytes", "size": record.get("size"), "hex": record.get("value")}
    value = record.get("value")
    if isinstance(value, str) and len(value) > MAX_STRING_CHARS:
        value = value[:MAX_STRING_CHARS]
    return {"kind": record["kind"], "value": value}


def inspect_pyc_code(path: str | Path) -> PycInspectSummary:
    """Walk one ``.pyc`` file's top-level code tables (pure Python, offline).

    The bytecode bytes are skipped, never decoded or unmarshalled; only the
    bounded constants/name tables and the nested code-object tree are read.

    Raises:
        AnalysisError: When the file is not readable, the 16-byte PEP 552
            header is truncated, the magic is 0, the body is truncated, a
            marshal type is unsupported, or the top-level object is not a
            code object.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    if len(data) < 16:
        raise AnalysisError("truncated .pyc header (16 bytes required)")
    magic = struct.unpack_from("<H", data, 0)[0]
    if data[2:4] != b"\r\n" or magic == 0:
        raise AnalysisError(f"bad .pyc magic bytes 0x{data[2:4].hex()} (magic {magic})")
    version = _version_from_magic(magic)
    (flags,) = struct.unpack_from("<I", data, 4)
    hash_based = bool(flags & 0x1)
    check_source = bool(flags & 0x2)
    codes: list[dict[str, Any]] = []
    reader = _Reader(data, 16)
    top_raw = reader.byte()  # the top-level type byte belongs to the walk
    top_type = top_raw & ~FLAG_REF
    if top_type != T_CODE:
        raise AnalysisError(f"top-level marshal object is not a code object (0x{top_type:02x})")
    ref_slot = -1
    if top_raw & FLAG_REF:
        ref_slot = len(reader.refs)
        reader.refs.append({})
    _read_code_object(reader, version, 0, codes, top=True)
    if not codes:
        raise AnalysisError("no code object parsed from the .pyc body")
    if ref_slot >= 0:
        reader.refs[ref_slot].update({"kind": "code", "name": codes[0].get("name")})
    # Nested code objects complete (and are appended) before the top-level
    # code object finishes, so the top record is the last one appended.
    top = codes[-1]
    nested = codes[:-1]
    nested_depth_max = max((record["depth"] for record in nested), default=0)
    names_list = [str(name) for name in top.get("names", [])]
    constants = list(top.get("constants", []))
    detail = (
        f"magic {magic}, top code {top.get('name')!r}; {top.get('constants_count')} constant(s), "
        f"{top.get('names_count')} name(s), {len(nested)} nested code object(s), depth {nested_depth_max}"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="marshal-shallow-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"bytecode_skipped": True},
    )
    return PycInspectSummary(
        path=str(target),
        magic=magic,
        python_version=_PYC_MAGIC_VERSIONS.get(magic),
        hash_based=hash_based,
        check_source=check_source,
        flags=flags,
        argcount=top["argcount"],
        kwonlyargcount=top["kwonlyargcount"],
        nlocals=top["nlocals"],
        stacksize=top["stacksize"],
        code_flags=top["flags"],
        bytecode_size=top["bytecode_size"],
        constant_count=int(top.get("constants_count", 0)),
        constants=tuple(constants),
        constants_truncated=int(top.get("constants_count", 0)) > MAX_CONSTANTS,
        name_count=int(top.get("names_count", 0)),
        names=tuple(names_list),
        names_truncated=int(top.get("names_count", 0)) > MAX_NAMES,
        nested_code_count=len(nested),
        nested_code=tuple(nested[:MAX_NESTED_CODE]),
        nested_code_truncated=len(nested) > MAX_NESTED_CODE,
        nested_depth_max=nested_depth_max,
        evidence=evidence,
    )
