"""Deep PE inspector tests (lane-depth2): resources, load config, .NET meta.

All fixtures are hand-built PE32+/PE32 images written to ``tmp_path`` --
no real binaries, no network, no external tools. Malformed cases prove the
typed :class:`~codevanta.core.report.AnalysisError`; the CLI sub-app and
the MCP ``codevanta_pe_deep`` tool are exercised against the same bytes.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis import binmeta, pe_loadconfig, pe_resources
from codevanta.analysis.managed_meta import inspect_managed_metadata
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

runner = CliRunner()

OPT_SIZE = {0x20B: 240, 0x10B: 224}
SECTION_VA = 0x1000


def _align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def make_pe(
    path: Path,
    *,
    opt_magic: int = 0x20B,
    data_dirs: dict[int, tuple[int, int]] | None = None,
    section_payload: bytes = b"",
    section_va: int = 0x1000,
    num_dirs: int = 16,
) -> Path:
    """Build a minimal PE with one section carrying ``section_payload``.

    RVAs are the file-offset-equivalent ``section_va + payload offset``
    (identity mapping), so callers can point a data directory at any byte
    they place in the payload.
    """
    data_dirs = data_dirs or {}
    opt_size = OPT_SIZE[opt_magic]
    num_sections = 1  # always emit the section table entry (even when empty)
    headers_size = 0x80 + 24 + opt_size + 40 * num_sections
    headers_size = _align(headers_size, 16)
    payload_off = headers_size

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = bytearray(24)
    coff[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", coff, 4, 0x8664, num_sections, 0, 0, 0, opt_size, 0x0022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    struct.pack_into("<I", opt, 16, section_va + 0x10)  # entry point
    struct.pack_into("<H", opt, 70, 0x0640)  # DllCharacteristics NX|DYNAMIC_BASE
    struct.pack_into("<I", opt, 92 if opt_magic == 0x10B else 108, num_dirs)
    dd_off = 96 if opt_magic == 0x10B else 112
    for index, (rva, size) in data_dirs.items():
        struct.pack_into("<II", opt, dd_off + 8 * index, rva, size)
    section = bytearray(40)
    section[0:6] = b".rsrc\x00"
    struct.pack_into(
        "<IIII",
        section, 8,
        len(section_payload), section_va, len(section_payload), payload_off,
    )
    out = bytearray(dos)
    out += coff
    out += opt
    out += section
    out += bytes(headers_size - len(out))
    out += section_payload
    path.write_bytes(bytes(out))
    return path


# ---- hand-built VS_VERSIONINFO -------------------------------------------------


def _u16blob(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def _vs_header(key: str, value_len: int, vtype: int, total: int) -> bytes:
    return struct.pack("<HHH", total, value_len, vtype) + _u16blob(key)


def _string_block(key: str, value: str) -> bytes:
    """One String block: key/value pair inside a StringTable (padded to total)."""
    key_bytes = _u16blob(key)
    value_bytes = value.encode("utf-16-le") + b"\x00\x00"
    value_off = _align(6 + len(key_bytes))
    total = _align(value_off + len(value_bytes))
    blob = _vs_header(key, len(value_bytes) // 2, 1, total)
    blob += bytes(value_off - len(blob))
    blob += value_bytes
    blob += bytes(total - len(blob))
    return blob


def _string_table(key: str, strings: list[bytes]) -> bytes:
    key_bytes = _u16blob(key)
    body_off = _align(6 + len(key_bytes))
    body = b"".join(strings)
    total = body_off + len(body)
    blob = _vs_header(key, 0, 1, total)
    blob += bytes(body_off - len(blob))
    blob += body
    return blob


def build_version_resource(pairs: list[tuple[str, str]]) -> bytes:
    """A full ``VS_VERSION_INFO`` with fixed info + StringFileInfo block."""
    fixed = bytearray(52)
    struct.pack_into("<I", fixed, 0, 0xFEEF04BD)  # signature
    struct.pack_into("<IIII", fixed, 8, (1 << 16) | 2, (3 << 16) | 4, (5 << 16) | 6, (7 << 16) | 8)
    strings = [_string_block(key, value) for key, value in pairs]
    table = _string_table("040904b0", strings)
    sfi_key_bytes = _u16blob("StringFileInfo")
    sfi_body_off = _align(6 + len(sfi_key_bytes))
    sfi_total = sfi_body_off + len(table)
    sfi = _vs_header("StringFileInfo", 0, 1, sfi_total)
    sfi += bytes(sfi_body_off - len(sfi))
    sfi += table
    key_bytes = _u16blob("VS_VERSION_INFO")
    value_off = _align(6 + len(key_bytes))
    children_off = _align(value_off + 52)
    total = children_off + len(sfi)
    head = _vs_header("VS_VERSION_INFO", 52, 0, total)
    head += bytes(value_off - len(head))
    head += fixed
    head += bytes(children_off - len(head))
    return head + sfi


# ---- resource-directory builder -------------------------------------------------


def _dir_blob(entries: list[bytes]) -> bytes:
    return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries)) + b"".join(entries)


def _entry_bytes(name_field: int, offset_field: int) -> bytes:
    return struct.pack("<II", name_field, offset_field)


def _utf16_name(text: str) -> bytes:
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


class _Payload:
    """Sequential payload writer (4-byte aligned, positions remembered)."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.pos: dict[str, int] = {}

    def put(self, key: str, blob: bytes) -> int:
        while len(self.buf) % 4:
            self.buf.append(0)
        self.pos[key] = len(self.buf)
        self.buf.extend(blob)
        return self.pos[key]

    def put_dir(self, key: str, entries: list[bytes]) -> int:
        return self.put(key, _dir_blob(entries))

    def rel(self, key: str) -> int:
        return self.pos[key]

    def sub(self, key: str) -> int:
        return self.pos[key] | 0x80000000

    def named(self, key: str) -> int:
        return self.pos[key] | 0x80000000


def build_resource_payload(
    version: bytes, manifest: bytes
) -> tuple[bytes, dict[str, int]]:
    """Resource section payload with ICON/VERSION/MANIFEST + named custom type.

    The root directory comes first (offsets inside a resource directory are
    relative to the root), so the layout is: root with placeholder entries,
    payloads, data entries, then the type/name/language dirs -- every entry
    is patched to its final root-relative offset afterwards.
    """
    p = _Payload()
    p.put("root", _dir_blob([b"\x00" * 8] * 4))
    p.put("icon_data", b"\x00\x00\x01\x00ICONBYTES")
    p.put("version_data", version)
    p.put("manifest_data", manifest)
    p.put("custom_data", b"CUSTOM-PAYLOAD")
    p.put("custom_name", _utf16_name("APPDATA"))
    # Data entries: RVA points at the payload, size at its byte length.
    p.put("icon_dentry", struct.pack("<IIII", SECTION_VA + p.rel("icon_data"), 16, 0, 0))
    p.put("version_dentry", struct.pack("<IIII", SECTION_VA + p.rel("version_data"), len(version), 0, 0))
    p.put("manifest_dentry", struct.pack("<IIII", SECTION_VA + p.rel("manifest_data"), len(manifest), 0, 0))
    p.put("custom_dentry", struct.pack("<IIII", SECTION_VA + p.rel("custom_data"), 14, 0, 0))

    patches: list[tuple[int, int, str, bool, bool]] = []

    def dir1(key: str, name_value: int, target: str, *, named: bool = False, subdir: bool = False) -> None:
        start = p.put_dir(key, [b"\x00" * 8])
        patches.append((start + 16, name_value, target, named, subdir))

    dir1("icon_lang", 0x409, "icon_dentry")
    dir1("version_lang", 1033, "version_dentry")
    dir1("manifest_lang", 1033, "manifest_dentry")
    dir1("custom_lang", 1033, "custom_dentry")
    # Name level (the dir its root entry points at carries name ids).
    dir1("icon_name", 1, "icon_lang", subdir=True)
    dir1("version_name", 1, "version_lang", subdir=True)
    dir1("manifest_name", 1, "manifest_lang", subdir=True)
    dir1("custom_named", p.rel("custom_name"), "custom_lang", named=True, subdir=True)
    root_start = p.rel("root")
    for index, (name_value, target) in enumerate(
        [(3, "icon_name"), (16, "version_name"), (24, "manifest_name"), (100, "custom_named")]
    ):
        patches.append((root_start + 16 + 8 * index, name_value, target, False, True))
    for offset, name_value, target, named, subdir in patches:
        name_field = name_value | (0x80000000 if named else 0)
        offset_field = p.rel(target) | (0x80000000 if subdir else 0)
        struct.pack_into("<II", p.buf, offset, name_field, offset_field)
    return bytes(p.buf), p.pos


def build_loadconfig_blob(
    *,
    is64: bool = True,
    guard_flags: int = 0x1400,
    guard_count: int = 42,
    seh_count: int = 0,
    size: int | None = None,
) -> bytes:
    """``IMAGE_LOAD_CONFIG_DIRECTORY`` blob with the fields this lane reads."""
    total = size if size is not None else (152 if is64 else 96)
    blob = bytearray(total)
    struct.pack_into("<I", blob, 0, total)
    struct.pack_into("<HH", blob, 8, 1, 0)  # version 1.0
    if is64:
        struct.pack_into("<Q", blob, 92, 0xDEADBEEF)  # SecurityCookie
        struct.pack_into("<Q", blob, 100, 0x2000)  # SEHandlerTable VA
        struct.pack_into("<Q", blob, 108, seh_count)
        struct.pack_into("<Q", blob, 116, 0x3000)  # GuardCFCheckFunctionPointer
        struct.pack_into("<Q", blob, 132, 0x4000)  # GuardCFFunctionTable VA
        struct.pack_into("<Q", blob, 140, guard_count)
        struct.pack_into("<I", blob, 148, guard_flags)
    else:
        struct.pack_into("<I", blob, 60, 0xDEADBEEF)
        struct.pack_into("<I", blob, 64, 0x2000)
        struct.pack_into("<I", blob, 68, seh_count)
        struct.pack_into("<I", blob, 72, 0x3000)
        struct.pack_into("<I", blob, 80, 0x4000)
        struct.pack_into("<I", blob, 84, guard_count)
        struct.pack_into("<I", blob, 88, guard_flags)
    return bytes(blob)


def build_tls_directory64(callbacks_va: int) -> bytes:
    """``IMAGE_TLS_DIRECTORY64`` with ``AddressOfCallBacks`` = callbacks_va."""
    return struct.pack("<QQQQII", 0x5000, 0x5100, 0x5200, callbacks_va, 0, 0)


def build_tls_directory32(callbacks_va: int) -> bytes:
    """``IMAGE_TLS_DIRECTORY32`` with ``AddressOfCallBacks`` = callbacks_va."""
    return struct.pack("<IIIIII", 0x5000, 0x5100, 0x5200, callbacks_va, 0, 0)


def build_tls_callback_array(vas: list[int], *, is64: bool = True) -> bytes:
    word = "<Q" if is64 else "<I"
    return b"".join(struct.pack(word, va) for va in vas) + struct.pack(word, 0)


# ---- .NET metadata builder ------------------------------------------------------


def build_metadata_root(
    *,
    tables_blob: bytes,
    strings_blob: bytes,
    guid_blob: bytes = b"\x01" * 16,
    blob_stream: bytes = b"\x00",
) -> bytes:
    """BSJB root with #~/#Strings/#GUID/#Blob streams (offsets relative)."""
    version = b"v4.0.30319\x00\x00\x00\x00\x00"
    stream_names = ["#~", "#Strings", "#GUID", "#Blob"]
    payloads = [tables_blob, strings_blob, guid_blob, blob_stream]
    header_size = 16 + len(version) + 4
    stream_headers_size = sum(8 + _align(len(name) + 1) for name in stream_names)
    offset = header_size + stream_headers_size
    streams = []
    for name, payload in zip(stream_names, payloads, strict=True):
        streams.append((name, offset, len(payload)))
        offset += len(payload)
    root = bytearray()
    root += b"BSJB"
    root += struct.pack("<HHI", 1, 1, 0)
    root += struct.pack("<I", len(version))
    root += version
    root += struct.pack("<HH", 0, len(streams))
    for name, so, size in streams:
        root += struct.pack("<II", so, size)
        encoded = name.encode("ascii") + b"\x00"
        encoded += bytes(_align(len(encoded)) - len(encoded))
        root += encoded
    for payload in payloads:
        root += payload
    return bytes(root)


def build_tables_stream(row_counts: dict[int, int], rows: bytes) -> bytes:
    valid = 0
    for table_id in row_counts:
        valid |= 1 << table_id
    head = bytearray(24)
    head[4] = 2  # major version
    head[5] = 0  # minor version
    head[6] = 0  # HeapSizes: all narrow heaps
    head[7] = 1
    struct.pack_into("<QQ", head, 8, valid, 0)
    counts = b"".join(struct.pack("<I", row_counts[t]) for t in sorted(row_counts))
    return bytes(head) + counts + rows


def build_managed_rows(strings: dict[str, int]) -> tuple[bytes, dict[int, int]]:
    """Module/TypeRef/TypeDef/Field/MethodDef rows for a tiny assembly."""
    module = struct.pack("<HHHHH", 1, strings["Sample.exe"], 1, 1, 1)
    typeref_object = struct.pack("<HHH", 0, strings["Object"], strings["System"])
    typeref_exc = struct.pack("<HHH", 0, strings["Exception"], strings["System"])
    # TypeDef: flags u4, name sidx, ns sidx, extends coded u2, fieldlist, methodlist
    typedef_module = struct.pack("<IHHHHH", 0, strings["<Module>"], 0, 0, 1, 1)
    typedef_greeter = struct.pack(
        "<IHHHHH", 0, strings["Greeter"], strings["Demo"], (1 << 2) | 1, 1, 1
    )  # extends TypeRef rid 1 = System.Object
    typedef_widget = struct.pack(
        "<IHHHHH", 0, strings["Widget"], strings["Demo"], (2 << 2) | 0, 2, 2
    )  # extends TypeDef rid 2 = Demo.Greeter (tag 0 << 2 | rid 2)
    typedef_iface = struct.pack(
        "<IHHHHH", 0, strings["IWidget"], strings["Demo"], 0, 2, 3
    )  # extends 0 = no base
    field = struct.pack("<HHH", 0, strings["_count"], 1)
    method1 = struct.pack("<IHHHHH", 0x600, 0, 0, strings["Greet"], 1, 1)
    method2 = struct.pack("<IHHHHH", 0x610, 0, 0, strings["Build"], 1, 1)
    method3 = struct.pack("<IHHHHH", 0x620, 0, 0, strings["Ping"], 1, 1)
    rows = (
        module
        + typeref_object
        + typeref_exc
        + typedef_module
        + typedef_greeter
        + typedef_widget
        + typedef_iface
        + field
        + method1
        + method2
        + method3
    )
    counts = {0x00: 1, 0x01: 2, 0x02: 4, 0x04: 1, 0x06: 3}
    return rows, counts


def build_strings_heap(names: list[str]) -> tuple[bytes, dict[str, int]]:
    heap = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(heap)
        heap += name.encode("utf-8") + b"\x00"
    return bytes(heap), offsets


def make_managed_pe(path: Path, root: bytes, *, section_va: int = 0x2000) -> Path:
    """PE whose CLR directory points at a metadata root in one section."""
    clr_rva = section_va
    meta_rva = section_va + 0x80
    clr = bytearray(72)
    struct.pack_into("<IHHIIII", clr, 0, 72, 4, 0, meta_rva, len(root), 1, 0x06000001)
    payload = clr + bytes(0x80 - len(clr)) + root
    return make_pe(
        path,
        data_dirs={14: (clr_rva, 0x48)},
        section_payload=payload,
        section_va=section_va,
    )


# ---- shared fixture payloads -----------------------------------------------------

VERSION_BLOB = build_version_resource(
    [("ProductName", "Codevanta Demo"), ("CompanyName", "Example Corp")]
)
MANIFEST_TEXT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">demo</assembly>"
)
RESOURCE_PAYLOAD, RESOURCE_POS = build_resource_payload(
    VERSION_BLOB, MANIFEST_TEXT.encode("utf-8")
)


def resource_dirs() -> dict[int, tuple[int, int]]:
    root_rva = SECTION_VA + RESOURCE_POS["root"]
    return {2: (root_rva, 0x400)}


# ---- PE resources ----------------------------------------------------------------


def test_resources_walk_types_and_entries(tmp_path: Path) -> None:
    target = make_pe(
        tmp_path / "res.exe", data_dirs=resource_dirs(), section_payload=RESOURCE_PAYLOAD
    )
    summary = pe_resources.inspect_pe_resources(target)
    assert summary.resource_table_present is True
    assert summary.types == ("ICON", "VERSION", "MANIFEST", "TYPE_100")
    assert summary.entry_count == 4
    assert summary.icon_count == 1
    assert summary.version_count == 1
    assert summary.manifest_count == 1
    named = [entry for entry in summary.entries if entry["name"] == "APPDATA"]
    assert len(named) == 1
    assert named[0]["type"] == "TYPE_100"
    assert named[0]["language"] == 1033
    assert summary.previews["ICON"].startswith("000001004943")
    assert "assembly" in (summary.manifest_preview or "")
    assert json.dumps(summary.to_dict())


def test_resources_version_pairs_and_fixed_version(tmp_path: Path) -> None:
    target = make_pe(
        tmp_path / "ver.exe", data_dirs=resource_dirs(), section_payload=RESOURCE_PAYLOAD
    )
    summary = pe_resources.inspect_pe_resources(target)
    assert summary.file_version == "1.2.3.4"
    assert summary.product_version == "5.6.7.8"
    assert ("ProductName", "Codevanta Demo") in summary.version_pairs
    assert ("CompanyName", "Example Corp") in summary.version_pairs


def test_resources_absent_directory_is_present_false(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "nores.exe")
    summary = pe_resources.inspect_pe_resources(target)
    assert summary.resource_table_present is False
    assert summary.type_count == 0
    assert summary.evidence.method == "data-directory-2-empty"


def test_resources_malformed_cases(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        pe_resources.inspect_pe_resources(tmp_path / "ghost.exe")
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not a pe at all" * 8)
    with pytest.raises(AnalysisError, match="missing MZ magic"):
        pe_resources.inspect_pe_resources(plain)
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"MZ" + bytes(0x40))
    with pytest.raises(AnalysisError, match="PE signature not found"):
        pe_resources.inspect_pe_resources(fake)
    bad = make_pe(
        tmp_path / "badrva.exe", data_dirs={2: (0x900000, 0x10)}, section_payload=b"\x00" * 16
    )
    with pytest.raises(AnalysisError, match="not mapped to file bytes"):
        pe_resources.inspect_pe_resources(bad)


def test_resources_pe32_variant_and_cycle_bound(tmp_path: Path) -> None:
    target = make_pe(
        tmp_path / "res32.exe",
        opt_magic=0x10B,
        data_dirs=resource_dirs(),
        section_payload=RESOURCE_PAYLOAD,
    )
    assert pe_resources.inspect_pe_resources(target).type_count == 4
    # Cyclic directory: the root's only entry points back at the root, so the
    # bounded directory budget must stop the walk (typed empty-tree error).
    cycle = bytearray(_dir_blob([_entry_bytes(3, 0)]))
    struct.pack_into("<I", cycle, 16 + 4, 0x80000000)
    cyclic = make_pe(
        tmp_path / "cycle.exe",
        data_dirs={2: (SECTION_VA, 0x10)},
        section_payload=bytes(cycle),
    )
    with pytest.raises(AnalysisError, match="carries no data entries"):
        pe_resources.inspect_pe_resources(cyclic)


def test_resources_detector_and_registry(tmp_path: Path) -> None:
    target = make_pe(
        tmp_path / "reg.exe", data_dirs=resource_dirs(), section_payload=RESOURCE_PAYLOAD
    )
    summary = binmeta.detect_pe_resources(target)
    assert summary is not None and summary.type_count == 4
    assert binmeta.detect_pe_resources(tmp_path) is None
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"ELF magicless" * 4)
    assert binmeta.detect_pe_resources(plain) is None
    report = binmeta.inspect_metadata(target)
    assert "pe-resources" in report.details


# ---- PE load config ---------------------------------------------------------------


def loadconfig_payload(
    lc: bytes,
    callbacks: list[int],
    *,
    is64: bool = True,
    section_va: int = SECTION_VA,
) -> tuple[bytes, dict[int, tuple[int, int]]]:
    buf = bytearray(lc)
    tls_pos = len(buf)
    if is64:
        # IMAGE_TLS_DIRECTORY64 is 40 bytes; the array follows it directly.
        tls_dir = build_tls_directory64(section_va + tls_pos + 40)
    else:
        # IMAGE_TLS_DIRECTORY32 is 24 bytes; the array follows it directly.
        tls_dir = build_tls_directory32(section_va + tls_pos + 24)
    buf += tls_dir
    buf += build_tls_callback_array(callbacks, is64=is64)
    return bytes(buf), {
        9: (section_va + tls_pos, len(tls_dir)),
        10: (section_va, len(lc)),
    }


def test_loadconfig_full_summary(tmp_path: Path) -> None:
    lc = build_loadconfig_blob(guard_flags=0x1500, guard_count=42, seh_count=7)
    payload, dirs = loadconfig_payload(lc, [0x401000, 0x401010, 0x401020])
    target = make_pe(tmp_path / "lc.exe", data_dirs=dirs, section_payload=payload)
    summary = pe_loadconfig.inspect_pe_load_config(target)
    assert summary.load_config_present is True
    assert summary.config_size == 152
    assert summary.config_version == "1.0"
    assert summary.guard_cf_function_count == 42
    assert "CF_INSTRUMENTED" in summary.guard_flag_names
    assert "CF_FUNCTION_TABLE_PRESENT" in summary.guard_flag_names
    assert summary.seh_handler_count == 7
    assert summary.security_cookie == 0xDEADBEEF
    assert summary.tls_callback_count == 3
    assert summary.tls_callbacks == (0x401000, 0x401010, 0x401020)
    assert summary.dep_nx_compat is True
    assert summary.dep_dynamic_base is True
    assert summary.evidence.confidence.value == "high"
    data = summary.to_dict()
    assert data["tls_callbacks"] == ["0x401000", "0x401010", "0x401020"]


def test_loadconfig_32bit_and_truncation(tmp_path: Path) -> None:
    lc = build_loadconfig_blob(is64=False, guard_count=5)
    payload, dirs = loadconfig_payload(
        lc, [0x401000 + i * 4 for i in range(20)], is64=False
    )
    target = make_pe(
        tmp_path / "lc32.exe", opt_magic=0x10B, data_dirs=dirs, section_payload=payload
    )
    summary = pe_loadconfig.inspect_pe_load_config(target)
    assert summary.tls_callback_count == 20
    assert len(summary.tls_callbacks) == 16
    assert summary.tls_callbacks_truncated is True
    assert summary.guard_cf_function_count == 5


def test_loadconfig_absent_and_warnings(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "nolc.exe")
    summary = pe_loadconfig.inspect_pe_load_config(target)
    assert summary.load_config_present is False
    assert summary.guard_cf_function_count is None
    assert summary.evidence.method == "data-directory-10-empty"
    lc = build_loadconfig_blob(seh_count=3)
    payload, dirs = loadconfig_payload(lc, [])
    special = make_pe(tmp_path / "noseh.exe", data_dirs=dirs, section_payload=payload)
    data = bytearray(special.read_bytes())
    struct.pack_into("<H", data, 0x80 + 24 + 70, 0x0600)  # NX|NO_SEH (spec bits)
    special.write_bytes(bytes(data))
    noseh = pe_loadconfig.inspect_pe_load_config(special)
    assert noseh.tls_callback_count == 0
    assert noseh.dep_policy == "nx+no-seh"
    assert any("NO_SEH" in warning for warning in noseh.warnings)


def test_loadconfig_malformed(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        pe_loadconfig.inspect_pe_load_config(tmp_path / "ghost.exe")
    tiny = make_pe(
        tmp_path / "tiny.exe", data_dirs={10: (SECTION_VA, 4)}, section_payload=b"\x02\x00\x00\x00"
    )
    with pytest.raises(AnalysisError, match="contradicts the directory bytes"):
        pe_loadconfig.inspect_pe_load_config(tiny)
    lie = bytearray(build_loadconfig_blob())
    struct.pack_into("<I", lie, 0, 400)
    liar = make_pe(
        tmp_path / "liar.exe",
        data_dirs={10: (SECTION_VA, len(lie))},
        section_payload=bytes(lie),
    )
    with pytest.raises(AnalysisError, match="contradicts the directory bytes"):
        pe_loadconfig.inspect_pe_load_config(liar)
    unmapped = make_pe(
        tmp_path / "unmapped.exe",
        data_dirs={10: (0x900000, 152)},
        section_payload=build_loadconfig_blob(),
    )
    with pytest.raises(AnalysisError, match="not mapped to file bytes"):
        pe_loadconfig.inspect_pe_load_config(unmapped)
    lc = build_loadconfig_blob()
    buf = bytearray(lc)
    tls_pos = len(buf)
    buf += build_tls_directory64(0x900000)
    bad_tls = make_pe(
        tmp_path / "badtls.exe",
        data_dirs={9: (SECTION_VA + tls_pos, 40), 10: (SECTION_VA, len(lc))},
        section_payload=bytes(buf),
    )
    with pytest.raises(AnalysisError, match="TLS callback array"):
        pe_loadconfig.inspect_pe_load_config(bad_tls)
    truncated = make_pe(
        tmp_path / "trunctls.exe",
        data_dirs={9: (SECTION_VA, 8)},
        section_payload=b"\x00" * 8,
    )
    with pytest.raises(AnalysisError, match="TLS directory truncated"):
        pe_loadconfig.inspect_pe_load_config(truncated)


def test_loadconfig_detector(tmp_path: Path) -> None:
    lc = build_loadconfig_blob()
    payload, dirs = loadconfig_payload(lc, [0x401000])
    target = make_pe(tmp_path / "det.exe", data_dirs=dirs, section_payload=payload)
    summary = binmeta.detect_pe_loadconfig(target)
    assert summary is not None and summary.tls_callback_count == 1
    assert binmeta.detect_pe_loadconfig(tmp_path) is None


# ---- .NET managed metadata ------------------------------------------------------


def managed_pe(path: Path) -> Path:
    strings_heap, strings = build_strings_heap(
        [
            "Sample.exe", "System", "Object", "Exception", "<Module>", "Demo",
            "Greeter", "Widget", "IWidget", "_count", "Greet", "Build", "Ping",
        ]
    )
    rows, counts = build_managed_rows(strings)
    tables = build_tables_stream(counts, rows)
    root = build_metadata_root(tables_blob=tables, strings_blob=strings_heap)
    return make_managed_pe(path, root)


def test_managed_metadata_summary(tmp_path: Path) -> None:
    target = managed_pe(tmp_path / "managed.exe")
    summary = inspect_managed_metadata(target)
    assert summary is not None
    assert summary.runtime_version == "4.0"
    assert summary.metadata_version == "1.1"
    assert summary.entry_point_token == 0x06000001
    assert summary.streams == ("#~", "#Strings", "#GUID", "#Blob")
    assert summary.type_count == 4
    assert summary.typeref_count == 2
    assert summary.method_count == 3
    assert summary.field_count == 1
    by_name = {row.name: row for row in summary.types}
    assert by_name["Greeter"].namespace == "Demo"
    assert by_name["Greeter"].base == "System.Object"
    assert by_name["Widget"].base == "Demo.Greeter"
    assert by_name["IWidget"].base is None
    assert summary.base_types == ("System.Object", "Demo.Greeter")
    assert summary.types_truncated is False
    assert summary.evidence.confidence.value == "high"
    assert json.dumps(summary.to_dict())


def test_managed_metadata_none_and_malformed(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        inspect_managed_metadata(tmp_path / "ghost.exe")
    plain_pe = make_pe(tmp_path / "plain.exe")
    assert inspect_managed_metadata(plain_pe) is None  # no CLR directory
    text = tmp_path / "text.bin"
    text.write_bytes(b"just text, not a PE")
    with pytest.raises(AnalysisError, match="missing MZ magic"):
        inspect_managed_metadata(text)
    # CLR header claiming less than its fixed layout.
    short = make_pe(
        tmp_path / "short.exe",
        data_dirs={14: (0x2000, 0x48)},
        # 76 bytes >= the 72-byte directory, so the parser reads the whole
        # header and rejects its own Size field (8 < the fixed layout).
        section_payload=struct.pack("<I", 8) + bytes(72),
        section_va=0x2000,
    )
    with pytest.raises(AnalysisError, match="CLR header size 8"):
        inspect_managed_metadata(short)
    # CLR header truncated by EOF.
    truncated = make_pe(
        tmp_path / "clipped.exe",
        data_dirs={14: (0x2000, 0x48)},
        section_payload=bytes(16),
        section_va=0x2000,
    )
    with pytest.raises(AnalysisError, match="CLR header truncated"):
        inspect_managed_metadata(truncated)
    # Metadata RVA outside the section table.
    strings_heap, _ = build_strings_heap(["x"])
    root = build_metadata_root(
        tables_blob=build_tables_stream({0x02: 1}, b"\x00" * 14),
        strings_blob=strings_heap,
    )
    payload = bytearray(
        struct.pack("<IHHIIII", 72, 4, 0, 0x900000, len(root), 1, 0x06000001)
    )
    payload += bytes(0x80 - len(payload)) + root
    bad_rva = make_pe(
        tmp_path / "badrva.exe",
        data_dirs={14: (0x2000, 0x48)},
        section_payload=bytes(payload),
        section_va=0x2000,
    )
    with pytest.raises(AnalysisError, match="metadata RVA 0x900000"):
        inspect_managed_metadata(bad_rva)
    # Corrupt BSJB signature.
    corrupt = managed_pe(tmp_path / "corrupt.exe")
    raw = bytearray(corrupt.read_bytes())
    bsjb_off = 0x80 + 24 + OPT_SIZE[0x20B] + 40 + 0x80
    raw[bsjb_off : bsjb_off + 4] = b"JUNK"
    corrupt.write_bytes(bytes(raw))
    with pytest.raises(AnalysisError, match="BSJB"):
        inspect_managed_metadata(corrupt)


def test_managed_bad_stream_layout(tmp_path: Path) -> None:
    strings_heap, _ = build_strings_heap(["Demo", "Widget"])
    # Unknown table id 0x2D anywhere in the valid mask -> typed schema error.
    tables = build_tables_stream({0x2D: 1, 0x02: 1}, b"\x00" * 32)
    root = build_metadata_root(tables_blob=tables, strings_blob=strings_heap)
    target = make_managed_pe(tmp_path / "unktable.exe", root)
    with pytest.raises(AnalysisError, match="unknown metadata table 0x2d"):
        inspect_managed_metadata(target)
    # Root with no table stream at all.
    version = b"v4.0.30319\x00\x00\x00\x00\x00"
    body = bytearray(b"BSJB")
    body += struct.pack("<HHI", 1, 1, 0)
    body += struct.pack("<I", len(version))
    body += version
    body += struct.pack("<HH", 0, 1)
    off = 16 + len(version) + 4 + 8 + _align(len("#Strings") + 1)
    body += struct.pack("<II", off, len(strings_heap))
    name = b"#Strings\x00"
    name += bytes(_align(len(name)) - len(name))
    body += name
    body += strings_heap
    nostreams = make_managed_pe(tmp_path / "nostreams.exe", bytes(body))
    with pytest.raises(AnalysisError, match="table stream"):
        inspect_managed_metadata(nostreams)
    # #Strings offset pointing past the heap.
    broken = build_tables_stream({0x02: 1}, struct.pack("<IHHHHH", 0, 9999, 0, 0, 0, 0))
    badroot = build_metadata_root(tables_blob=broken, strings_blob=strings_heap)
    badheap = make_managed_pe(tmp_path / "badheap.exe", badroot)
    with pytest.raises(AnalysisError, match="#Strings offset"):
        inspect_managed_metadata(badheap)


# ---- CLI + MCP surface ----------------------------------------------------------


def test_cli_deep_pe_resources_json(tmp_path: Path) -> None:
    target = make_pe(
        tmp_path / "cli.exe", data_dirs=resource_dirs(), section_payload=RESOURCE_PAYLOAD
    )
    result = runner.invoke(app, ["deep", "pe-resources", str(target), "--json"])
    assert result.exit_code == 0, result.stdout
    assert "resource_table_present" in result.stdout


def test_cli_deep_pe_loadconfig_table(tmp_path: Path) -> None:
    lc = build_loadconfig_blob()
    payload, dirs = loadconfig_payload(lc, [0x401000])
    target = make_pe(tmp_path / "clilc.exe", data_dirs=dirs, section_payload=payload)
    result = runner.invoke(app, ["deep", "pe-loadconfig", str(target)])
    assert result.exit_code == 0, result.stdout
    assert "guard_cf_function_count" in result.stdout


def test_cli_deep_managed_meta(tmp_path: Path) -> None:
    target = managed_pe(tmp_path / "climanaged.exe")
    result = runner.invoke(app, ["deep", "managed-meta", str(target), "--json"])
    assert result.exit_code == 0, result.stdout
    assert "System.Object" in result.stdout


def test_cli_deep_error_path(tmp_path: Path) -> None:
    result = runner.invoke(app, ["deep", "pe-resources", str(tmp_path / "ghost.exe")])
    assert result.exit_code == 2
    result = runner.invoke(app, ["deep", "elf-dynamic", str(tmp_path / "ghost.exe")])
    assert result.exit_code == 2


def test_mcp_pe_deep_tool(tmp_path: Path) -> None:
    lc = build_loadconfig_blob()
    # Resources keep their own layout (RVA base SECTION_VA); the load-config
    # payload is rebuilt against a section_va shifted past the resource bytes,
    # so every RVA baked into its TLS directory stays consistent after the
    # two payloads are concatenated.
    base = len(RESOURCE_PAYLOAD)
    lc_payload, lc_dirs = loadconfig_payload(
        lc, [0x401000], section_va=SECTION_VA + base
    )
    combined = RESOURCE_PAYLOAD + lc_payload
    merged = {**lc_dirs, **resource_dirs()}
    target = make_pe(tmp_path / "mcp.exe", data_dirs=merged, section_payload=combined)
    payload = tools.codevanta_pe_deep(str(target))
    assert payload["format"] == "pe"
    assert payload["resources"]["resource_table_present"] is True
    assert payload["loadconfig"]["tls_callback_count"] == 1
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_pe_deep(str(tmp_path / "ghost.exe"))


def test_mcp_elf_macho_rejects_non_matching(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "notelf.exe")
    with pytest.raises(AnalysisError, match="neither an ELF nor a thin Mach-O"):
        tools.codevanta_elf_macho(str(target))
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_elf_macho(str(tmp_path / "ghost.exe"))
