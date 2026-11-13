"""Crash-lane tests: ELF core parser, Apple .ips parser, CLI and MCP wiring.

Every fixture is assembled byte by byte in this module, so the tests stay
offline and self-contained: a synthetic ELF64 core (``NT_PRSTATUS`` with
``rip=0x401000``, ``NT_SIGINFO`` with signal 11, ``NT_PRPSINFO``, ``NT_FILE``),
an ELF32 i386 core, a core without ``NT_FILE`` (``PT_LOAD`` fallback), a
deliberately chopped core, and ``.ips`` reports in the JSON-body, marker and
legacy-plist generations. What is asserted is every extracted field, the typed
``AnalysisError`` for malformed input, and the wiring only -- the parsers have
their guarantees, the CLI/MCP layers just have to reach them.
"""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import apple_ips, crash_core
from codevanta.analysis.apple_ips import MAX_IMAGES, parse_ips_report
from codevanta.analysis.crash_core import parse_core_dump
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

runner = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``, keeping its layout."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(result: Result) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(result.stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _align4(size: int) -> int:
    return (size + 3) & ~3


def _note(name: bytes, note_type: int, descriptor: bytes) -> bytes:
    """One ELF note: 12-byte header, name and descriptor, each padded to 4."""
    return (
        struct.pack("<III", len(name), len(descriptor), note_type)
        + name
        + b"\x00" * (_align4(len(name)) - len(name))
        + descriptor
        + b"\x00" * (_align4(len(descriptor)) - len(descriptor))
    )


_CORE_NAME = b"CORE\x00"

RIP = 0x401000
RSP = 0x7FFD0000
RBP = 0x7FFC0000
TID = 1234
FAULT_ADDR = 0xDEADBEE0


def _prstatus64(tid: int, signal: int) -> bytes:
    """``NT_PRSTATUS`` descriptor: 324 bytes, x86_64 register slots filled."""
    descriptor = bytearray(324)
    struct.pack_into("<II", descriptor, 0, signal, 1)  # pr_info.si_signo/.si_code
    struct.pack_into("<H", descriptor, 16, signal)  # pr_cursig
    struct.pack_into("<I", descriptor, 24, tid)  # pr_pid
    struct.pack_into("<Q", descriptor, 104 + 4 * 8, RBP)  # pr_reg[4] = rbp
    struct.pack_into("<Q", descriptor, 104 + 16 * 8, RIP)  # pr_reg[16] = rip
    struct.pack_into("<Q", descriptor, 104 + 19 * 8, RSP)  # pr_reg[19] = rsp
    return bytes(descriptor)


def _siginfo64(signal: int, code: int, addr: int) -> bytes:
    """Kernel ``siginfo_t``: si_signo@0, si_errno@4, si_code@8, si_addr@16."""
    descriptor = bytearray(128)
    struct.pack_into("<III", descriptor, 0, signal, 0, code)
    struct.pack_into("<Q", descriptor, 16, addr)
    return bytes(descriptor)


def _prpsinfo64(pid: int, comm: bytes, args: bytes) -> bytes:
    descriptor = bytearray(136)
    struct.pack_into("<I", descriptor, 24, pid)
    descriptor[40 : 40 + len(comm)] = comm
    descriptor[56 : 56 + len(args)] = args
    return bytes(descriptor)


def _nt_file64(entries: Sequence[tuple[int, int]], names: Sequence[bytes]) -> bytes:
    descriptor = bytearray()
    descriptor += struct.pack("<QQ", len(entries), 4096)
    for start, end in entries:
        descriptor += struct.pack("<QQQ", start, end, 0)
    for name in names:
        descriptor += name + b"\x00"
    return bytes(descriptor)


def _elf64_header(phoff: int, phnum: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    return ident + struct.pack(
        "<HHIQQQIHHHHHH",
        4,  # e_type = ET_CORE
        62,  # e_machine = EM_X86_64
        1,  # e_version
        0,  # e_entry
        phoff,
        0,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        phnum,
        64,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )


def _phdr64(p_type: int, p_offset: int, p_vaddr: int, p_filesz: int, p_memsz: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, 0, p_offset, p_vaddr, 0, p_filesz, p_memsz, 4)


def make_core64(
    path: Path,
    notes: Sequence[bytes],
    *,
    load_segment: tuple[int, int] | None = None,
    note_filesz_override: int | None = None,
) -> Path:
    """Write an ELF64 core with one ``PT_NOTE`` (and optional ``PT_LOAD``)."""
    phoff = 64
    note_offset = phoff + 56 * (2 if load_segment else 1)
    note_blob = b"".join(notes)
    note_filesz = (
        note_filesz_override if note_filesz_override is not None else len(note_blob)
    )
    blob = bytearray(_elf64_header(phoff, 2 if load_segment else 1))
    blob += _phdr64(4, note_offset, 0, note_filesz, note_filesz)
    if load_segment is not None:
        vaddr, size = load_segment
        load_offset = note_offset + len(note_blob)
        blob += _phdr64(1, load_offset, vaddr, size, size)
    blob += note_blob
    if load_segment is not None:
        blob += bytes(load_segment[1])
    path.write_bytes(bytes(blob))
    return path


def core64_path(tmp_path: Path) -> Path:
    """The canonical synthetic x86_64 core: four notes, one per parser branch."""
    return make_core64(
        tmp_path / "synthetic.core",
        [
            _note(_CORE_NAME, 1, _prstatus64(TID, 11)),  # NT_PRSTATUS
            _note(
                _CORE_NAME,
                3,
                _prpsinfo64(TID, b"crashtest\x00", b"crashtest --run\x00"),
            ),
            _note(_CORE_NAME, 0x53494749, _siginfo64(11, 1, FAULT_ADDR)),  # NT_SIGINFO
            _note(
                _CORE_NAME,
                0x46494C45,  # NT_FILE
                _nt_file64([(0x7F1000000000, 0x7F1000001000)], [b"/lib/libtest.so"]),
            ),
        ],
    )


# ---- ELF core parser ---------------------------------------------------------


def test_core64_extracts_every_field(tmp_path: Path) -> None:
    summary = parse_core_dump(core64_path(tmp_path))
    assert summary.arch == "x86_64"
    assert summary.signal == 11
    assert summary.signal_code == 1
    assert summary.fault_addr == FAULT_ADDR
    assert summary.pid == TID
    assert summary.comm == "crashtest"
    assert summary.exe == "crashtest"
    assert summary.faulting_thread == TID
    assert summary.registers == {"rip": RIP, "rsp": RSP, "rbp": RBP}
    assert summary.threads == 1
    assert summary.notes_seen == 4
    assert summary.fpregset_present is False
    assert summary.truncated is False
    assert summary.evidence.source == "crash.elfcore"
    assert summary.evidence.confidence.value == "high"


def test_core64_nt_file_modules(tmp_path: Path) -> None:
    summary = parse_core_dump(core64_path(tmp_path))
    assert len(summary.mapped_modules) == 1
    module = summary.mapped_modules[0]
    assert module.name == "/lib/libtest.so"
    assert module.start == 0x7F1000000000
    assert module.end == 0x7F1000001000


def test_core32_extracts_eip(tmp_path: Path) -> None:
    descriptor = bytearray(140)
    struct.pack_into("<H", descriptor, 16, 11)  # pr_cursig
    struct.pack_into("<I", descriptor, 24, 4321)  # pr_pid
    struct.pack_into("<I", descriptor, 68 + 5 * 4, 0x7FFB0000)  # ebp
    struct.pack_into("<I", descriptor, 68 + 12 * 4, 0x08048000)  # eip
    struct.pack_into("<I", descriptor, 68 + 15 * 4, 0x7FFA0000)  # esp
    siginfo = struct.pack("<IIII", 11, 0, 2, 0x41414141) + b"\x00" * 8
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", 4, 3, 1, 0, 52, 0, 0, 52, 32, 1, 40, 0, 0
    )
    notes = (
        _note(_CORE_NAME, 1, bytes(descriptor))
        + _note(_CORE_NAME, 0x53494749, siginfo)
    )
    phdr = struct.pack("<IIIIIIII", 4, 84, 0, 0, len(notes), len(notes), 0, 4)
    path = tmp_path / "synthetic32.core"
    path.write_bytes(header + phdr + notes)
    summary = parse_core_dump(path)
    assert summary.arch == "i386"
    assert summary.signal == 11
    assert summary.faulting_thread == 4321
    assert summary.registers == {
        "eip": 0x08048000,
        "esp": 0x7FFA0000,
        "ebp": 0x7FFB0000,
    }
    assert summary.fault_addr == 0x41414141


def test_core_without_nt_file_falls_back_to_pt_load(tmp_path: Path) -> None:
    path = make_core64(
        tmp_path / "fallback.core",
        [_note(_CORE_NAME, 1, _prstatus64(TID, 11))],
        load_segment=(0x400000, 0x1000),
    )
    summary = parse_core_dump(path)
    assert len(summary.mapped_modules) == 1
    assert summary.mapped_modules[0].name == "PT_LOAD segment 0"
    assert summary.mapped_modules[0].start == 0x400000
    assert any("PT_LOAD" in warning for warning in summary.warnings)


def test_truncated_note_descriptor_reports_and_continues(tmp_path: Path) -> None:
    prstatus = _note(_CORE_NAME, 1, _prstatus64(TID, 11))
    prpsinfo = _note(_CORE_NAME, 3, _prpsinfo64(TID, b"crashtest\x00", b"crashtest --run\x00"))
    siginfo = _note(_CORE_NAME, 0x53494749, _siginfo64(11, 1, FAULT_ADDR))
    path = tmp_path / "chopped.core"
    blob = bytearray()
    blob += _elf64_header(64, 1)
    blob += _phdr64(4, 120, 0, len(prstatus) + len(prpsinfo) + len(siginfo), 0)
    keep = len(prstatus) + len(prpsinfo) + 12 + 8 + 24
    blob += prstatus + prpsinfo + siginfo
    path.write_bytes(bytes(blob[: 120 + keep]))
    summary = parse_core_dump(path)
    assert summary.truncated is True
    assert any("is truncated" in warning for warning in summary.warnings)
    # The notes before the cut still parse; the signal falls back to pr_cursig.
    assert summary.registers["rip"] == RIP
    assert summary.signal == 11
    assert summary.notes_seen == 3


def test_truncated_program_header_table_is_a_typed_error(tmp_path: Path) -> None:
    path = core64_path(tmp_path)
    path.write_bytes(path.read_bytes()[:100])
    with pytest.raises(AnalysisError, match="truncated program header table"):
        parse_core_dump(path)


def test_exec_elf_is_rejected_as_not_a_core(elf64_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not a core dump"):
        parse_core_dump(elf64_path)


def test_garbage_file_is_a_typed_error(tmp_path: Path) -> None:
    path = tmp_path / "garbage.bin"
    path.write_bytes(b"this is not a core dump at all, just text")
    with pytest.raises(AnalysisError, match="not an ELF core dump"):
        parse_core_dump(path)


def test_big_endian_elf_is_a_typed_error(tmp_path: Path) -> None:
    ident = b"\x7fELF" + bytes([2, 2, 1, 0]) + bytes(8)
    path = tmp_path / "be.core"
    path.write_bytes(ident + bytes(120))
    with pytest.raises(AnalysisError, match="little-endian"):
        parse_core_dump(path)


def test_missing_file_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot stat"):
        parse_core_dump(tmp_path / "missing.core")


def test_oversized_core_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crash_core, "MAX_CORE_BYTES", 16)
    path = core64_path(tmp_path)
    with pytest.raises(AnalysisError, match="parse budget"):
        parse_core_dump(path)


def test_unknown_machine_keeps_thread_without_registers(tmp_path: Path) -> None:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 4, 40, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )  # e_machine = 40 (EM_ARM): no register layout
    notes = _note(_CORE_NAME, 1, _prstatus64(TID, 11))
    phdr = struct.pack("<IIQQQQQQ", 4, 0, 120, 0, 0, len(notes), len(notes), 4)
    path = tmp_path / "arm.core"
    path.write_bytes(header + phdr + notes)
    summary = parse_core_dump(path)
    assert summary.arch.startswith("unknown")
    assert summary.threads == 1
    assert summary.faulting_thread == TID
    assert summary.registers == {}
    assert summary.signal == 11
    assert any("e_machine" in warning for warning in summary.warnings)


def test_core_summary_payload_is_json_safe(tmp_path: Path) -> None:
    payload = parse_core_dump(core64_path(tmp_path)).to_dict()
    encoded = json.dumps(payload)
    assert payload["registers"]["rip"] == f"0x{RIP:x}"
    assert payload["evidence"]["source"] == "crash.elfcore"
    assert "0x401000" in encoded


# ---- Apple .ips parser -------------------------------------------------------

IPS_HEADER = (
    '{"app_name":"CrashyApp","timestamp":"2024-05-01 12:00:00.00 +0000",'
    '"bug_type":"309","os_version":"macOS 14.2 (23C64)","product":"Mac15,7",'
    '"build_version":"23C64"}'
)

IPS_BODY = (
    '{"uptime":4200,"faultingThread":0,'
    '"exception":{"type":"EXC_BAD_ACCESS (SIGSEGV)","signal":"SIGSEGV",'
    '"subtype":"KERN_INVALID_ADDRESS at 0x0000000000000000"},'
    '"termination":{"indicator":"Libsystem Signal","namespace":"SIGNAL",'
    '"details":"Signal 11 detected"},'
    '"threads":[{"triggered":true,"frames":['
    '{"imageIndex":0,"imageOffset":12345,"symbol":"_main","symbolLocation":16},'
    '{"imageIndex":1,"imageOffset":999}]}],'
    '"images":['
    '{"name":"CrashyApp","path":"/Applications/CrashyApp.app/CrashyApp",'
    '"uuid":"11111111-2222-3333-4444-555555555555"},'
    '{"name":"libsystem_c.dylib","path":"/usr/lib/system/libsystem_c.dylib",'
    '"uuid":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}]}'
)


def ips_json_path(tmp_path: Path) -> Path:
    path = tmp_path / "modern.ips"
    path.write_text(f"{IPS_HEADER}\n{IPS_BODY}\n", encoding="utf-8")
    return path


IPS_PLIST_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>OS Version</key><string>iOS 12.4 (16G77)</string>
\t<key>Time Stamp</key><string>2019-08-01 12:00:00.00 +0000</string>
\t<key>Exception Type</key><string>EXC_BAD_ACCESS (SIGSEGV)</string>
\t<key>Exception Codes</key><string>KERN_INVALID_ADDRESS at 0x0000000041414141</string>
\t<key>Faulting Thread</key><integer>1</integer>
\t<key>Threads</key><array>
\t\t<dict><key>frames</key><array>
\t\t\t<dict><key>imageOffset</key><integer>4660</integer></dict>
\t\t</array></dict>
\t\t<dict><key>triggered</key><true/><key>frames</key><array>
\t\t\t<dict><key>imageIndex</key><integer>0</integer><key>imageOffset</key><integer>1234</integer><key>symbol</key><string>_main</string><key>symbolLocation</key><integer>12</integer></dict>
\t\t\t<dict><key>imageIndex</key><integer>1</integer><key>imageOffset</key><integer>88</integer></dict>
\t\t</array></dict>
\t</array>
\t<key>Images</key><array>
\t\t<dict><key>name</key><string>LegacyApp</string><key>path</key><string>/var/containers/Bundle/Application/LegacyApp</string><key>uuid</key><string>FFFF-0001</string></dict>
\t\t<dict><key>name</key><string>libsystem_c.dylib</string><key>path</key><string>/usr/lib/system/libsystem_c.dylib</string></dict>
\t</array>
</dict>
</plist>
"""


def ips_plist_path(tmp_path: Path) -> Path:
    path = tmp_path / "legacy.ips"
    # Real legacy reports cut the header line mid-object; the tolerant header
    # scanner must still recover product/os_version before the XML body.
    path.write_text(
        '{"bug_type":"309","product":"iPhone8,1","os_version":"iOS 12.4 (16G77)"\n'
        + IPS_PLIST_BODY,
        encoding="utf-8",
    )
    return path


def test_ips_json_extracts_every_field(tmp_path: Path) -> None:
    summary = parse_ips_report(ips_json_path(tmp_path))
    assert summary.format == "json"
    assert summary.product == "Mac15,7"
    assert summary.os_version == "macOS 14.2 (23C64)"
    assert summary.crash_time == "2024-05-01 12:00:00.00 +0000"
    assert summary.exception_type == "EXC_BAD_ACCESS (SIGSEGV)"
    assert summary.exception_signal == "SIGSEGV"
    assert summary.termination_reason is not None
    assert "Libsystem Signal" in summary.termination_reason
    assert summary.faulting_thread == 0
    assert len(summary.frames) == 2
    first = summary.frames[0]
    assert first.image == "CrashyApp"
    assert first.offset == 12345
    assert first.symbol == "_main"
    assert first.symbol_location == 16
    second = summary.frames[1]
    assert second.image == "libsystem_c.dylib"
    assert second.offset == 999
    assert second.symbol is None
    assert len(summary.images) == 2
    assert summary.images[0].uuid == "11111111-2222-3333-4444-555555555555"
    assert summary.truncated is False
    assert summary.evidence.source == "crash.ips"
    assert summary.evidence.confidence.value == "high"


def test_ips_marker_line_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "marker.ips"
    body = json.loads(IPS_BODY)
    body["product"] = "Mac15,7"
    path.write_text("JSON dump header\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.format == "json"
    assert summary.product == "Mac15,7"
    assert summary.exception_signal == "SIGSEGV"
    assert summary.frames[0].symbol == "_main"


def test_ips_plist_extracts_every_field(tmp_path: Path) -> None:
    summary = parse_ips_report(ips_plist_path(tmp_path))
    assert summary.format == "plist"
    assert summary.product == "iPhone8,1"
    assert summary.os_version == "iOS 12.4 (16G77)"
    assert summary.crash_time == "2019-08-01 12:00:00.00 +0000"
    assert summary.exception_type == "EXC_BAD_ACCESS (SIGSEGV)"
    assert summary.exception_signal == "SIGSEGV"
    assert summary.faulting_thread == 1
    assert len(summary.frames) == 2
    assert summary.frames[0].image == "LegacyApp"
    assert summary.frames[0].symbol == "_main"
    assert summary.frames[1].image == "libsystem_c.dylib"
    assert summary.frames[1].symbol is None
    assert len(summary.images) == 2
    assert summary.evidence.confidence.value == "high"


def test_ips_image_ceiling_truncates(tmp_path: Path) -> None:
    body = json.loads(IPS_BODY)
    body["images"] = [
        {"name": f"image_{index}", "path": f"/tmp/{index}"}
        for index in range(MAX_IMAGES + 5)
    ]
    path = tmp_path / "many_images.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.truncated is True
    assert len(summary.images) == MAX_IMAGES
    assert any("image limit" in warning for warning in summary.warnings)


def test_ips_summary_payload_is_json_safe(tmp_path: Path) -> None:
    payload = parse_ips_report(ips_json_path(tmp_path)).to_dict()
    encoded = json.dumps(payload)
    assert payload["frames"][0]["offset"] == "0x3039"
    assert payload["evidence"]["source"] == "crash.ips"
    assert "_main" in encoded


@pytest.mark.parametrize(
    "content",
    [
        "",
        "random log text with no structure\n",
        '{"bug_type":"309"}\nno json or plist here\n',
        "JSON dump header\nnot json at all\n",
    ],
)
def test_ips_malformed_inputs_are_typed_errors(tmp_path: Path, content: str) -> None:
    path = tmp_path / "broken.ips"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AnalysisError):
        parse_ips_report(path)


def test_ips_missing_file_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot stat"):
        parse_ips_report(tmp_path / "missing.ips")


# ---- CLI wiring (`codevanta crash core|ips`) ---------------------------------


def test_cli_core_table(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "core", str(core64_path(tmp_path))])
    assert result.exit_code == 0
    text = _output(result)
    assert "x86_64" in text
    assert "0x401000" in text
    assert "SIGSEGV (11)" in text
    assert "/lib/libtest.so" in text
    assert "crash.elfcore" in text
    assert "confidence: high" in text


def test_cli_core_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "core", str(core64_path(tmp_path)), "--json"])
    assert result.exit_code == 0
    payload = _payload(result)
    assert payload["arch"] == "x86_64"
    assert payload["signal"] == 11
    assert payload["registers"]["rip"] == "0x401000"
    assert payload["faulting_thread"] == TID
    assert payload["mapped_modules"][0]["name"] == "/lib/libtest.so"
    assert payload["evidence"]["confidence"] == "high"


def test_cli_core_missing_file_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "core", str(tmp_path / "missing.core")])
    assert result.exit_code == 2
    assert "error:" in _output(result)


def test_cli_core_rejects_non_core_file(tmp_path: Path) -> None:
    path = tmp_path / "text.file"
    path.write_text("definitely not a core dump", encoding="utf-8")
    result = runner.invoke(app, ["crash", "core", str(path)])
    assert result.exit_code == 2
    assert "error:" in _output(result)


def test_cli_ips_table(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "ips", str(ips_json_path(tmp_path))])
    assert result.exit_code == 0
    text = _output(result)
    assert "EXC_BAD_ACCESS (SIGSEGV)" in text
    assert "_main + 16" in text
    assert "CrashyApp" in text
    assert "crash.ips" in text


def test_cli_ips_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "ips", str(ips_json_path(tmp_path)), "--json"])
    assert result.exit_code == 0
    payload = _payload(result)
    assert payload["format"] == "json"
    assert payload["product"] == "Mac15,7"
    assert payload["exception_signal"] == "SIGSEGV"
    assert payload["frames"][0]["symbol"] == "_main"


def test_cli_ips_legacy_plist(tmp_path: Path) -> None:
    result = runner.invoke(app, ["crash", "ips", str(ips_plist_path(tmp_path))])
    assert result.exit_code == 0
    text = _output(result)
    assert "plist format" in text
    assert "iPhone8,1" in text


def test_cli_crash_group_help_lists_both_commands() -> None:
    result = runner.invoke(app, ["crash", "--help"])
    assert result.exit_code == 0
    text = _output(result)
    assert "core" in text
    assert "ips" in text


# ---- MCP tool layer (`codevanta_crash`) --------------------------------------


def test_mcp_crash_auto_detects_elf_core(tmp_path: Path) -> None:
    payload = tools.codevanta_crash(str(core64_path(tmp_path)))
    assert payload["format"] == "elf-core"
    assert payload["path"].endswith("synthetic.core")
    assert payload["arch"] == "x86_64"
    assert payload["registers"]["rip"] == "0x401000"
    assert payload["evidence"]["source"] == "crash.elfcore"


def test_mcp_crash_auto_detects_ips(tmp_path: Path) -> None:
    payload = tools.codevanta_crash(str(ips_json_path(tmp_path)))
    assert payload["format"] == "apple-ips"
    assert payload["exception_type"] == "EXC_BAD_ACCESS (SIGSEGV)"
    assert payload["frames"][0]["symbol"] == "_main"
    assert payload["evidence"]["source"] == "crash.ips"


def test_mcp_crash_missing_path_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_crash(str(tmp_path / "missing.core"))


def test_mcp_crash_non_crash_file_is_a_typed_error(tmp_path: Path) -> None:
    path = tmp_path / "noise.txt"
    path.write_text("no crash format here\n", encoding="utf-8")
    with pytest.raises(AnalysisError):
        tools.codevanta_crash(str(path))


def test_mcp_tools_module_exports_codevanta_crash() -> None:
    assert callable(tools.codevanta_crash)


# ---- .ips parser: bounds, degenerate payloads, alternate generations ----------


def test_ips_oversized_report_is_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report above the parse budget is refused before any read."""
    monkeypatch.setattr(apple_ips, "MAX_IPS_BYTES", 16)
    path = tmp_path / "huge.ips"
    path.write_text(IPS_HEADER + "\n" + IPS_BODY + "\n", encoding="utf-8")
    with pytest.raises(AnalysisError, match="parse budget"):
        parse_ips_report(path)


def test_ips_unreadable_report_is_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` while reading the body surfaces as a typed error."""
    path = tmp_path / "locked.ips"
    path.write_text(IPS_HEADER + "\n" + IPS_BODY + "\n", encoding="utf-8")

    def _boom(self: Path) -> bytes:
        raise OSError("simulated read failure")

    monkeypatch.setattr(Path, "read_bytes", _boom)
    with pytest.raises(AnalysisError, match="cannot read"):
        parse_ips_report(path)


def test_ips_string_termination_reason_is_kept(tmp_path: Path) -> None:
    """A string-shaped ``termination`` becomes the reason verbatim."""
    body = json.loads(IPS_BODY)
    body["termination"] = "process crashed because the needle was empty"
    path = tmp_path / "strterm.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.termination_reason == (
        "process crashed because the needle was empty"
    )


def test_ips_degenerate_images_and_frames_are_skipped(tmp_path: Path) -> None:
    """Non-array images, junk entries and list-pair frames all degrade cleanly."""
    body = json.loads(IPS_BODY)
    body["images"] = [42, {"name": "good.dylib"}, {"path": "/x/noname"}]
    body["threads"] = [
        {
            "triggered": True,
            "frames": [
                [0, 4660],  # list-pair frame: imageIndex, imageOffset
                "junk-frame",  # unsupported shape -> skipped with a warning
                {"imageIndex": 0, "imageOffset": 88},
            ],
        }
    ]
    path = tmp_path / "degenerate.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert [image.name for image in summary.images] == ["good.dylib", "image 2"]
    assert len(summary.frames) == 2
    assert summary.frames[0].image == "good.dylib"
    assert summary.frames[0].offset == 4660
    assert any("unsupported shape" in w for w in summary.warnings)


def test_ips_non_array_images_are_ignored(tmp_path: Path) -> None:
    """An images payload that is not an array warns and yields no images."""
    body = json.loads(IPS_BODY)
    body["images"] = {"name": "not-an-array"}
    path = tmp_path / "weird_images.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.images == ()
    assert any("images list is not an array" in w for w in summary.warnings)


def test_ips_frame_ceiling_truncates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Frames beyond the budget are dropped with a warning, not an error."""
    monkeypatch.setattr(apple_ips, "MAX_FRAMES", 2)
    body = json.loads(IPS_BODY)
    body["threads"] = [
        {
            "triggered": True,
            "frames": [
                {"imageIndex": index, "imageOffset": index * 16}
                for index in range(6)
            ],
        }
    ]
    path = tmp_path / "many_frames.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert len(summary.frames) == 2
    assert summary.truncated is True
    assert any("frame limit" in w for w in summary.warnings)


def test_ips_non_array_frames_are_ignored(tmp_path: Path) -> None:
    """A frame payload that is not an array warns and yields no frames."""
    body = json.loads(IPS_BODY)
    body["threads"] = [{"triggered": True, "frames": {"0": {}}}]
    path = tmp_path / "weird_frames.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.frames == ()
    assert any("no frame array" in w for w in summary.warnings)


def test_ips_non_array_threads_are_ignored(tmp_path: Path) -> None:
    """A threads payload that is not an array warns and yields no frames."""
    body = json.loads(IPS_BODY)
    body["threads"] = "thread zero"
    path = tmp_path / "weird_threads.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.frames == ()
    assert summary.faulting_thread is None
    assert any("threads list is not an array" in w for w in summary.warnings)


def test_ips_out_of_range_faulting_thread_falls_back(tmp_path: Path) -> None:
    """A bogus declared index falls back to the triggered, then first thread."""
    body = json.loads(IPS_BODY)
    body["faultingThread"] = 9
    body["threads"] = [
        {"frames": [{"imageIndex": 0, "imageOffset": 1}]},
        {"triggered": True, "frames": [{"imageIndex": 0, "imageOffset": 2}]},
    ]
    path = tmp_path / "badindex.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.faulting_thread == 1
    assert summary.frames[0].offset == 2
    assert any("out of range" in w for w in summary.warnings)


def test_ips_non_dict_thread_entry_warns(tmp_path: Path) -> None:
    """A thread entry that is not a dictionary keeps its index, drops frames."""
    body = json.loads(IPS_BODY)
    body["threads"] = ["just a string"]
    path = tmp_path / "strthread.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.faulting_thread == 0
    assert summary.frames == ()
    assert any("not a dictionary" in w for w in summary.warnings)


def test_ips_exception_signal_parsed_from_type(tmp_path: Path) -> None:
    """Signal-less JSON bodies recover the signal from the exception type."""
    body = {
        "exception": {"type": "EXC_BAD_ACCESS (SIGSEGV)"},
        "images": [],
        "threads": [],
    }
    path = tmp_path / "signal_only.ips"
    path.write_text(IPS_HEADER + "\n" + json.dumps(body) + "\n", encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.exception_signal == "SIGSEGV"
    assert summary.frames == ()
    assert summary.evidence.confidence.value == "medium"


def test_ips_two_line_marker_body_is_merged(tmp_path: Path) -> None:
    """Marker reports with the header and body on separate JSON lines merge."""
    dump_header = '{"bug_type":"309","product":"Mac15,7"}'
    crash_body = json.dumps(json.loads(IPS_BODY))
    path = tmp_path / "twolines.ips"
    path.write_text(
        "JSON dump header\n" + dump_header + "\nlog noise line\n" + crash_body + "\n",
        encoding="utf-8",
    )
    summary = parse_ips_report(path)
    assert summary.product == "Mac15,7"
    assert summary.frames[0].symbol == "_main"


def test_ips_header_line_with_two_json_lines_merges(tmp_path: Path) -> None:
    """Marker generation keeps merging even when the dump header is absent."""
    first = json.dumps(
        {
            "uptime": 100,
            "faultingThread": 0,
            "threads": [{"frames": [{"imageIndex": 0, "imageOffset": 7}]}],
        }
    )
    second = json.dumps({"exception": {"type": "EXC_BREAKPOINT (SIGTRAP)"}})
    path = tmp_path / "merged.ips"
    path.write_text(
        "JSON dump header\n" + first + "\n" + second + "\n", encoding="utf-8"
    )
    summary = parse_ips_report(path)
    assert summary.format == "json"
    assert summary.exception_signal == "SIGTRAP"
    assert summary.faulting_thread == 0


def test_ips_bplist_body_malformed_is_a_typed_error(tmp_path: Path) -> None:
    """A binary-plist-looking body that fails to parse is a typed error."""
    path = tmp_path / "bplist.ips"
    path.write_text(
        IPS_HEADER + "\nbplist00" + bytes(range(32)).decode("latin-1"),
        encoding="utf-8",
        errors="replace",
    )
    with pytest.raises(AnalysisError, match="plist body"):
        parse_ips_report(path)


def test_ips_plist_array_body_degrades_to_metadata(tmp_path: Path) -> None:
    """A plist body whose root is an array warns and yields metadata only."""
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><array><string>x</string></array></plist>\n'
    )
    path = tmp_path / "arraybody.ips"
    path.write_text(IPS_HEADER + "\n" + plist, encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.format == "plist"
    assert summary.frames == ()
    assert summary.evidence.confidence.value == "low"
    assert any("not a dictionary" in w for w in summary.warnings)


def test_ips_plist_triggered_by_thread_fallback(tmp_path: Path) -> None:
    """Legacy reports fall back to ``Triggered by Thread`` for the index."""
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><dict>\n'
        "<key>Product</key><string>TriggeredApp</string>\n"
        "<key>Triggered by Thread</key><integer>0</integer>\n"
        '<key>Threads</key><array><dict><key>frames</key><array/>\n'
        "</dict></array>\n"
        "</dict></plist>\n"
    )
    header = '{"app_name":"TriggeredApp","timestamp":"2024-01-01 00:00:00 +0000"}'
    path = tmp_path / "triggered.ips"
    path.write_text(header + "\n" + plist, encoding="utf-8")
    summary = parse_ips_report(path)
    assert summary.product == "TriggeredApp"
    assert summary.faulting_thread == 0
    assert summary.crash_time == "2024-01-01 00:00:00 +0000"


def test_ips_header_scanner_and_marker_helpers() -> None:
    """The tolerant header scanner and marker prober handle degenerate text."""
    assert apple_ips._first_key({"a": "", "b": "x"}, "a", "b") == "x"
    assert apple_ips._first_key({"a": None}, "a") is None
    assert apple_ips._json_object_after_marker("\n\n") is None
    assert apple_ips._json_object_after_marker("\nnot json") is None
    assert apple_ips._json_object_after_marker('\n{"a": 1}') == {"a": 1}


# ---- MCP tool (`codevanta_crash`): argument validation ------------------------


def test_mcp_crash_rejects_bad_path_arguments(tmp_path: Path) -> None:
    """Non-string, empty and non-file paths are typed errors."""
    with pytest.raises(AnalysisError, match="must be a string"):
        tools.codevanta_crash(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="must not be empty"):
        tools.codevanta_crash("   ")
    with pytest.raises(AnalysisError, match="not a regular file"):
        tools.codevanta_crash(str(tmp_path))


def test_mcp_crash_unreadable_file_is_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` during the magic peek surfaces as a typed error."""
    path = core64_path(tmp_path)

    def _boom(self: Path, mode: str) -> object:
        raise OSError("simulated open failure")

    monkeypatch.setattr(Path, "open", _boom)
    with pytest.raises(AnalysisError, match="cannot read"):
        tools.codevanta_crash(str(path))



