"""Bridge-lane tests: canned-parser coverage, wiring offline, probes live.

Every transcript below is a realistic capture of what the external tool
prints (a ``binwalk -e`` scan table, an unblob chunk log, ``tshark -T fields``
TSV with its header line, ``wasm-validate`` stderr diagnostics, a
``wasm-objdump -d`` listing and ``objdump -d`` in AT&T and Intel column
layouts), so the parsers are exercised offline exactly as they will see live
output. The wrappers are driven through the injectable ``runner``/``which``
contracts -- no external tool is ever spawned by the wrapper tests -- the
missing-tool failures are asserted with ``shutil.which`` taken away, the CLI
is tested through monkeypatched lane functions, and the probe tests touch the
real machine honestly (structure and determinism, whatever is installed).
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import binwalk_bridge, objdump_bridge, tshark_bridge, wabt_bridge
from codevanta.analysis import bridge as bridge_module
from codevanta.analysis.bridge import (
    KNOWN_BRIDGES,
    BridgeCapability,
    bridges_report,
    parse_version_banner,
    probe_bridge,
)
from codevanta.cli import bridges as bridges_cli
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import ext_bridges, tools
from codevanta.mcp_server.server import build_server

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


class _Outcome:
    """``subprocess.CompletedProcess``-shaped stand-in for injected runners."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Record argv and replay one canned outcome (no process is spawned)."""

    def __init__(self, outcome: _Outcome) -> None:
        self.outcome = outcome
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> _Outcome:
        self.commands.append(command)
        return self.outcome


BINWALK_OUTPUT = """\
Scan Time:     2026-11-14 12:00:00
Target File:   /fw/image.bin
MD5 Checksum:  9f86d081884c7d659a2feaa0c55ad015
Signatures:    451

Decimal       Hexadecimal     Description
--------------------------------------------------------------------------------
0             0x0             TP-Link firmware header, firmware version: 0.9.1
12300         0x300C          gzip compressed data, has original file name: "kernel", from Unix, original size 3211264
48128         0xBC00          SquashFS filesystem, little endian, version 4.0, compression:lzma, size: 3207168 bytes, 314 inodes
"""

UNBLOB_OUTPUT = """\
[2026-11-14 12:00:00.000] INFO     unblob.cli: Extracting with unblob 24.11.21
[2026-11-14 12:00:00.010] DEBUG    unblob.finder: Chunk found: gzip 0x0-0x400
[2026-11-14 12:00:00.012] INFO     unblob.extractor: Extracted gzip chunk to 0x0.gz.extract
[2026-11-14 12:00:00.030] DEBUG    unblob.finder: Chunk found: squashfs 0xbc00-0x31c800
[2026-11-14 12:00:01.500] INFO     unblob.extractor: Extracted squashfs chunk to 0xbc00.squashfs.extract
[2026-11-14 12:00:01.501] DEBUG    unblob.report: nothing else matched
"""

TSHARK_TSV = (
    "frame.number\tip.src\ttcp.srcport\n"
    "1\t10.0.0.5\t443\n"
    "2\t10.0.0.9\t\x00\n"
    "3\t10.0.0.5\t8080\n"
).replace("\x00", "")

WASM_VALIDATE_ERR = """\
bad.wasm:0000021: error: unexpected end of section or function (at offset 0x21)
bad.wasm:0000030: error: length out of bounds (at offset 0x30)
usage: wasm-validate [options] filename
"""

WASM_OBJDUMP_OUTPUT = """\
calc.wasm:	file format wasm 0x1

Sections:

 Type start=0x0000000b end=0x00000015 (size=0x0000000a) count: 2
 Function start=0x00000017 end=0x00000019 (size=0x00000002) count: 1
 Code start=0x0000001f end=0x0000003a (size=0x0000001b) count: 1

Code Disassembly:

[000] func[0] <wasm.f0.>;
 00000d: 41 01                      i32.const 1
 00000f: 6a                         i32.add
 000010: 0b                         end
"""

OBJDUMP_ATT_OUTPUT = """\
/home/u/hello:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <main>:
  401000:\t55                    push   %rbp
  401001:\t48 89 e5              mov    %rsp,%rbp
  401004:\t31 c0                 xor    %eax,%eax
  401006:\tc3                    ret
"""

OBJDUMP_INTEL_OUTPUT = """\
hello.exe:     file format pe-x86-64

Disassembly of section .text:

0000000140001000 <main>:
  140001000:\t55                   push   rbp
  140001001:\t48 89 e5             mov    rbp,rsp
  140001004:\tc3                   ret
"""

# ---------------------------------------------------------------------------
# bridge.py -- the shared probe framework
# ---------------------------------------------------------------------------


def test_parse_version_banner_picks_the_first_semver_token() -> None:
    assert parse_version_banner("TShark (Wireshark) 4.2.2 (v4.2.2-0)\nCopyright...") == "4.2.2"
    assert parse_version_banner("Binwalk v2.3.4\n", scan_limit_lines=1) == "2.3.4"
    assert parse_version_banner("GNU objdump (GNU Binutils) 2.42") == "2.42"
    assert parse_version_banner("Android Debug Bridge version 1.0.41") == "1.0.41"


def test_parse_version_banner_scans_only_the_first_lines() -> None:
    banner = "first line\nsecond line\nversion 9.9.9 far below the cap\n"
    assert parse_version_banner(banner, scan_limit_lines=2) is None
    assert parse_version_banner(banner, scan_limit_lines=4) == "9.9.9"


def test_parse_version_banner_rejects_non_string() -> None:
    with pytest.raises(AnalysisError, match="must be a string"):
        parse_version_banner(b"bytes banner")  # type: ignore[arg-type]


def _available_report(**kwargs: Any) -> list[BridgeCapability]:
    """Probe a machine where every executable answers ``wabt 1.0.36``."""
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    runner = FakeRunner(_Outcome(0, stdout="wasm-validate 1.0.36\n"))
    return bridges_report(which=which, runner=runner)


def test_bridges_report_is_deterministic_and_honest_offline() -> None:
    report = bridges_report(
        which=lambda name: f"/usr/bin/{name}",
        runner=FakeRunner(_Outcome(0, stdout="tool 7.7.7\n")),
    )
    again = bridges_report(
        which=lambda name: f"/usr/bin/{name}",
        runner=FakeRunner(_Outcome(0, stdout="tool 7.7.7\n")),
    )
    assert [cap.to_dict() for cap in report] == [cap.to_dict() for cap in again]
    for capability in report:
        assert capability.available is True
        if capability.tool != "z3":  # z3 is the honest import probe of this machine
            assert capability.version == "7.7.7"
            assert capability.reason is None
        assert json.loads(json.dumps(capability.to_dict())) == capability.to_dict()


def test_probe_bridge_wabt_needs_both_executables() -> None:
    missing_objdump = probe_bridge(
        "wabt",
        which=lambda name: f"/usr/bin/{name}" if name == "wasm-validate" else None,
    )
    assert missing_objdump.available is False
    assert "wasm-objdump" in (missing_objdump.reason or "")
    assert "WebAssembly/wabt" in (missing_objdump.reason or "")

    runner = FakeRunner(_Outcome(0, stdout="wabt 1.0.36\n"))
    complete = probe_bridge(
        "wabt",
        which=lambda name: f"/usr/bin/{name}",
        runner=runner,
    )
    assert complete.available is True
    assert complete.version == "1.0.36"


def test_probe_bridge_reports_missing_tools_as_records_not_errors() -> None:
    capability = probe_bridge("binwalk", which=lambda name: None)
    assert capability == BridgeCapability(
        tool="binwalk",
        available=False,
        version=None,
        reason="'binwalk' is not on PATH; install it with "
        "pip install binwalk (or https://github.com/ReFirmLabs/binwalk)",
    )


def test_probe_bridge_version_call_failures_stay_typed() -> None:
    # Nonzero exit degrades into a reason.
    failing = probe_bridge(
        "gdb",
        which=lambda name: "/usr/bin/gdb",
        runner=FakeRunner(_Outcome(127)),
    )
    assert failing.available is False
    assert "exited with code 127" in (failing.reason or "")
    # A banner without a version token is a reason, not a crash.
    empty = probe_bridge(
        "gdb",
        which=lambda name: "/usr/bin/gdb",
        runner=FakeRunner(_Outcome(0, stdout="no version here\n")),
    )
    assert empty.available is False
    assert "no parseable version banner" in (empty.reason or "")
    # A timeout is a reason, not a crash.
    slow = probe_bridge("gdb", which=lambda name: "/usr/bin/gdb", runner=_TimeoutRunner())
    assert slow.available is False
    assert "timed out" in (slow.reason or "")


class _TimeoutRunner:
    """Runner stand-in that always blows the probe's wall-clock budget."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=command[0], timeout=bridge_module.PROBE_TIMEOUT)


def test_probe_bridge_runner_exceptions_degrade_into_reasons() -> None:
    vanished = probe_bridge(
        "adb", which=lambda name: "/usr/bin/adb", runner=_VanishingRunner()
    )
    assert vanished.available is False
    assert "vanished" in (vanished.reason or "")
    broken = probe_bridge(
        "objdump", which=lambda name: "/usr/bin/objdump", runner=_OSErrorRunner()
    )
    assert broken.available is False
    assert "could not be executed" in (broken.reason or "")


class _VanishingRunner:
    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
        raise FileNotFoundError(command[0])


class _OSErrorRunner:  # noqa: N801 -- stand-in class, ``__call__`` is duck typing
    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:  # noqa: N807
        raise PermissionError(13, "permission denied")


def test_bridges_report_on_this_machine_is_honest() -> None:
    """Live probes: whatever is installed is reported, absence is typed."""
    report = bridges_report()
    assert [capability.tool for capability in report] == list(KNOWN_BRIDGES)
    for capability in report:
        assert isinstance(capability.available, bool)
        if capability.available:
            assert capability.version, f"{capability.tool} claims availability without a version"
        else:
            assert capability.reason, f"{capability.tool} is unavailable without a reason"
        assert json.loads(json.dumps(capability.to_dict())) == capability.to_dict()


def test_probe_bridge_z3_is_an_import_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    capability = probe_bridge("z3")
    assert capability.tool == "z3"
    assert isinstance(capability.available, bool)
    if capability.available:
        assert capability.version is not None or capability.reason
    else:
        assert "z3-solver" in (capability.reason or "")
    # The import probe never touches subprocess: removing shutil.which must not matter.
    monkeypatch.setattr(bridge_module.shutil, "which", lambda name: None)
    assert probe_bridge("z3").available == capability.available


def test_live_bridge_matches_its_lane_skip_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bridge report and the lane wrappers must agree about tshark."""
    report = {capability.tool: capability for capability in bridges_report()}
    tshark_live = shutil.which("tshark") is not None
    assert report["tshark"].available is tshark_live
    assert tshark_bridge.tshark_available() is tshark_live
    assert objdump_bridge.objdump_available() is (shutil.which("objdump") is not None)
    assert wabt_bridge.wasm_available() is (
        shutil.which("wasm-validate") is not None
        and shutil.which("wasm-objdump") is not None
    )


# ---------------------------------------------------------------------------
# binwalk_bridge.py -- firmware extraction
# ---------------------------------------------------------------------------


def test_parse_binwalk_output_reads_the_scan_table() -> None:
    parsed = binwalk_bridge.parse_binwalk_output(BINWALK_OUTPUT)
    assert [entry.offset for entry in parsed.entries] == [0, 12300, 48128]
    assert parsed.entries[0].kind.startswith("TP-Link firmware header")
    assert parsed.entries[0].size is None
    assert parsed.entries[1].size == 3211264  # "original size 3211264"
    assert parsed.entries[2].size == 3207168  # "size: 3207168 bytes"
    assert parsed.truncated is False


def test_probe_bridge_version_banner_bytes_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """A runner that returns bytes stdout still yields a parsed version."""

    class _BytesRunner:
        def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
            return _Outcome(0, stdout=b"gdb 14.1\n")

    capability = probe_bridge("gdb", which=lambda name: "/usr/bin/gdb", runner=_BytesRunner())
    assert capability.available is True
    assert capability.version == "14.1"


def test_probe_bridge_z3_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    """The z3 import probe has three honest outcomes; exercise them all."""
    # z3 absent from the environment.
    monkeypatch.setattr(bridge_module.importlib.util, "find_spec", lambda name: None)
    absent = probe_bridge("z3")
    assert absent.available is False
    assert "z3-solver" in (absent.reason or "")
    # z3 importable but distribution metadata missing.
    monkeypatch.setattr(bridge_module.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(
        bridge_module.importlib.metadata,
        "version",
        lambda name: (_ for _ in ()).throw(bridge_module.importlib.metadata.PackageNotFoundError),
    )
    imported = probe_bridge("z3")
    assert imported.available is True
    assert imported.version is None
    assert "metadata did not name a version" in (imported.reason or "")


def test_parser_note_caps_and_dedupes() -> None:
    """Every parser's ``_note`` dedupes and summarises past its cap."""
    binwalk_junk = binwalk_bridge.parse_binwalk_output("junk one\njunk one\n")
    assert sum(1 for w in binwalk_junk.warnings if "junk one" in w) == 1
    flood = "".join(f"junk {index}\n" for index in range(50))
    capped = binwalk_bridge.parse_binwalk_output(flood)
    # 32 distinct junk notes plus the summarising "32+ warnings" line.
    assert len(capped.warnings) == binwalk_bridge.MAX_WARNINGS + 1
    assert capped.warnings[-1].endswith("...")
    # The wabt disassembly parser warns per junk line, so its cap fires too.
    *_, wabt_warns = wabt_bridge.parse_wasm_objdump("same junk\nsame junk\n")
    assert sum(1 for w in wabt_warns if "same junk" in w) == 1
    *_, wabt_flood_warns = wabt_bridge.parse_wasm_objdump(
        "".join(f"junk {index}\n" for index in range(50))
    )
    assert len(wabt_flood_warns) == wabt_bridge.MAX_WARNINGS + 1
    assert wabt_flood_warns[-1].endswith("...")
    # Same for the objdump disassembly parser.
    objdump_capped = objdump_bridge.parse_objdump_text("same junk: yes\nsame junk: yes\n")
    assert sum(1 for w in objdump_capped.warnings if "same junk" in w) == 1
    objdump_flood = objdump_bridge.parse_objdump_text(
        "".join(f"junk {index}: yes\n" for index in range(50))
    )
    assert len(objdump_flood.warnings) == objdump_bridge.MAX_WARNINGS + 1
    assert objdump_flood.warnings[-1].endswith("...")

def test_parse_binwalk_output_bounds_and_warns() -> None:
    parsed = binwalk_bridge.parse_binwalk_output(BINWALK_OUTPUT)
    junk_lines = [warning for warning in parsed.warnings if "unrecognised" in warning]
    # Banner chatter surfaces as warnings, it never silently vanishes.
    assert junk_lines, "banner chatter must become warnings"
    # Bounded work: a transcript with more rows than the cap keeps 64.
    big = "".join(f"{offset} 0x{offset:x} filler kind {offset}\n" for offset in range(200))
    bounded = binwalk_bridge.parse_binwalk_output(big)
    assert len(bounded.entries) == binwalk_bridge.MAX_ENTRIES
    assert bounded.truncated is True
    assert any("entry limit" in warning for warning in bounded.warnings)


def test_parse_binwalk_output_rejects_non_string_and_empty() -> None:
    with pytest.raises(AnalysisError, match="must be a string"):
        binwalk_bridge.parse_binwalk_output(None)  # type: ignore[arg-type]
    empty = binwalk_bridge.parse_binwalk_output("\n\n")
    assert empty.entries == ()
    assert any("no extraction rows" in warning for warning in empty.warnings)


def test_probe_bridge_rejects_unknown_names() -> None:
    with pytest.raises(AnalysisError, match="unknown bridge"):
        probe_bridge("totally-not-a-tool")
    with pytest.raises(AnalysisError, match="must be a string"):
        probe_bridge(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="whitespace"):
        probe_bridge(" binwalk")


def test_parse_unblob_output_reads_chunks_and_paths() -> None:
    parsed = binwalk_bridge.parse_unblob_output(UNBLOB_OUTPUT)
    assert len(parsed.entries) == 2
    first, second = parsed.entries
    assert first.kind == "gzip"
    assert first.offset == 0x0
    assert first.size == 0x400
    assert first.path == "0x0.gz.extract"
    assert second.kind == "squashfs"
    assert second.offset == 0xBC00
    assert second.size == 0x31C800 - 0xBC00
    assert second.path == "0xbc00.squashfs.extract"
    # The report line at the end is chatter.
    assert any("unrecognised" in warning for warning in parsed.warnings)


def test_parse_unblob_output_bounds_and_rejects_non_string() -> None:
    big = "".join(
        f"[t] DEBUG finder: Chunk found: gzip 0x{offset:x}-0x{offset + 0x10:x}\n"
        for offset in range(100)
    )
    bounded = binwalk_bridge.parse_unblob_output(big)
    assert len(bounded.entries) == binwalk_bridge.MAX_ENTRIES
    assert bounded.truncated is True
    with pytest.raises(AnalysisError, match="must be a string"):
        binwalk_bridge.parse_unblob_output(3.5)  # type: ignore[arg-type]
    empty = binwalk_bridge.parse_unblob_output("")
    assert any("no extraction rows" in warning for warning in empty.warnings)


def test_scan_extract_tree_is_sorted_bounded_and_missing_safe(tmp_path: Path) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "a.txt").write_bytes(b"x")
    (tmp_path / "b" / "c.bin").write_bytes(b"y")
    tree, truncated = binwalk_bridge.scan_extract_tree(tmp_path)
    assert tree == ("a.txt", "b", str(Path("b") / "c.bin"))
    assert truncated is False
    # Bounded at 64 paths, truncation reported.
    for index in range(80):
        (tmp_path / f"f{index:03d}.bin").write_bytes(b"z")
    big_tree, big_truncated = binwalk_bridge.scan_extract_tree(tmp_path)
    assert len(big_tree) == binwalk_bridge.MAX_TREE
    assert big_truncated is True
    # A directory that does not exist is an empty tree, not an error.
    assert binwalk_bridge.scan_extract_tree(tmp_path / "missing") == ((), False)

def test_firmware_extract_runs_binwalk_through_the_injected_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56" + b"\x00" * 16)
    out_dir = tmp_path / "extract"
    (out_dir / "0.bin.extract").mkdir(parents=True, exist_ok=True)
    (out_dir / "0.bin.extract" / "kernel").write_bytes(b"data")
    runner = FakeRunner(_Outcome(0, stdout=BINWALK_OUTPUT))
    monkeypatch.setattr(binwalk_bridge.shutil, "which", lambda name: "/usr/bin/binwalk")
    result = binwalk_bridge.firmware_extract(image, out_dir, runner=runner)
    assert runner.commands == [("binwalk", "-e", "--directory", str(out_dir), str(image))]
    assert result.tool == "binwalk"
    assert len(result.entries) == 3
    assert result.entries[1].size == 3211264
    assert result.tree == ("0.bin.extract", str(Path("0.bin.extract") / "kernel"))
    assert result.tree_truncated is False
    assert Path(result.transcript_path or "").read_text(encoding="utf-8").startswith("Scan Time")
def test_wrappers_decode_bytes_transcripts_and_validate_timeouts(tmp_path: Path) -> None:
    """Bytes transcripts decode; non-numeric timeouts fail typed, in every lane."""
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56")
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm")
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"MZ")
    # binwalk: bytes stdout decodes (and the typed timeout check fires).
    result = binwalk_bridge.firmware_extract(
        image,
        tmp_path / "out",
        runner=FakeRunner(_Outcome(0, stdout=BINWALK_OUTPUT.encode("utf-8"))),
    )
    assert result.entries[0].offset == 0
    with pytest.raises(AnalysisError, match="must be a number of seconds"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", timeout=True)
    # tshark: bytes stdout decodes; the non-numeric timeout fails typed.
    tshark = tshark_bridge.pcap_fields(
        capture, "frame.number", runner=FakeRunner(_Outcome(0, stdout=TSHARK_ROWS.encode()))
    )
    assert len(tshark.rows) == 3
    with pytest.raises(AnalysisError, match="must be a number of seconds"):
        tshark_bridge.pcap_fields(capture, "frame.number", timeout="soon")
    # wabt: bytes stdout/stderr decode in the shared runner.
    ok = wabt_bridge.wasm_validate(
        module, runner=FakeRunner(_Outcome(1, stderr=WASM_VALIDATE_ERR.encode()))
    )
    assert ok.valid is False
    with pytest.raises(AnalysisError, match="must be a number of seconds"):
        wabt_bridge.wasm_validate(module, timeout=True)  # type: ignore[arg-type]
    # objdump: bytes stdout decodes; the non-numeric timeout fails typed.
    disasm = objdump_bridge.objdump_disasm(
        binary, runner=FakeRunner(_Outcome(0, stdout=OBJDUMP_ATT_OUTPUT.encode()))
    )
    assert disasm.rows[0].mnemonic == "push"
    with pytest.raises(AnalysisError, match="must be a number of seconds"):
        objdump_bridge.objdump_disasm(binary, timeout=True)


def test_wasm_validate_stderr_blank_lines_and_objdump_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Blank stderr lines are skipped; wasm_objdump works without out_dir."""
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm")
    errors = wabt_bridge.parse_wasm_validate_stderr("\n\nbad.wasm:1: error: oob\n\n")
    assert errors == ("bad.wasm:1: error: oob",)
    monkeypatch.setattr(wabt_bridge.shutil, "which", lambda name: "/usr/bin/" + name)
    result = wabt_bridge.wasm_objdump(
        module, runner=FakeRunner(_Outcome(0, stdout=WASM_OBJDUMP_OUTPUT))
    )
    assert result.transcript_path is None  # no out_dir, no transcript written
    assert len(result.instructions) == 3
    # Non-Path inputs stay typed on both wrappers.
    with pytest.raises(AnalysisError, match="input_path must be"):
        wabt_bridge.wasm_objdump(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="input_path must be"):
        wabt_bridge.wasm_validate(42)  # type: ignore[arg-type]


def test_tshark_parse_skips_blank_lines_and_bad_packet_numbers() -> None:
    """Blank TSV lines are skipped; a non-numeric frame.number stays None."""
    transcript = TSHARK_ROWS + "\nnot-a-number\t10.0.0.1\t22\n"
    header, rows, _, _ = tshark_bridge.parse_tshark_fields(transcript)
    assert header == ("frame.number", "ip.src", "tcp.srcport")
    assert len(rows) == 4
    assert rows[3].number is None
    assert rows[3].fields["ip.src"] == "10.0.0.1"


def test_unblob_blank_lines_and_path_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Blank unblob log lines are skipped; entries with paths round-trip."""
    image = tmp_path / "image.bin"
    image.write_bytes(b"PK\x03\x04")
    transcript = UNBLOB_OUTPUT.replace(
        "0xbc00.squashfs.extract", "0xbc00.squashfs.extract\n\n"
    )
    monkeypatch.setattr(binwalk_bridge.shutil, "which", lambda name: None)
    result = binwalk_bridge.firmware_extract(
        image, tmp_path / "out", tool="unblob", runner=FakeRunner(_Outcome(0, stdout=transcript))
    )
    assert result.entries[1].path == "0xbc00.squashfs.extract"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()
    payload = result.to_dict()
    assert payload["entries"][1]["path"] == "0xbc00.squashfs.extract"


def test_binwalk_plain_byte_size_hint() -> None:
    """A description with a bare ``N bytes`` hint reports its size."""
    transcript = "0\t0x0\tstuffed data, 512 bytes of padding\n"
    parsed = binwalk_bridge.parse_binwalk_output(transcript)
    assert parsed.entries[0].size == 512


def test_firmware_extract_runs_unblob_through_the_injected_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"PK\x03\x04" + b"\x00" * 8)
    out_dir = tmp_path / "unblob-out"
    out_dir.mkdir()
    runner = FakeRunner(_Outcome(0, stdout=UNBLOB_OUTPUT))
    monkeypatch.setattr(binwalk_bridge.shutil, "which", lambda name: None)
    result = binwalk_bridge.firmware_extract(image, out_dir, tool="unblob", runner=runner)
    assert runner.commands == [("unblob", "-e", str(out_dir), str(image))]
    assert result.tool == "unblob"
    assert result.evidence.source == "bridge.unblob"
    assert result.entries[0].path == "0x0.gz.extract"


def test_firmware_extract_typed_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"MZ")
    # Missing tools: typed error naming the codevanta binmeta fallback.
    monkeypatch.setattr(binwalk_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError, match="codevanta binmeta") as excinfo:
        binwalk_bridge.firmware_extract(image, tmp_path / "out")
    assert "binwalk is not on PATH" in str(excinfo.value)
    with pytest.raises(AnalysisError, match="codevanta binmeta"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", tool="unblob")
    # Argument validation happens before any tool probe.
    with pytest.raises(AnalysisError, match="tool must be one of"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", tool="dd")
    with pytest.raises(AnalysisError, match="input_path must be"):
        binwalk_bridge.firmware_extract(42, tmp_path / "out")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="not found"):
        binwalk_bridge.firmware_extract(tmp_path / "missing.bin", tmp_path / "out")
    with pytest.raises(AnalysisError, match="out_dir must be"):
        binwalk_bridge.firmware_extract(image, 42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="out of range"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", timeout=0.5)
    # Runner contract violations and tool failures stay typed.
    monkeypatch.setattr(binwalk_bridge.shutil, "which", lambda name: "/usr/bin/binwalk")
    with pytest.raises(AnalysisError, match="injection contract"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", runner=_BrokenRunner())
    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        binwalk_bridge.firmware_extract(
            image, tmp_path / "out", runner=_TimeoutRunnerTool(), timeout=30
        )
    with pytest.raises(AnalysisError, match="vanished between"):
        binwalk_bridge.firmware_extract(image, tmp_path / "out", runner=_VanishRunnerTool())
    with pytest.raises(AnalysisError, match="exited with code 3"):
        binwalk_bridge.firmware_extract(
            image, tmp_path / "out", runner=FakeRunner(_Outcome(3, stderr="boom"))
        )


class _BrokenRunner:
    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
        return "not a CompletedProcess"


class _TimeoutRunnerTool:
    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=command[0], timeout=30)


class _VanishRunnerTool:
    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any:
        raise FileNotFoundError(command[0])

# ---------------------------------------------------------------------------
# tshark_bridge.py -- pcap field extraction
# ---------------------------------------------------------------------------

TSHARK_ROWS = "frame.number\tip.src\ttcp.srcport\n1\t10.0.0.5\t443\n2\t10.0.0.9\t80\n3\t10.0.0.5\t\t\n"


def test_parse_tshark_fields_reads_header_and_rows() -> None:
    header, rows, truncated, warnings = tshark_bridge.parse_tshark_fields(TSHARK_ROWS)
    assert header == ("frame.number", "ip.src", "tcp.srcport")
    assert len(rows) == 3
    assert rows[0].number == 1
    assert rows[0].fields == {"frame.number": "1", "ip.src": "10.0.0.5", "tcp.srcport": "443"}
    # An empty column decodes as None, not "".
    assert rows[2].fields["tcp.srcport"] is None
    assert truncated is False
    assert warnings == []
    assert json.loads(json.dumps(rows[0].to_dict())) == rows[0].to_dict()


def test_parse_tshark_fields_bounds_rows_at_100() -> None:
    body = "".join(f"{index}\t10.0.0.5\t80\n" for index in range(1, 120))
    _, rows, truncated, warnings = tshark_bridge.parse_tshark_fields(
        f"{TSHARK_ROWS}{body}"
    )
    assert len(rows) == tshark_bridge.MAX_ROWS
    assert truncated is True
    assert any("row limit" in warning for warning in warnings)


def test_parse_tshark_fields_handles_missing_header_and_junk() -> None:
    # The first line always becomes the header; rows follow from line two.
    header, rows, _, warnings = tshark_bridge.parse_tshark_fields("junk line\n1\t2\n")
    assert header == ("junk line",)
    assert len(rows) == 1
    assert rows[0].number is None
    assert rows[0].fields == {"junk line": "1"}
    no_header, no_rows, _, warn = tshark_bridge.parse_tshark_fields("")
    assert no_header == () and no_rows == ()
    assert any("no header line" in warning for warning in warn)
    with pytest.raises(AnalysisError, match="must be a string"):
        tshark_bridge.parse_tshark_fields(99)  # type: ignore[arg-type]


def test_pcap_fields_runs_tshark_through_the_injected_runner(tmp_path: Path) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    runner = FakeRunner(_Outcome(0, stdout=TSHARK_ROWS))
    result = tshark_bridge.pcap_fields(
        capture, "frame.number,ip.src,tcp.srcport", packet_limit=7, runner=runner
    )
    command = runner.commands[0]
    assert command[:4] == ("tshark", "-r", str(capture), "-T")
    assert command[command.index("-c") + 1] == "7"
    assert "-Y" not in command
    assert command.count("-e") == 3
    assert result.rows[0].fields["ip.src"] == "10.0.0.5"
    assert result.packet_limit == 7
    assert result.evidence.source == "bridge.tshark"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_pcap_fields_passes_the_display_filter_and_saves_transcript(tmp_path: Path) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    runner = FakeRunner(_Outcome(0, stdout=TSHARK_ROWS))
    result = tshark_bridge.pcap_fields(
        capture,
        ["frame.number", "ip.src"],
        display_filter="tcp.port == 443",
        runner=runner,
        out_dir=tmp_path / "transcripts",
    )
    command = runner.commands[0]
    assert command[command.index("-Y") + 1] == "tcp.port == 443"
    saved = tmp_path / "transcripts" / "tshark-fields.txt"
    assert saved.read_text(encoding="utf-8") == TSHARK_ROWS
    assert result.transcript_path is not None


def test_pcap_fields_warns_when_header_order_differs(tmp_path: Path) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    runner = FakeRunner(_Outcome(0, stdout="ip.src\tframe.number\nx\t1\n"))
    result = tshark_bridge.pcap_fields(capture, "frame.number,ip.src", runner=runner)
    assert any("header field order" in warning for warning in result.warnings)

def test_pcap_fields_typed_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    monkeypatch.setattr(tshark_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError, match="tshark is not on PATH") as excinfo:
        tshark_bridge.pcap_fields(capture, "frame.number")
    assert "codevanta binmeta" in str(excinfo.value)
    with pytest.raises(AnalysisError, match="vanished between"):
        tshark_bridge.pcap_fields(capture, "frame.number", runner=_VanishRunnerTool())
    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        tshark_bridge.pcap_fields(capture, "frame.number", runner=_TimeoutRunnerTool())
    with pytest.raises(AnalysisError, match="exited with code 2"):
        tshark_bridge.pcap_fields(
            capture, "frame.number", runner=FakeRunner(_Outcome(2, stderr="bad filter"))
        )
    with pytest.raises(AnalysisError, match="injection contract"):
        tshark_bridge.pcap_fields(capture, "frame.number", runner=_BrokenRunner())
    # Argument validation happens before the tool gate.
    with pytest.raises(AnalysisError, match="capture file not found"):
        tshark_bridge.pcap_fields(tmp_path / "missing.pcap", "frame.number")
    with pytest.raises(AnalysisError, match="input_path must be"):
        tshark_bridge.pcap_fields(42, "frame.number")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="fields must be"):
        tshark_bridge.pcap_fields(capture, 42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="at least one"):
        tshark_bridge.pcap_fields(capture, "")
    with pytest.raises(AnalysisError, match="too many fields"):
        tshark_bridge.pcap_fields(capture, ",".join(f"f{i}" for i in range(20)))
    with pytest.raises(AnalysisError, match="not a tshark field name"):
        tshark_bridge.pcap_fields(capture, "frame number!")
    with pytest.raises(AnalysisError, match="packet_limit must be an integer"):
        tshark_bridge.pcap_fields(capture, "frame.number", packet_limit="10")
    with pytest.raises(AnalysisError, match="out of range"):
        tshark_bridge.pcap_fields(capture, "frame.number", packet_limit=1000)
    with pytest.raises(AnalysisError, match="display_filter must be"):
        tshark_bridge.pcap_fields(capture, "frame.number", display_filter="  ")
    with pytest.raises(AnalysisError, match="out of range"):
        tshark_bridge.pcap_fields(capture, "frame.number", timeout=0.1)


# ---------------------------------------------------------------------------
# wabt_bridge.py -- wasm validate + objdump
# ---------------------------------------------------------------------------


def test_parse_wasm_validate_stderr_pulls_diagnostics() -> None:
    errors = wabt_bridge.parse_wasm_validate_stderr(WASM_VALIDATE_ERR)
    assert len(errors) == 2
    assert errors[0].startswith("bad.wasm:0000021: error: unexpected end")
    assert errors[1] == "bad.wasm:0000030: error: length out of bounds (at offset 0x30)"
    assert wabt_bridge.parse_wasm_validate_stderr("") == ()
    with pytest.raises(AnalysisError, match="must be a string"):
        wabt_bridge.parse_wasm_validate_stderr(None)  # type: ignore[arg-type]


def test_parse_wasm_validate_stderr_bounds_errors() -> None:
    flood = "".join(f"m.wasm:{index:x}: error: e{index}\n" for index in range(50))
    errors = wabt_bridge.parse_wasm_validate_stderr(flood)
    assert len(errors) == wabt_bridge.MAX_ERRORS


def test_parse_wasm_objdump_reads_sections_and_instructions() -> None:
    sections, instructions, truncated, warnings = wabt_bridge.parse_wasm_objdump(
        WASM_OBJDUMP_OUTPUT
    )
    assert [(s.name, s.start, s.size) for s in sections] == [
        ("Type", 0x0B, 0x0A),
        ("Function", 0x17, 0x02),
        ("Code", 0x1F, 0x1B),
    ]
    assert len(instructions) == 3
    assert instructions[0].offset == 0x0D
    assert instructions[0].raw_bytes == "41 01"
    assert instructions[0].text == "i32.const 1"
    assert instructions[2].text == "end"
    assert truncated is False
    # The banner and the func heading are chatter.
    assert any("unrecognised" in warning for warning in warnings)


def test_parse_wasm_objdump_bounds_instructions() -> None:
    body = "".join(f" {index:06x}: 0b                         end\n" for index in range(200))
    _, instructions, truncated, warnings = wabt_bridge.parse_wasm_objdump(body)
    assert len(instructions) == wabt_bridge.MAX_INSTRUCTIONS
    assert truncated is True
    assert any("instruction limit" in warning for warning in warnings)
    with pytest.raises(AnalysisError, match="must be a string"):
        wabt_bridge.parse_wasm_objdump(7)  # type: ignore[arg-type]

def test_wasm_validate_accepts_and_rejects_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm" + b"\x01\x00\x00\x00")
    # Valid module: exit 0.
    monkeypatch.setattr(wabt_bridge.shutil, "which", lambda name: "/usr/bin/" + name)
    ok = wabt_bridge.wasm_validate(module, runner=FakeRunner(_Outcome(0)))
    assert ok.valid is True
    assert ok.errors == ()
    assert ok.evidence.source == "bridge.wabt"
    assert json.loads(json.dumps(ok.to_dict())) == ok.to_dict()
    # Invalid module: exit 1 is a verdict, not a tool failure.
    bad = wabt_bridge.wasm_validate(
        module, runner=FakeRunner(_Outcome(1, stderr=WASM_VALIDATE_ERR))
    )
    assert bad.valid is False
    assert len(bad.errors) == 2
    # Exit 2 is a tool failure (usage/crash), not a verdict.
    with pytest.raises(AnalysisError, match="exited with code 2"):
        wabt_bridge.wasm_validate(module, runner=FakeRunner(_Outcome(2, stderr="boom")))


def test_wasm_objdump_parses_and_saves_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm" + b"\x01\x00\x00\x00")
    monkeypatch.setattr(wabt_bridge.shutil, "which", lambda name: None)
    result = wabt_bridge.wasm_objdump(
        module,
        runner=FakeRunner(_Outcome(0, stdout=WASM_OBJDUMP_OUTPUT)),
        out_dir=tmp_path / "tr",
    )
    assert len(result.sections) == 3
    assert result.instructions[1].text == "i32.add"
    assert result.evidence.method == "wasm-objdump -d"
    saved = tmp_path / "tr" / "wasm-objdump.txt"
    assert saved.read_text(encoding="utf-8") == WASM_OBJDUMP_OUTPUT
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_wasm_wrappers_typed_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm")
    monkeypatch.setattr(wabt_bridge.shutil, "which", lambda name: None)
    for call in (
        lambda: wabt_bridge.wasm_validate(module),
        lambda: wabt_bridge.wasm_objdump(module),
    ):
        with pytest.raises(AnalysisError, match="wabt is not on PATH") as excinfo:
            call()
        assert "wasm-validate" in str(excinfo.value)
        assert "WebAssembly/wabt" in str(excinfo.value)
    with pytest.raises(AnalysisError, match="vanished between"):
        wabt_bridge.wasm_validate(module, runner=_VanishRunnerTool())
    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        wabt_bridge.wasm_objdump(module, runner=_TimeoutRunnerTool())
    with pytest.raises(AnalysisError, match="injection contract"):
        wabt_bridge.wasm_validate(module, runner=_BrokenRunner())
    with pytest.raises(AnalysisError, match="exited with code 3"):
        wabt_bridge.wasm_objdump(module, runner=FakeRunner(_Outcome(3, stdout="bad")))
    with pytest.raises(AnalysisError, match="input_path must be"):
        wabt_bridge.wasm_validate(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="not found"):
        wabt_bridge.wasm_objdump(tmp_path / "missing.wasm")
    with pytest.raises(AnalysisError, match="out of range"):
        wabt_bridge.wasm_validate(module, timeout=0.5)


# ---------------------------------------------------------------------------
# objdump_bridge.py -- native disassembly
# ---------------------------------------------------------------------------


def test_parse_objdump_text_reads_att_and_intel_layouts() -> None:
    att = objdump_bridge.parse_objdump_text(OBJDUMP_ATT_OUTPUT)
    assert [row.address for row in att.rows] == [0x401000, 0x401001, 0x401004, 0x401006]
    assert att.rows[0].bytes == "55"
    assert att.rows[0].mnemonic == "push"
    assert att.rows[0].operands == "%rbp"
    assert att.rows[1].bytes == "48 89 e5"
    assert att.rows[1].operands == "%rsp,%rbp"
    assert att.rows[3].operands is None  # `ret` has no operands
    assert att.truncated is False
    assert att.warnings == []
    intel = objdump_bridge.parse_objdump_text(OBJDUMP_INTEL_OUTPUT)
    assert intel.rows[0].operands == "rbp"
    assert intel.rows[1].operands == "rbp,rsp"
    assert json.loads(json.dumps(att.rows[0].to_dict())) == att.rows[0].to_dict()


def test_parse_objdump_text_bounds_rows_and_flags_truncation() -> None:
    body = "".join(f"  {index:06x}:\t90                    nop\n" for index in range(700))
    parsed = objdump_bridge.parse_objdump_text(body)
    assert len(parsed.rows) == objdump_bridge.MAX_LINES
    assert parsed.truncated is True
    assert any("row limit" in warning for warning in parsed.warnings)
    limited = objdump_bridge.parse_objdump_text(body, limit=5)
    assert len(limited.rows) == 5


def test_parse_objdump_text_warns_on_junk_and_rejects_non_string() -> None:
    parsed = objdump_bridge.parse_objdump_text("note: this is not an instruction\n")
    assert parsed.rows == ()
    assert any("unrecognised" in warning for warning in parsed.warnings)
    empty = objdump_bridge.parse_objdump_text("")
    assert empty.rows == ()
    assert any("no instruction rows" in warning for warning in empty.warnings)
    with pytest.raises(AnalysisError, match="must be a string"):
        objdump_bridge.parse_objdump_text([])  # type: ignore[arg-type]

def test_objdump_disasm_runs_through_the_injected_runner(tmp_path: Path) -> None:
    binary = tmp_path / "hello.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 8)
    runner = FakeRunner(_Outcome(0, stdout=OBJDUMP_ATT_OUTPUT))
    result = objdump_bridge.objdump_disasm(binary, arch="i386:x86-64", runner=runner)
    assert runner.commands[0] == ("objdump", "-d", "-m", "i386:x86-64", str(binary))
    assert result.arch == "i386:x86-64"
    assert result.rows[0].mnemonic == "push"
    assert result.evidence.source == "bridge.objdump"
    assert "arch i386:x86-64" in (result.evidence.detail or "")
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_objdump_disasm_caps_output_at_512_lines(tmp_path: Path) -> None:
    binary = tmp_path / "big.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 8)
    body = "".join(f"  {index:06x}:\t90                    nop\n" for index in range(600))
    runner = FakeRunner(_Outcome(0, stdout=body))
    result = objdump_bridge.objdump_disasm(binary, runner=runner)
    assert len(result.rows) == objdump_bridge.MAX_LINES
    assert result.truncated is True
    assert any("output capped" in warning for warning in result.warnings)


def test_objdump_disasm_typed_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(objdump_bridge.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError, match="objdump is not on PATH") as excinfo:
        objdump_bridge.objdump_disasm(binary)
    assert "binutils" in str(excinfo.value)
    with pytest.raises(AnalysisError, match="vanished between"):
        objdump_bridge.objdump_disasm(binary, runner=_VanishRunnerTool())
    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        objdump_bridge.objdump_disasm(binary, runner=_TimeoutRunnerTool())
    with pytest.raises(AnalysisError, match="exited with code 1"):
        objdump_bridge.objdump_disasm(binary, runner=FakeRunner(_Outcome(1, stderr="bad arch")))
    with pytest.raises(AnalysisError, match="injection contract"):
        objdump_bridge.objdump_disasm(binary, runner=_BrokenRunner())
    # Argument validation before the gate.
    with pytest.raises(AnalysisError, match="binary file not found"):
        objdump_bridge.objdump_disasm(tmp_path / "missing.bin")
    with pytest.raises(AnalysisError, match="input_path must be"):
        objdump_bridge.objdump_disasm(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="not an objdump architecture"):
        objdump_bridge.objdump_disasm(binary, arch="bad arch!")
    with pytest.raises(AnalysisError, match="out of range"):
        objdump_bridge.objdump_disasm(binary, timeout=0.25)


# ---------------------------------------------------------------------------
# cli/bridges.py -- CLI sub-apps (monkeypatched lane functions)
# ---------------------------------------------------------------------------


def test_cli_bridges_report_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bridges_cli,
        "bridges_report",
        lambda: [
            BridgeCapability(tool="binwalk", available=True, version="2.3.4"),
            BridgeCapability(tool="unblob", available=False, reason="'unblob' is not on PATH"),
        ],
    )
    result = runner.invoke(app, ["bridges", "--json"])
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["count"] == 2
    assert payload["available"] == 1
    assert payload["bridges"][0]["version"] == "2.3.4"


def test_cli_bridges_report_human(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bridges_cli,
        "bridges_report",
        lambda: [
            BridgeCapability(tool="tshark", available=True, version="4.2.2"),
            BridgeCapability(tool="gdb", available=False, reason="'gdb' is not on PATH"),
        ],
    )
    result = runner.invoke(app, ["bridges"])
    assert result.exit_code == 0, _output(result)
    text = _output(result)
    assert "available tshark" in text
    assert "version 4.2.2" in text
    assert "missing" in text and "gdb" in text


def _firmware_result(out_dir: Path) -> binwalk_bridge.FirmwareExtractResult:
    """A tiny real result for CLI printing (entries + tree)."""
    return binwalk_bridge.FirmwareExtractResult(
        tool="binwalk",
        path="/fw/image.bin",
        out_dir=str(out_dir),
        entries=(
            binwalk_bridge.ExtractedEntry(kind="gzip compressed data", offset=12300, size=100),
            binwalk_bridge.ExtractedEntry(kind="SquashFS filesystem", offset=48128),
        ),
        tree=("0.bin.extract",),
        transcript_path=str(out_dir / "binwalk-transcript.txt"),
        warnings=["1 unrecognised line skipped"],
    )


def test_cli_firmware_extract_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56")
    monkeypatch.setattr(
        binwalk_bridge, "firmware_extract", lambda *a, **k: _firmware_result(tmp_path)
    )
    result = runner.invoke(
        app, ["firmware", "extract", str(image), "--out-dir", str(tmp_path / "out"), "--json"]
    )
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["tool"] == "binwalk"
    assert payload["count"] == 2
    assert payload["entries"][0]["size"] == 100


def test_cli_firmware_extract_human_and_missing_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56")
    monkeypatch.setattr(
        binwalk_bridge, "firmware_extract", lambda *a, **k: _firmware_result(tmp_path)
    )
    result = runner.invoke(
        app,
        [
            "firmware",
            "extract",
            str(image),
            "--out-dir",
            str(tmp_path / "out"),
            "--tool",
            "binwalk",
        ],
    )
    assert result.exit_code == 0, _output(result)
    text = _output(result)
    assert "firmware extract (binwalk)" in text
    assert "gzip compressed data" in text
    assert "warning:" in text
    assert "evidence: bridge.binwalk" in text

    def _raise(*args: Any, **kwargs: Any) -> None:
        raise AnalysisError(binwalk_bridge.BINWALK_MISSING_MESSAGE)

    monkeypatch.setattr(binwalk_bridge, "firmware_extract", _raise)
    missing = runner.invoke(app, ["firmware", "extract", str(image), "--out-dir", str(tmp_path)])
    assert missing.exit_code == 2
    assert "codevanta binmeta" in _output(missing)

def test_cli_pcap_fields_json_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)

    def _fake(*args: Any, **kwargs: Any) -> tshark_bridge.PcapFieldsResult:
        return tshark_bridge.PcapFieldsResult(
            path=str(capture),
            fields=("frame.number", "ip.src"),
            display_filter="tcp.port == 443",
            packet_limit=10,
            rows=(
                tshark_bridge.PcapRow(
                    number=1, fields={"frame.number": "1", "ip.src": "10.0.0.5"}
                ),
            ),
            warnings=["header field order differs"],
        )

    monkeypatch.setattr(tshark_bridge, "pcap_fields", _fake)
    result = runner.invoke(
        app,
        [
            "pcap",
            "fields",
            str(capture),
            "--fields",
            "frame.number,ip.src",
            "--filter",
            "tcp.port == 443",
            "--limit",
            "10",
            "--json",
        ],
    )
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["count"] == 1
    assert payload["display_filter"] == "tcp.port == 443"
    assert payload["rows"][0]["number"] == 1

    def _raise(*args: Any, **kwargs: Any) -> None:
        raise AnalysisError(tshark_bridge.TSHARK_MISSING_MESSAGE)

    monkeypatch.setattr(tshark_bridge, "pcap_fields", _raise)
    missing = runner.invoke(app, ["pcap", "fields", str(capture), "--fields", "frame.number"])
    assert missing.exit_code == 2
    text = _output(missing)
    assert "tshark is not on PATH" in text
    assert "codevanta binmeta" in text


def test_cli_wasm_validate_disasm_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    ok = wabt_bridge.WasmValidateResult(
        path=str(module), valid=True
    )
    monkeypatch.setattr(wabt_bridge, "wasm_validate", lambda *a, **k: ok)
    valid = runner.invoke(app, ["wasm", "validate", str(module)])
    assert valid.exit_code == 0, _output(valid)
    assert "valid" in _output(valid)
    assert "evidence: bridge.wabt" in _output(valid)

    invalid_result = wabt_bridge.WasmValidateResult(
        path=str(module), valid=False, errors=("bad.wasm:21: error: oob",)
    )
    monkeypatch.setattr(wabt_bridge, "wasm_validate", lambda *a, **k: invalid_result)
    invalid = runner.invoke(app, ["wasm", "validate", str(module), "--json"])
    assert invalid.exit_code == 0, _output(invalid)
    payload = _payload(invalid)
    assert payload["valid"] is False
    assert payload["errors"] == ["bad.wasm:21: error: oob"]

    objdump_result = wabt_bridge.WasmObjdumpResult(
        path=str(module),
        sections=(wabt_bridge.WasmSection(name="Code", start=0x1F, size=0x1B),),
        instructions=(wabt_bridge.WasmInstruction(offset=0x0D, raw_bytes="41 01", text="i32.const 1"),),
    )
    monkeypatch.setattr(wabt_bridge, "wasm_objdump", lambda *a, **k: objdump_result)
    disasm = runner.invoke(app, ["wasm", "disasm", str(module), "--json"])
    assert disasm.exit_code == 0, _output(disasm)
    assert _payload(disasm)["instruction_count"] == 1

    def _raise(*args: Any, **kwargs: Any) -> None:
        raise AnalysisError(wabt_bridge.WABT_MISSING_MESSAGE)

    monkeypatch.setattr(wabt_bridge, "wasm_validate", _raise)
    missing = runner.invoke(app, ["wasm", "validate", str(module)])
    assert missing.exit_code == 2
    assert "wabt is not on PATH" in _output(missing)

def test_cli_objdump_json_human_and_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "hello.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 8)
    human = objdump_bridge.parse_objdump_text(OBJDUMP_ATT_OUTPUT)
    human = objdump_bridge.ObjdumpDisasmResult(
        path=str(binary),
        arch="i386:x86-64",
        rows=human.rows,
        truncated=True,
        warnings=["output capped at 512 lines; further lines dropped"],
    )
    monkeypatch.setattr(
        objdump_bridge, "objdump_disasm", lambda *a, **k: human
    )
    json_run = runner.invoke(
        app, ["objdump", str(binary), "--arch", "i386:x86-64", "--json"]
    )
    assert json_run.exit_code == 0, _output(json_run)
    payload = _payload(json_run)
    assert payload["arch"] == "i386:x86-64"
    assert payload["instruction_count"] == 4
    assert payload["truncated"] is True
    human_run = runner.invoke(app, ["objdump", str(binary)])
    assert human_run.exit_code == 0, _output(human_run)
    text = _output(human_run)
    assert "objdump -d" in text
    assert "0x401000" in text
    assert "push %rbp" in text
    assert "output was truncated" in text
    assert "evidence: bridge.objdump" in text

    def _raise(*args: Any, **kwargs: Any) -> None:
        raise AnalysisError(objdump_bridge.OBJDUMP_MISSING_MESSAGE)

    monkeypatch.setattr(objdump_bridge, "objdump_disasm", _raise)
    missing = runner.invoke(app, ["objdump", str(binary)])
    assert missing.exit_code == 2
    assert "objdump is not on PATH" in _output(missing)
    assert "binutils" in _output(missing)


# ---------------------------------------------------------------------------
# MCP layer -- ext_bridges functions and build_server registration
# ---------------------------------------------------------------------------


def test_mcp_codevanta_bridges_reports_the_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ext_bridges,
        "bridges_report",
        lambda: [
            BridgeCapability(tool="binwalk", available=True, version="2.3.4"),
            BridgeCapability(tool="unblob", available=False, reason="missing"),
        ],
    )
    payload = tools.codevanta_bridges()
    assert payload["count"] == 2
    assert payload["available"] == 1
    assert payload["bridges"][0] == {
        "tool": "binwalk",
        "available": True,
        "version": "2.3.4",
        "reason": None,
    }
    assert json.loads(json.dumps(payload)) == payload


def test_mcp_codevanta_firmware_extract_delegates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56")
    seen: dict[str, Any] = {}

    def _fake(path: str, out_dir: str, *, tool: str) -> binwalk_bridge.FirmwareExtractResult:
        seen["args"] = (path, out_dir, tool)
        return _firmware_result(tmp_path)

    monkeypatch.setattr(binwalk_bridge, "firmware_extract", _fake)
    payload = tools.codevanta_firmware_extract(str(image), str(tmp_path / "out"), "unblob")
    assert seen["args"] == (str(image), str(tmp_path / "out"), "unblob")
    assert payload["tool"] == "binwalk"
    with pytest.raises(AnalysisError, match="tool must be one of"):
        tools.codevanta_firmware_extract(str(image), str(tmp_path / "out"), "dd")


def test_mcp_codevanta_pcap_fields_delegates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    seen: dict[str, Any] = {}

    def _fake(*args: Any, **kwargs: Any) -> tshark_bridge.PcapFieldsResult:
        seen["args"] = (args, kwargs)
        return tshark_bridge.PcapFieldsResult(path=str(capture), fields=("frame.number",))

    monkeypatch.setattr(tshark_bridge, "pcap_fields", _fake)
    payload = tools.codevanta_pcap_fields(
        str(capture), "frame.number", display_filter="tcp", packet_limit=5
    )
    assert seen["args"][0] == (str(capture), "frame.number")
    assert seen["args"][1] == {"display_filter": "tcp", "packet_limit": 5}
    assert payload["fields"] == ["frame.number"]


def test_mcp_server_registers_the_three_bridge_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert {"codevanta_bridges", "codevanta_firmware_extract", "codevanta_pcap_fields"} <= names

def test_cli_pcap_fields_human(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The pcap fields table prints rows, the footer and the evidence line."""
    capture = tmp_path / "trace.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
    result = tshark_bridge.PcapFieldsResult(
        path=str(capture),
        fields=("frame.number", "ip.src", "tcp.srcport"),
        display_filter="tcp.port == 443",
        packet_limit=10,
        rows=(
            tshark_bridge.PcapRow(
                number=1, fields={"frame.number": "1", "ip.src": "10.0.0.5", "tcp.srcport": "443"}
            ),
            tshark_bridge.PcapRow(
                number=2, fields={"frame.number": "2", "ip.src": "10.0.0.9", "tcp.srcport": None}
            ),
        ),
        warnings=["header field order differs"],
    )
    monkeypatch.setattr(tshark_bridge, "pcap_fields", lambda *a, **k: result)
    run = runner.invoke(
        app,
        [
            "pcap",
            "fields",
            str(capture),
            "--fields",
            "frame.number,ip.src,tcp.srcport",
            "--filter",
            "tcp.port == 443",
        ],
    )
    assert run.exit_code == 0, _output(run)
    text = _output(run)
    assert "pcap fields (frame.number" in text
    assert "10.0.0.5" in text
    assert "filter: tcp.port == 443" in text
    assert "evidence: bridge.tshark" in text
    # The no-rows variant prints the yellow note.
    empty = tshark_bridge.PcapFieldsResult(
        path=str(capture), fields=("frame.number",), packet_limit=10
    )
    monkeypatch.setattr(tshark_bridge, "pcap_fields", lambda *a, **k: empty)
    empty_run = runner.invoke(app, ["pcap", "fields", str(capture), "--fields", "frame.number"])
    assert empty_run.exit_code == 0, _output(empty_run)
    assert "no packets matched" in _output(empty_run)


def test_cli_wasm_human_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """wasm validate/disasm print verdicts, errors and the bounded table."""
    module = tmp_path / "mod.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    invalid = wabt_bridge.WasmValidateResult(
        path=str(module), valid=False, errors=("bad.wasm:21: error: oob",)
    )
    monkeypatch.setattr(wabt_bridge, "wasm_validate", lambda *a, **k: invalid)
    invalid_run = runner.invoke(app, ["wasm", "validate", str(module)])
    assert invalid_run.exit_code == 0, _output(invalid_run)
    invalid_text = _output(invalid_run)
    assert "invalid" in invalid_text
    assert "error: bad.wasm:21" in invalid_text
    assert "evidence: bridge.wabt" in invalid_text
    disasm = wabt_bridge.WasmObjdumpResult(
        path=str(module),
        sections=(wabt_bridge.WasmSection(name="Code", start=0x1F, size=0x1B),),
        instructions=(
            wabt_bridge.WasmInstruction(offset=0x0D, raw_bytes="41 01", text="i32.const 1"),
        ),
        truncated=True,
        warnings=["one junk line"],
    )
    monkeypatch.setattr(wabt_bridge, "wasm_objdump", lambda *a, **k: disasm)
    disasm_run = runner.invoke(app, ["wasm", "disasm", str(module)])
    assert disasm_run.exit_code == 0, _output(disasm_run)
    text = _output(disasm_run)
    assert "sections: Code(0x1b)" in text
    assert "i32.const 1" in text
    assert "instruction list was truncated" in text
    assert "evidence: bridge.wabt" in text

    empty = wabt_bridge.WasmObjdumpResult(path=str(module))
    monkeypatch.setattr(wabt_bridge, "wasm_objdump", lambda *a, **k: empty)
    empty_run = runner.invoke(app, ["wasm", "disasm", str(module)])
    assert empty_run.exit_code == 0, _output(empty_run)
    assert "no instructions decoded" in _output(empty_run)


def test_cli_firmware_extract_empty_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An extractor that reports nothing still prints the (nothing written) note."""
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x27\x05\x19\x56")
    empty = binwalk_bridge.FirmwareExtractResult(
        tool="binwalk", path=str(image), out_dir=str(tmp_path)
    )
    monkeypatch.setattr(binwalk_bridge, "firmware_extract", lambda *a, **k: empty)
    run = runner.invoke(app, ["firmware", "extract", str(image), "--out-dir", str(tmp_path)])
    assert run.exit_code == 0, _output(run)
    text = _output(run)
    assert "no extraction entries reported" in text
    assert "(nothing written)" in text


def test_cli_objdump_human_arch_and_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The objdump header names the arch; an empty disassembly keeps its note."""
    binary = tmp_path / "hello.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 8)
    parsed = objdump_bridge.parse_objdump_text(OBJDUMP_ATT_OUTPUT)
    human = objdump_bridge.ObjdumpDisasmResult(
        path=str(binary), arch="i386:x86-64", rows=parsed.rows
    )
    monkeypatch.setattr(objdump_bridge, "objdump_disasm", lambda *a, **k: human)
    run = runner.invoke(app, ["objdump", str(binary), "--arch", "i386:x86-64"])
    assert run.exit_code == 0, _output(run)
    assert "arch i386:x86-64" in _output(run)

    empty = objdump_bridge.ObjdumpDisasmResult(path=str(binary))
    monkeypatch.setattr(objdump_bridge, "objdump_disasm", lambda *a, **k: empty)
    empty_run = runner.invoke(app, ["objdump", str(binary)])
    assert empty_run.exit_code == 0, _output(empty_run)
    assert "no instructions decoded" in _output(empty_run)


def test_cli_bridges_report_available_with_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """An available capability may still carry a probe detail line."""
    monkeypatch.setattr(
        bridges_cli,
        "bridges_report",
        lambda: [
            BridgeCapability(
                tool="z3",
                available=True,
                version="4.13.0",
                reason="z3 imports; distribution metadata did not name a version",
            )
        ],
    )
    run = runner.invoke(app, ["bridges"])
    assert run.exit_code == 0, _output(run)
    text = _output(run)
    assert "available z3" in text
    assert "metadata did not name a version" in text

