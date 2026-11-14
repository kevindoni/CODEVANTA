"""Lane-bridge-b tests: apktool/wakaru wrappers, CLI and MCP plumbing.

Everything here is offline: the external tools never run (skip-gates are
exercised via monkeypatched PATH probes; live calls use injectable runners
returning canned transcripts), the CLI runs under ``CliRunner`` and the MCP
layer runs in-process against a hand-built PE certificate table.
"""

from __future__ import annotations

import asyncio
import json
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis import apktool_bridge, wakaru_bridge
from codevanta.analysis.apktool_bridge import (
    apk_available,
    apk_decode,
    parse_apktool_console,
    summarize_decode_dir,
)
from codevanta.analysis.wakaru_bridge import (
    js_recover,
    parse_wakaru_output,
    wakaru_available,
)
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools as mcp_tools
from codevanta.mcp_server.server import build_server

runner_cli = CliRunner()


@dataclass
class FakeOutcome:
    """``subprocess.CompletedProcess``-shaped runner outcome."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


APKTOOL_CONSOLE = """\
I: Using Apktool 2.9.3 on demo.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with arsenals...
I: Decoding file-resources...
I: Copying assets and libs...
java.lang.RuntimeException: binary soda
I: Copying unknown files...
"""

WAKARU_CONSOLE = """\
Loaded bundle app.min.js
app.min.js -> out/app.js (unminified)
vendor.min.js -> out/vendor.js
packer type: webpack
42 modules written
Done in 1.2s
"""


def make_fake_decode_dir(root: Path) -> Path:
    """Build the tree ``apktool d --no-src`` would leave behind."""
    (root / "res" / "layout").mkdir(parents=True)
    (root / "res" / "values").mkdir(parents=True, exist_ok=True)
    (root / "res" / "values" / "strings.xml").write_text("<r/>", encoding="utf-8")
    (root / "res" / "layout" / "main.xml").write_text("<l/>", encoding="utf-8")
    (root / "res" / "layout" / "other.xml").write_text("<l/>", encoding="utf-8")
    (root / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (root / "apktool.yml").write_text("!!brut.androlib.apk", encoding="utf-8")
    (root / "original").mkdir()
    (root / "assets").mkdir()
    return root


# ---- apktool console parser ---------------------------------------------------


def test_apktool_console_parses_levels_and_banner() -> None:
    console = parse_apktool_console(APKTOOL_CONSOLE)
    assert console.framework_version == "2.9.3"
    assert console.apk_name == "demo.apk"
    assert console.truncated is False
    assert [message.level for message in console.messages] == ["I"] * 6
    assert any("Decoding AndroidManifest.xml" in message.text for message in console.messages)
    assert any("java.lang" in warning for warning in console.warnings)
    assert console.evidence.source == "bridge.apktool"


def test_apktool_console_rejects_non_string() -> None:
    with pytest.raises(AnalysisError, match="transcript must be a string"):
        parse_apktool_console(b"I: bytes")  # type: ignore[arg-type]


def test_apktool_console_empty_transcript_warns() -> None:
    console = parse_apktool_console("")
    assert console.messages == ()
    assert console.warnings == ["no apktool console lines in the transcript"]


def test_apktool_console_truncates_at_cap() -> None:
    text = "\n".join(f"I: line {index}" for index in range(apktool_bridge.MAX_ENTRIES + 5))
    console = parse_apktool_console(text)
    assert len(console.messages) == apktool_bridge.MAX_ENTRIES
    assert console.truncated is True
    assert any("message limit" in warning for warning in console.warnings)


# ---- decode tree walker -------------------------------------------------------


def test_summarize_decode_dir_reports_expected_shape(tmp_path: Path) -> None:
    out_dir = make_fake_decode_dir(tmp_path / "demo")
    summary = summarize_decode_dir(out_dir)
    assert summary.manifest_decoded is True
    assert summary.apktool_yml is True
    assert summary.res_count == 3
    assert summary.smali_present is False
    assert summary.smali_expected_absent is True
    assert summary.entries_truncated is False
    assert set(summary.entries) == {
        "AndroidManifest.xml",
        "apktool.yml",
        "assets",
        "original",
        "res",
    }
    assert summary.evidence.source == "bridge.apktool"
    assert json.loads(json.dumps(summary.to_dict())) == summary.to_dict()


def test_summarize_decode_dir_flags_smali_when_present(tmp_path: Path) -> None:
    out_dir = make_fake_decode_dir(tmp_path / "demo")
    (out_dir / "smali_classes2").mkdir()
    summary = summarize_decode_dir(out_dir)
    assert summary.smali_present is True
    assert summary.smali_expected_absent is False
# ---- skip-gated apktool wrapper -----------------------------------------------


def test_apk_available_reports_path_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apktool_bridge, "_apktool_path", lambda: None)
    assert apk_available() is False
    monkeypatch.setattr(apktool_bridge, "_apktool_path", lambda: "/usr/bin/apktool")
    assert apk_available() is True


def test_apk_decode_requires_apktool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(apktool_bridge, "_apktool_path", lambda: None)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    with pytest.raises(AnalysisError) as excinfo:
        apk_decode(apk, tmp_path / "out")
    message = str(excinfo.value)
    assert "apktool is not on PATH" in message
    assert "https://apktool.org" in message
    assert "codevanta metadata" in message


def test_apk_decode_rejects_missing_apk(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="APK file not found"):
        apk_decode(tmp_path / "missing.apk", tmp_path / "out")


def test_apk_decode_rejects_bad_types_and_timeout(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="apk_path must be a str or Path"):
        apk_decode(123, tmp_path / "out")  # type: ignore[arg-type]
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    with pytest.raises(AnalysisError, match="out_dir must be a str or Path"):
        apk_decode(apk, 456)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="timeout must be a number"):
        apk_decode(apk, tmp_path / "out", timeout="slow")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="out of range"):
        apk_decode(apk, tmp_path / "out", timeout=apktool_bridge.MAX_TIMEOUT + 1)


def runner_writes_tree(out_root: Path) -> Any:
    """A runner that both checks the argv and fakes the decode output."""

    def _runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        assert "--no-src" in command and "-f" in command
        out_dir = Path(command[command.index("-o") + 1])
        make_fake_decode_dir(out_dir)
        return FakeOutcome(returncode=0, stdout=APKTOOL_CONSOLE, stderr="")

    return _runner


def test_apk_decode_with_injected_runner_parses_and_walks(tmp_path: Path) -> None:
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    out_dir = tmp_path / "decoded"
    summary = apk_decode(apk, out_dir, runner=runner_writes_tree(out_dir))
    assert summary.apk == str(apk)
    assert summary.framework_version == "2.9.3"
    assert summary.manifest_decoded is True
    assert summary.res_count == 3
    assert summary.smali_present is False
    assert summary.apktool_yml is True
    assert summary.evidence.method == "apktool d --no-src"
    assert json.loads(json.dumps(summary.to_dict())) == summary.to_dict()


def test_apk_decode_wraps_runner_failures(tmp_path: Path) -> None:
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    out_dir = tmp_path / "out"

    def timeout_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        raise subprocess.TimeoutExpired(cmd=command, timeout=1)

    def missing_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        raise FileNotFoundError("apktool")

    def lying_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        return "not an outcome"  # type: ignore[return-value]

    def failing_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        return FakeOutcome(returncode=2, stdout="", stderr="brut.common.BrutException: x")

    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        apk_decode(apk, out_dir, runner=timeout_runner)
    with pytest.raises(AnalysisError, match="vanished between the PATH probe"):
        apk_decode(apk, out_dir, runner=missing_runner)
    with pytest.raises(AnalysisError, match="injection contract"):
        apk_decode(apk, out_dir, runner=lying_runner)
    with pytest.raises(AnalysisError, match="exited with code 2") as excinfo:
        apk_decode(apk, out_dir, runner=failing_runner)
    assert "BrutException" in str(excinfo.value)



def test_summarize_decode_dir_bounds_entries_and_res(tmp_path: Path) -> None:
    out_dir = tmp_path / "big"
    out_dir.mkdir()
    for index in range(apktool_bridge.MAX_ENTRIES + 4):
        (out_dir / f"e{index:02d}").mkdir()
    res = out_dir / "res"
    res.mkdir()
    for index in range(apktool_bridge.MAX_ENTRIES + 4):
        (res / f"f{index:02d}.xml").write_text("<x/>", encoding="utf-8")
    summary = summarize_decode_dir(out_dir)
    assert len(summary.entries) == apktool_bridge.MAX_ENTRIES
    assert summary.entries_truncated is True
    assert summary.res_count == apktool_bridge.MAX_ENTRIES
    assert summary.res_truncated is True


def test_summarize_decode_dir_missing_dir_is_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="decode output directory not found"):
        summarize_decode_dir(tmp_path / "nope")
# ---- wakaru console parser ----------------------------------------------------


def test_wakaru_console_parses_entries_counts_and_packer() -> None:
    console = parse_wakaru_output(WAKARU_CONSOLE, "minify")
    assert [entry.source for entry in console.entries] == ["app.min.js", "vendor.min.js"]
    assert console.entries[0].target == "out/app.js"
    assert console.entries[0].note == "unminified"
    assert console.entries[1].note is None
    assert console.module_count == 42
    assert console.packer == "webpack"
    assert console.truncated is False
    assert any("Done in 1.2s" in warning for warning in console.warnings)
    assert console.evidence.source == "bridge.wakaru"
    assert json.loads(json.dumps(console.to_dict())) == console.to_dict()


def test_wakaru_console_rejects_bad_mode_and_text() -> None:
    with pytest.raises(AnalysisError, match="invalid mode"):
        parse_wakaru_output("x -> y", "split")
    with pytest.raises(AnalysisError, match="mode must be a string"):
        parse_wakaru_output("x -> y", 7)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="transcript must be a string"):
        parse_wakaru_output(None, "unpack")  # type: ignore[arg-type]


def test_wakaru_console_folds_mode_case() -> None:
    console = parse_wakaru_output(WAKARU_CONSOLE, " Unpack ")
    assert console.module_count == 42


def test_wakaru_console_truncates_entries_at_cap() -> None:
    lines = [f"src/{index}.js -> out/{index}.js" for index in range(wakaru_bridge.MAX_ENTRIES + 3)]
    console = parse_wakaru_output("\n".join(lines), "unpack")
    assert len(console.entries) == wakaru_bridge.MAX_ENTRIES
    assert console.truncated is True
    assert any("entry limit" in warning for warning in console.warnings)


def test_wakaru_console_empty_transcript_warns() -> None:
    console = parse_wakaru_output("", "minify")
    assert console.entries == ()
    assert console.warnings == ["no wakaru output lines in the transcript"]


# ---- wakaru availability probe ------------------------------------------------


def test_wakaru_available_prefers_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: "wakaru")
    assert wakaru_available() is True


def test_wakaru_available_uses_npx_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: None)
    monkeypatch.setattr(wakaru_bridge, "_npx_available", lambda: True)
    seen: list[tuple[str, ...]] = []

    def probe(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        seen.append(command)
        return FakeOutcome(returncode=0, stdout="1.1.0")

    assert wakaru_available(runner=probe) is True
    assert seen and seen[0][:3] == ("npx", "--no-install", "wakaru")


def test_wakaru_available_false_when_probes_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: None)
# ---- skip-gated wakaru wrapper -------------------------------------------------


def test_js_recover_requires_wakaru(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: None)
    monkeypatch.setattr(wakaru_bridge, "_npx_available", lambda: False)
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    with pytest.raises(AnalysisError) as excinfo:
        js_recover(bundle, tmp_path / "out")
    assert "npm i -g @wakaru/cli" in str(excinfo.value)


def test_js_recover_rejects_bad_inputs(tmp_path: Path) -> None:
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    with pytest.raises(AnalysisError, match="invalid mode"):
        js_recover(bundle, tmp_path / "out", "bundle")
    with pytest.raises(AnalysisError, match="bundle file not found"):
        js_recover(tmp_path / "nope.js", tmp_path / "out", "minify")
    with pytest.raises(AnalysisError, match="bundle_path must be a str or Path"):
        js_recover(99, tmp_path / "out", "minify")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="out_dir must be a str or Path"):
        js_recover(bundle, [], "minify")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="timeout must be a number"):
        js_recover(bundle, tmp_path / "out", "minify", timeout=None)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="out of range"):
        js_recover(bundle, tmp_path / "out", "minify", timeout=wakaru_bridge.MAX_TIMEOUT + 1)


def runner_for(stdout: str, returncode: int = 0) -> Any:
    def _runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        return FakeOutcome(returncode=returncode, stdout=stdout, stderr="")

    return _runner


def test_js_recover_minify_with_injected_runner(tmp_path: Path) -> None:
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out_dir = tmp_path / "recovered"
    result = js_recover(bundle, out_dir, "minify", runner=runner_for(WAKARU_CONSOLE))
    assert result.mode == "minify"
    assert "unminify" in result.command
    assert not result.command.startswith("npx") or "--no-install" in result.command
    assert len(result.entries) == 2
    assert result.module_count == 42
    assert result.packer == "webpack"
    assert result.transcript_path is not None
    assert Path(result.transcript_path).read_text(encoding="utf-8").startswith("Loaded bundle")
    assert result.evidence.method == "wakaru unminify"
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_js_recover_unpack_maps_verb(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.js"
    bundle.write_text("webpackJsonp([],1)", encoding="utf-8")
    result = js_recover(bundle, tmp_path / "out", "unpack", runner=runner_for("done\n"))
    assert result.mode == "unpack"
    assert "unpack" in result.command
    assert result.evidence.method == "wakaru unpack"


def test_js_recover_wraps_runner_failures(tmp_path: Path) -> None:
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out_dir = tmp_path / "out"

    def timeout_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        raise subprocess.TimeoutExpired(cmd=command, timeout=1)

    def missing_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        raise FileNotFoundError("wakaru")

    def lying_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        return 3  # type: ignore[return-value]

    def failing_runner(command: tuple[str, ...], **kwargs: Any) -> FakeOutcome:
        return FakeOutcome(returncode=1, stdout="", stderr="Cannot find module 'x'")

    with pytest.raises(AnalysisError, match="exceeded its timeout"):
        js_recover(bundle, out_dir, "minify", runner=timeout_runner)
    with pytest.raises(AnalysisError, match="vanished between the probe"):
        js_recover(bundle, out_dir, "minify", runner=missing_runner)
    with pytest.raises(AnalysisError, match="injection contract"):
        js_recover(bundle, out_dir, "minify", runner=lying_runner)
    with pytest.raises(AnalysisError, match="exited with code 1") as excinfo:
        js_recover(bundle, out_dir, "minify", runner=failing_runner)
    assert "Cannot find module" in str(excinfo.value)


# ---- CLI (depth sub-apps) -----------------------------------------------------


def test_cli_apk_decode_reports_skip_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(apktool_bridge, "_apktool_path", lambda: None)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    result = runner_cli.invoke(
        app, ["apk", "decode", str(apk), "--out-dir", str(tmp_path / "out")]
    )
    assert result.exit_code == 2
    assert "apktool is not on PATH" in result.stdout


def test_cli_apk_decode_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out_dir = make_fake_decode_dir(tmp_path / "tree")
    summary = summarize_decode_dir(out_dir)

    def fake_decode(apk: Path, out: Path, **kwargs: Any) -> Any:
        return summary

    monkeypatch.setattr("codevanta.cli.depth.apk_decode", fake_decode)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    result = runner_cli.invoke(
        app, ["apk", "decode", str(apk), "--out-dir", str(tmp_path / "x"), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["manifest_decoded"] is True
    assert payload["res_count"] == 3


def test_cli_js_recover_rejects_invalid_mode(tmp_path: Path) -> None:
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    result = runner_cli.invoke(
        app, ["js", "recover", str(bundle), "--out-dir", str(tmp_path / "o"), "--mode", "zip"]
    )
    assert result.exit_code == 2
    assert "invalid mode" in result.stdout


def test_cli_js_recover_reports_skip_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: None)
    monkeypatch.setattr(wakaru_bridge, "_npx_available", lambda: False)
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    result = runner_cli.invoke(
        app, ["js", "recover", str(bundle), "--out-dir", str(tmp_path / "o")]
    )
    assert result.exit_code == 2
    assert "@wakaru/cli" in result.stdout
    assert "not available" in result.stdout


def test_cli_apk_decode_table_render(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out_dir = make_fake_decode_dir(tmp_path / "tree")
    summary = summarize_decode_dir(out_dir)

    def fake_decode(apk: Path, out: Path, **kwargs: Any) -> Any:
        return summary

    monkeypatch.setattr("codevanta.cli.depth.apk_decode", fake_decode)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    result = runner_cli.invoke(
        app, ["apk", "decode", str(apk), "--out-dir", str(tmp_path / "x")]
    )
    assert result.exit_code == 0, result.stdout
    assert "apktool decode" in result.stdout
    assert "decoded" in result.stdout
    assert "evidence: bridge.apktool" in result.stdout


def test_cli_apk_decode_renders_warnings_and_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out_dir = make_fake_decode_dir(tmp_path / "tree")
    summary = apktool_bridge.ApkDecodeSummary(
        apk=str(tmp_path / "demo.apk"),
        out_dir=str(out_dir),
        manifest_decoded=True,
        framework_version="2.9.3",
        warnings=["no res/ directory in the decode output"],
    )

    def fake_decode(apk: Path, out: Path, **kwargs: Any) -> Any:
        return summary

    monkeypatch.setattr("codevanta.cli.depth.apk_decode", fake_decode)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    result = runner_cli.invoke(
        app, ["apk", "decode", str(apk), "--out-dir", str(tmp_path / "x")]
    )
    assert result.exit_code == 0, result.stdout
    assert "warning:" in result.stdout
    assert "2.9.3" in result.stdout


def test_cli_certs_without_signers_renders_placeholder(tmp_path: Path) -> None:
    from test_pe_certs import build_signed_data_blob, make_signed_pe_file

    blob = build_signed_data_blob()
    entry = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0004) + blob
    pe = make_signed_pe_file(tmp_path / "other.exe", blob=entry, wrap=False)
    result = runner_cli.invoke(app, ["certs", str(pe)])
    assert result.exit_code == 0, result.stdout
    assert "signers: 0" in result.stdout



def test_cli_js_recover_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codevanta.analysis.wakaru_bridge import RecoveredEntry, WakaruRecoverResult

    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")

    def fake_recover(bundle_path: Path, out: Path, mode: str = "minify", **kwargs: Any) -> Any:
        return WakaruRecoverResult(
            bundle=str(bundle_path),
            out_dir=str(out),
            mode=mode,
            entries=(RecoveredEntry(source="app.min.js", target="out/app.js"),),
            module_count=7,
            packer="webpack",
        )

    monkeypatch.setattr("codevanta.cli.depth.js_recover", fake_recover)
    result = runner_cli.invoke(
        app, ["js", "recover", str(bundle), "--out-dir", str(tmp_path / "o"), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["module_count"] == 7


def test_cli_js_recover_table_render(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codevanta.analysis.wakaru_bridge import RecoveredEntry, WakaruRecoverResult

    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")

    def fake_recover(bundle_path: Path, out: Path, mode: str = "minify", **kwargs: Any) -> Any:
        return WakaruRecoverResult(
            bundle=str(bundle_path),
            out_dir=str(out),
            mode=mode,
            entries=(
                RecoveredEntry(source="a.js", target="out/a.js", note="ok"),
                RecoveredEntry(source="b.js"),
            ),
            module_count=7,
            packer="webpack",
            transcript_path=str(out / "wakaru-minify.txt"),
        )

    monkeypatch.setattr("codevanta.cli.depth.js_recover", fake_recover)
    result = runner_cli.invoke(
        app, ["js", "recover", str(bundle), "--out-dir", str(tmp_path / "o")]
    )
    assert result.exit_code == 0, result.stdout
    assert "a.js" in result.stdout and "evidence: bridge.wakaru" in result.stdout


# ---- CLI certs (offline, uses the hand-built PE from test_pe_certs) ------------


def test_cli_certs_renders_and_json(tmp_path: Path) -> None:
    from test_pe_certs import make_signed_pe_file

    pe = make_signed_pe_file(tmp_path / "signed.exe")
    table = runner_cli.invoke(app, ["certs", str(pe)])
    assert table.exit_code == 0, table.stdout
    assert "certificate table" in table.stdout
    assert "issuer name not decoded" in table.stdout
    assert "evidence: cert.pe" in table.stdout
    payload = runner_cli.invoke(app, ["certs", str(pe), "--json"])
    assert payload.exit_code == 0, payload.stdout
    data = json.loads(payload.stdout)
    assert data["status"] == "present"
    assert data["signer_count"] == 1


def test_cli_certs_missing_file_fails_typed(tmp_path: Path) -> None:
    result = runner_cli.invoke(app, ["certs", str(tmp_path / "nope.exe")])
    assert result.exit_code == 2
    assert "file not found" in result.stdout


# ---- MCP layer ----------------------------------------------------------------


def test_mcp_tools_codevanta_certs(tmp_path: Path) -> None:
    from test_pe_certs import make_signed_pe_file

    pe = make_signed_pe_file(tmp_path / "signed.exe")
    payload = mcp_tools.codevanta_certs(str(pe))
    assert payload["table_present"] is True
    assert payload["status"] == "present"
    assert payload["signer_count"] == 1
    signer = payload["signers"][0]
    assert signer["digest_algorithm"] == "sha256"
    assert signer["signature_algorithm"] == "sha256WithRSAEncryption"
    assert json.loads(json.dumps(payload)) == payload


def test_mcp_tools_codevanta_certs_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        mcp_tools.codevanta_certs(str(tmp_path / "missing.exe"))


def test_mcp_tools_codevanta_apk_decode_skip_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(apktool_bridge, "_apktool_path", lambda: None)
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK")
    with pytest.raises(AnalysisError, match="apktool is not on PATH"):
        mcp_tools.codevanta_apk_decode(str(apk), str(tmp_path / "out"))


def test_mcp_tools_codevanta_js_recover_skip_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(wakaru_bridge, "_wakaru_binary", lambda: None)
    monkeypatch.setattr(wakaru_bridge, "_npx_available", lambda: False)
    bundle = tmp_path / "app.min.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    with pytest.raises(AnalysisError, match="npm i -g @wakaru/cli"):
        mcp_tools.codevanta_js_recover(str(bundle), str(tmp_path / "out"))


def test_mcp_server_registers_the_three_depth_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert {"codevanta_apk_decode", "codevanta_js_recover", "codevanta_certs"} <= names


def test_mcp_server_call_tool_certs(tmp_path: Path) -> None:
    from test_pe_certs import make_signed_pe_file

    pe = make_signed_pe_file(tmp_path / "signed.exe")
    result = asyncio.run(build_server().call_tool("codevanta_certs", {"path": str(pe)}))
    structured = getattr(result, "structuredContent", None)
    payload: Any = structured
    if not payload:
        for block in getattr(result, "content", []):
            text = getattr(block, "text", None)
            if text:
                payload = json.loads(text)
                break
    assert payload is not None
    assert payload["status"] == "present"
