"""ADB-lane tests: parsers against canned transcripts, wiring offline, adb live.

Every transcript below is a realistic byte-for-byte capture of what adb prints
(``devices -l`` with its daemon chatter, ``pm list packages -3`` bare and
``-f`` rows, ``ps -A`` in the modern and legacy column layouts, ``service
list``, ``getprop`` bracketed and plain, one ``dumpsys package`` block and a
``dumpsys window`` focus dump), so the parsers are exercised offline exactly
as they will see live output. The wrappers are driven through the injectable
``runner`` contract -- no adb call is ever spawned here -- the adb-missing
failure is asserted by taking ``shutil.which`` away, the CLI is tested through
monkeypatched wrapper functions, and exactly one skipif-gated test touches a
real adb when one happens to be installed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import adb
from codevanta.cli import mobile as mobile_cli
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.mcp_server import ext_mobile, tools

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


DEVICES_OUTPUT = """\
* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64xa transport_id:1
R58M3017XYZ           device usb:1-1 product:raven model:Pixel_6 device:raven transport_id:2
192.168.1.50:5555     offline transport_id:3
"""

DEVICES_OUTPUT_CRLF = DEVICES_OUTPUT.replace("\n", "\r\n")

PACKAGES_OUTPUT = """\
package:com.example.notes
package:com.example.game
package:/data/app/~~AbCd==/com.example.paid-1==/base.apk=com.example.paid
this line is not a package
package:=com.example.nameless
"""

PROCESSES_OUTPUT_MODERN = """\
USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME
root              1     0   10936   3448 do_exit           0 S init
u0_a123        12345   811 4681220 128400 0                 0 S com.example.notes
system         12346   811 4400232  98304 binder_thread_read 0 S com.android.systemui:ui with spaces
"""

PROCESSES_OUTPUT_LEGACY = """\
USER      PID   PPID  VSIZE  RSS     WCHAN    NAME
root      1     0     884    444   ffffffff init
u0_a5   1204   811   993284 52732 ffffffff com.example.oldapp
"""

SERVICES_OUTPUT = """\
   59 window: [android.view.IWindowManager]
   19 activity: [android.app.ActivityManager]
   42 audio: []
not-a-service-line
"""

GETPROP_OUTPUT_BRACKETED = """\
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2024-05-05]
[ro.product.model]: [Pixel 6]
[ro.product.brand]: [google]
[ro.product.name]: [raven]
[ro.build.fingerprint]: [google/raven/raven:14/AP2A.240505.005/11948163:user/release-keys]
[ro.build.date]: [Fri May  3 12:00:00 UTC 2024]
[persist.sys.timezone]: [Europe/Berlin]
"""

GETPROP_OUTPUT_PLAIN = """\
ro.build.version.release: 13
ro.product.model: SM-G991B
ro.build.fingerprint: samsung/o1sxx/o1s:13/TP1A.220624.014/G991BXXS9DWK1:user/release-keys
ro.bootloader: G991BXXS9DWK1
"""

DUMPSYS_PACKAGE_OUTPUT = """\
DUMP OF SERVICE package:
  Package [com.example.notes] (9ab3c1d):
    userId=10123
    pkg=com.example.notes
    codePath=/data/app/~~x==/com.example.notes-y==/base.apk
    versionName=2.3.1
    versionCode=231
    firstInstallTime=2024-03-01 12:34:56
    lastUpdateTime=2024-05-10 08:00:00
    installerPackageName=com.android.vending
    installer=com.android.vending
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
      android.permission.POST_NOTIFICATIONS
    install permissions:
      android.permission.INTERNET: granted=true
"""

DUMPSYS_PACKAGE_OUTPUT_LEGACY_INSTALLER = """\
  Package [com.example.oldapp] (77aa01):
    versionName=1.0.4
    firstInstallTime=2021-07-15 09:00:00
    installerPackageName=com.android.vending
    requested permissions:
      android.permission.INTERNET
"""

WINDOW_FOCUS_OUTPUT = """\
WINDOW MANAGER STATE (dumpsys window)
  mCurrentFocus=Window{7c1e02f u0 com.example.notes/com.example.notes.MainActivity}
  mFocusedWindow=Window{7c1e02f u0 com.example.notes/com.example.notes.MainActivity}
  mFocusedApp=AppWindowToken{6fa097b token=Token{ae12 ActivityRecord{2f3 u0 com.example.notes/.MainActivity t42}}}
"""

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class FakeOutcome:
    """A ``subprocess.CompletedProcess`` stand-in with plain attributes."""

    def __init__(self, returncode: int, stdout: object, stderr: object) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Record the commands it is given and replay one canned outcome."""

    def __init__(self, outcome: FakeOutcome) -> None:
        self.outcome = outcome
        self.calls: list[tuple[tuple[str, ...], dict]] = []

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        self.calls.append((command, dict(kwargs)))
        return self.outcome


class TimeoutRunner:
    """A runner that always exceeds its budget, like a hung adb."""

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        raise subprocess.TimeoutExpired(cmd="adb", timeout=float(kwargs.get("timeout", 0)))


class MissingRunner:
    """A runner whose executable vanished between probe and call."""

    def __call__(self, command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
        raise FileNotFoundError("adb")


def _devices_result() -> adb.AdbDevicesResult:
    return adb.parse_devices(DEVICES_OUTPUT)


class TestParseDevices:
    """``adb devices -l`` transcript parsing."""

    def test_rows_fields_and_kind(self) -> None:
        result = _devices_result()
        assert result.truncated is False
        assert result.warnings == []
        assert [device.serial for device in result.devices] == [
            "emulator-5554",
            "R58M3017XYZ",
            "192.168.1.50:5555",
        ]
        first, second, third = result.devices
        assert first.state == "device"
        assert first.kind == "emulator"
        assert first.model == "sdk_gphone64_x86_64"
        assert second.kind == "physical"
        assert second.model == "Pixel_6"
        assert third.state == "offline"
        assert third.kind == "physical"

    def test_crlf_transcript_parses_identically(self) -> None:
        result = adb.parse_devices(DEVICES_OUTPUT_CRLF)
        assert [device.serial for device in result.devices] == [
            "emulator-5554",
            "R58M3017XYZ",
            "192.168.1.50:5555",
        ]

    def test_empty_transcript_is_unknown_not_an_error(self) -> None:
        result = adb.parse_devices("")
        assert result.devices == ()
        assert result.evidence.confidence is Confidence.UNKNOWN

    def test_junk_rows_become_warnings_and_drop_confidence(self) -> None:
        result = adb.parse_devices("just-one-token\n- weird row\n")
        # 'just-one-token' has no state column; '- weird row' still parses
        # structurally (serial '-', state 'weird') because adb serials are
        # opaque tokens -- both are tolerated, only the first warns.
        assert len(result.warnings) == 1
        assert len(result.devices) == 1
        assert result.devices[0].serial == "-"
        assert result.devices[0].state == "weird"
        assert result.evidence.confidence is Confidence.MEDIUM

    def test_device_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb, "MAX_DEVICES", 2)
        result = _devices_result()
        assert len(result.devices) == 2
        assert result.truncated is True
        assert any("limit 2" in warning for warning in result.warnings)

    def test_to_dict_is_json_safe(self) -> None:
        payload = _devices_result().to_dict()
        assert json.dumps(payload)
        assert payload["count"] == 3
        assert payload["evidence"]["source"] == "adb.devices"
        assert payload["evidence"]["method"] == "devices -l"

    def test_non_string_input_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="must be a string"):
            adb.parse_devices(123)  # type: ignore[arg-type]


class TestParsePackages:
    """``pm list packages -3`` transcript parsing."""

    def test_bare_rows_have_no_path(self) -> None:
        result = adb.parse_packages(PACKAGES_OUTPUT)
        by_name = {package.name: package for package in result.packages}
        assert by_name["com.example.notes"].path is None
        assert by_name["com.example.game"].path is None

    def test_f_rows_carry_the_apk_path(self) -> None:
        result = adb.parse_packages(PACKAGES_OUTPUT)
        paid = next(p for p in result.packages if p.name == "com.example.paid")
        assert paid.path == "/data/app/~~AbCd==/com.example.paid-1==/base.apk"

    def test_empty_path_falls_back_to_nameless_path(self) -> None:
        result = adb.parse_packages(PACKAGES_OUTPUT)
        nameless = next(p for p in result.packages if p.name == "com.example.nameless")
        assert nameless.path is None

    def test_junk_line_warns(self) -> None:
        result = adb.parse_packages(PACKAGES_OUTPUT)
        assert any("not a package" in warning for warning in result.warnings)
        assert result.evidence.confidence is Confidence.MEDIUM

    def test_package_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb, "MAX_PACKAGES", 1)
        result = adb.parse_packages(PACKAGES_OUTPUT)
        assert len(result.packages) == 1
        assert result.truncated is True

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_packages(PACKAGES_OUTPUT).to_dict()
        assert json.dumps(payload)
        assert payload["count"] == 4
        assert payload["evidence"]["source"] == "adb.pm_list_packages"


class TestParseProcesses:
    """``ps -A`` transcript parsing in both column layouts."""

    def test_modern_layout(self) -> None:
        result = adb.parse_processes(PROCESSES_OUTPUT_MODERN)
        assert result.warnings == []
        assert len(result.processes) == 3
        first = result.processes[0]
        assert (first.user, first.pid, first.ppid, first.rss, first.state, first.name) == (
            "root",
            1,
            0,
            3448,
            "S",
            "init",
        )
        second = result.processes[1]
        assert second.pid == 12345
        assert second.rss == 128400
        assert second.name == "com.example.notes"
        third = result.processes[2]
        assert third.name == "com.android.systemui:ui with spaces"

    def test_legacy_layout(self) -> None:
        result = adb.parse_processes(PROCESSES_OUTPUT_LEGACY)
        assert result.warnings == []
        first = result.processes[0]
        assert first.pid == 1
        assert first.rss == 444
        assert first.state is None  # the legacy layout carries no S column
        assert first.name == "init"
        second = result.processes[1]
        assert second.pid == 1204
        assert second.rss == 52732
        assert second.name == "com.example.oldapp"

    def test_missing_header_falls_back_to_modern_layout(self) -> None:
        fallback = adb.parse_processes(
            "root              1     0   10936   3448 do_exit           0 S init\n"
        )
        assert len(fallback.processes) == 1
        assert fallback.processes[0].name == "init"
        assert fallback.processes[0].rss == 3448
        assert fallback.processes[0].state == "S"
        assert any("no ps header row" in warning for warning in fallback.warnings)

    def test_empty_transcript_warns_without_rows(self) -> None:
        result = adb.parse_processes("")
        assert result.processes == ()
        assert any("no ps rows found" in warning for warning in result.warnings)

    def test_process_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb, "MAX_PROCESSES", 1)
        result = adb.parse_processes(PROCESSES_OUTPUT_MODERN)
        assert len(result.processes) == 1
        assert result.truncated is True

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_processes(PROCESSES_OUTPUT_MODERN).to_dict()
        assert json.dumps(payload)
        assert payload["count"] == 3
        assert payload["evidence"]["source"] == "adb.ps"


class TestParseServices:
    """``service list`` transcript parsing."""

    def test_rows(self) -> None:
        result = adb.parse_services(SERVICES_OUTPUT)
        assert [(s.number, s.name) for s in result.services] == [
            (59, "window"),
            (19, "activity"),
            (42, "audio"),
        ]
        assert result.services[0].interface == "android.view.IWindowManager"
        assert result.services[2].interface is None
        assert any("not-a-service-line" in warning for warning in result.warnings)

    def test_service_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb, "MAX_SERVICES", 2)
        result = adb.parse_services(SERVICES_OUTPUT)
        assert len(result.services) == 2
        assert result.truncated is True

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_services(SERVICES_OUTPUT).to_dict()
        assert json.dumps(payload)
        assert payload["evidence"]["source"] == "adb.service_list"


class TestParseGetprop:
    """``getprop`` whitelist parsing in both renderings."""

    def test_bracketed_form_whitelist_only(self) -> None:
        result = adb.parse_getprop(GETPROP_OUTPUT_BRACKETED)
        assert result.truncated is False
        assert result.props["ro.build.version.release"] == "14"
        assert result.props["ro.build.version.sdk"] == "34"
        assert result.props["ro.build.version.security_patch"] == "2024-05-05"
        assert result.props["ro.product.model"] == "Pixel 6"
        assert result.props["ro.product.brand"] == "google"
        assert result.props["ro.product.name"] == "raven"
        assert result.props["ro.build.fingerprint"].startswith("google/raven/raven:14")
        # The whitelist is the point: non-identity keys must be gone.
        assert "ro.build.date" not in result.props
        assert "persist.sys.timezone" not in result.props
        assert result.warnings == []
        assert result.evidence.confidence is Confidence.CERTAIN

    def test_plain_form(self) -> None:
        result = adb.parse_getprop(GETPROP_OUTPUT_PLAIN)
        assert result.props["ro.build.version.release"] == "13"
        assert result.props["ro.product.model"] == "SM-G991B"
        assert result.props["ro.build.fingerprint"].startswith("samsung/o1sxx")
        assert "ro.bootloader" not in result.props
        assert list(result.props) == sorted(result.props)

    def test_values_keep_colons_and_spaces(self) -> None:
        result = adb.parse_getprop(GETPROP_OUTPUT_BRACKETED)
        fingerprint = result.props["ro.build.fingerprint"]
        assert fingerprint.count(":") >= 2  # "raven:14/AP2A...:user/release-keys"

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_getprop(GETPROP_OUTPUT_BRACKETED).to_dict()
        assert json.dumps(payload)
        assert payload["count"] == 7
        assert payload["evidence"]["source"] == "adb.getprop"


class TestParseDumpsysPackage:
    """``dumpsys package`` identity decoding."""

    def test_fields_and_permission_count(self) -> None:
        result = adb.parse_dumpsys_package(DUMPSYS_PACKAGE_OUTPUT)
        assert result.package == "com.example.notes"
        assert result.version_name == "2.3.1"
        assert result.installer == "com.android.vending"
        assert result.first_install_time == "2024-03-01 12:34:56"
        assert result.requested_permissions_count == 3
        assert result.warnings == []
        assert result.evidence.confidence is Confidence.CERTAIN

    def test_legacy_installer_key(self) -> None:
        result = adb.parse_dumpsys_package(DUMPSYS_PACKAGE_OUTPUT_LEGACY_INSTALLER)
        assert result.package == "com.example.oldapp"
        assert result.version_name == "1.0.4"
        assert result.installer == "com.android.vending"
        assert result.requested_permissions_count == 1

    def test_transcript_without_permissions_block_warns(self) -> None:
        result = adb.parse_dumpsys_package("  Package [com.lonely] (1):\n    versionName=9.9\n")
        assert result.requested_permissions_count == 0
        assert any("requested permissions" in warning for warning in result.warnings)

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_dumpsys_package(DUMPSYS_PACKAGE_OUTPUT).to_dict()
        assert json.dumps(payload)
        assert payload["evidence"]["source"] == "adb.dumpsys_package"


class TestParseWindowFocus:
    """``dumpsys window`` focus decoding."""

    def test_focus_values_and_components(self) -> None:
        result = adb.parse_window_focus(WINDOW_FOCUS_OUTPUT)
        assert result.current_focus.startswith("Window{7c1e02f")
        assert result.current_focus_component == (
            "com.example.notes/com.example.notes.MainActivity"
        )
        assert result.focused_app.startswith("AppWindowToken{")
        assert result.focused_app_component == "com.example.notes/.MainActivity"
        assert result.warnings == []
        assert result.evidence.confidence is Confidence.CERTAIN

    def test_transcript_without_focus_lines_warns(self) -> None:
        result = adb.parse_window_focus("WINDOW MANAGER STATE (dumpsys window)\n")
        assert result.current_focus is None
        assert result.focused_app is None
        assert any("no mCurrentFocus" in warning for warning in result.warnings)
        assert result.evidence.confidence is Confidence.UNKNOWN

    def test_focused_window_fallback(self) -> None:
        result = adb.parse_window_focus(
            "  mFocusedWindow=Window{abc u0 com.only.fallback/com.only.fallback.Boot}\n"
        )
        assert result.current_focus == (
            "Window{abc u0 com.only.fallback/com.only.fallback.Boot}"
        )
        assert result.current_focus_component == "com.only.fallback/com.only.fallback.Boot"

    def test_to_dict_is_json_safe(self) -> None:
        payload = adb.parse_window_focus(WINDOW_FOCUS_OUTPUT).to_dict()
        assert json.dumps(payload)
        assert payload["evidence"]["source"] == "adb.dumpsys_window"


class TestWrapperPlumbing:
    """Wrappers driven through the injectable runner -- never a real adb."""

    def test_list_devices_argv_and_kwargs(self) -> None:
        fake = FakeRunner(FakeOutcome(0, DEVICES_OUTPUT, ""))
        result = adb.list_devices(runner=fake)
        assert [device.serial for device in result.devices] == [
            "emulator-5554",
            "R58M3017XYZ",
            "192.168.1.50:5555",
        ]
        command, kwargs = fake.calls[0]
        assert command == ("adb", "devices", "-l")
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == adb.DEFAULT_TIMEOUT

    def test_inspect_device_argv(self) -> None:
        fake = FakeRunner(FakeOutcome(0, GETPROP_OUTPUT_BRACKETED, ""))
        result = adb.inspect_device("emulator-5554", runner=fake)
        assert result.props["ro.build.version.release"] == "14"
        command, _ = fake.calls[0]
        assert command == ("adb", "-s", "emulator-5554", "shell", "getprop")

    def test_list_packages_argv(self) -> None:
        fake = FakeRunner(FakeOutcome(0, PACKAGES_OUTPUT, ""))
        result = adb.list_packages("R58M3017XYZ", runner=fake)
        assert len(result.packages) == 4
        command, _ = fake.calls[0]
        assert command == (
            "adb",
            "-s",
            "R58M3017XYZ",
            "shell",
            "pm",
            "list",
            "packages",
            "-3",
        )

    def test_list_processes_argv(self) -> None:
        fake = FakeRunner(FakeOutcome(0, PROCESSES_OUTPUT_MODERN, ""))
        result = adb.list_processes("127.0.0.1:5555", runner=fake)
        assert result.processes[1].pid == 12345
        command, _ = fake.calls[0]
        assert command == ("adb", "-s", "127.0.0.1:5555", "shell", "ps", "-A")

    def test_nonzero_exit_is_typed(self) -> None:
        fake = FakeRunner(FakeOutcome(1, "", "error: device 'ghost' not found"))
        with pytest.raises(AnalysisError, match="exited with code 1.*device 'ghost'"):
            adb.inspect_device("ghost", runner=fake)

    def test_timeout_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="exceeded its timeout of 20"):
            adb.list_devices(runner=TimeoutRunner())

    def test_vanished_executable_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            adb.list_devices(runner=MissingRunner())

    def test_serial_validation(self) -> None:
        for bad in ("", "   ", "bad serial; rm -rf /", "serial\ninjected", "x" * 300):
            with pytest.raises(AnalysisError):
                adb.inspect_device(bad, runner=FakeRunner(FakeOutcome(0, "", "")))

    def test_timeout_bounds(self) -> None:
        for bad_timeout in (0, 0.5, adb.MAX_TIMEOUT + 1, True, "20"):
            with pytest.raises(AnalysisError, match="timeout"):
                adb.list_devices(
                    runner=FakeRunner(FakeOutcome(0, DEVICES_OUTPUT, "")),
                    timeout=bad_timeout,
                )

    def test_adb_missing_is_typed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb.shutil, "which", lambda name: None)
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            adb.list_devices()
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            adb.list_packages("emulator-5554")
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            adb.list_processes("emulator-5554")
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            adb.inspect_device("emulator-5554")

    def test_adb_available_reports_the_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adb.shutil, "which", lambda name: None)
        assert adb.adb_available() is False
        monkeypatch.setattr(adb.shutil, "which", lambda name: "/usr/bin/adb")
        assert adb.adb_available() is True


class TestInstall:
    """``install_apk``: confirmation gate, host digest, typed adb failures."""

    def _apk(self, tmp_path: Path, payload: bytes = b"PK\x03\x04fake-apk-bytes") -> Path:
        path = tmp_path / "app.apk"
        path.write_bytes(payload)
        return path

    def test_refuses_without_confirm(self, tmp_path: Path) -> None:
        apk = self._apk(tmp_path)
        with pytest.raises(AnalysisError, match="requires confirm=True"):
            adb.install_apk("emulator-5554", apk)

    def test_refuses_missing_or_empty_apk(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError, match="APK not found"):
            adb.install_apk("emulator-5554", tmp_path / "missing.apk", confirm=True)
        empty = tmp_path / "empty.apk"
        empty.write_bytes(b"")
        with pytest.raises(AnalysisError, match="is empty"):
            adb.install_apk("emulator-5554", empty, confirm=True)

    def test_install_records_host_sha256_and_size(self, tmp_path: Path) -> None:
        apk = self._apk(tmp_path, payload=b"PK\x03\x04deterministic-bytes")
        fake = FakeRunner(FakeOutcome(0, "Success\n", ""))
        result = adb.install_apk("emulator-5554", apk, confirm=True, runner=fake)
        digest = hashlib.sha256(b"PK\x03\x04deterministic-bytes").hexdigest()
        assert result.sha256 == digest
        assert result.size == len(b"PK\x03\x04deterministic-bytes")
        assert result.serial == "emulator-5554"
        assert result.evidence.source == "adb.install"
        command, kwargs = fake.calls[0]
        assert command == ("adb", "-s", "emulator-5554", "install", "-r", str(apk))
        assert kwargs["text"] is True

    def test_install_failure_is_typed(self, tmp_path: Path) -> None:
        apk = self._apk(tmp_path)
        fake = FakeRunner(FakeOutcome(0, "Failure [INSTALL_FAILED_ALREADY_EXISTS]\n", ""))
        with pytest.raises(AnalysisError, match="INSTALL_FAILED_ALREADY_EXISTS"):
            adb.install_apk("emulator-5554", apk, confirm=True, runner=fake)

    def test_to_dict_is_json_safe(self, tmp_path: Path) -> None:
        apk = self._apk(tmp_path)
        result = adb.install_apk(
            "emulator-5554", apk, confirm=True, runner=FakeRunner(FakeOutcome(0, "Success", ""))
        )
        payload = result.to_dict()
        assert json.dumps(payload)
        assert payload["evidence"]["confidence"] == "certain"


class TestScreencap:
    """``screencap``: binary capture, PNG check, typed empty-capture failure."""

    def test_capture_writes_png(self, tmp_path: Path) -> None:
        target = tmp_path / "shot.png"
        data = PNG_MAGIC + b"rest-of-image"
        fake = FakeRunner(FakeOutcome(0, data, b""))
        result = adb.screencap("emulator-5554", target, runner=fake)
        assert target.read_bytes() == data
        assert result.is_png is True
        assert result.size == len(data)
        assert result.sha256 == hashlib.sha256(data).hexdigest()
        assert result.warnings == []
        command, kwargs = fake.calls[0]
        assert command == ("adb", "-s", "emulator-5554", "exec-out", "screencap", "-p")
        assert kwargs["text"] is False

    def test_non_png_capture_is_flagged(self, tmp_path: Path) -> None:
        target = tmp_path / "shot.png"
        result = adb.screencap(
            "emulator-5554", target, runner=FakeRunner(FakeOutcome(0, b"not a png", b""))
        )
        assert result.is_png is False
        assert any("not a PNG" in warning for warning in result.warnings)

    def test_empty_capture_is_typed(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError, match="returned no bytes"):
            adb.screencap(
                "emulator-5554",
                tmp_path / "shot.png",
                runner=FakeRunner(FakeOutcome(0, b"", b"")),
            )

    def test_nested_out_directory_is_created(self, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "nested" / "shot.png"
        adb.screencap(
            "emulator-5554",
            target,
            runner=FakeRunner(FakeOutcome(0, PNG_MAGIC + b"x", b"")),
        )
        assert target.exists()


class TestBugreport:
    """``bugreport``: zip written into a caller directory, typed failures."""

    def test_bugreport_writes_zip(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "reports"

        def writing_runner(command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
            Path(command[-1]).write_bytes(b"PK zip payload")
            return FakeOutcome(0, "written to " + command[-1], "")

        result = adb.bugreport("emulator-5554", out_dir, runner=writing_runner)
        expected = out_dir / "codevanta-bugreport-emulator-5554.zip"
        assert result.path == str(expected)
        assert result.size == len(b"PK zip payload")
        assert result.evidence.source == "adb.bugreport"

    def test_missing_zip_is_typed(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError, match="wrote nothing"):
            adb.bugreport("emulator-5554", tmp_path, runner=FakeRunner(FakeOutcome(0, "", "")))

    def test_empty_zip_warns(self, tmp_path: Path) -> None:
        def writing_runner(command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
            Path(command[-1]).write_bytes(b"")
            return FakeOutcome(0, "written", "")

        result = adb.bugreport("emulator-5554", tmp_path, runner=writing_runner)
        assert result.size == 0
        assert any("is empty" in warning for warning in result.warnings)

    def test_serial_is_sanitised_in_the_filename(self, tmp_path: Path) -> None:
        def writing_runner(command: tuple[str, ...], **kwargs: object) -> FakeOutcome:
            Path(command[-1]).write_bytes(b"PK")
            return FakeOutcome(0, "written", "")

        result = adb.bugreport("192.168.1.50:5555", tmp_path, runner=writing_runner)
        assert Path(result.path).name == "codevanta-bugreport-192.168.1.50_5555.zip"


class TestCli:
    """CLI wiring through monkeypatched wrapper functions (never adb)."""

    def test_devices_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mobile_cli, "list_devices", _devices_result)
        result = runner.invoke(app, ["mobile", "devices"])
        assert result.exit_code == 0
        text = _output(result)
        assert "emulator-5554" in text
        assert "Pixel_6" in text
        assert "offline" in text
        assert "evidence: adb.devices" in text

    def test_devices_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mobile_cli, "list_devices", _devices_result)
        result = runner.invoke(app, ["mobile", "devices", "--json"])
        assert result.exit_code == 0
        payload = _payload(result)
        assert payload["count"] == 3
        assert payload["devices"][0]["kind"] == "emulator"

    def test_devices_absent_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse() -> adb.AdbDevicesResult:
            raise AnalysisError(adb.ADB_MISSING_MESSAGE)

        monkeypatch.setattr(mobile_cli, "list_devices", refuse)
        result = runner.invoke(app, ["mobile", "devices"])
        assert result.exit_code == 2
        assert "adb is not on PATH" in _output(result)

    def test_props_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def canned_props(serial: str) -> adb.AdbPropsResult:
            assert serial == "emulator-5554"
            return adb.parse_getprop(GETPROP_OUTPUT_BRACKETED)

        monkeypatch.setattr(mobile_cli, "inspect_device", canned_props)
        result = runner.invoke(app, ["mobile", "props", "emulator-5554", "--json"])
        assert result.exit_code == 0
        payload = _payload(result)
        assert payload["props"]["ro.build.version.release"] == "14"

    def test_packages_table_and_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            mobile_cli, "list_packages", lambda serial: adb.parse_packages(PACKAGES_OUTPUT)
        )
        table = runner.invoke(app, ["mobile", "packages", "emulator-5554"])
        assert table.exit_code == 0
        assert "com.example.paid" in _output(table)
        payload = _payload(runner.invoke(app, ["mobile", "packages", "emulator-5554", "--json"]))
        assert payload["count"] == 4

    def test_processes_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            mobile_cli,
            "list_processes",
            lambda serial: adb.parse_processes(PROCESSES_OUTPUT_MODERN),
        )
        result = runner.invoke(app, ["mobile", "processes", "emulator-5554"])
        assert result.exit_code == 0
        text = _output(result)
        assert "12345" in text
        assert "com.example.notes" in text
        assert "evidence: adb.ps" in text

    def test_install_requires_yes(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04")
        result = runner.invoke(app, ["mobile", "install", "emulator-5554", str(apk)])
        assert result.exit_code == 2
        assert "requires confirm=True" in _output(result)

    def test_install_with_yes_records_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04payload")
        seen: dict = {}

        def canned_install(serial: str, apk_path: str, *, confirm: bool) -> adb.AdbInstallResult:
            seen["serial"] = serial
            seen["confirm"] = confirm
            return adb.install_apk(
                serial, apk_path, confirm=confirm, runner=FakeRunner(FakeOutcome(0, "Success", ""))
            )

        monkeypatch.setattr(mobile_cli, "install_apk", canned_install)
        result = runner.invoke(app, ["mobile", "install", "emulator-5554", str(apk), "--yes"])
        assert result.exit_code == 0
        assert seen == {"serial": "emulator-5554", "confirm": True}
        assert "evidence: adb.install" in _output(result)


def _writing_runner(payload: bytes):
    """A runner stand-in that writes the bugreport target adb was handed."""

    def runner(command: tuple[str, ...], **kwargs: object):
        Path(command[-1]).write_bytes(payload)
        return FakeOutcome(0, "written", "")

    return runner


class TestCliScreencapBugreport:
    """The two file-writing commands through monkeypatched wrappers."""

    def test_screencap_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "shot.png"

        def canned_screencap(serial: str, out: str) -> adb.AdbScreencapResult:
            assert (serial, out) == ("emulator-5554", str(target))
            return adb.screencap(
                serial, out, runner=FakeRunner(FakeOutcome(0, PNG_MAGIC + b"body", b""))
            )

        monkeypatch.setattr(mobile_cli, "screencap", canned_screencap)
        result = runner.invoke(
            app, ["mobile", "screencap", "emulator-5554", str(target), "--json"]
        )
        assert result.exit_code == 0
        payload = _payload(result)
        assert payload["is_png"] is True

    def test_bugreport_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def canned_bugreport(serial: str, outdir: str) -> adb.AdbBugreportResult:
            assert (serial, outdir) == ("emulator-5554", str(tmp_path))
            return adb.bugreport(serial, outdir, runner=_writing_runner(b"PK zip"))

        monkeypatch.setattr(mobile_cli, "bugreport", canned_bugreport)
        result = runner.invoke(
            app, ["mobile", "bugreport", "emulator-5554", str(tmp_path), "--json"]
        )
        assert result.exit_code == 0
        payload = _payload(result)
        assert payload["size"] == len(b"PK zip")


class TestMcpTool:
    """``codevanta_adb`` wiring through monkeypatched wrappers."""

    def test_devices_action(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ext_mobile, "list_devices", _devices_result)
        payload = tools.codevanta_adb("devices")
        assert payload["action"] == "devices"
        assert payload["count"] == 3
        assert payload["evidence"]["source"] == "adb.devices"

    def test_device_actions_forward_the_serial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def canned_props(serial: str) -> adb.AdbPropsResult:
            seen.append(serial)
            return adb.parse_getprop(GETPROP_OUTPUT_BRACKETED)

        def canned_packages(serial: str) -> adb.AdbPackagesResult:
            seen.append(serial)
            return adb.parse_packages(PACKAGES_OUTPUT)

        def canned_processes(serial: str) -> adb.AdbProcessesResult:
            seen.append(serial)
            return adb.parse_processes(PROCESSES_OUTPUT_MODERN)

        monkeypatch.setattr(ext_mobile, "inspect_device", canned_props)
        monkeypatch.setattr(ext_mobile, "list_packages", canned_packages)
        monkeypatch.setattr(ext_mobile, "list_processes", canned_processes)
        assert tools.codevanta_adb("props", "emulator-5554")["action"] == "props"
        assert tools.codevanta_adb("packages", "emulator-5554")["count"] == 4
        assert tools.codevanta_adb("processes", "emulator-5554")["count"] == 3
        assert seen == ["emulator-5554", "emulator-5554", "emulator-5554"]

    def test_unknown_action_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="unknown action"):
            tools.codevanta_adb("shell")

    def test_missing_device_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="requires a device serial"):
            tools.codevanta_adb("props")
        with pytest.raises(AnalysisError, match="requires a device serial"):
            tools.codevanta_adb("packages", "   ")

    def test_adb_absent_surfaces_the_typed_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse() -> adb.AdbDevicesResult:
            raise AnalysisError(adb.ADB_MISSING_MESSAGE)

        monkeypatch.setattr(ext_mobile, "list_devices", refuse)
        with pytest.raises(AnalysisError, match="adb is not on PATH"):
            tools.codevanta_adb("devices")


requires_adb = pytest.mark.skipif(
    shutil.which("adb") is None, reason="adb is not installed on this machine"
)


@requires_adb
class TestLiveAdb:
    """The only tests that touch a real adb; skipped everywhere else."""

    def test_live_devices_round_trip(self) -> None:
        result = adb.list_devices()
        assert json.dumps(result.to_dict())
        assert result.evidence.source == "adb.devices"

    def test_live_props_round_trip(self) -> None:
        listing = adb.list_devices()
        device = next((d for d in listing.devices if d.state == "device"), None)
        if device is None:
            pytest.skip("no device in 'device' state attached")
        result = adb.inspect_device(device.serial)
        assert result.props
        assert json.dumps(result.to_dict())









