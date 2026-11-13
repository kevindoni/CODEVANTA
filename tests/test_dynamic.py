"""Tests for the dynamic provider layer: probing, script generation, argv.

Nothing here runs gdb or Frida, or needs either to be installed: the whole
contract of :mod:`codevanta.analysis.dynamic` is that a missing debugger degrades
into an ``available=False`` record with a reason, while script generation stays a
pure, deterministic function of its inputs. The probes are therefore exercised
with ``shutil.which``/``importlib.util.find_spec`` monkeypatched, so the tests
mean the same thing on a machine that has both tools and on one that has neither.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import dynamic
from codevanta.analysis.dynamic import (
    BACKTRACE_DEPTH,
    DEFAULT_MAX_HITS,
    MAX_MAX_HITS,
    PROVIDERS,
    SCRIPT_FILE_NAMES,
    DynamicAvailability,
    DynamicScript,
    attach_command,
    available_backends,
    build_frida_script,
    build_gdb_script,
    provider_status,
    script_file_name,
)
from codevanta.core.loader import BinaryInfo, SectionInfo
from codevanta.core.report import AnalysisError

TEXT_VA = 0x401000
IMAGE_BASE = 0x400000


def _info(*, architecture: str = "x86_64", image_base: int = IMAGE_BASE) -> BinaryInfo:
    """Return hand-built ELF metadata with one executable ``.text`` section."""
    return BinaryInfo(
        path=Path("sample.bin"),
        format="ELF",
        architecture=architecture,
        bitness=64,
        endianness="little",
        entry_point=TEXT_VA,
        image_base=image_base,
        sha256="0" * 64,
        file_size=4096,
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=TEXT_VA,
                size=0x100,
                offset=0x1000,
                raw_size=0x100,
                is_executable=True,
            ),
            SectionInfo(
                name=".data",
                virtual_address=0x402000,
                size=0x100,
                offset=0x2000,
                raw_size=0x100,
            ),
        ],
    )


# --------------------------------------------------------------------------- #
# Availability probing
# --------------------------------------------------------------------------- #


def test_available_backends_reports_gdb_then_frida() -> None:
    backends = available_backends()
    assert [backend.name for backend in backends] == list(PROVIDERS)
    assert PROVIDERS == ("gdb", "frida")


def test_availability_always_explains_itself_and_is_json_safe() -> None:
    for backend in available_backends():
        assert isinstance(backend, DynamicAvailability)
        assert backend.reason.strip(), backend.reason
        assert isinstance(backend.available, bool)
        # Probing a version would mean executing the provider, which we refuse.
        assert backend.version is None
        assert json.loads(json.dumps(backend.to_dict()))["name"] == backend.name


def test_gdb_probe_reports_a_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: None)
    status = provider_status("gdb")
    assert status.available is False
    assert "not on PATH" in status.reason
    assert "install" in status.reason
    assert status.requires == ("gdb",)


def test_gdb_probe_reports_the_binary_it_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: "/usr/bin/gdb")
    status = provider_status("gdb")
    assert status.available is True
    assert "/usr/bin/gdb" in status.reason


def test_frida_probe_names_both_missing_pieces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: None)
    monkeypatch.setattr(dynamic.importlib.util, "find_spec", lambda name: None)
    status = provider_status("frida")
    assert status.available is False
    assert "frida CLI" in status.reason
    assert "python bindings" in status.reason
    assert status.requires == ("frida", "frida-tools")


def test_frida_probe_is_available_when_cli_and_bindings_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: "/usr/local/bin/frida")
    monkeypatch.setattr(dynamic.importlib.util, "find_spec", lambda name: object())
    status = provider_status("frida")
    assert status.available is True
    assert "/usr/local/bin/frida" in status.reason


def test_frida_probe_reports_bindings_that_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: "/usr/local/bin/frida")
    monkeypatch.setattr(dynamic.importlib.util, "find_spec", lambda name: None)
    status = provider_status("frida")
    assert status.available is False
    assert "python bindings" in status.reason
    assert "frida CLI" not in status.reason


def test_frida_probe_reports_a_cli_that_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dynamic.shutil, "which", lambda name: None)
    monkeypatch.setattr(dynamic.importlib.util, "find_spec", lambda name: object())
    status = provider_status("frida")
    assert status.available is False
    assert "frida CLI" in status.reason
    assert "python bindings" not in status.reason


def test_provider_status_rejects_an_unknown_provider() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        provider_status("lldb")
    assert "lldb" in str(excinfo.value)
    assert "gdb" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# gdb script generation
# --------------------------------------------------------------------------- #


def test_gdb_script_is_a_non_interactive_command_list() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    assert isinstance(script, DynamicScript)
    assert script.provider == "gdb"
    text = script.text
    for marker in (
        "set pagination off",
        "set confirm off",
        "set disable-randomization on",
        "set breakpoint pending on",
        "break *0x401000",
        "commands",
        "  silent",
        '  printf "BACKTRACE\\n"',
        f"  bt {BACKTRACE_DEPTH}",
        "  continue",
        "run",
        "quit",
    ):
        assert marker in text, marker
    # Non-interactive means nothing waits for input at the end of the session.
    assert text.rstrip().endswith("quit")


def test_gdb_script_prints_a_hit_line_with_a_register_snapshot() -> None:
    text = build_gdb_script("sample.bin", _info(), [TEXT_VA]).text
    hit_line = next(line for line in text.splitlines() if '"HIT ' in line)
    assert '"HIT 0x401000 pc=%#lx sp=%#lx fp=%#lx ps=%#lx rip=%#lx' in hit_line
    assert "(unsigned long)$pc" in hit_line
    assert "(unsigned long)$rip" in hit_line


def test_gdb_script_sets_one_breakpoint_per_distinct_address() -> None:
    text = build_gdb_script("sample.bin", _info(), [TEXT_VA, TEXT_VA + 4, TEXT_VA]).text
    assert text.count("break *0x") == 2
    assert text.count('"HIT ') == 2
    assert "break *0x401000" in text
    assert "break *0x401004" in text


def test_gdb_script_is_deterministic() -> None:
    first = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    second = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    assert first.text == second.text
    assert first.entry_commands == second.entry_commands
    assert first.notes == second.notes


def test_gdb_script_respects_max_hits() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA], max_hits=3)
    assert "set $cv_hits = 0" in script.text
    assert "  if $cv_hits >= 3" in script.text
    assert 'printf "LIMIT 3 hits reached\\n"' in script.text
    assert any("after 3 hit(s)" in note for note in script.notes)


def test_gdb_script_default_hit_ceiling_is_the_documented_one() -> None:
    text = build_gdb_script("sample.bin", _info(), [TEXT_VA]).text
    assert f"  if $cv_hits >= {DEFAULT_MAX_HITS}" in text


def test_gdb_script_follows_forks_only_on_request() -> None:
    quiet = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    assert "set follow-fork-mode parent" in quiet.text
    following = build_gdb_script("sample.bin", _info(), [TEXT_VA], follow_forks=True)
    assert "set follow-fork-mode child" in following.text
    assert "set detach-on-fork on" in following.text
    assert quiet.text != following.text


def test_gdb_script_uses_the_binary_registers_per_architecture() -> None:
    assert "rip=%#lx" in build_gdb_script("s.bin", _info(), [TEXT_VA]).text
    arm = build_gdb_script("s.bin", _info(architecture="aarch64"), [TEXT_VA]).text
    assert "x0=%#lx" in arm
    assert "rip=%#lx" not in arm


def test_gdb_script_without_metadata_keeps_the_portable_registers_only() -> None:
    script = build_gdb_script("sample.bin", None, [TEXT_VA])
    assert "pc=%#lx" in script.text
    assert "rip=%#lx" not in script.text
    assert any("no binary metadata" in note for note in script.notes)


def test_gdb_script_entry_commands_are_the_setup_and_the_run() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA, TEXT_VA + 8])
    assert script.entry_commands[0] == "set pagination off"
    assert "break *0x401000" in script.entry_commands
    assert "break *0x401008" in script.entry_commands
    assert script.entry_commands[-1] == "run"
    assert all(command in script.text for command in script.entry_commands)
    assert json.loads(json.dumps(script.to_dict()))["provider"] == "gdb"


@pytest.mark.parametrize("addresses", [[], [TEXT_VA, "0x401000"], [0], [-8], [True]])
def test_gdb_script_rejects_bad_addresses(addresses: list[Any]) -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), addresses)
    assert "address" in str(excinfo.value).lower()


def test_gdb_script_rejects_an_address_outside_an_executable_section() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), [0x402000])
    message = str(excinfo.value)
    assert "0x402000" in message
    assert ".data" in message


def test_gdb_script_rejects_an_empty_address_iterable() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), iter(()))
    assert "empty" in str(excinfo.value)


@pytest.mark.parametrize("max_hits", [0, -1, MAX_MAX_HITS + 1, "8", 8.0, True])
def test_gdb_script_rejects_an_out_of_range_max_hits(max_hits: Any) -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), [TEXT_VA], max_hits=max_hits)
    assert "max_hits" in str(excinfo.value)


def test_gdb_script_rejects_a_non_boolean_follow_forks() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), [TEXT_VA], follow_forks="yes")  # type: ignore[arg-type]
    assert "follow_forks" in str(excinfo.value)


def test_gdb_script_rejects_an_empty_path() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("   ", _info(), [TEXT_VA])
    assert "path" in str(excinfo.value)


def test_gdb_script_rejects_a_text_address_list() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), "0x401000")
    assert "not text" in str(excinfo.value)


def test_gdb_script_rejects_a_non_iterable_address_argument() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_gdb_script("sample.bin", _info(), 5)  # type: ignore[arg-type]
    assert "iterable of ints" in str(excinfo.value)


def test_gdb_script_header_summarises_a_long_address_list() -> None:
    addresses = [TEXT_VA + offset for offset in range(12)]
    header = next(
        line
        for line in build_gdb_script("sample.bin", _info(), addresses).text.splitlines()
        if line.startswith("# breakpoints")
    )
    assert "12 (" in header
    assert "(+4 more)" in header


# --------------------------------------------------------------------------- #
# Frida script generation
# --------------------------------------------------------------------------- #


def test_frida_script_hooks_module_relative_offsets() -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA + 0x10], max_hits=5)
    assert script.provider == "frida"
    text = script.text
    assert "Module.getBaseAddress(MODULE_NAME)" in text
    assert 'Interceptor.attach(base.add(0x1010), makeHandler("0x401010"))' in text
    assert "var MAX_HITS = 5;" in text
    assert "var hits = 0;" in text
    assert "//   offset 0x1010 <- 0x401010" in text
    assert json.loads(json.dumps(script.to_dict()))["provider"] == "frida"


def test_frida_script_sends_bounded_json_messages() -> None:
    text = build_frida_script("sample.bin", _info(), [TEXT_VA]).text
    for marker in (
        "send({",
        "hit: hits,",
        "address: address,",
        "tid: Process.getCurrentThreadId(),",
        "args: values",
        'send({ event: "limit", hits: hits });',
        "detachAll();",
        "listener.detach();",
    ):
        assert marker in text, marker
    assert "// max hits    : 64" in text


def test_frida_script_notes_that_offsets_are_module_relative() -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA])
    assert any("module-relative" in note for note in script.notes)
    assert any("Module.getBaseAddress" in note for note in script.notes)
    assert any("never killed" in note for note in script.notes)


def test_frida_script_is_deterministic() -> None:
    first = build_frida_script("sample.bin", _info(), [TEXT_VA, TEXT_VA + 8])
    second = build_frida_script("sample.bin", _info(), [TEXT_VA, TEXT_VA + 8])
    assert first.text == second.text
    assert first.entry_commands == second.entry_commands


def test_frida_script_entry_commands_are_the_attach_expressions() -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA, TEXT_VA + 8])
    assert script.entry_commands == (
        'Interceptor.attach(base.add(0x1000), makeHandler("0x401000"))',
        'Interceptor.attach(base.add(0x1008), makeHandler("0x401008"))',
    )
    for command in script.entry_commands:
        assert command in script.text


def test_frida_script_requires_binary_metadata() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_frida_script("sample.bin", None, [TEXT_VA])
    assert "image base" in str(excinfo.value)


def test_frida_script_rejects_an_address_below_the_image_base() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_frida_script("sample.bin", _info(image_base=0x500000), [TEXT_VA])
    message = str(excinfo.value)
    assert "0x401000" in message and "below the image base" in message


@pytest.mark.parametrize("max_hits", [0, MAX_MAX_HITS + 1])
def test_frida_script_rejects_an_out_of_range_max_hits(max_hits: int) -> None:
    with pytest.raises(AnalysisError) as excinfo:
        build_frida_script("sample.bin", _info(), [TEXT_VA], max_hits=max_hits)
    assert "max_hits" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# attach_command
# --------------------------------------------------------------------------- #


def test_attach_command_for_gdb_is_the_batch_invocation() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    assert attach_command("gdb", "sample.bin", script) == (
        "gdb",
        "-q",
        "-batch",
        "-x",
        SCRIPT_FILE_NAMES["gdb"],
        "--args",
        "sample.bin",
    )


def test_attach_command_for_frida_launches_the_target() -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA])
    assert attach_command("frida", "sample.bin", script) == (
        "frida",
        "-l",
        SCRIPT_FILE_NAMES["frida"],
        "-f",
        "sample.bin",
    )


def test_attach_command_for_frida_can_target_a_pid() -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA])
    assert attach_command("frida", "sample.bin", script, pid=4242) == (
        "frida",
        "-l",
        SCRIPT_FILE_NAMES["frida"],
        "-p",
        "4242",
    )


def test_attach_command_is_a_tuple_of_plain_arguments() -> None:
    script = build_gdb_script("dir with space/sample.bin", _info(), [TEXT_VA])
    command = attach_command("gdb", "dir with space/sample.bin", script)
    assert isinstance(command, tuple)
    assert all(isinstance(part, str) for part in command)
    assert command[-1] == "dir with space/sample.bin"


def test_attach_command_rejects_a_pid_for_gdb() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("gdb", "sample.bin", script, pid=123)
    assert "pid" in str(excinfo.value)


@pytest.mark.parametrize("pid", [0, -5, "123", True])
def test_attach_command_rejects_a_bad_pid(pid: Any) -> None:
    script = build_frida_script("sample.bin", _info(), [TEXT_VA])
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("frida", "sample.bin", script, pid=pid)
    assert "pid" in str(excinfo.value)


def test_attach_command_rejects_an_unknown_provider() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("lldb", "sample.bin", script)
    assert "lldb" in str(excinfo.value)


def test_attach_command_rejects_a_script_from_another_provider() -> None:
    frida_script = build_frida_script("sample.bin", _info(), [TEXT_VA])
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("gdb", "sample.bin", frida_script)
    assert "frida" in str(excinfo.value)


def test_attach_command_rejects_an_empty_path() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("gdb", "", script)
    assert "path" in str(excinfo.value)


def test_attach_command_rejects_something_that_is_not_a_script() -> None:
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("gdb", "sample.bin", "run")  # type: ignore[arg-type]
    assert "DynamicScript" in str(excinfo.value)


def test_attach_command_rejects_an_empty_script() -> None:
    script = build_gdb_script("sample.bin", _info(), [TEXT_VA])
    blank = DynamicScript(
        provider="gdb",
        text="   \n",
        entry_commands=script.entry_commands,
        notes=script.notes,
    )
    with pytest.raises(AnalysisError) as excinfo:
        attach_command("gdb", "sample.bin", blank)
    assert "must not be empty" in str(excinfo.value)


def test_script_file_name_is_fixed_per_provider_and_validated() -> None:
    assert script_file_name("gdb") == SCRIPT_FILE_NAMES["gdb"]
    assert script_file_name("frida") == SCRIPT_FILE_NAMES["frida"]
    with pytest.raises(AnalysisError):
        script_file_name("windbg")
