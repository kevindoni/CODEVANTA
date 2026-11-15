"""MCP expose-lane tool tests (codevanta_emulate / codevanta_wasm / codevanta_types).

All fixtures are hand-built files written to ``tmp_path`` -- no real
binaries, no network. Unicorn is never executed (the availability test
patches ``emulate.EMULATOR_AVAILABLE`` off, and every other emulate case
raises before the emulator starts) and wabt is never executed (the tests
inject ``_FakeRunner`` / ``which`` stand-ins into the bridge's documented
seams). Malformed cases prove the typed
:class:`~codevanta.core.report.AnalysisError`, and the registration tests
prove the three tools are listed by the MCP server with stable schemas.
"""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from codevanta.analysis import emulate, wabt_bridge
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

#: Virtual address of .text in the hand-built ELF64 samples.
TEXT_VA = 0x401000

#: ``mov eax, 42; ret`` -- the return-value probe from tests/test_emulate.py.
CODE_RET42 = bytes.fromhex("b82a000000c3")

#: ``push rbp; mov rbp, rsp; ret`` -- no argument reads, no return write.
CODE_PROLOGUE = bytes.fromhex("554889e5c3")

#: ``mov rax, qword ptr [rdi]; ret`` -- a pointer deref of a0, then a 64-bit return.
CODE_DEREF = bytes.fromhex("488b07c3")

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: Canned ``wasm-objdump -d`` transcript (same shape as tests/test_bridges.py).
WASM_OBJDUMP_OUTPUT = """\
calc.wasm:\tfile format wasm 0x1

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

#: Canned ``wasm-validate`` stderr for a module that fails validation.
WASM_VALIDATE_ERR = """\
bad.wasm:0000021: error: unexpected end of section or function (at offset 0x21)
bad.wasm:0000030: error: length out of bounds (at offset 0x30)
usage: wasm-validate [options] filename
"""


def write_elf64_with_text(path: Path, code: bytes, *, entry: int = TEXT_VA) -> Path:
    """Write a minimal ELF64 with one executable ``.text`` section at ``entry``."""
    shstr = _SHSTRTAB
    off_shstr = _TEXT_OFFSET + len(code)
    off_sh = off_shstr + len(shstr)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, off_sh, 0, 64, 56, 0, 64, 3, 2
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 6, entry,
        _TEXT_OFFSET, len(code), 0, 0, 16, 0,
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", SHT_STRTAB, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(off_sh)
    blob[0:64] = header
    blob[_TEXT_OFFSET:_TEXT_OFFSET + len(code)] = code
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + str_section
    path.write_bytes(blob)
    return path


class FakeRunner:
    """``subprocess.run`` stand-in returning a canned outcome (no wabt run)."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Any, **_kwargs: Any) -> FakeRunner:
        self.commands.append(tuple(command))
        return self


# ---- codevanta_emulate ------------------------------------------------------


def test_emulate_reports_an_unavailable_emulator_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without unicorn the run is an honest ``unsupported`` result, not a crash."""
    monkeypatch.setattr(emulate, "EMULATOR_AVAILABLE", False)
    sample = write_elf64_with_text(tmp_path / "ret42.bin", CODE_RET42)

    payload = tools.codevanta_emulate(str(sample), TEXT_VA)

    assert payload["stopped_reason"] == "unsupported"
    assert payload["instructions"] == 0
    assert payload["emulator"]["available"] is False
    assert payload["emulator"]["status"] == emulate.emulator_status()
    assert payload["path"] == str(sample)
    assert json.loads(json.dumps(payload)) == payload


def test_emulate_missing_file_is_the_exact_typed_error(tmp_path: Path) -> None:
    missing = tmp_path / "no_such.bin"
    with pytest.raises(AnalysisError) as excinfo:
        tools.codevanta_emulate(str(missing), TEXT_VA)
    assert str(excinfo.value) == f"file not found: {missing}"


def test_emulate_rejects_an_out_of_range_budget(tmp_path: Path) -> None:
    """Budget validation happens before the emulator exists, so it is exact."""
    sample = write_elf64_with_text(tmp_path / "ret42.bin", CODE_RET42)
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.codevanta_emulate(str(sample), TEXT_VA, max_instructions=0)
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.codevanta_emulate(
            str(sample), TEXT_VA, max_instructions=emulate.MAX_MAX_INSTRUCTIONS + 1
        )


def test_emulate_surfaces_an_unreadable_binary_as_a_typed_error(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(b"this is not an image at all")
    with pytest.raises(AnalysisError, match="cannot load"):
        tools.codevanta_emulate(str(garbage), TEXT_VA)


# ---- codevanta_wasm ---------------------------------------------------------


def _wasm_sample(tmp_path: Path) -> Path:
    sample = tmp_path / "sample.wasm"
    sample.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return sample


def test_wasm_validate_reports_a_valid_module(tmp_path: Path) -> None:
    runner = FakeRunner(returncode=0)
    sample = _wasm_sample(tmp_path)

    payload = tools.codevanta_wasm(str(sample), runner=runner, which=lambda name: "x")

    assert payload["valid"] is True
    assert payload["errors"] == []
    assert payload["mode"] == "validate"
    assert payload["evidence"]["source"] == wabt_bridge.EVIDENCE_SOURCE
    assert isinstance(payload["wabt_available"], bool)
    assert runner.commands == [("wasm-validate", str(sample))]
    assert json.loads(json.dumps(payload)) == payload


def test_wasm_validate_reports_module_errors_as_a_result(tmp_path: Path) -> None:
    """A module that FAILS validation is a verdict, not a tool failure."""
    runner = FakeRunner(returncode=1, stderr=WASM_VALIDATE_ERR)
    sample = _wasm_sample(tmp_path)

    payload = tools.codevanta_wasm(str(sample), runner=runner, which=lambda name: "x")

    assert payload["valid"] is False
    assert len(payload["errors"]) == 2
    assert "unexpected end of section or function" in payload["errors"][0]


def test_wasm_objdump_parses_sections_and_instructions(tmp_path: Path) -> None:
    runner = FakeRunner(returncode=0, stdout=WASM_OBJDUMP_OUTPUT)
    sample = _wasm_sample(tmp_path)

    payload = tools.codevanta_wasm(
        str(sample), mode="objdump", runner=runner, which=lambda name: "x"
    )

    assert payload["mode"] == "objdump"
    assert [section["name"] for section in payload["sections"]] == [
        "Type", "Function", "Code",
    ]
    assert payload["instructions"][0] == {
        "offset": 0xD, "bytes": "41 01", "text": "i32.const 1",
    }
    assert payload["truncated"] is False
    assert runner.commands == [("wasm-objdump", "-d", str(sample))]


def test_wasm_reports_a_missing_wabt_as_the_typed_error(tmp_path: Path) -> None:
    sample = _wasm_sample(tmp_path)
    with pytest.raises(AnalysisError, match="wabt is not on PATH"):
        tools.codevanta_wasm(str(sample), which=lambda name: None)


def test_wasm_missing_file_is_the_exact_typed_error(tmp_path: Path) -> None:
    missing = tmp_path / "no_such.wasm"
    with pytest.raises(AnalysisError) as excinfo:
        tools.codevanta_wasm(str(missing))
    assert str(excinfo.value) == f"file not found: {missing}"


def test_wasm_rejects_an_unknown_mode(tmp_path: Path) -> None:
    sample = _wasm_sample(tmp_path)
    with pytest.raises(AnalysisError, match="mode must be one of"):
        tools.codevanta_wasm(str(sample), mode="decompile")


def test_wasm_surfaces_a_runner_failure_as_a_typed_error(tmp_path: Path) -> None:
    runner = FakeRunner(returncode=2, stderr="boom")
    sample = _wasm_sample(tmp_path)
    with pytest.raises(AnalysisError, match="exited with code 2"):
        tools.codevanta_wasm(str(sample), runner=runner, which=lambda name: "x")


# ---- codevanta_types --------------------------------------------------------


def test_types_infers_pointer_argument_and_return(tmp_path: Path) -> None:
    sample = write_elf64_with_text(tmp_path / "deref.bin", CODE_DEREF)

    payload = tools.codevanta_types(str(sample), TEXT_VA)

    assert payload["address"] == f"0x{TEXT_VA:x}"
    assert payload["pointer_width"] == 8
    assert payload["instruction_count"] == 2
    (argument,) = payload["arguments"]
    assert argument["register"] == "rdi"
    assert argument["name"] == "a0"
    assert argument["c_type"] == "uint64_t *"
    assert "mov" in argument["evidence_note"]
    assert argument["confidence"] == "medium"
    assert payload["return_type"]["c_type"] == "uint64_t"
    assert payload["return_type"]["confidence"] == "medium"
    assert payload["evidence"]["source"] == "mcp.expose"
    assert json.loads(json.dumps(payload)) == payload


def test_types_reports_void_when_nothing_is_known(tmp_path: Path) -> None:
    sample = write_elf64_with_text(tmp_path / "prologue.bin", CODE_PROLOGUE)

    payload = tools.codevanta_types(str(sample), TEXT_VA)

    assert payload["arguments"] == []
    assert payload["return_type"]["c_type"] == "void"
    assert payload["return_type"]["confidence"] == "low"
    assert payload["truncated"] is False


def test_types_missing_file_is_the_exact_typed_error(tmp_path: Path) -> None:
    missing = tmp_path / "no_such.bin"
    with pytest.raises(AnalysisError) as excinfo:
        tools.codevanta_types(str(missing), TEXT_VA)
    assert str(excinfo.value) == f"file not found: {missing}"


def test_types_rejects_a_non_executable_address(tmp_path: Path) -> None:
    sample = write_elf64_with_text(tmp_path / "deref.bin", CODE_DEREF)
    with pytest.raises(AnalysisError, match="not inside an executable section"):
        tools.codevanta_types(str(sample), 0x999000)


def test_types_rejects_an_out_of_range_window(tmp_path: Path) -> None:
    sample = write_elf64_with_text(tmp_path / "deref.bin", CODE_DEREF)
    with pytest.raises(AnalysisError, match="max_instructions must be between"):
        tools.codevanta_types(str(sample), TEXT_VA, max_instructions=0)


def test_types_rejects_an_unknown_abi(tmp_path: Path) -> None:
    sample = write_elf64_with_text(tmp_path / "deref.bin", CODE_DEREF)
    with pytest.raises(AnalysisError, match="unknown ABI"):
        tools.codevanta_types(str(sample), TEXT_VA, abi="msdos")


def test_types_surfaces_an_unreadable_binary_as_a_typed_error(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(b"neither elf nor pe")
    with pytest.raises(AnalysisError, match="cannot load"):
        tools.codevanta_types(str(garbage), TEXT_VA)


# ---- registration (server wiring) ------------------------------------------


def _listed_tools() -> dict[str, Any]:
    return {tool.name: tool for tool in asyncio.run(build_server().list_tools())}


def test_expose_tools_are_registered_with_descriptions() -> None:
    listed = _listed_tools()
    for name, fragment in (
        ("codevanta_emulate", "Emulate one function"),
        ("codevanta_wasm", "WebAssembly"),
        ("codevanta_types", "Infer the C argument and return types"),
    ):
        assert name in listed
        assert fragment in listed[name].description


def test_expose_tools_have_stable_schemas() -> None:
    listed = _listed_tools()

    emulate_schema = listed["codevanta_emulate"].input_schema
    assert emulate_schema["required"] == ["path", "address"]
    assert set(emulate_schema["properties"]) == {
        "path", "address", "initial_registers", "max_instructions", "stack_size",
    }

    wasm_schema = listed["codevanta_wasm"].input_schema
    assert wasm_schema["required"] == ["path"]
    assert set(wasm_schema["properties"]) == {"path", "mode", "timeout", "out_dir"}
    assert wasm_schema["properties"]["mode"]["enum"] == ["validate", "objdump"]
    assert wasm_schema["properties"]["mode"]["default"] == "validate"

    types_schema = listed["codevanta_types"].input_schema
    assert types_schema["required"] == ["path", "address"]
    assert set(types_schema["properties"]) == {
        "path", "address", "abi", "max_instructions",
    }


@pytest.mark.parametrize("tool_name", [
    "codevanta_emulate",
    "codevanta_wasm",
    "codevanta_types",
])
def test_server_call_tool_translates_typed_errors(
    tool_name: str, tmp_path: Path
) -> None:
    """The wrapper blocks translate AnalysisError into ToolError, keeping the text."""
    arguments: dict[str, Any] = {"path": str(tmp_path / "missing.bin")}
    if tool_name in ("codevanta_emulate", "codevanta_types"):
        arguments["address"] = TEXT_VA
    with pytest.raises(ToolError, match="file not found"):
        asyncio.run(build_server().call_tool(tool_name, arguments))

