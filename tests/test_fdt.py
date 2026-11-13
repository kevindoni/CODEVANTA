"""FDT (flattened devicetree) parser tests: synthetic blobs, byte by byte.

Every malformed case the parser detects has a test here: the blob is
crafted in-test from header + reservation block + structure block + strings
block, so each typed error path is reachable offline.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis import fdt as fdt_mod
from codevanta.analysis.fdt import parse_dtb, parse_dtb_file
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.mcp_server import ext_signal

runner_cli = CliRunner()

FDT_MAGIC = 0xD00DFEED


def u32(*values: int) -> bytes:
    return struct.pack(f">{len(values)}I", *values)


def pad4(data: bytes) -> bytes:
    return data + bytes((-len(data)) % 4)


DEFAULT_STRINGS = b"compatible\x00#address-cells\x00clock-frequency\x00reg\x00"
# offsets into DEFAULT_STRINGS: compatible=0, #address-cells=11, clock-frequency=26, reg=42


def begin_node(name: bytes) -> bytes:
    return u32(1) + pad4(name + b"\x00")


def prop(nameoff: int, value: bytes) -> bytes:
    return u32(3, len(value), nameoff) + pad4(value)


def default_body() -> bytes:
    """Root with two props, one child with one prop, one grandchild ignored."""
    body = begin_node(b"")  # root
    body += prop(0, b"codevanta,test")  # compatible
    body += prop(11, u32(2))  # #address-cells
    body += begin_node(b"uart0")
    body += prop(42, u32(0x1000))  # reg
    body += begin_node(b"fifo")
    body += prop(26, u32(16))  # clock-frequency (depth 2: never kept)
    body += u32(2)  # END_NODE fifo
    body += u32(2)  # END_NODE uart0
    body += u32(2)  # END_NODE root
    body += u32(9)  # FDT_END
    return body


def make_dtb(
    *,
    magic: int = FDT_MAGIC,
    version: int = 17,
    last_comp: int = 16,
    reservations: list[tuple[int, int]] | None = None,
    terminate_reservations: bool = True,
    body: bytes | None = None,
    strings: bytes | None = None,
    totalsize_delta: int = 0,
    header_overrides: dict[str, int] | None = None,
) -> bytes:
    """Assemble a synthetic devicetree blob with the classic layout."""
    if reservations is None:
        reservations = [(0x80000000, 0x1000)]
    if body is None:
        body = default_body()
    if strings is None:
        strings = DEFAULT_STRINGS
    rsv = b"".join(struct.pack(">QQ", address, size) for address, size in reservations)
    if terminate_reservations:
        rsv += struct.pack(">QQ", 0, 0)
    off_struct = 40 + len(rsv)
    off_strings = off_struct + len(body)
    totalsize = off_strings + len(strings) + totalsize_delta
    header = {
        "magic": magic,
        "totalsize": totalsize,
        "off_dt_struct": off_struct,
        "off_dt_strings": off_strings,
        "off_mem_rsvmap": 40,
        "version": version,
        "last_comp_version": last_comp,
        "boot_cpuid_phys": 0,
        "size_dt_strings": len(strings),
        "size_dt_struct": len(body),
    }
    header.update(header_overrides or {})
    fields = (
        header["magic"],
        header["totalsize"],
        header["off_dt_struct"],
        header["off_dt_strings"],
        header["off_mem_rsvmap"],
        header["version"],
        header["last_comp_version"],
        header["boot_cpuid_phys"],
        header["size_dt_strings"],
        header["size_dt_struct"],
    )
    return struct.pack(">10I", *fields) + rsv + body + strings


class TestParseDtbHappy:
    """Synthetic blob parses into the typed summary."""

    def test_root_properties_and_nodes(self) -> None:
        summary = parse_dtb(make_dtb())
        assert summary.version == 17
        assert summary.last_comp_version == 16
        assert summary.boot_cpuid_phys == 0
        assert summary.total_size == len(make_dtb())
        assert summary.strings_size == len(DEFAULT_STRINGS)
        assert summary.struct_size == len(default_body())
        assert summary.nodes == ("uart0",)
        assert summary.chosen_node == "root"
        assert [(p.name, p.to_dict()["value_ascii"]) for p in summary.properties] == [
            ("compatible", "codevanta,test"),
            ("#address-cells", "...."),
        ]
        assert summary.properties[1].to_dict()["value_hex"] == "00000002"
        assert summary.properties[1].truncated is False
        assert summary.evidence.source == "fdt.parse"
        assert summary.evidence.confidence is Confidence.HIGH

    def test_chosen_node_properties_and_grandchild_ignored(self) -> None:
        summary = parse_dtb(make_dtb(), node="uart0")
        assert summary.chosen_node == "uart0"
        assert [(p.name, p.to_dict()["value_hex"]) for p in summary.properties] == [
            ("reg", "00001000")
        ]

    def test_reservations(self) -> None:
        summary = parse_dtb(
            make_dtb(reservations=[(0x80000000, 0x1000), (0x40000000, 0x4000)])
        )
        assert len(summary.reservations) == 2
        assert summary.reservations[0].to_dict() == {"address": "0x80000000", "size": "0x1000"}
        assert summary.reservations_truncated is False

    def test_value_truncated_to_64_bytes(self) -> None:
        big_value = bytes(range(100))
        body = begin_node(b"") + prop(0, big_value) + u32(2) + u32(9)
        summary = parse_dtb(make_dtb(body=body))
        assert len(summary.properties) == 1
        prop0 = summary.properties[0]
        assert prop0.length == 100
        assert len(prop0.value) == 64
        assert prop0.truncated is True

    def test_empty_property_value(self) -> None:
        body = begin_node(b"") + prop(0, b"") + u32(2) + u32(9)
        summary = parse_dtb(make_dtb(body=body))
        assert summary.properties[0].length == 0
        assert summary.properties[0].to_dict()["value_hex"] == ""

    def test_nop_tokens_are_skipped(self) -> None:
        body = u32(4) + begin_node(b"") + u32(4) + prop(0, b"") + u32(4) + u32(2) + u32(9)
        summary = parse_dtb(make_dtb(body=body))
        assert [p.name for p in summary.properties] == ["compatible"]

    def test_to_dict_is_json_safe(self) -> None:
        payload = parse_dtb(make_dtb(), node="uart0").to_dict()
        roundtrip = json.loads(json.dumps(payload))
        assert roundtrip["nodes"] == ["uart0"]
        assert roundtrip["properties"][0]["name"] == "reg"
        assert roundtrip["evidence"]["source"] == "fdt.parse"


class TestParseDtbBounds:
    """Caps bound the walk; caps reached are warnings, not errors."""

    def test_prop_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fdt_mod, "MAX_PROPS", 2)
        body = begin_node(b"")
        for offset in range(4):
            body += prop(0, u32(offset))
        body += u32(2) + u32(9)
        summary = parse_dtb(make_dtb(body=body))
        assert len(summary.properties) == 2
        assert summary.props_truncated is True
        assert any("property limit" in w for w in summary.warnings)

    def test_node_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fdt_mod, "MAX_NODES", 2)
        body = begin_node(b"")
        for name in (b"n0", b"n1", b"n2", b"n3"):
            body += begin_node(name) + u32(2)
        body += u32(2) + u32(9)
        summary = parse_dtb(make_dtb(body=body))
        assert summary.nodes == ("n0", "n1")
        assert summary.nodes_truncated is True
        assert any("node limit" in w for w in summary.warnings)

    def test_reservation_cap_truncates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fdt_mod, "MAX_RESERVATIONS", 3)
        summary = parse_dtb(make_dtb(reservations=[(0x1000 + i, 0x100) for i in range(6)]))
        assert len(summary.reservations) == 3
        assert summary.reservations_truncated is True
        assert any("reservation limit" in w for w in summary.warnings)


class TestParseDtbMalformed:
    """Every malformed blob is a typed AnalysisError, never a bare exception."""

    def test_short_header(self) -> None:
        with pytest.raises(AnalysisError, match="header alone needs 40 bytes"):
            parse_dtb(make_dtb()[:30])

    def test_bad_magic(self) -> None:
        with pytest.raises(AnalysisError, match="bad devicetree magic"):
            parse_dtb(make_dtb(magic=0xDEADBEEF))

    def test_unsupported_compat_level(self) -> None:
        with pytest.raises(AnalysisError, match="unsupported devicetree compatibility"):
            parse_dtb(make_dtb(last_comp=2))

    def test_compat_above_version(self) -> None:
        with pytest.raises(AnalysisError, match="above its own version"):
            parse_dtb(make_dtb(version=16, last_comp=17))

    def test_totalsize_beyond_file(self) -> None:
        with pytest.raises(AnalysisError, match="truncated"):
            parse_dtb(make_dtb(totalsize_delta=64))

    def test_offset_outside_blob(self) -> None:
        with pytest.raises(AnalysisError, match="outside the blob"):
            parse_dtb(make_dtb(header_overrides={"off_dt_struct": 4}))

    def test_struct_block_runs_past_totalsize(self) -> None:
        with pytest.raises(AnalysisError, match="runs past the blob totalsize"):
            parse_dtb(make_dtb(header_overrides={"size_dt_struct": 10_000}))

    def test_empty_structure_block(self) -> None:
        with pytest.raises(AnalysisError, match="empty structure block"):
            parse_dtb(make_dtb(header_overrides={"size_dt_struct": 0}))

    def test_reservation_terminator_missing(self) -> None:
        with pytest.raises(AnalysisError, match="no \\(0, 0\\) terminator"):
            parse_dtb(make_dtb(terminate_reservations=False))

    def test_unknown_token(self) -> None:
        body = begin_node(b"") + u32(0xDEAD) + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="unknown structure-block token 0x0000dead"):
            parse_dtb(make_dtb(body=body))

    def test_prop_outside_any_node(self) -> None:
        body = prop(0, b"x") + begin_node(b"") + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="outside any node"):
            parse_dtb(make_dtb(body=body))

    def test_end_node_without_begin(self) -> None:
        body = u32(2) + begin_node(b"") + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="never began"):
            parse_dtb(make_dtb(body=body))

    def test_missing_fdt_end(self) -> None:
        body = begin_node(b"") + prop(0, b"") + u32(2)  # no FDT_END
        with pytest.raises(AnalysisError, match="no FDT_END"):
            parse_dtb(make_dtb(body=body))

    def test_unclosed_root_node(self) -> None:
        body = begin_node(b"") + prop(0, b"") + u32(9)
        with pytest.raises(AnalysisError, match="unclosed node"):
            parse_dtb(make_dtb(body=body))

    def test_node_name_without_nul(self) -> None:
        body = u32(1) + b"neverending-name"
        with pytest.raises(AnalysisError, match="no NUL terminator"):
            parse_dtb(make_dtb(body=body))

    def test_prop_header_truncated(self) -> None:
        body = begin_node(b"") + prop(0, b"ABCD") + u32(2) + u32(9)
        # Cut the structure block right after the PROP token: header unreadable.
        with pytest.raises(AnalysisError, match="inside a property header"):
            parse_dtb(make_dtb(body=body, header_overrides={"size_dt_struct": 16}))

    def test_prop_value_truncated(self) -> None:
        body = begin_node(b"") + prop(0, b"ABCD") + u32(2) + u32(9)
        # Cut the structure block after the PROP header, inside its value.
        with pytest.raises(AnalysisError, match="inside a property value"):
            parse_dtb(make_dtb(body=body, header_overrides={"size_dt_struct": 20}))

    def test_string_offset_out_of_range(self) -> None:
        body = begin_node(b"") + prop(900, b"") + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="outside the strings block"):
            parse_dtb(make_dtb(body=body))

    def test_string_without_terminator(self) -> None:
        strings = b"compatible"  # no NUL at all
        body = begin_node(b"") + prop(0, b"") + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="no NUL terminator"):
            parse_dtb(make_dtb(body=body, strings=strings))

    def test_non_utf8_property_name(self) -> None:
        strings = b"\xff\xfe\xfd\x00"
        body = begin_node(b"") + prop(0, b"") + u32(2) + u32(9)
        with pytest.raises(AnalysisError, match="not UTF-8"):
            parse_dtb(make_dtb(body=body, strings=strings))

    def test_unknown_node_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="not a top-level node"):
            parse_dtb(make_dtb(), node="ethernet0")

    def test_non_bytes_input_is_typed(self) -> None:
        with pytest.raises(AnalysisError, match="dtb data must be bytes"):
            parse_dtb("not bytes")  # type: ignore[arg-type]

    def test_blob_over_ceiling_is_typed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fdt_mod, "MAX_FILE_BYTES", 16)
        with pytest.raises(AnalysisError, match="ceiling"):
            parse_dtb(make_dtb())

    def test_memoryview_input_accepted(self) -> None:
        summary = parse_dtb(memoryview(make_dtb()))
        assert summary.nodes == ("uart0",)


class TestParseDtbFileCliMcp:
    """File entry, the top-level ``codevanta dtb`` command, and the MCP tool."""

    def _write(self, tmp_path: Path) -> Path:
        path = tmp_path / "board.dtb"
        path.write_bytes(make_dtb())
        return path

    def test_file_entry_and_errors(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        summary = parse_dtb_file(path, node="uart0")
        assert summary.chosen_node == "uart0"
        with pytest.raises(AnalysisError, match="not found"):
            parse_dtb_file(tmp_path / "absent.dtb")
        with pytest.raises(AnalysisError, match="path must be"):
            parse_dtb_file(42)  # type: ignore[arg-type]

    def test_cli_dtb_table(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        result = runner_cli.invoke(app, ["dtb", str(path)])
        assert result.exit_code == 0
        assert "devicetree" in result.stdout
        assert "uart0" in result.stdout
        assert "evidence: fdt.parse" in result.stdout

    def test_cli_dtb_node_and_json(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        result = runner_cli.invoke(app, ["dtb", str(path), "--node", "uart0", "--json"])
        assert result.exit_code == 0
        text = result.stdout
        payload = json.loads(text[text.index("{") : text.rindex("}") + 1])
        assert payload["chosen_node"] == "uart0"

    def test_cli_dtb_unknown_node_exits_two(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        result = runner_cli.invoke(app, ["dtb", str(path), "--node", "ethernet0"])
        assert result.exit_code == 2
        assert "not a top-level node" in result.stdout

    def test_cli_dtb_missing_file_exits_two(self, tmp_path: Path) -> None:
        result = runner_cli.invoke(app, ["dtb", str(tmp_path / "absent.dtb")])
        assert result.exit_code == 2
        assert "error:" in result.stdout

    def test_mcp_dtb(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        payload = ext_signal.codevanta_dtb(str(path), node="uart0")
        assert payload["chosen_node"] == "uart0"
        assert payload["properties"][0]["name"] == "reg"

    def test_mcp_dtb_typed_errors(self, tmp_path: Path) -> None:
        path = self._write(tmp_path)
        with pytest.raises(AnalysisError, match="not a top-level node"):
            ext_signal.codevanta_dtb(str(path), node="ethernet0")
        with pytest.raises(AnalysisError, match="non-empty string"):
            ext_signal.codevanta_dtb(str(path), node="  ")
        with pytest.raises(AnalysisError, match="non-empty string"):
            ext_signal.codevanta_dtb("")

    def test_tools_registration(self) -> None:
        from codevanta.mcp_server import tools

        for name in ("codevanta_signal_sr", "codevanta_uart_decode", "codevanta_dtb"):
            assert callable(getattr(tools, name))



