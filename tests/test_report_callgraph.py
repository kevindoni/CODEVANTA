"""Tests for the optional call graph embedded in the analysis report.

Covered here:

* ``build_report`` omits the ``callgraph`` key unless asked for it;
* ``build_report(..., include_callgraph=True)`` adds a bounded graph payload
  (``nodes`` / ``edges`` / ``truncated``) and forwards ``functions`` plus the
  1000 node / 5000 edge ceilings to ``build_call_graph``;
* the analysis layer is imported lazily, never at ``codevanta.core.report``
  import time;
* ``codevanta analyze --callgraph --output`` writes JSON that contains the graph
  and prints a dim node/edge/truncation summary.

The ELF64 samples are assembled byte-by-byte with :mod:`struct` inside this
module, so the tests are self-contained and never touch real binaries.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.core.report import (
    REPORT_MAX_CALLGRAPH_EDGES,
    REPORT_MAX_CALLGRAPH_FUNCTIONS,
    build_report,
)

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: ``a``: call 0x401010 ; ret -- then 10 nops -- then ``b``: call 0x401000 ; ret.
#: Two direct calls, each attributed to a discovered candidate.
CALL_CODE = bytes.fromhex("e80b000000c3") + b"\x90" * 10 + bytes.fromhex("e8fbffffffc3")


def _align(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = _align(text_offset + len(code), 8)
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        text_address,  # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        3,             # e_shnum (null, .text, .shstrtab)
        2,             # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,             # sh_name -> ".text"
        1,             # sh_type = SHT_PROGBITS
        6,             # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,  # sh_addr
        text_offset,   # sh_offset
        len(code),     # sh_size
        0,             # sh_link
        0,             # sh_info
        16,            # sh_addralign
        0,             # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                 # sh_name -> ".shstrtab"
        3,                 # sh_type = SHT_STRTAB
        0,                 # sh_flags
        0,                 # sh_addr
        shstrtab_offset,   # sh_offset
        len(shstrtab),     # sh_size
        0,                 # sh_link
        0,                 # sh_info
        1,                 # sh_addralign
        0,                 # sh_entsize
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    # The 64 bytes at ``shoff`` stay zero: that is the SHT_NULL section header.
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def _calls_sample(tmp_path: Path) -> Path:
    """Return a sample ELF64 whose ``.text`` contains two direct calls."""
    return _write_elf64(tmp_path / "calls.bin", CALL_CODE)


# ---- build_report -----------------------------------------------------------


def test_default_report_has_no_callgraph_key(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)

    report = build_report(sample)

    assert "callgraph" not in report
    assert set(report) == {"provenance", "binary", "functions", "strings", "disassembly"}


def test_explicit_false_omits_callgraph_key(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)

    report = build_report(sample, include_callgraph=False)

    assert "callgraph" not in report


def test_include_callgraph_adds_nodes_edges_and_truncated(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)

    graph = build_report(sample, include_callgraph=True)["callgraph"]

    assert set(graph) >= {"nodes", "edges", "truncated"}
    assert graph["edges"], "the sample has two direct calls"
    assert graph["node_count"] == len(graph["nodes"])
    assert graph["edge_count"] == len(graph["edges"])
    assert isinstance(graph["truncated"], bool)
    for edge in graph["edges"]:
        assert {"source", "target", "from_address", "label"} <= set(edge)


def test_report_callgraph_is_bounded(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)

    graph = build_report(sample, include_callgraph=True)["callgraph"]

    assert REPORT_MAX_CALLGRAPH_FUNCTIONS == 1000
    assert REPORT_MAX_CALLGRAPH_EDGES == 5000
    assert graph["node_count"] <= REPORT_MAX_CALLGRAPH_FUNCTIONS
    assert graph["edge_count"] <= REPORT_MAX_CALLGRAPH_EDGES


def test_callgraph_flag_does_not_change_the_rest_of_the_report(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)

    plain = build_report(sample)
    with_graph = build_report(sample, include_callgraph=True)

    assert set(with_graph) == set(plain) | {"callgraph"}
    # ``provenance`` carries a wall-clock timestamp, so compare everything else.
    for key in set(plain) - {"provenance"}:
        assert with_graph[key] == plain[key]


def test_report_forwards_candidates_and_bounds_to_build_call_graph(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = _calls_sample(tmp_path)
    calls: list[dict[str, Any]] = []

    class _StubGraph:
        """Stand-in for :class:`codevanta.analysis.callgraph.CallGraph`."""

        def to_dict(self) -> dict[str, Any]:
            return {"nodes": [], "edges": [], "truncated": True}

    def _fake_build(path: Any, info: Any, **kwargs: Any) -> _StubGraph:
        calls.append({"path": path, "info": info, **kwargs})
        return _StubGraph()

    # The lazy import resolves this attribute at call time, so patching the
    # module attribute is enough -- the analysis layer need not be imported here.
    monkeypatch.setattr("codevanta.analysis.callgraph.build_call_graph", _fake_build)

    report = build_report(sample, include_callgraph=True)

    assert report["callgraph"] == {"nodes": [], "edges": [], "truncated": True}
    assert len(calls) == 1
    assert calls[0]["max_functions"] == 1000
    assert calls[0]["max_edges"] == 5000
    assert calls[0]["functions"], "the report's own candidates are reused"

    build_report(sample, include_callgraph=False)
    assert len(calls) == 1, "no graph is built without the flag"


def test_core_report_does_not_import_analysis_at_import_time() -> None:
    src_dir = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_dir) + os.pathsep + env.get("PYTHONPATH", "")
    script = (
        "import sys\n"
        "import codevanta.core.report\n"
        "eager = sorted(m for m in sys.modules if m.startswith('codevanta.analysis'))\n"
        "print(','.join(eager))\n"
    )

    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "", "core must not import the analysis layer eagerly"


# ---- CLI --------------------------------------------------------------------


def test_analyze_without_flag_writes_report_without_callgraph(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)
    target = tmp_path / "report_plain.json"

    result = runner.invoke(app, ["analyze", str(sample), "--output", str(target)])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert "callgraph" not in payload
    assert "callgraph:" not in result.stdout


def test_analyze_callgraph_output_writes_json_with_callgraph(tmp_path: Path) -> None:
    sample = _calls_sample(tmp_path)
    target = tmp_path / "report_graph.json"

    result = runner.invoke(
        app, ["analyze", str(sample), "--callgraph", "--output", str(target)]
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(target.read_text(encoding="utf-8"))
    graph = payload["callgraph"]
    assert graph["node_count"] == len(graph["nodes"])
    assert graph["edge_count"] == len(graph["edges"])
    assert isinstance(graph["truncated"], bool)
    assert graph["edges"], "the sample has two direct calls"
    # Dim summary: node count, edge count and truncation state.
    assert "callgraph:" in result.stdout
    assert f"{graph['node_count']} nodes" in result.stdout
    assert f"{graph['edge_count']} edges" in result.stdout
    assert "truncated:" in result.stdout


def test_analyze_callgraph_stdout_mentions_callgraph(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setenv("COLUMNS", "400")
    sample = _calls_sample(tmp_path)

    result = runner.invoke(app, ["analyze", str(sample), "--callgraph"])

    assert result.exit_code == 0, result.stdout
    assert '"callgraph"' in result.stdout
    assert '"node_count"' in result.stdout


def test_analyze_callgraph_on_header_only_elf(tmp_path: Path) -> None:
    # A header-only ELF64 (no sections, no entry point) still yields a bounded
    # graph payload rather than an error.
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    sample = tmp_path / "header_only.bin"
    sample.write_bytes(header)
    target = tmp_path / "report_header.json"

    result = runner.invoke(
        app, ["analyze", str(sample), "--callgraph", "--output", str(target)]
    )

    assert result.exit_code == 0, result.stdout
    graph = json.loads(target.read_text(encoding="utf-8"))["callgraph"]
    assert set(graph) >= {"nodes", "edges", "truncated"}
    assert isinstance(graph["truncated"], bool)
    assert "truncated:" in result.stdout
