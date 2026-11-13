"""CLI tests for the phase 7 additions: ``symbolic``, ``dataflow``, ``plugins``
and ``evidence-bundle``.

All four commands sit in front of layers that already have their own tests
(``tests/test_symbolic.py``, ``tests/test_dataflow.py``,
``tests/test_plugins.py``, ``tests/test_evidence_bundle.py``); what is asserted
here is the wiring only: arguments, options, the text rendering, the ``--json``
payloads and the exit code of every refusal. The fixture is the ELF64 builder
copied from ``tests/test_cli_trace.py``, so the tests stay self-contained, and
no test executes anything on the host: ``symbolic`` replays branch decisions on
the emulator's private CPU, ``dataflow`` is a static pass, ``plugins run
metrics`` reads the repository sample through the public API, and
``evidence-bundle`` only hashes bytes and writes JSON.

``unicorn`` gates the exploration tests (they are skipped, not failed, when the
optional engine is missing), so the module starts passing the moment it is
installed.
"""

from __future__ import annotations

import faulthandler
import hashlib
import json
import re
import struct
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import emulate
from codevanta.analysis.evidence_bundle import read_bundle, verify_bundle
from codevanta.cli.main import app

runner = CliRunner()

#: Where the fixture's ``.text`` is mapped; the entry point names the same window.
TEXT_ADDRESS = 0x401000

#: ``cmp eax, 42`` / ``je +6`` / ``mov eax, 1`` / ``ret`` / ``mov eax, 2`` / ``ret``:
#: a two-way branch. With the ABI-default (zeroed) ``eax`` the comparison is
#: false, so the observed direction falls through and returns 1, and the seeded
#: opposite direction is taken and returns 2 -- one branch, two paths, two
#: returns. ``--set eax=42`` flips which side the observed direction takes.
BRANCH_CODE = (
    bytes.fromhex("83f82a")  # cmp eax, 42
    + bytes.fromhex("7406")  # je +6 (to the second ``mov eax, 2`` body)
    + bytes.fromhex("b801000000")  # mov eax, 1
    + b"\xc3"  # ret
    + bytes.fromhex("b802000000")  # mov eax, 2
    + b"\xc3"  # ret
)

#: ``mov eax, 42`` / ``add eax, 13`` / ``ret``: one constant definition and one
#: folded arithmetic definition, leaving ``rax = 0x37`` provably constant.
MOV_ADD_CODE = bytes.fromhex("b82a000000") + bytes.fromhex("83c00d") + b"\xc3"

#: ``(name, address)`` pairs of the fixture symbol table (the builder below
#: writes one global ``STT_FUNC`` per pair).
SYMBOLS = (("main", TEXT_ADDRESS),)

#: The repository sample ``plugins run metrics`` analyses end to end.
REPO_SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "elf64_text.bin"

#: Skip condition for the one optional dependency ``symbolic`` talks to.
needs_unicorn = pytest.mark.skipif(
    not emulate.EMULATOR_AVAILABLE, reason="the optional unicorn engine is not installed"
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def _faulthandler_stays_off() -> Iterator[None]:
    """Keep CPython's fault handler disabled for every test in this module.

    The emulation layer under ``symbolic`` disables ``faulthandler`` around
    ``emu_start`` and re-enabling it needs a real stderr file descriptor, which
    ``CliRunner`` replaces with an in-memory stream (same workaround as
    ``tests/test_cli_phase3.py``).
    """
    faulthandler.disable()
    yield


def _sample(tmp_path: Path, name: str, code: bytes) -> Path:
    """Write one fixture binary under ``tmp_path``."""
    return _write_elf64_with_symbols(tmp_path / name, code, SYMBOLS)


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``, keeping its layout."""
    return _ANSI_ESCAPE.sub("", text)


def _write_elf64_with_symbols(
    path: Path,
    code: bytes,
    symbols: Sequence[tuple[str, int]],
    *,
    text_address: int = TEXT_ADDRESS,
) -> Path:
    """Write a minimal ELF64 executable holding ``code`` in one ``.text``.

    ``.text`` is mapped at :data:`TEXT_ADDRESS` and ``e_entry`` points at it, so
    the entry point and an explicit address name the same window; ``symbols``
    appends one global ``STT_FUNC`` per ``(name, address)`` to an
    ``.symtab``/``.strtab`` pair. Copied verbatim from
    ``tests/test_cli_trace.py`` so every phase 7 test builds the same fixture
    shape the earlier CLI tests used.
    """
    if not code:
        raise ValueError("code must not be empty")
    shstrtab = b"\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00"
    names: list[bytes] = []
    offsets: list[int] = []
    cursor = 1
    for name, _ in symbols:
        offsets.append(cursor)
        encoded = name.encode() + b"\x00"
        names.append(encoded)
        cursor += len(encoded)
    strtab = b"\x00" + b"".join(names)
    entries = [bytes(24)]  # STN_UNDEF
    for index, (_, value) in enumerate(symbols):
        entries.append(
            struct.pack(
                "<IBBHQQ",
                offsets[index],
                0x12,  # STB_GLOBAL | STT_FUNC
                0,  # st_other
                1,  # st_shndx: .text
                value,  # st_value
                len(code),  # st_size
            )
        )
    symtab = b"".join(entries)
    text_offset = 0x40
    strtab_offset = text_offset + len(code)
    symtab_offset = strtab_offset + len(strtab)
    shstrtab_offset = symtab_offset + len(symtab)
    shoff = shstrtab_offset + len(shstrtab)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    sections = [
        bytes(64),  # SHT_NULL
        struct.pack(  # .text: SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
            "<IIQQQQIIQQ", 1, 1, 6, text_address, text_offset, len(code), 0, 0, 16, 0
        ),
        struct.pack(  # .strtab: SHT_STRTAB
            "<IIQQQQIIQQ", 7, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0
        ),
        struct.pack(  # .symtab: SHT_SYMTAB, link=.strtab, first global = 1
            "<IIQQQQIIQQ", 15, 2, 0, 0, symtab_offset, len(symtab), 2, 1, 8, 24
        ),
        struct.pack(  # .shstrtab: SHT_STRTAB
            "<IIQQQQIIQQ", 23, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
        ),
    ]
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        text_address,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        len(sections),  # e_shnum
        4,  # e_shstrndx
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[strtab_offset : strtab_offset + len(strtab)] = strtab
    blob[symtab_offset : symtab_offset + len(symtab)] = symtab
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob += b"".join(sections)
    path.write_bytes(bytes(blob))
    return path


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened.

    Flattening also survives Rich soft-wrapping long error lines, which splits
    a message across terminal-width boundaries.
    """
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(result: Result) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(result.stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _json_array(result: Result) -> list:
    """Return the parsed JSON array printed by a ``--json`` option."""
    text = _plain(result.stdout)
    return json.loads(text[text.index("[") : text.rindex("]") + 1])


def _table_rows(stdout: str, columns: int) -> list[list[str]]:
    """Return the cell lists of every data row in a Rich table."""
    rows: list[list[str]] = []
    for line in _plain(stdout).splitlines():
        stripped = line.strip()
        for bar in ("\u2502", "|"):
            if stripped.count(bar) != columns + 1:
                continue
            cells = [cell.strip() for cell in stripped.strip(bar).split(bar)]
            if len(cells) == columns:
                rows.append(cells)
            break
    return rows


def _path_rows(result: Result) -> list[list[str]]:
    """Return the data rows of the ``symbolic`` path table (header dropped)."""
    return [row for row in _table_rows(result.stdout, 5) if row[0].isdigit()]


def _definition_rows(result: Result) -> list[list[str]]:
    """Return the data rows of the ``dataflow`` definition table."""
    return [row for row in _table_rows(result.stdout, 5) if row[0].startswith("0x")]


# ---- symbolic: the two-way branch -------------------------------------------


@needs_unicorn
def test_symbolic_reports_both_sides_of_a_two_way_branch(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["symbolic", str(sample), hex(TEXT_ADDRESS)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    rows = _path_rows(result)
    assert len(rows) == 2, output  # one path per side of the branch
    # The observed side falls through (``je-``) and returns 1; the seeded side is
    # taken (``je+``), announces that its direction was forced, and returns 2.
    assert rows[0][1] == "je-", output
    assert rows[0][2] == "0x1", output
    assert rows[0][3] == "return", output
    assert rows[1][1] == "je+ (1 seeded)", output
    assert rows[1][2] == "0x2", output
    assert "complete: yes" in output, output
    assert "explorer: unicorn" in output, output
    # The seeded direction is an assumption, and the output says so.
    assert "warning:" in output, output
    assert "assumed feasible" in output, output


@needs_unicorn
def test_symbolic_json_reports_the_two_paths(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["symbolic", str(sample), hex(TEXT_ADDRESS), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["paths"] == 2
    assert payload["explorer"] == "unicorn"
    assert payload["address"] == f"0x{TEXT_ADDRESS:x}"
    assert payload["complete"] is True
    assert sorted(payload["return_values"]) == ["0x1", "0x2"]
    assert len(payload["entries"]) == 2
    observed = payload["entries"][0]["decisions"][0]
    seeded = payload["entries"][1]["decisions"][0]
    assert observed == {
        "address": f"0x{TEXT_ADDRESS + 3:x}",
        "mnemonic": "je",
        "taken": False,
        "target": f"0x{TEXT_ADDRESS + 5:x}",
        "basis": "observed",
        "note": "",
    }
    assert seeded["basis"] == "seeded"
    assert seeded["taken"] is True
    assert seeded["note"], "a seeded branch must record the seed it used"
    assert any("assumed feasible" in warning for warning in payload["entries"][1]["warnings"])


@needs_unicorn
def test_symbolic_seed_flips_the_observed_direction(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(
        app,
        [
            "symbolic",
            str(sample),
            hex(TEXT_ADDRESS),
            "--set",
            "eax=42",
            "--json",
        ],
    )

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["paths"] == 2
    observed = payload["entries"][0]["decisions"][0]
    # ``eax`` now holds 42, so ``je`` really is taken without any seeding.
    assert observed["basis"] == "observed"
    assert observed["taken"] is True
    assert payload["entries"][0]["return_value"] == "0x2"
    assert payload["entries"][0]["seeded_branches"] == 0


def test_symbolic_refuses_a_malformed_register_seed(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["symbolic", str(sample), hex(TEXT_ADDRESS), "--set", "eax"])

    assert result.exit_code == 2
    assert "invalid --set" in _output(result), _output(result)


def test_symbolic_refuses_an_out_of_range_budget(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["symbolic", str(sample), hex(TEXT_ADDRESS), "--max-paths", "0"])

    assert result.exit_code == 2
    output = _output(result)
    assert "max_paths must be >= 1" in output, output


def test_symbolic_refuses_an_address_outside_executable_bytes(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["symbolic", str(sample), "0"])

    assert result.exit_code == 2
    assert "address must be positive" in _output(result), _output(result)


# ---- dataflow: mov + add ----------------------------------------------------


def test_dataflow_reports_definitions_and_constant_registers(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "movadd.bin", MOV_ADD_CODE)

    result = runner.invoke(app, ["dataflow", str(sample), hex(TEXT_ADDRESS)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    rows = _definition_rows(result)
    assert len(rows) == 2, output  # the ``mov`` and the ``add`` each define ``rax``
    assert rows[0] == [
        f"0x{TEXT_ADDRESS:x}",
        "rax",
        "const",
        "0x2a",
        "-",
    ], output
    assert rows[1][1:] == ["rax", "arithmetic", "0x37", "-"], output
    assert "constant registers: rax=0x37" in output, output
    assert "warning:" not in output, "the straight-line fixture has nothing to warn about"


def test_dataflow_json_payload(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "movadd.bin", MOV_ADD_CODE)

    result = runner.invoke(app, ["dataflow", str(sample), hex(TEXT_ADDRESS), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["address"] == f"0x{TEXT_ADDRESS:x}"
    assert payload["definition_count"] == 2
    assert payload["definitions"][0] == {
        "address": f"0x{TEXT_ADDRESS:x}",
        "register": "rax",
        "kind": "const",
        "value": 42,
        "source_register": None,
    }
    assert payload["constant_registers"] == {"rax": 55}


def test_dataflow_refuses_an_out_of_range_budget(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "movadd.bin", MOV_ADD_CODE)

    result = runner.invoke(
        app, ["dataflow", str(sample), hex(TEXT_ADDRESS), "--max-instructions", "0"]
    )

    assert result.exit_code == 2
    assert "max_instructions must be >= 1" in _output(result), _output(result)


def test_dataflow_refuses_an_address_outside_executable_bytes(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "movadd.bin", MOV_ADD_CODE)

    result = runner.invoke(app, ["dataflow", str(sample), "0"])

    assert result.exit_code == 2
    assert "address" in _output(result), _output(result)


# ---- plugins: list and run --------------------------------------------------


def test_plugins_list_includes_the_builtin_metrics_analyzer() -> None:
    result = runner.invoke(app, ["plugins", "list"])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "metrics" in output, output
    assert "analyzer" in output, output


def test_plugins_list_json_prints_plugin_descriptions() -> None:
    result = runner.invoke(app, ["plugins", "list", "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _json_array(result)
    names = [info["name"] for info in payload]
    assert "metrics" in names
    metrics = next(info for info in payload if info["name"] == "metrics")
    assert metrics["kind"] == "analyzer"
    assert metrics["version"]
    assert set(metrics) == {"name", "version", "kind", "entry_point", "description"}


def test_plugins_run_metrics_on_the_repository_sample() -> None:
    result = runner.invoke(app, ["plugins", "run", "metrics", str(REPO_SAMPLE)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "function_count" in output, output
    assert "plugin: metrics" in output, output


def test_plugins_run_metrics_json_payload() -> None:
    result = runner.invoke(app, ["plugins", "run", "metrics", str(REPO_SAMPLE), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["plugin"]["name"] == "metrics"
    assert payload["payload"]["format"] == "ELF"
    assert payload["payload"]["bitness"] == 64
    assert isinstance(payload["payload"]["function_count"], int)
    assert payload["payload"]["function_count"] >= 1
    assert isinstance(payload["payload"]["string_count"], int)
    assert payload["evidence"]["source"] == "plugin.metrics"


def test_plugins_run_accepts_an_explicit_focus_address(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(
        app,
        ["plugins", "run", "metrics", str(sample), hex(TEXT_ADDRESS), "--json"],
    )

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["plugin"]["name"] == "metrics"
    assert payload["payload"]["format"] == "ELF"


def test_plugins_run_refuses_an_unknown_plugin_name(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["plugins", "run", "does-not-exist", str(sample)])

    assert result.exit_code == 2
    assert "no plugin 'does-not-exist'" in _output(result), _output(result)


# ---- evidence-bundle: round trip and refusals -------------------------------


def test_evidence_bundle_round_trip_and_verify(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    payload_file = tmp_path / "payload.json"
    document = {"answer": 42, "tool": "phase7"}
    payload_file.write_text(json.dumps(document), encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    bundle_path = out_dir / "bundle.json"

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={payload_file}",
            "--output",
            str(bundle_path),
        ],
    )

    assert result.exit_code == 0, _output(result)
    assert "bundle written" in _output(result), _output(result)
    assert bundle_path.is_file()
    bundle = read_bundle(bundle_path)
    assert bundle.names == ("meta",)
    assert bundle.payload("meta") == document
    assert bundle.manifest.subject_sha256 == hashlib.sha256(sample.read_bytes()).hexdigest()
    verification = verify_bundle(bundle, subject_path=sample)
    assert verification.passed, verification.problems


def test_evidence_bundle_json_prints_the_document(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    payload_file = tmp_path / "payload.json"
    payload_file.write_text(json.dumps({"answer": 42}), encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={payload_file}",
            "--output",
            str(out_dir / "bundle.json"),
            "--json",
        ],
    )

    assert result.exit_code == 0, _output(result)
    document = _payload(result)
    assert set(document) == {"manifest", "entries"}
    assert set(document["manifest"]) == {
        "algorithm",
        "created_at",
        "tool_version",
        "subject",
        "subject_sha256",
        "entries_sha256",
        "entry_count",
    }
    assert document["manifest"]["algorithm"] == "sha256"
    assert document["entries"]["meta"]["payload"] == {"answer": 42}


def test_evidence_bundle_requires_at_least_one_entry(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(app, ["evidence-bundle", str(sample), "--output", "unused.json"])

    assert result.exit_code == 2


def test_evidence_bundle_refuses_a_malformed_entry(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    out_path = tmp_path / "bundle.json"

    result = runner.invoke(
        app,
        ["evidence-bundle", str(sample), "--entry", "no-file-side", "--output", str(out_path)],
    )

    assert result.exit_code == 2
    assert "invalid --entry" in _output(result), _output(result)
    assert not out_path.exists()


def test_evidence_bundle_refuses_a_duplicate_entry_name(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    payload_file = tmp_path / "payload.json"
    payload_file.write_text("{}", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={payload_file}",
            "--entry",
            f"meta={payload_file}",
            "--output",
            str(tmp_path / "bundle.json"),
        ],
    )

    assert result.exit_code == 2
    assert "duplicate --entry name 'meta'" in _output(result), _output(result)


def test_evidence_bundle_refuses_a_missing_entry_file(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={tmp_path / 'missing.json'}",
            "--output",
            str(tmp_path / "bundle.json"),
        ],
    )

    assert result.exit_code == 2
    assert "cannot read entry" in _output(result), _output(result)


def test_evidence_bundle_refuses_a_non_json_entry(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    payload_file = tmp_path / "payload.txt"
    payload_file.write_text("not json at all", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={payload_file}",
            "--output",
            str(tmp_path / "bundle.json"),
        ],
    )

    assert result.exit_code == 2
    assert "not valid JSON" in _output(result), _output(result)


def test_evidence_bundle_refuses_output_over_the_analysed_binary(tmp_path: Path) -> None:
    sample = _sample(tmp_path, "branch.bin", BRANCH_CODE)
    payload_file = tmp_path / "payload.json"
    payload_file.write_text("{}", encoding="utf-8")
    before = sample.read_bytes()

    result = runner.invoke(
        app,
        [
            "evidence-bundle",
            str(sample),
            "--entry",
            f"meta={payload_file}",
            "--output",
            str(sample),
        ],
    )

    assert result.exit_code == 2
    assert "would overwrite the analysed binary" in _output(result), _output(result)
    assert sample.read_bytes() == before, "the subject must not be touched"
