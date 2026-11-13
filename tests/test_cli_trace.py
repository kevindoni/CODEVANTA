"""CLI tests for the dynamic-session commands: ``codevanta trace`` and ``attach``.

Both commands sit in front of layers that already have their own tests
(``tests/test_trace.py``, ``tests/test_dynamic.py``); what is asserted here is the
wiring only: arguments, options, provider detection, the per-function table, the
``--json`` payloads, the file ``--write`` creates and the exit code of every
refusal. The fixture is an ELF64 file assembled byte by byte in this module, so
the tests stay self-contained, and no test launches a provider: the commands under
test parse a saved trace and print a script plus its command line, nothing more.
"""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import dynamic
from codevanta.cli.main import app

runner = CliRunner()

#: Where the fixture's ``.text`` is mapped, so the entry point and the first
#: trace hit name the same address.
TEXT_ADDRESS = 0x401000
#: Start of the second fixture function, where the second trace hit lands.
SECOND_ADDRESS = 0x401002

#: ``mov eax, 42`` + ``ret``: a straight-line function that is not interesting on
#: its own, but gives the two symbols a body to enclose.
CODE = bytes.fromhex("b82a000000") + b"\xc3"

#: ``(name, address)`` pairs of the fixture symbol table. Both sizes cover the
#: whole ``.text``, so attribution rests on the greatest start below the address.
SYMBOLS = (("main", TEXT_ADDRESS), ("second", SECOND_ADDRESS))

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


def _gdb_trace() -> str:
    """Return a gdb session as the generated script prints it: three hits.

    ``main`` is hit twice and ``second`` once, one backtrace follows each hit,
    and gdb's own noise (``Breakpoint 1 at``, ``Inferior 1 exited``, ``DONE``)
    wraps the whole capture, exactly as a saved log does.
    """
    frames = f"#0  0x{TEXT_ADDRESS:016x} in main ()\n#1  0x{TEXT_ADDRESS + 0x10:016x} in ?? ()"
    hits = [
        (
            f"HIT 0x{TEXT_ADDRESS:x} pc=0x{TEXT_ADDRESS:x} sp=0x7ffffffde0 "
            f"fp=0x7ffffffde0 ps=0x246 rip=0x{TEXT_ADDRESS:x} rax=0x1\n"
            f"BACKTRACE\n{frames}"
        ),
        (
            f"HIT 0x{SECOND_ADDRESS:x} pc=0x{SECOND_ADDRESS:x} sp=0x7ffffffdd0 "
            f"fp=0x7ffffffdd0 ps=0x202 rip=0x{SECOND_ADDRESS:x} rax=0x0\n"
            f"BACKTRACE\n#0  0x{SECOND_ADDRESS:016x} in second ()"
        ),
        (
            f"HIT 0x{TEXT_ADDRESS:x} pc=0x{TEXT_ADDRESS:x} sp=0x7ffffffdc0 "
            f"fp=0x7ffffffdc0 ps=0x246 rip=0x{TEXT_ADDRESS:x} rax=0x2"
        ),
    ]
    lines = [
        f"Breakpoint 1 at 0x{TEXT_ADDRESS:x}",
        *hits,
        "[Inferior 1 (process 1234) exited normally]",
        "DONE 3 hits",
    ]
    return "\n".join(lines) + "\n"


def _frida_trace(count: int = 2) -> str:
    """Return the JSON lines a generated Frida hook sends for ``count`` hits."""
    return (
        "\n".join(
            json.dumps(
                {
                    "hit": index,
                    "address": hex(SECOND_ADDRESS),
                    "tid": 4321,
                    "args": ["0x1", "0x2", "0x3", "0x4"],
                }
            )
            for index in range(1, count + 1)
        )
        + "\n"
    )


def _trace_file(tmp_path: Path, text: str, name: str = "session.log") -> Path:
    """Write a captured trace under ``tmp_path`` and return its path."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _probe(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    *,
    available: bool,
    reason: str | None = None,
) -> dynamic.DynamicAvailability:
    """Make ``provider_status`` report ``provider`` without probing the host.

    ``attach`` reads availability through
    :func:`codevanta.analysis.dynamic.provider_status` and nothing else, so
    patching that one function keeps these wiring tests deterministic on a
    machine that has neither gdb nor frida -- and it never executes either.
    """
    status = dynamic.DynamicAvailability(
        name=provider,
        available=available,
        reason=reason or f"{provider} found on PATH (/usr/bin/{provider})",
        requires=(provider,),
    )
    monkeypatch.setattr(dynamic, "provider_status", lambda name: status)
    return status


#: The first provider this host cannot run, established by the same
#: ``shutil.which``/``find_spec`` probe the command itself uses.
UNAVAILABLE = next((status for status in dynamic.available_backends() if not status.available), None)
needs_unavailable_provider = pytest.mark.skipif(
    UNAVAILABLE is None, reason="gdb and frida are both installed here"
)


# ---- trace: the saved-session table ----------------------------------------


def test_trace_reports_hits_per_function(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, _gdb_trace())

    result = runner.invoke(app, ["trace", str(sample), "--input", str(trace_file)])

    assert result.exit_code == 0, _output(result)
    # One row per function that was hit: name, start address, hits in it.
    # The first table row is the header ("Function | Address | Hits").
    assert _table_rows(result.stdout, 3)[1:] == [
        ["main", "0x401000", "2"],
        ["second", "0x401002", "1"],
    ], _output(result)
    output = _output(result)
    # The provider was read off the file shape, and the render says so.
    assert "provider: gdb" in output, output
    assert "auto-detected" in output, output
    # The totals line repeats what the parser saw.
    assert "hits: 3" in output, output
    assert "kept: 3" in output, output
    assert "unique addresses: 2" in output, output
    assert "functions hit: 2" in output, output
    assert "unattributed: 0" in output, output
    assert "truncated: no" in output, output


def test_trace_json_is_the_report_payload(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, _gdb_trace())

    result = runner.invoke(app, ["trace", str(sample), "--input", str(trace_file), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["provider"] == "gdb"
    assert payload["total_hits"] == 3
    assert payload["truncated"] is False
    assert payload["warnings"] == []
    assert payload["unique_addresses"] == ["0x401000", "0x401002"]
    assert payload["function_coverage"] == {"0x401000": 2, "0x401002": 1}
    assert [hit["address"] for hit in payload["hits"]] == [
        "0x401000",
        "0x401002",
        "0x401000",
    ]
    assert payload["hits"][0]["function_name"] == "main"
    assert payload["hits"][0]["backtrace"] == ["0x401000", "0x401010"]
    assert "evidence" in payload


def test_trace_detects_a_frida_trace(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, _frida_trace(), name="frida.log")

    result = runner.invoke(app, ["trace", str(sample), "--input", str(trace_file)])

    assert result.exit_code == 0, _output(result)
    assert _table_rows(result.stdout, 3)[1:] == [["second", "0x401002", "2"]], _output(result)
    output = _output(result)
    assert "provider: frida" in output, output
    assert "auto-detected" in output, output
    # The runtime-address caveat is stated rather than left implicit.
    assert "runtime addresses" in output, output


def test_trace_explicit_provider_is_not_reported_as_detected(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, _gdb_trace())

    result = runner.invoke(
        app, ["trace", str(sample), "--input", str(trace_file), "--provider", "gdb"]
    )

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    assert "provider: gdb" in output, output
    # Nothing was detected, so nothing claims to have been.
    assert "auto-detected" not in output, output


def test_trace_reports_unattributed_hits_and_warnings(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    text = "HIT 0x900000 pc=0x900000 rax=0x0\nHIT not-an-address\n"
    trace_file = _trace_file(tmp_path, text)

    result = runner.invoke(app, ["trace", str(sample), "--input", str(trace_file)])

    assert result.exit_code == 0, _output(result)
    output = _output(result)
    # An address outside every candidate is reported, never guessed onto one.
    assert "no hit landed inside a discovered function" in output, output
    assert "unattributed: 1" in output, output
    # The malformed HIT line keeps its own warning line.
    assert "warning:" in output, output
    assert "unparseable HIT line" in output, output


def test_trace_unknown_provider_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, _gdb_trace())

    result = runner.invoke(
        app, ["trace", str(sample), "--input", str(trace_file), "--provider", "delve"]
    )

    assert result.exit_code == 2
    assert "--provider" in _output(result), _output(result)


def test_trace_undetectable_input_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    trace_file = _trace_file(tmp_path, "program finished with exit code 0\n")

    result = runner.invoke(app, ["trace", str(sample), "--input", str(trace_file)])

    assert result.exit_code == 2
    assert "cannot tell whether" in _output(result), _output(result)


def test_trace_missing_input_file_exits_2(tmp_path: Path) -> None:
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["trace", str(sample), "--input", str(tmp_path / "nope.log")])

    assert result.exit_code == 2
    assert "cannot read" in _output(result), _output(result)


# ---- attach: the script and its command line -------------------------------


def test_attach_prints_the_script_and_the_gdb_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample)])

    assert result.exit_code == 0, _output(result)
    # The script sets a breakpoint at the entry point, which is the default target.
    assert "break *0x401000" in _plain(result.stdout), _plain(result.stdout)
    # The exact argv follows, naming the script by its fixed file name.
    assert "gdb -q -batch -x codevanta-session.gdb --args" in _output(result), _output(result)
    # Without --write nothing went to disk, and the render says so.
    assert "nothing was written" in _output(result), _output(result)
    assert not (tmp_path / "codevanta-session.gdb").exists()


def test_attach_uses_the_given_addresses_and_hit_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "0x401002", "--max-hits", "3"])

    assert result.exit_code == 0, _output(result)
    script = _plain(result.stdout)
    assert "break *0x401002" in script, script
    assert "break *0x401000" not in script, script
    # The ceiling is in the script itself, not only on the command line.
    assert "# max hits    : 3" in script, script
    assert "$cv_hits >= 3" in script, script


def test_attach_write_saves_the_script_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)
    out_dir = tmp_path / "sessions"

    result = runner.invoke(app, ["attach", str(sample), "--write", str(out_dir)])

    assert result.exit_code == 0, _output(result)
    script_path = out_dir / "codevanta-session.gdb"
    assert script_path.is_file(), _output(result)
    written = script_path.read_text(encoding="utf-8")
    assert "break *0x401000" in written, written
    output = _output(result)
    assert "script written:" in output, output
    assert script_path.name in output, output
    # The path is followed by what has to happen before the argv is run.
    assert "run the command above from" in output, output
    # The text went to the file, so it is not printed as well.
    assert "break *0x401000" not in output, output


def test_attach_json_carries_the_script_text_and_the_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["provider"] == "gdb"
    assert "break *0x401000" in payload["script"]["text"]
    assert payload["script"]["provider"] == "gdb"
    # Nothing was written, so there is no path to report.
    assert payload["script_path"] is None
    assert payload["attach_command"][:5] == ["gdb", "-q", "-batch", "-x", "codevanta-session.gdb"]
    assert payload["attach_command"][-2] == "--args"
    assert payload["attach_command"][-1] == str(sample)
    assert payload["addresses"] == ["0x401000"]
    assert payload["max_hits"] == dynamic.DEFAULT_MAX_HITS
    assert payload["availability"] == {
        "name": "gdb",
        "available": True,
        "reason": "gdb found on PATH (/usr/bin/gdb)",
        "requires": ["gdb"],
        "version": None,
    }


def test_attach_json_reports_the_written_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)
    out_dir = tmp_path / "sessions"

    result = runner.invoke(app, ["attach", str(sample), "--write", str(out_dir), "--json"])

    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["script_path"] == str(out_dir / "codevanta-session.gdb")
    assert (out_dir / "codevanta-session.gdb").is_file()


def test_attach_builds_a_frida_hook_when_frida_is_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "frida", available=True)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "--provider", "frida"])

    assert result.exit_code == 0, _output(result)
    # The Frida script hooks by module-relative offset, and the argv matches.
    assert "Interceptor.attach" in _plain(result.stdout), _plain(result.stdout)
    assert "frida -l codevanta-hooks.js -f" in _output(result), _output(result)


def test_attach_refuses_an_unavailable_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reason = "frida is not installed: missing the frida CLI; install with 'pip install frida'"
    _probe(monkeypatch, "frida", available=False, reason=reason)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "--provider", "frida"])

    assert result.exit_code == 2
    output = _output(result)
    assert "frida is unavailable" in output, output
    # The refusal repeats the probe's own reason instead of inventing one.
    assert reason in output, output


@needs_unavailable_provider
def test_attach_refuses_a_provider_this_host_cannot_run(tmp_path: Path) -> None:
    assert UNAVAILABLE is not None
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "--provider", UNAVAILABLE.name])

    assert result.exit_code == 2
    output = _output(result)
    assert f"{UNAVAILABLE.name} is unavailable" in output, output
    assert UNAVAILABLE.reason[:40] in output, output


def test_attach_rejects_an_unparseable_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _probe(monkeypatch, "gdb", available=True)
    sample = _sample(tmp_path)

    result = runner.invoke(app, ["attach", str(sample), "not-an-address"])

    assert result.exit_code == 2
    assert "invalid address" in _output(result), _output(result)


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
    ``.symtab``/``.strtab`` pair, which is what gives the trace table function
    names to print.
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
            "<IIQQQQIIQQ", 1, 1, 6, TEXT_ADDRESS, text_offset, len(code), 0, 0, 16, 0
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
        TEXT_ADDRESS,  # e_entry
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


def _sample(tmp_path: Path) -> Path:
    """Write the fixture binary under ``tmp_path``."""
    return _write_elf64_with_symbols(tmp_path / "sample.bin", CODE, SYMBOLS)

