"""Tests for ``scripts/report_bundle.py`` -- analyze report + trace in one bundle.

The script is exercised the way a developer runs it -- through a subprocess --
so the tests cover the real CLI surface: argument parsing, exit codes,
stdout/stderr separation and the on-disk bundle document.

The dynamic trace comes from the committed ``samples/gdb_trace.log``.  That
file is being committed by a sibling agent in this wave; if it has not landed
yet when the suite runs, the build fixture synthesizes an equivalent hand-made
gdb trace under ``tmp_path`` instead, so the tests never depend on commit
timing (and the fixture records which source was used).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "report_bundle.py"
SAMPLES_DIR = REPO_ROOT / "samples"
PE_SAMPLE = SAMPLES_DIR / "pe64_text.bin"
GDB_TRACE_SAMPLE = SAMPLES_DIR / "gdb_trace.log"

#: Hand-made gdb session trace, byte-equivalent in shape to the committed
#: sample.  Only used when ``samples/gdb_trace.log`` is absent.
HAND_MADE_GDB_TRACE = """\
Breakpoint 1 at 0x401000
Breakpoint 2 at 0x401002
HIT 0x401000 rip=0x401000 rax=0x0 rbx=0x0 rcx=0x0 rdx=0x1
BACKTRACE
#0  0x0000000000401000 in main ()
HIT 0x401002 rip=0x401002 rax=0x2a rbx=0x0 rcx=0x0 rdx=0x1
BACKTRACE
#0  0x0000000000401002 in helper ()
DONE 2 hits
"""

#: Entries every build must contain (build with a trace attached).
FULL_ENTRY_NAMES = {"report", "trace", "metadata"}


def run_script(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    """Run ``scripts/report_bundle.py`` in a subprocess and capture both streams."""
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(REPO_ROOT),
        timeout=timeout,
        check=False,
    )


def read_bundle_document(path: Path) -> dict:
    """Load a written bundle file as a plain dict."""
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class BuiltBundle:
    """A bundle the CLI wrote, together with the build run that produced it."""

    process: subprocess.CompletedProcess[str]
    path: Path


@pytest.fixture(scope="module")
def trace_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The gdb trace to embed: the committed sample, or a hand-made copy.

    Falls back to a hand-made trace under ``tmp_path`` when
    ``samples/gdb_trace.log`` has not been committed yet.
    """
    if GDB_TRACE_SAMPLE.is_file():
        return GDB_TRACE_SAMPLE
    fallback = tmp_path_factory.mktemp("hand_made_trace") / "gdb_trace.log"
    fallback.write_text(HAND_MADE_GDB_TRACE, encoding="utf-8")
    return fallback


@pytest.fixture(scope="module")
def built_bundle(
    tmp_path_factory: pytest.TempPathFactory, trace_file: Path
) -> BuiltBundle:
    """Build one full bundle (report + trace + notes) for the module to reuse."""
    output = tmp_path_factory.mktemp("bundle") / "report_bundle.json"
    done = run_script(
        str(PE_SAMPLE),
        "--output",
        str(output),
        "--trace",
        str(trace_file),
        "--notes",
        "module-fixture build",
    )
    assert done.returncode == 0, done.stderr
    assert output.is_file()
    return BuiltBundle(process=done, path=output)


def test_end_to_end_build_then_verify(built_bundle: BuiltBundle) -> None:
    """A bundle the CLI just wrote must pass the CLI's own --verify."""
    done = run_script("--verify", str(built_bundle.path))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.startswith("OK:")
    # Nothing was printed on stdout except the one OK line.
    assert len(done.stdout.strip().splitlines()) == 1


def test_manifest_reported_on_stdout(built_bundle: BuiltBundle) -> None:
    """stdout carries the manifest as JSON and pins the analysed bytes."""
    manifest = json.loads(built_bundle.process.stdout)
    assert manifest["algorithm"] == "sha256"
    assert manifest["entry_count"] == 3
    assert manifest["subject"] == "analyze+trace"
    assert manifest["subject_sha256"] == hashlib.sha256(PE_SAMPLE.read_bytes()).hexdigest()
    assert len(manifest["entries_sha256"]) == 64

    # The written document mirrors the printed manifest and holds the entries.
    document = read_bundle_document(built_bundle.path)
    assert set(document["entries"]) == FULL_ENTRY_NAMES
    assert document["manifest"]["subject_sha256"] == manifest["subject_sha256"]


def test_verify_detects_tampering(built_bundle: BuiltBundle, tmp_path: Path) -> None:
    """One flipped character inside an entry payload must fail --verify (exit 1)."""
    document = read_bundle_document(built_bundle.path)
    document["entries"]["metadata"]["payload"]["notes"] += " TAMPERED"
    tampered = tmp_path / "tampered_bundle.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")

    done = run_script("--verify", str(tampered))
    assert done.returncode == 1
    # Problems are printed verbatim, naming the entry and the mismatch.
    assert "entry 'metadata': payload sha256 mismatch" in done.stdout


def test_notes_are_stored_in_the_manifest(tmp_path: Path, trace_file: Path) -> None:
    """--notes text lands verbatim in the metadata entry payload."""
    output = tmp_path / "with_notes.json"
    done = run_script(
        str(PE_SAMPLE),
        "--output",
        str(output),
        "--trace",
        str(trace_file),
        "--notes",
        "hand-checked by qa on 2026-11-13",
    )
    assert done.returncode == 0, done.stderr

    document = read_bundle_document(output)
    notes = document["entries"]["metadata"]["payload"]["notes"]
    assert "hand-checked by qa on 2026-11-13" in notes
    assert document["entries"]["metadata"]["payload"]["trace_provider"] == "gdb"


def test_missing_trace_is_omitted_with_a_manifest_note(tmp_path: Path) -> None:
    """Without --trace there is no trace entry, and the metadata says so."""
    output = tmp_path / "no_trace.json"
    done = run_script(str(PE_SAMPLE), "--output", str(output))
    assert done.returncode == 0, done.stderr

    document = read_bundle_document(output)
    assert set(document["entries"]) == {"report", "metadata"}
    assert "trace omitted" in document["entries"]["metadata"]["payload"]["notes"]
    # The manifest label records the difference too.
    assert document["manifest"]["subject"] == "analyze"


def test_missing_binary_exits_2(tmp_path: Path) -> None:
    """A subject that does not exist is a usage error, not a crash."""
    done = run_script(str(tmp_path / "no_such.bin"), "--output", str(tmp_path / "out.json"))
    assert done.returncode == 2
    assert "error:" in done.stderr


def test_missing_trace_file_exits_2(tmp_path: Path) -> None:
    """A --trace path that does not exist is refused before any analysis."""
    done = run_script(
        str(PE_SAMPLE),
        "--output",
        str(tmp_path / "out.json"),
        "--trace",
        str(tmp_path / "no_such.log"),
    )
    assert done.returncode == 2
    assert "trace file not found" in done.stderr
    assert not (tmp_path / "out.json").exists()


def test_output_equal_to_input_is_refused(tmp_path: Path) -> None:
    """The bundle must never overwrite the analysed binary."""
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"MZ fake")
    done = run_script(str(subject), "--output", str(subject))
    assert done.returncode == 2
    assert "same file" in done.stderr
    assert subject.read_bytes() == b"MZ fake"


def test_output_inside_input_directory_is_refused(tmp_path: Path) -> None:
    """A directory-shaped input refuses outputs nested inside it."""
    done = run_script(str(tmp_path), "--output", str(tmp_path / "out.json"))
    assert done.returncode == 2
    assert "inside the input directory" in done.stderr


def test_missing_verify_target_exits_2(tmp_path: Path) -> None:
    """--verify on a path that does not exist is a usage error (exit 2)."""
    done = run_script("--verify", str(tmp_path / "no_such.json"))
    assert done.returncode == 2
    assert "not found" in done.stderr


def test_output_required_in_build_mode(tmp_path: Path) -> None:
    """Without --verify, --output is mandatory; argparse exits 2."""
    done = run_script(str(PE_SAMPLE))
    assert done.returncode == 2
    assert "--output" in done.stderr
