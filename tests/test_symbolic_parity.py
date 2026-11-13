"""Parity test: the angr bridge in :mod:`codevanta.analysis.symbolic` against a
**real** angr installation.

``tests/test_symbolic.py`` pins down the unicorn explorer and can only exercise
the angr bridge's *unavailable* path, because angr is deliberately not part of
the ``dev`` extra. This module is the complement: it is skipped wholesale unless
angr is importable (``pip install -e ".[decompilers]"``; the ``decompile-parity``
CI job installs exactly that), and when angr *is* present it asserts the parity
claim instead of leaving it in prose: :func:`explore_with_angr` really drives a
third-party symbolic executor over the same tiny ELF samples and reports the
paths through the same :class:`~codevanta.analysis.symbolic.PathExploration`
shape the unicorn explorer uses.

The fixtures are assembled byte by byte here, with the builder copied verbatim
from ``tests/test_symbolic.py``, so this file needs no compiler, no linker and no
sample checked into the repository. angr only ever *analyses* the bytes; nothing
is executed on the host.

What each test pins down:

1. ``angr_available()`` is ``True`` -- the module gate that the skipped-by-default
   suite can never check on a machine without the extra.
2. ``mov rax, rdi; add rax, rsi; ret`` with concrete register seeds yields
   exactly one found path whose recorded return value is ``rdi + rsi``.
3. A two-way conditional resolves to a path list of at least one entry, every
   reported path a ``return`` -- the bridge's actual guarantee (see the test
   docstring for the two options and why only ``>= 1`` is asserted).
4. A fake ``angr`` module whose import raises still surfaces as a clear
   :class:`~codevanta.core.report.AnalysisError` naming angr.
5. The angr paths survive :meth:`PathExploration.to_dict` round-tripping through
   JSON, i.e. the bridge feeds the same report pipeline as the unicorn explorer.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

from codevanta.analysis import symbolic
from codevanta.analysis.symbolic import angr_available, explore_with_angr
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError

#: Skip the whole module when the optional backend is absent. Kept after the
#: imports on purpose, like ``tests/test_decompiler_parity.py``: the module
#: itself imports fine without angr (it is only probed, never imported), so the
#: import order stays lint-clean and only the *tests* need angr.
pytest.importorskip("angr", reason="the [decompilers] extra (angr) is not installed")

#: Virtual address of .text in the ELF64 samples (same as ``test_symbolic``).
TEXT_VA = 0x401000

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_STRTAB = 3

_TEXT_OFFSET = 0x40
_SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
_NAME_TEXT = 1
_NAME_SHSTRTAB = 7

#: x86-64 ``mov rax, rdi`` -- reads argument register 0.
MOV_RAX_RDI = bytes.fromhex("4889f8")  # 0x00

#: x86-64 ``add rax, rsi`` -- reads argument register 1.
ADD_RAX_RSI = bytes.fromhex("4801f0")  # 0x03

#: x86-64 ``ret``.
RET = bytes.fromhex("c3")  # 0x06

#: Straight-line two-argument function: ``rax = rdi + rsi``. One block, one
#: ``ret``, so angr has exactly one path to find.
CODE_ADD_ARGS = MOV_RAX_RDI + ADD_RAX_RSI + RET

#: x86-64 ``test edi, edi; jz +6; mov eax, 1; ret; mov eax, 2; ret`` (copied
#: from ``tests/test_symbolic.py``). Offsets: ``test`` at 0x0, ``je`` at 0x2
#: (target 0xa), the two mov/ret pairs at 0x4/0x9 and 0xa/0xf, so the two sides
#: return different values.
CODE_TWO_WAY = (
    bytes.fromhex("85ff")            # 0x00: test edi, edi
    + bytes.fromhex("7406")          # 0x02: je 0xa   (Capstone spells 0x74 "je")
    + bytes.fromhex("b801000000")    # 0x04: mov eax, 1
    + bytes.fromhex("c3")            # 0x09: ret
    + bytes.fromhex("b802000000")    # 0x0a: mov eax, 2
    + bytes.fromhex("c3")            # 0x0f: ret
)

#: 64-bit mask for the expected return value (angr's ``rax`` is a full word).
MASK_64 = (1 << 64) - 1

#: Concrete seeds for the straight-line fixture and the sum they must produce.
SEED_RDI = 0x10
SEED_RSI = 0x20
EXPECTED_RETURN = (SEED_RDI + SEED_RSI) & MASK_64


def _write_elf(path: Path, code: bytes, *, va: int) -> Path:
    """Write a tiny ELF64 whose ``.text`` holds ``code`` at ``va``.

    Copied verbatim from ``tests/test_symbolic.py``: three sections (null,
    ``.text``, ``.shstrtab``), no program headers and no other content -- enough
    for :class:`~codevanta.core.loader.BinaryLoader` and for the bridge.

    Args:
        path: Destination file.
        code: Bytes placed at the start of ``.text``.
        va: Virtual address of ``.text``.

    Returns:
        ``path``, written to disk.
    """
    shstr_offset = _TEXT_OFFSET + len(code)
    sh_offset = (shstr_offset + len(_SHSTRTAB) + 7) & ~7
    blob = bytearray(sh_offset)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        62,         # e_machine = EM_X86_64
        1,          # e_version
        va,         # e_entry
        0,          # e_phoff
        sh_offset,  # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        3,          # e_shnum: null, .text, .shstrtab
        2,          # e_shstrndx
    )
    text_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        va, _TEXT_OFFSET, len(code), 0, 0, 16, 0,
    )
    str_header = struct.pack(
        "<IIQQQQIIQQ",
        _NAME_SHSTRTAB, SHT_STRTAB, 0, 0, shstr_offset, len(_SHSTRTAB), 0, 0, 1, 0,
    )
    blob[0 : len(header)] = header
    blob[_TEXT_OFFSET : _TEXT_OFFSET + len(code)] = code
    blob[shstr_offset : shstr_offset + len(_SHSTRTAB)] = _SHSTRTAB
    blob += bytes(64) + text_header + str_header
    path.write_bytes(bytes(blob))
    return path


def _sample(tmp_path: Path, code: bytes, *, name: str = "sample.elf") -> Path:
    """Write a sample ELF with ``code`` in ``.text`` at :data:`TEXT_VA`."""
    return _write_elf(tmp_path / name, code, va=TEXT_VA)


def _load(path: Path) -> BinaryInfo:
    """Load a sample through the real loader."""
    return BinaryLoader().load(path)


# ---- availability ----------------------------------------------------------


def test_angr_bridge_is_available() -> None:
    """With angr importable, the module gate reports True (the parity premise)."""
    assert angr_available() is True


# ---- straight-line path ----------------------------------------------------


def test_straight_line_yields_one_path_with_recorded_return(tmp_path: Path) -> None:
    """``mov rax, rdi; add rax, rsi; ret`` -> one path returning ``rdi + rsi``.

    The seeds are concrete, so the found state's ``rax`` is concrete too and the
    bridge must record it as the return value -- the parity claim against the
    unicorn explorer, which reports the same sum for the same bytes.
    """
    path = _sample(tmp_path, CODE_ADD_ARGS, name="angr_straight.elf")
    info = _load(path)

    exploration = explore_with_angr(
        path,
        info,
        TEXT_VA,
        initial_registers={"rdi": SEED_RDI, "rsi": SEED_RSI},
    )

    assert exploration.explorer == "angr"
    assert exploration.max_steps == 0  # angr explores until its simgr stops
    assert len(exploration.entries) == 1  # one straight-line route, one ret
    entry = exploration.entries[0]
    assert entry.stopped_reason == "return"
    assert entry.return_value == EXPECTED_RETURN
    assert exploration.return_values == (EXPECTED_RETURN,)
    # At least the three instructions of the function ran; angr owns the block
    # splitting, so the exact count is angr's business, not this bridge's.
    assert entry.instructions >= 3


# ---- two-way conditional ---------------------------------------------------


def test_two_way_conditional_resolves_at_least_one_return_path(tmp_path: Path) -> None:
    """The conditional fixture resolves to a path list of >= 1 resolved return.

    Honest contract note -- two options exist for the count, and only one of
    them is the module's guarantee:

    * Option A (typical): angr explores both branch sides without state
      merging, so both ``ret`` sites are found and two entries come back,
      returning 1 and 2.
    * Option B (allowed): angr's simgr stops after fewer paths (deduplication,
      version differences), reporting only one side.

    What the bridge itself guarantees is "report up to ``max_paths`` found
    paths" -- each of them a state angr solved *to* a ``ret``. So the floor
    asserted here is one resolved path, plus invariants that hold under both
    options: every reported path ended in a ``return`` and its return value is
    one of the fixture's two concrete answers. A stronger assertion (exactly 2,
    or a set equality) would pin angr's internal behaviour, not this module's
    contract.
    """
    path = _sample(tmp_path, CODE_TWO_WAY, name="angr_two_way.elf")
    info = _load(path)

    exploration = explore_with_angr(path, info, TEXT_VA)

    assert exploration.explorer == "angr"
    assert len(exploration.entries) >= 1
    for entry in exploration.entries:
        assert entry.stopped_reason == "return"
        assert entry.return_value in (1, 2)
    assert {entry.return_value for entry in exploration.entries} <= {1, 2}
    assert len(exploration.return_values) >= 1


# ---- the missing-angr error path -------------------------------------------


def test_module_gate_refuses_exploration_without_angr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ANGR_AVAILABLE`` False: the gate itself raises, naming angr and the fix.

    Forcing the flag False (instead of relying on the host machine) keeps this
    deterministic in CI, where angr *is* installed: the refusal must come from
    the gate, before any import is attempted.
    """
    path = _sample(tmp_path, CODE_ADD_ARGS, name="gate.elf")
    info = _load(path)
    monkeypatch.setattr(symbolic, "ANGR_AVAILABLE", False)

    with pytest.raises(AnalysisError) as excinfo:
        explore_with_angr(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "angr" in message
    assert "not installed" in message
    assert "pip install" in message  # points at the extra that provides it


def test_broken_angr_module_import_raises_clear_analysis_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fake ``angr`` whose import raises still fails with AnalysisError.

    ``sys.modules["angr"] = None`` makes ``import angr`` raise ``ImportError``
    even where a spec was findable (this is the fake-module trick). The gate is
    forced True so the flow actually *reaches* the import instead of stopping at
    ``ANGR_AVAILABLE`` -- deterministic whether or not the host has real angr.
    The error must name angr, say the import failed, and point at the extra.
    """
    path = _sample(tmp_path, CODE_ADD_ARGS, name="broken_angr.elf")
    info = _load(path)
    monkeypatch.setattr(symbolic, "ANGR_AVAILABLE", True)
    monkeypatch.setitem(sys.modules, "angr", None)

    with pytest.raises(AnalysisError) as excinfo:
        explore_with_angr(path, info, TEXT_VA)

    message = str(excinfo.value)
    assert "angr" in message
    assert "failed" in message  # "importing 'angr' failed (...)"
    assert "pip install" in message


# ---- serialization ---------------------------------------------------------


def test_angr_paths_survive_to_dict_json_round_trip(tmp_path: Path) -> None:
    """The angr paths are JSON serializable like the unicorn explorer's."""
    path = _sample(tmp_path, CODE_ADD_ARGS, name="angr_json.elf")
    info = _load(path)
    exploration = explore_with_angr(
        path,
        info,
        TEXT_VA,
        initial_registers={"rdi": SEED_RDI, "rsi": SEED_RSI},
    )

    payload = exploration.to_dict()
    text = json.dumps(payload)  # no bytes, no Paths, no enums, no sets
    reloaded = json.loads(text)

    assert reloaded["explorer"] == "angr"
    assert reloaded["address"] == f"0x{TEXT_VA:x}"
    assert reloaded["paths"] == 1
    assert reloaded["return_values"] == [f"0x{EXPECTED_RETURN:x}"]
    entry = reloaded["entries"][0]
    assert entry["return_value"] == f"0x{EXPECTED_RETURN:x}"
    assert entry["stopped_reason"] == "return"
    assert entry["decisions"] == []  # angr does not reconstruct the decisions
    assert isinstance(entry["taken_targets"], list)
    assert all(target.startswith("0x") for target in entry["taken_targets"])
    assert isinstance(entry["registers"], dict)
    assert all(isinstance(value, str) for value in entry["registers"].values())
