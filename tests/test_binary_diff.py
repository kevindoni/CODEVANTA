"""Binary diff tests (structural matching, evidence, bounds, semantic pairing)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.binary_diff import (
    DEFAULT_MAX_FUNCTIONS,
    DEFAULT_SEMANTIC_THRESHOLD,
    MAX_MAX_FUNCTIONS,
    MAX_SEMANTIC_PAIRS,
    FunctionDelta,
    diff_binaries,
    diff_infos,
)
from codevanta.core.functions import FunctionCandidate
from codevanta.core.loader import (
    BinaryInfo,
    BinaryLoader,
    ExportInfo,
    ImportInfo,
    SectionInfo,
)
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence


def _make_info(**overrides: object) -> BinaryInfo:
    defaults: dict[str, object] = {
        "path": Path("left.bin"),
        "format": "ELF",
        "architecture": "x86_64",
        "bitness": 64,
        "endianness": "little",
        "entry_point": 0x401000,
        "image_base": 0x400000,
        "sha256": "0" * 64,
        "file_size": 1024,
    }
    defaults.update(overrides)
    return BinaryInfo(**defaults)  # type: ignore[arg-type]


def _candidate(
    address: int,
    name: str | None = None,
    *,
    size: int | None = None,
    source: str = "binary.entry_point",
) -> FunctionCandidate:
    confidence = Confidence.MEDIUM
    return FunctionCandidate(
        address=address,
        name=name,
        size=size,
        source=source,
        confidence=confidence,
        evidence=Evidence(
            source=source,
            method="test_fixture",
            confidence=confidence,
            address=address,
        ),
    )


def _section(name: str, virtual_address: int = 0x401000) -> SectionInfo:
    return SectionInfo(name=name, virtual_address=virtual_address, size=16, offset=0x400)


def test_same_file_compared_with_itself_is_identical(elf64_text_path: Path) -> None:
    diff = diff_binaries(elf64_text_path, elf64_text_path)

    assert diff.identical is True
    assert diff.functions_added == ()
    assert diff.functions_removed == ()
    assert diff.functions_changed == ()
    assert diff.sections_added == ()
    assert diff.sections_removed == ()
    assert diff.warnings == ()
    assert Path(diff.left_path) == elf64_text_path
    assert Path(diff.right_path) == elf64_text_path


def test_different_entry_points_produce_function_deltas(tmp_path: Path) -> None:
    from conftest import make_elf64_with_text

    left = make_elf64_with_text(tmp_path / "left.bin", entry=0x401000)
    right = make_elf64_with_text(tmp_path / "right.bin", entry=0x401050)

    diff = diff_binaries(left, right)

    assert diff.identical is False
    assert [delta.address for delta in diff.functions_added] == [0x401050]
    assert [delta.address for delta in diff.functions_removed] == [0x401000]
    assert diff.functions_changed == ()
    assert diff.functions_added[0].left is None
    assert diff.functions_removed[0].right is None
    # Only the entry point candidate exists, so nothing else moves.
    assert diff.sections_added == ()
    assert diff.sections_removed == ()


def test_injected_added_and_removed_candidates() -> None:
    left_functions = [_candidate(0x401000, "main"), _candidate(0x401100, "gone")]
    right_functions = [_candidate(0x401000, "main"), _candidate(0x401200, "fresh")]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert diff.identical is False
    assert [(d.address, d.name, d.change) for d in diff.functions_added] == [
        (0x401200, "fresh", "added")
    ]
    assert [(d.address, d.name, d.change) for d in diff.functions_removed] == [
        (0x401100, "gone", "removed")
    ]
    assert diff.functions_changed == ()


def test_renamed_candidate_is_a_change_in_place() -> None:
    left_functions = [_candidate(0x401000, "old_name")]
    right_functions = [_candidate(0x401000, "new_name")]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert diff.identical is False
    assert len(diff.functions_changed) == 1
    delta = diff.functions_changed[0]
    assert delta.change == "changed"
    assert delta.address == 0x401000
    assert delta.name == "new_name"
    assert delta.left is not None and delta.right is not None
    assert delta.left["name"] == "old_name"
    assert delta.right["name"] == "new_name"
    assert "name" in (delta.evidence.detail or "")
    assert diff.functions_added == ()
    assert diff.functions_removed == ()


def test_moved_candidate_is_matched_by_name() -> None:
    left_functions = [_candidate(0x401000, "helper", size=32)]
    right_functions = [_candidate(0x401800, "helper", size=32)]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert diff.identical is False
    assert diff.functions_added == ()
    assert diff.functions_removed == ()
    assert len(diff.functions_changed) == 1
    delta = diff.functions_changed[0]
    # A move is reported as one change, never as remove + add.
    assert delta.change == "changed"
    assert delta.address == 0x401800
    assert delta.left is not None and delta.right is not None
    assert delta.left["address"] == "0x401000"
    assert delta.right["address"] == "0x401800"
    assert "0x401000" in (delta.evidence.detail or "")
    assert "0x401800" in (delta.evidence.detail or "")


def test_size_change_at_same_address_is_a_change() -> None:
    left_functions = [_candidate(0x401000, "func", size=16)]
    right_functions = [_candidate(0x401000, "func", size=24)]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert len(diff.functions_changed) == 1
    assert "size" in (diff.functions_changed[0].evidence.detail or "")


def test_discovery_provenance_only_difference_is_not_a_delta() -> None:
    left_functions = [_candidate(0x401000, "func", source="elf.symtab")]
    right_functions = [_candidate(0x401000, "func", source="elf.dynsym")]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert diff.identical is True
    assert diff.functions_changed == ()


def test_section_name_differences() -> None:
    left_info = _make_info(sections=[_section(".text"), _section(".old", 0x402000)])
    right_info = _make_info(sections=[_section(".text"), _section(".new", 0x402000)])

    diff = diff_infos(left_info, right_info, [], [])

    assert diff.identical is False
    assert diff.sections_added == (".new",)
    assert diff.sections_removed == (".old",)
    assert diff.functions_added == ()


def test_import_and_export_differences() -> None:
    left_info = _make_info(
        imports=[
            ImportInfo(name="CreateFileA", library="kernel32.dll"),
            ImportInfo(name="puts"),
        ],
        exports=[ExportInfo(name="start", address=0x401000)],
    )
    right_info = _make_info(
        imports=[
            ImportInfo(name="CreateFileA", library="kernel32.dll"),
            ImportInfo(name="CreateFileA", library="other.dll"),
        ],
        exports=[ExportInfo(name="main", address=0x401000)],
    )

    diff = diff_infos(left_info, right_info, [], [])

    # The same symbol name from a different library is a different import.
    assert diff.imports_added == ("other.dll!CreateFileA",)
    assert diff.imports_removed == ("puts",)
    assert diff.exports_added == ("main",)
    assert diff.exports_removed == ("start",)
    assert diff.identical is False


def test_identical_ignores_hash_when_no_deltas() -> None:
    left_info = _make_info(sha256="a" * 64)
    right_info = _make_info(sha256="b" * 64)

    diff = diff_infos(left_info, right_info, [], [])

    assert diff.identical is True


def test_max_functions_truncates_with_warning() -> None:
    left_functions = [_candidate(0x401000), _candidate(0x401100), _candidate(0x401200)]
    right_functions = [_candidate(0x401000), _candidate(0x401100), _candidate(0x401200)]

    diff = diff_infos(
        _make_info(), _make_info(), left_functions, right_functions, max_functions=2
    )

    assert diff.identical is True
    assert len(diff.warnings) == 2
    assert all("max_functions" in warning for warning in diff.warnings)
    assert "left" in diff.warnings[0]
    assert "right" in diff.warnings[1]
    assert diff.evidence.extra["max_functions"] == 2


def test_max_functions_is_clamped_to_supported_range() -> None:
    functions = [_candidate(0x401000), _candidate(0x401100)]

    low = diff_infos(_make_info(), _make_info(), functions, functions, max_functions=0)
    assert low.evidence.extra["max_functions"] == 1
    assert any("minimum" in warning for warning in low.warnings)
    # Only the lowest address per side survives the clamp.
    assert low.identical is True

    high = diff_infos(
        _make_info(), _make_info(), functions, functions, max_functions=MAX_MAX_FUNCTIONS + 1
    )
    assert high.evidence.extra["max_functions"] == MAX_MAX_FUNCTIONS
    assert any("maximum" in warning for warning in high.warnings)


def test_default_max_functions_is_used_when_not_an_integer() -> None:
    diff = diff_infos(
        _make_info(), _make_info(), [], [], max_functions="lots"  # type: ignore[arg-type]
    )

    assert diff.evidence.extra["max_functions"] == DEFAULT_MAX_FUNCTIONS
    assert any("not an integer" in warning for warning in diff.warnings)


def test_diff_infos_does_not_mutate_inputs() -> None:
    left_functions = [_candidate(0x401200, "b"), _candidate(0x401000, "a")]
    right_functions = [_candidate(0x401400, "a")]
    before_left = list(left_functions)
    before_right = list(right_functions)

    diff_infos(_make_info(), _make_info(), left_functions, right_functions)

    assert left_functions == before_left
    assert right_functions == before_right


def test_evidence_carries_structural_caveat() -> None:
    diff = diff_infos(
        _make_info(),
        _make_info(),
        [_candidate(0x401000, "a")],
        [_candidate(0x401100, "b")],
    )

    assert diff.evidence.source == "binary_diff.structural"
    assert diff.evidence.method == "metadata_compare"
    assert diff.evidence.confidence is Confidence.MEDIUM
    assert "structural" in (diff.evidence.detail or "")

    for delta in diff.functions_added + diff.functions_removed:
        assert delta.evidence.source == "binary_diff.structural"
        assert delta.evidence.method == "metadata_compare"
        assert delta.evidence.confidence is Confidence.MEDIUM
        assert "structural" in (delta.evidence.detail or "")


def test_to_dict_is_json_serialisable_and_addresses_are_hex() -> None:
    diff = diff_infos(
        _make_info(sections=[_section(".text")]),
        _make_info(sections=[_section(".data", 0x402000)]),
        [_candidate(0x401000, "old")],
        [_candidate(0x401200, "new")],
    )

    payload = diff.to_dict()
    text = json.dumps(payload)  # must not raise

    assert payload["identical"] is False
    assert payload["functions_added"][0]["address"] == "0x401200"
    assert payload["functions_removed"][0]["address"] == "0x401000"
    assert payload["sections_added"] == [".data"]
    assert payload["sections_removed"] == [".text"]
    assert payload["evidence"]["source"] == "binary_diff.structural"
    assert json.loads(text)["identical"] is False


def test_function_delta_to_dict_omits_absent_side() -> None:
    diff = diff_infos(_make_info(), _make_info(), [_candidate(0x401000, "gone")], [])

    delta: FunctionDelta = diff.functions_removed[0]
    payload = delta.to_dict()

    assert payload["change"] == "removed"
    assert payload["name"] == "gone"
    assert "right" not in payload
    assert payload["left"]["address"] == "0x401000"


# ---- deep (content) mode -------------------------------------------------

TEXT_VA = 0x401000

NOP_TEXT = bytes.fromhex("90")  # nop
RET_TEXT = bytes.fromhex("c3")  # ret
MOV_RET_42 = bytes.fromhex("b82a000000c3")  # mov eax, 0x2a; ret
MOV_RET_99 = bytes.fromhex("b863000000c3")  # mov eax, 0x63; ret


def _make_code_elf(path: Path, code: bytes, entry: int = TEXT_VA) -> Path:
    """Write an ELF64 file whose executable ``.text`` holds ``code``."""
    shstr = b"\x00.text\x00.shstrtab\x00"
    off_text = 0x40
    off_shstr = off_text + len(code)
    shoff = off_shstr + len(shstr)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, shoff, 0, 64, 56, 0, 64, 3, 2
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0
    )
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[off_text:off_text + len(code)] = code
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += bytes(64) + text_section + str_section
    path.write_bytes(blob)
    return path


def test_deep_identical_code_produces_no_delta(tmp_path: Path) -> None:
    binary = _make_code_elf(tmp_path / "same.bin", MOV_RET_42)

    diff = diff_binaries(binary, binary, deep=True)

    assert diff.identical is True
    assert diff.functions_changed == ()
    assert diff.warnings == ()
    assert diff.evidence.extra["deep"] is True


def test_deep_nop_versus_ret_at_the_same_address_is_changed(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "nop.bin", NOP_TEXT)
    right = _make_code_elf(tmp_path / "ret.bin", RET_TEXT)

    diff = diff_binaries(left, right, deep=True)

    assert diff.identical is False
    assert len(diff.functions_changed) == 1
    delta = diff.functions_changed[0]
    assert delta.address == TEXT_VA
    assert delta.change == "changed"
    assert delta.left_digest is not None
    assert delta.right_digest is not None
    assert delta.left_digest != delta.right_digest
    assert "content changed" in (delta.evidence.detail or "")
    assert delta.left_digest in (delta.evidence.detail or "")
    assert "structural" in (delta.evidence.detail or "")
    assert "#" in (delta.evidence.detail or "")


def test_deep_false_keeps_the_structural_verdict(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "nop.bin", NOP_TEXT)
    right = _make_code_elf(tmp_path / "ret.bin", RET_TEXT)

    diff = diff_binaries(left, right)

    assert diff.identical is True
    assert diff.functions_changed == ()
    assert diff.evidence.detail is not None
    assert "no instruction bytes were read" in diff.evidence.detail
    assert "deep" not in diff.evidence.extra


def test_deep_ignores_differing_immediates(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", MOV_RET_42)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_99)

    diff = diff_binaries(left, right, deep=True)

    assert diff.identical is True
    assert diff.functions_changed == ()


def test_deep_reports_content_and_metadata_in_one_delta(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", NOP_TEXT)
    right = _make_code_elf(tmp_path / "right.bin", RET_TEXT)

    loader = BinaryLoader()
    left_info = loader.load(left)
    right_info = loader.load(right)

    diff = diff_infos(
        left_info,
        right_info,
        [_candidate(TEXT_VA, "left_name", size=1)],
        [_candidate(TEXT_VA, "right_name", size=2)],
        deep=True,
    )

    assert len(diff.functions_changed) == 1
    delta = diff.functions_changed[0]
    assert "metadata changed" in (delta.evidence.detail or "")
    assert "content changed" in (delta.evidence.detail or "")
    payload = delta.to_dict()
    assert payload["left_digest"] != payload["right_digest"]


def test_deep_serialises_digests_only_when_set(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "nop.bin", NOP_TEXT)
    right = _make_code_elf(tmp_path / "ret.bin", RET_TEXT)

    deep = diff_binaries(left, right, deep=True).to_dict()
    structural = diff_infos(_make_info(), _make_info(), [_candidate(TEXT_VA)], [])

    assert deep["functions_changed"][0]["left_digest"]
    assert deep["functions_changed"][0]["right_digest"]
    assert "left_digest" not in structural.functions_removed[0].to_dict()
    assert json.dumps(deep)  # must not raise


def test_deep_warns_when_a_side_cannot_be_fingerprinted(tmp_path: Path) -> None:
    # The metadata points at files that do not exist, so deep mode must degrade
    # to the structural verdict instead of raising.
    diff = diff_infos(
        _make_info(path=tmp_path / "missing.bin"),
        _make_info(path=tmp_path / "missing2.bin"),
        [_candidate(TEXT_VA)],
        [_candidate(TEXT_VA)],
        deep=True,
    )

    assert diff.identical is True
    assert diff.functions_changed == ()
    assert any("could not be fingerprinted" in warning for warning in diff.warnings)


def test_deep_warns_about_truncated_fingerprints(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", NOP_TEXT * 2_100)
    right = _make_code_elf(tmp_path / "right.bin", NOP_TEXT * 2_000 + RET_TEXT)

    diff = diff_binaries(left, right, deep=True)

    # Both fingerprints stop at the budget, so only the shared prefix is compared.
    assert diff.identical is True
    assert any("DEEP_MAX_INSTRUCTIONS" in warning for warning in diff.warnings)


# ---- semantic (similarity) mode ------------------------------------------


def test_semantic_pairs_identical_code_at_a_new_address(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", MOV_RET_42, entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_42, entry=0x401010)

    structural = diff_binaries(left, right)
    semantic = diff_binaries(left, right, semantic=True)

    # No shared address and no symbol name, so a structural diff reports a move
    # as one removal plus one addition.
    assert structural.identical is False
    assert [delta.address for delta in structural.functions_removed] == [0x401000]
    assert [delta.address for delta in structural.functions_added] == [0x401010]
    assert structural.functions_changed == ()
    assert "semantic" not in structural.evidence.extra

    # The very same inputs, scored, become one changed (moved) function.
    assert semantic.identical is False
    assert semantic.functions_added == ()
    assert semantic.functions_removed == ()
    assert len(semantic.functions_changed) == 1
    delta = semantic.functions_changed[0]
    assert delta.change == "changed"
    assert delta.address == 0x401010
    assert delta.name is None
    assert delta.similarity == pytest.approx(1.0)
    assert delta.left_digest is None and delta.right_digest is None
    assert delta.left is not None and delta.left["address"] == "0x401000"
    assert delta.right is not None and delta.right["address"] == "0x401010"
    detail = delta.evidence.detail or ""
    assert "similarity" in detail
    assert "0x401000" in detail
    assert "0x401010" in detail
    assert "not proof" in detail
    assert semantic.evidence.extra["semantic"] is True
    assert semantic.evidence.extra["semantic_threshold"] == DEFAULT_SEMANTIC_THRESHOLD
    assert semantic.evidence.extra["max_semantic_pairs"] == MAX_SEMANTIC_PAIRS

    # The threshold is validated on the file-loading entry point too.
    with pytest.raises(AnalysisError, match="threshold"):
        diff_binaries(left, right, semantic=True, threshold=1.01)


def test_semantic_pairing_never_overrides_an_address_match(tmp_path: Path) -> None:
    binary = _make_code_elf(tmp_path / "code.bin", MOV_RET_42)

    diff = diff_infos(
        _make_info(path=binary),
        _make_info(path=binary),
        [_candidate(TEXT_VA, "old_name")],
        [_candidate(TEXT_VA, "new_name")],
        semantic=True,
    )

    assert len(diff.functions_changed) == 1
    # The address already proved identity, so no score was needed.
    assert diff.functions_changed[0].similarity is None
    assert "similarity" not in diff.functions_changed[0].to_dict()


def test_semantic_pairs_each_leftover_once_highest_score_first(tmp_path: Path) -> None:
    block_small = bytes.fromhex("9090c3")  # nop; nop; ret
    block_large = bytes.fromhex("909090c3")  # nop; nop; nop; ret
    # Two functions per side, the second one 0x20 bytes into the section, with no
    # shared address and no name: only the scores can pair them.
    code = block_small + bytes(0x20 - len(block_small)) + block_large
    left_path = _make_code_elf(tmp_path / "left.bin", code, entry=0x401000)
    right_path = _make_code_elf(tmp_path / "right.bin", code, entry=0x402000)

    loader = BinaryLoader()
    left_info = loader.load(left_path)
    right_info = loader.load(right_path)

    diff = diff_infos(
        left_info,
        right_info,
        [_candidate(0x401000), _candidate(0x401020)],
        [_candidate(0x402000), _candidate(0x402020)],
        semantic=True,
    )

    assert diff.functions_added == ()
    assert diff.functions_removed == ()
    assert [
        (delta.left["address"], delta.right["address"])
        for delta in diff.functions_changed
        if delta.left is not None and delta.right is not None
    ] == [("0x401000", "0x402000"), ("0x401020", "0x402020")]
    assert all(delta.similarity == pytest.approx(1.0) for delta in diff.functions_changed)


def test_semantic_and_deep_modes_combine(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", MOV_RET_42, entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_42, entry=0x401010)

    diff = diff_binaries(left, right, deep=True, semantic=True)

    assert len(diff.functions_changed) == 1
    assert diff.evidence.extra["deep"] is True
    assert diff.evidence.extra["semantic"] is True
    assert diff.functions_changed[0].similarity == pytest.approx(1.0)
    # Name and address matching left nothing to fingerprint, so no digest pair.
    assert diff.functions_changed[0].left_digest is None


def test_semantic_keeps_below_threshold_leftovers_one_sided(tmp_path: Path) -> None:
    # nop; nop; ret scores 0.25 against mov eax, #; ret, far below the default.
    left = _make_code_elf(tmp_path / "left.bin", bytes.fromhex("9090c3"), entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_42, entry=0x401010)

    diff = diff_binaries(left, right, semantic=True)

    assert diff.functions_changed == ()
    assert [delta.address for delta in diff.functions_removed] == [0x401000]
    assert [delta.address for delta in diff.functions_added] == [0x401010]
    assert diff.warnings == ()


def test_semantic_pairing_is_skipped_above_the_pair_cap() -> None:
    left_functions = [_candidate(0x401000 + 0x10 * index) for index in range(65)]
    right_functions = [_candidate(0x500000 + 0x10 * index) for index in range(65)]

    diff = diff_infos(_make_info(), _make_info(), left_functions, right_functions, semantic=True)

    # 65 * 65 = 4225 pairs would exceed the cap, so nothing is scored.
    assert len(diff.functions_removed) == 65
    assert len(diff.functions_added) == 65
    assert diff.functions_changed == ()
    assert any(str(MAX_SEMANTIC_PAIRS) in warning for warning in diff.warnings)


def test_semantic_warns_when_a_pair_cannot_be_scored(tmp_path: Path) -> None:
    diff = diff_infos(
        _make_info(path=tmp_path / "missing.bin"),
        _make_info(path=tmp_path / "missing2.bin"),
        [_candidate(TEXT_VA)],
        [_candidate(TEXT_VA + 0x10)],
        semantic=True,
    )

    assert diff.functions_changed == ()
    assert [delta.address for delta in diff.functions_removed] == [TEXT_VA]
    assert [delta.address for delta in diff.functions_added] == [TEXT_VA + 0x10]
    assert any("could not be scored" in warning for warning in diff.warnings)


@pytest.mark.parametrize("threshold", [1.01, 1.5, -0.01, -1.0, float("nan")])
def test_semantic_threshold_outside_the_unit_interval_is_rejected(
    threshold: float,
) -> None:
    with pytest.raises(AnalysisError, match="threshold"):
        diff_infos(_make_info(), _make_info(), [], [], semantic=True, threshold=threshold)


def test_threshold_is_validated_even_without_semantic_matching() -> None:
    with pytest.raises(AnalysisError, match="threshold"):
        diff_infos(_make_info(), _make_info(), [], [], threshold=1.01)


def test_semantic_threshold_must_be_a_number() -> None:
    with pytest.raises(AnalysisError, match="threshold"):
        diff_infos(
            _make_info(),
            _make_info(),
            [],
            [],
            semantic=True,
            threshold="0.9",  # type: ignore[arg-type]
        )


def test_similarity_is_serialised_only_when_set(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", MOV_RET_42, entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_42, entry=0x401010)

    semantic = diff_binaries(left, right, semantic=True).to_dict()
    structural = diff_infos(_make_info(), _make_info(), [_candidate(TEXT_VA, "gone")], [])

    assert semantic["functions_changed"][0]["similarity"] == 1.0
    assert json.loads(json.dumps(semantic))["functions_changed"][0]["similarity"] == 1.0
    assert "similarity" not in structural.functions_removed[0].to_dict()


def test_semantic_reported_score_never_rounds_below_its_threshold(tmp_path: Path) -> None:
    # nop against nop;ret;hlt shares one of three tokens: exactly 1/3.
    left = _make_code_elf(tmp_path / "left.bin", bytes.fromhex("90"), entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", bytes.fromhex("90c3f4"), entry=0x401010)

    diff = diff_binaries(left, right, semantic=True, threshold=0.33333)

    assert len(diff.functions_changed) == 1
    assert diff.functions_changed[0].similarity == pytest.approx(0.3333)
    # The payload must agree with the threshold that authorised the pair.
    threshold = diff.evidence.extra["semantic_threshold"]
    assert diff.functions_changed[0].similarity >= round(threshold, 4)


def test_semantic_never_pairs_on_zero_overlap(tmp_path: Path) -> None:
    # nop and ret share no token, so a zero threshold still must not pair them.
    left = _make_code_elf(tmp_path / "left.bin", bytes.fromhex("90"), entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", bytes.fromhex("c3"), entry=0x401010)

    diff = diff_binaries(left, right, semantic=True, threshold=0.0)

    assert diff.functions_changed == ()
    assert [delta.address for delta in diff.functions_removed] == [0x401000]
    assert [delta.address for delta in diff.functions_added] == [0x401010]


def test_deep_and_semantic_caveat_names_both_modes(tmp_path: Path) -> None:
    left = _make_code_elf(tmp_path / "left.bin", MOV_RET_42, entry=0x401000)
    right = _make_code_elf(tmp_path / "right.bin", MOV_RET_42, entry=0x401010)

    diff = diff_binaries(left, right, deep=True, semantic=True)

    detail = diff.evidence.detail
    assert "instruction shapes" in detail
    assert "similarity" in detail


def test_diff_binaries_validates_threshold_before_loading(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"

    with pytest.raises(AnalysisError, match="threshold"):
        diff_binaries(missing, missing, semantic=True, threshold=2.0)
