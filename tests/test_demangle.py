"""Tests for the pure-Python symbol demangler.

Every expected output in the known-symbol table was verified by hand against
the grammar the module implements: the Itanium C++ ABI rules (source-name
lengths, nested-name ``N...E`` frames, builtin type codes, the substitution
table and the ``T_``/``S_`` abbreviations), the MSVC decorated-name format
(innermost-first ``name@@`` lists, the ``Y``/``Q`` grouping letters, ``XZ``
void encodings) and Rust v0 per RFC 2603 (crate roots, namespace tags,
length-prefixed identifiers). No fixtures, no binaries, no host execution --
these are pure string tests, so the module runs anywhere the rest of the
suite does.
"""

from __future__ import annotations

import json

import pytest

from codevanta.analysis.demangle import (
    DEFAULT_MAX_SYMBOLS,
    MAX_NAME_CHARS,
    MAX_SYMBOLS,
    DemangleResult,
    DemangleSummary,
    demangle_symbol,
    demangle_symbols,
    detect_scheme,
)
from codevanta.core.report import AnalysisError

# ---- the known-symbol table (hand-verified expectations) -------------------

#: (symbol, scheme, expected demangled, complete)
KNOWN_SYMBOLS = [
    # Itanium: data symbols (a nested name with no argument types).
    ("_ZN3foo3barE", "itanium", "foo::bar", True),
    ("_ZN9wikipedia7article6formatE", "itanium", "wikipedia::article::format", True),
    # Itanium: functions with argument and return types.
    ("_Z3fooi", "itanium", "foo(int)", True),
    ("_ZN3foo3barEi", "itanium", "foo::bar(int)", True),
    ("_Z9hyperbolaif", "itanium", "hyperbola(int, float)", True),
    ("_Z3foov", "itanium", "foo()", True),
    # Itanium: operators and constructor/destructor specials.
    ("_ZdlPv", "itanium", "operator delete(void*)", True),
    ("_ZN4BaseC1Ev", "itanium", "Base::Base()", True),
    ("_ZN4BaseD1Ev", "itanium", "Base::~Base()", True),
    # Itanium: std:: names, template args, well-known substitution, T_/S0_.
    (
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "itanium",
        "std::vector<int, std::allocator<int>>::push_back(int const&)",
        True,
    ),
    ("_Z3addIiET_S0_", "itanium", "int add<int>(int)", True),
    # MSVC: free function with __cdecl, member function (x64 __ptr64 slots).
    ("?foo@@YAXH@Z", "msvc", "void __cdecl foo(int)", True),
    ("?foo@Bar@@QEAAXXZ", "msvc", "public: void Bar::foo(void)", True),
    # Rust legacy: Itanium-shaped with the 17h<hash> suffix.
    (
        "_ZN4main17h0e6d2e2c8b3f1a9aE",
        "rust-legacy",
        "main::h0e6d2e2c8b3f1a9a",
        True,
    ),
    # Rust v0 (RFC 2603): nested paths over a crate root with disambiguator.
    (
        "_RNvNtNtCs1234_7mycrate3foo3bar3baz",
        "rust-v0",
        "mycrate::foo::bar::baz",
        True,
    ),
    ("_RNvNvCs1234_7mycrate4QUUX3FOO", "rust-v0", "mycrate::QUUX::FOO", True),
]


@pytest.mark.parametrize(("symbol", "scheme", "expected", "complete"), KNOWN_SYMBOLS)
def test_known_symbols_decode_exactly(
    symbol: str, scheme: str, expected: str, complete: bool
) -> None:
    result = demangle_symbol(symbol)
    assert result.scheme == scheme
    assert result.demangled == expected
    assert result.complete is complete
    assert result.evidence.source == "demangle.symbol"


# ---- honest partials: decoded prefix kept, gap named -----------------------


def test_itanium_function_type_is_partial_not_guessed() -> None:
    # `_Z3fooPFivE`: the argument is a pointer to `int ()`, a function type.
    result = demangle_symbol("_Z3fooPFivE")
    assert result.scheme == "itanium"
    assert result.demangled == "foo"
    assert result.complete is False
    assert "function types (F...E) are not decoded" in result.notes


def test_itanium_local_names_are_named_not_guessed() -> None:
    result = demangle_symbol("_ZZ4mainE1x")
    assert result.scheme == "itanium"
    assert result.demangled is None
    assert result.complete is False
    assert "local names" in result.notes[0]


def test_itanium_nesting_depth_cap_fires_honestly() -> None:
    deep = "_ZN" + "3foo" * 40 + "E"
    result = demangle_symbol(deep)
    assert result.scheme == "itanium"
    assert result.complete is False
    assert any("nesting deeper" in note for note in result.notes)
    assert result.demangled is not None  # the sound prefix is kept
    assert result.demangled.count("foo") == 32


def test_msvc_substitution_codes_are_partial_not_guessed() -> None:
    # `?foo@@YAX01@Z`: arguments are MSVC substitution codes.
    result = demangle_symbol("?foo@@YAX01@Z")
    assert result.scheme == "msvc"
    assert result.demangled == "foo"
    assert result.complete is False
    assert "substitution code '0'" in result.notes[0]


def test_msvc_constructor_special_decodes_to_the_name_only() -> None:
    # `??0Bar@foo@@QEAA@AEBV01@@Z`: ctor of foo::Bar; args need substitutions.
    result = demangle_symbol("??0Bar@foo@@QEAA@AEBV01@@Z")
    assert result.scheme == "msvc"
    assert result.demangled == "public: foo::Bar::Bar"
    assert result.complete is False


def test_rust_v0_backref_compression_is_partial_not_guessed() -> None:
    # A path that *is* a backref: nothing sound to decode, the gap is named.
    result = demangle_symbol("_RNvB4_3bar")
    assert result.scheme == "rust-v0"
    assert result.demangled is None
    assert result.complete is False
    assert "backref compression (B...) is not decoded" in result.notes[0]


def test_rust_v0_generic_args_stop_before_the_compression() -> None:
    # RFC 2603 compressed-prefix example: the base path is sound, the
    # generic-argument body (which needs backrefs) is not decoded.
    result = demangle_symbol("_RINvCs1234_7mycrate3fooNvB4_3barNvBn_3bazE")
    assert result.scheme == "rust-v0"
    assert result.demangled == "mycrate::foo"
    assert result.complete is False
    assert "generic arguments (I...E) are not decoded" in result.notes[0]


def test_rust_v0_impl_paths_are_partial_not_guessed() -> None:
    result = demangle_symbol("_RNvNvMCs1234_7mycrateINtCs1234_7mycrate3FoopE3bar4QUUX")
    assert result.scheme == "rust-v0"
    assert result.demangled == "mycrate"
    assert result.complete is False
    assert "impl paths" in result.notes[-1]


def test_swift_is_always_an_honest_best_effort() -> None:
    result = demangle_symbol("_$s4main3FooC")
    assert result.scheme == "swift"
    assert result.demangled == "main.Foo"
    assert result.complete is False
    assert "class (C)" in result.notes[0]

    fn = demangle_symbol("_$s4main4mainyyF")
    assert fn.demangled == "main.main"
    assert "function (F)" in fn.notes[0]
    assert "'yy' not decoded" in fn.notes[0]


def test_swift_legacy_prefix_is_reported() -> None:
    result = demangle_symbol("__T4main4mainF")
    assert result.scheme == "swift"
    assert "legacy (pre-Swift 5) mangling prefix" in result.notes[0]
    assert result.demangled == "main.main"


def test_unknown_input_is_not_an_error() -> None:
    result = demangle_symbol("hello_world")
    assert result.scheme == "unknown"
    assert result.demangled is None
    assert result.complete is False
    assert result.notes


def test_scheme_but_no_decode_is_still_that_scheme() -> None:
    # Looks Itanium, decodes to nothing: the prefix test result is kept.
    result = demangle_symbol("_Z")
    assert result.scheme == "itanium"
    assert result.demangled is None
    assert result.complete is False


def test_detect_scheme_prefixes() -> None:
    assert detect_scheme("_Z3fooi") == "itanium"
    assert detect_scheme("__ZN3foo3barE") == "itanium"
    assert detect_scheme("?foo@@YAXH@Z") == "msvc"
    assert detect_scheme("_RNvCs1234_7mycrate") == "rust-v0"
    assert detect_scheme("_ZN4main17h0e6d2e2c8b3f1a9aE") == "rust-legacy"
    assert detect_scheme("_$s4main4mainyyF") == "swift"
    assert detect_scheme("__T4main4mainF") == "swift"
    assert detect_scheme("plain_name") == "unknown"


# ---- typed errors: caller mistakes only ------------------------------------


@pytest.mark.parametrize("bad", [123, None, 4.5, b"_Z3fooi", ""])
def test_demangle_symbol_typed_errors(bad: object) -> None:
    with pytest.raises(AnalysisError):
        demangle_symbol(bad)  # type: ignore[arg-type]


def test_oversized_symbol_is_a_typed_error() -> None:
    with pytest.raises(AnalysisError, match="too long"):
        demangle_symbol("x" * (MAX_NAME_CHARS + 1))


def test_demangle_symbols_rejects_non_sequences() -> None:
    with pytest.raises(AnalysisError):
        demangle_symbols(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        demangle_symbols("_Z3fooi")  # a bare string is not a batch


def test_demangle_symbols_rejects_bad_items_and_bounds() -> None:
    with pytest.raises(AnalysisError, match="symbol 1"):
        demangle_symbols(["_Z3fooi", ""])
    with pytest.raises(AnalysisError, match="symbol 0"):
        demangle_symbols([7, "_Z3fooi"])  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="max_count"):
        demangle_symbols(["_Z3fooi"], max_count=0)
    with pytest.raises(AnalysisError, match="max_count"):
        demangle_symbols(["_Z3fooi"], max_count=MAX_SYMBOLS + 1)


# ---- batch summary ---------------------------------------------------------


def test_batch_summary_counts_and_order() -> None:
    summary = demangle_symbols(
        [
            "_Z3fooi",
            "?foo@Bar@@QEAAXXZ",
            "_ZN4main17h0e6d2e2c8b3f1a9aE",
            "_RCs1234_7mycrate",
            "hello_world",
            "_Z3barf",
        ]
    )
    assert isinstance(summary, DemangleSummary)
    assert summary.to_dict()["total"] == 6
    assert summary.counts == {
        "itanium": 2,
        "msvc": 1,
        "rust-legacy": 1,
        "rust-v0": 1,
        "unknown": 1,
    }
    assert summary.truncated is False
    assert summary.complete_count == 5
    assert [r.input for r in summary.results] == [
        "_Z3fooi",
        "?foo@Bar@@QEAAXXZ",
        "_ZN4main17h0e6d2e2c8b3f1a9aE",
        "_RCs1234_7mycrate",
        "hello_world",
        "_Z3barf",
    ]


def test_batch_truncates_at_max_count_with_a_warning() -> None:
    symbols = ["_Z3fooi", "_Z3barf", "_Z3bazz"] * 3
    summary = demangle_symbols(symbols, max_count=4)
    assert len(summary.results) == 4
    assert summary.truncated is True
    assert summary.warnings
    assert "max_count=4" in summary.warnings[0]
    assert summary.counts == {"itanium": 4}


def test_batch_caps_at_max_symbols() -> None:
    symbols = ["_Z3fooi"] * (MAX_SYMBOLS + 10)
    summary = demangle_symbols(symbols, max_count=MAX_SYMBOLS)
    assert len(summary.results) == MAX_SYMBOLS
    assert summary.truncated is True


def test_default_max_count_is_the_documented_constant() -> None:
    assert DEFAULT_MAX_SYMBOLS == 64


# ---- serialization ---------------------------------------------------------


def test_result_to_dict_is_json_safe_for_every_scheme() -> None:
    symbols = [
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "?foo@Bar@@QEAAXXZ",
        "_ZN4main17h0e6d2e2c8b3f1a9aE",
        "_RNvNtNtCs1234_7mycrate3foo3bar3baz",
        "_$s4main4mainyyF",
        "hello_world",
        "_Z3fooPFivE",  # partial
    ]
    for symbol in symbols:
        result = demangle_symbol(symbol)
        assert isinstance(result, DemangleResult)
        reloaded = json.loads(json.dumps(result.to_dict()))
        assert reloaded["input"] == symbol
        assert reloaded["scheme"] == result.scheme
        assert reloaded["demangled"] == result.demangled
        assert reloaded["complete"] == result.complete
        assert isinstance(reloaded["notes"], list)
        assert reloaded["evidence"]["source"] == "demangle.symbol"
        assert reloaded["evidence"]["method"] == "pure_python_parser"
        assert reloaded["evidence"]["confidence"] in (
            "high",
            "medium",
            "low",
            "certain",
            "unknown",
        )


def test_summary_to_dict_is_json_safe() -> None:
    summary = demangle_symbols(["_Z3fooi", "?foo@@YAXH@Z", "nope"])
    reloaded = json.loads(json.dumps(summary.to_dict()))
    assert reloaded["total"] == 3
    assert reloaded["counts"] == {"itanium": 1, "msvc": 1, "unknown": 1}
    assert reloaded["complete"] == 2
    assert reloaded["truncated"] is False
    assert len(reloaded["results"]) == 3
    assert reloaded["evidence"]["confidence"] == "medium"


def test_complete_decodes_carry_high_confidence_evidence() -> None:
    result = demangle_symbol("_Z3fooi")
    assert result.evidence.confidence.value == "high"
    partial = demangle_symbol("_Z3fooPFivE")
    assert partial.evidence.confidence.value == "low"
