"""Pure-Python, offline demangler for the common C++/Rust/Swift mangling schemes.

Symbol tables, crash logs and export lists are full of mangled names --
``_ZNSt6vectorIiSaIiEE9push_backERKi`` instead of
``std::vector<int, std::allocator<int>>::push_back(int const&)``. This module
turns them back into readable declarations without shelling out to
``c++filt``, ``llvm-cxxfilt`` or any other external tool: the parsers here are
bounded recursive-descent decoders written against the public grammar of each
scheme (Itanium C++ ABI, MSVC decorated names, Rust legacy/v0 per RFC 2603 and
the Swift mangling prefixes).

Schemes and coverage
--------------------
* **itanium** (``_Z...``): nested names, source names, common operators,
  constructors/destructors, builtin/composite types (pointer, reference,
  const/volatile, arrays), template arguments and the well-known
  substitution abbreviations (``S_``, ``Sa``..``St``) plus numbered
  substitutions, all under hard depth/argument caps.
* **msvc** (``?...@@``): qualified names, free and member functions, the
  common builtin types, pointers/references, ``__cdecl``/``__stdcall``/
  ``__fastcall`` on free functions. Constructor specials (``??0``/``??1``)
  decode to the name only. Substitution codes, templates and throw specs are
  honestly reported as unsupported instead of guessed.
* **rust-legacy** (``_ZN...17h<hash>E``): decoded through the Itanium path;
  the legacy hash suffix is a plain source name and survives verbatim.
* **rust-v0** (``_R...``, RFC 2603): crate roots, nested paths with namespace
  tags and length-prefixed identifiers (including disambiguator stripping).
  Generic arguments, impl paths and backref compression are reported as
  unsupported -- the decoded prefix is kept, never invented.
* **swift** (``_$s...`` / ``__T...``): best-effort only. Leading
  length-prefixed identifiers (module/declaration names) and the trailing
  entity-kind letter (function/class/struct/...) are decoded; everything
  else in the Swift type encoding is reported as not decoded.

Honesty contract
----------------
A partial decode is *better* than a guessed one: when a construct is not
supported the parser stops, keeps whatever prefix it decoded soundly,
reports ``complete=False`` and names the offending construct in ``notes``.
Unknown or non-mangled input is not an error either -- it comes back as
``scheme="unknown"`` with ``demangled=None`` and an explanatory note.
:class:`~codevanta.core.report.AnalysisError` is raised *only* for caller
mistakes: a non-string, an empty string or an oversized symbol.

Guarantees
----------
* **Offline.** Pure string parsing on the host; no subprocess, no network.
* **Bounded.** Symbol count, symbol length, nesting depth, argument count
  and output length all carry hard caps (:data:`MAX_SYMBOLS`,
  :data:`MAX_NAME_CHARS`, :data:`MAX_DEPTH`, :data:`MAX_ARGS`); every cap
  that fires is reported in ``notes`` or ``warnings`` -- never silently.
* **Honest.** ``complete`` is True only when the whole input was consumed
  by the grammar with no cap and no unsupported construct on the way.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_SYMBOLS",
    "MAX_ARGS",
    "MAX_DEPTH",
    "MAX_NAME_CHARS",
    "MAX_SYMBOLS",
    "DemangleResult",
    "DemangleSummary",
    "demangle_symbol",
    "demangle_symbols",
    "detect_scheme",
]


# ---- limits ----------------------------------------------------------------

#: Symbols demangled when the caller does not pass ``max_count``.
DEFAULT_MAX_SYMBOLS = 64

#: Hard ceiling on batch size (bounded work, whatever the caller asks).
MAX_SYMBOLS = 256

#: Hard ceiling on the length of one input symbol; longer input is a caller
#: mistake (a typed error), not a truncation.
MAX_NAME_CHARS = 256

#: Maximum nesting depth (nested names, template arguments, composite types).
MAX_DEPTH = 32

#: Maximum number of function arguments decoded for one symbol.
MAX_ARGS = 64

#: Maximum number of template arguments decoded per template-args group.
MAX_TEMPLATE_ARGS = 32

#: Evidence identity shared by every result in this module.
_EVIDENCE_SOURCE = "demangle.symbol"
_EVIDENCE_METHOD = "pure_python_parser"

#: Schemes a result can report.
SCHEMES = ("itanium", "msvc", "rust-legacy", "rust-v0", "swift", "unknown")

#: The Rust legacy mangling is Itanium-shaped plus a fixed-length hash suffix
#: (a source name of length 17: ``h`` + 16 hex digits) at the very end.
_LEGACY_RUST_HASH = re.compile(r"17h[0-9a-fA-F]{16}E$")


# ---- records ---------------------------------------------------------------


@dataclass(frozen=True)
class DemangleResult:
    """The outcome of demangling one symbol.

    Attributes:
        input: The symbol exactly as given.
        scheme: One of :data:`SCHEMES`; ``"unknown"`` when no known mangling
            prefix matched (never an error, see the honesty contract).
        demangled: The decoded declaration, or ``None`` when nothing could be
            decoded soundly (unknown scheme, or failure before any prefix).
        complete: True only when the whole input was consumed by the grammar
            with no cap and no unsupported construct on the way.
        notes: What was truncated, skipped or not decoded, one item each.
        evidence: Provenance for this decode.
    """

    input: str
    scheme: str
    demangled: str | None
    complete: bool
    notes: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "input": self.input,
            "scheme": self.scheme,
            "demangled": self.demangled,
            "complete": self.complete,
            "notes": list(self.notes),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class DemangleSummary:
    """The bounded result of demangling a batch of symbols.

    Attributes:
        results: One :class:`DemangleResult` per demangled symbol, in input
            order, capped by ``max_count``.
        counts: Decoded-count per scheme, including ``"unknown"``.
        truncated: True when the input list was longer than ``max_count``;
            the tail symbols were not demangled (and said so in warnings).
        warnings: Every degradation, bounded by ``MAX_SYMBOLS`` items.
        evidence: Provenance for the whole batch.
    """

    results: tuple[DemangleResult, ...]
    counts: dict[str, int]
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    @property
    def complete_count(self) -> int:
        """How many results decoded completely."""
        return sum(1 for result in self.results if result.complete)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "total": len(self.results),
            "counts": dict(sorted(self.counts.items())),
            "complete": self.complete_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "results": [result.to_dict() for result in self.results],
            "evidence": self.evidence.to_dict(),
        }


# ---- scheme detection ------------------------------------------------------


def detect_scheme(symbol: str) -> str:
    """Return the mangling scheme suggested by ``symbol``'s prefix.

    This is a cheap prefix test, not a parse: a symbol may report a scheme
    yet still fail to decode, which the result carries honestly.
    """
    if symbol.startswith("_$s") or symbol.startswith("__T"):
        return "swift"
    if symbol.startswith("_R"):
        return "rust-v0"
    if symbol.startswith("_ZN") and _LEGACY_RUST_HASH.search(symbol):
        return "rust-legacy"
    if symbol.startswith("_Z") or symbol.startswith("__Z"):
        return "itanium"
    if symbol.startswith("?"):
        return "msvc"
    return "unknown"


# ---- internal parse errors -------------------------------------------------


class _MalformedError(Exception):
    """The input violates the grammar at the current position."""


class _UnsupportedError(Exception):
    """A construct this bounded decoder deliberately does not decode."""


class _CapExceededError(Exception):
    """A bounded budget (depth, arguments) fired."""


# ---- Itanium C++ ABI -------------------------------------------------------

#: Builtin type codes (Itanium ABI Â§5.1.9.1); ``Dn`` is the two-char code.
_ITANIUM_BUILTINS: dict[str, str] = {
    "v": "void",
    "b": "bool",
    "w": "wchar_t",
    "c": "char",
    "a": "signed char",
    "h": "unsigned char",
    "s": "short",
    "t": "unsigned short",
    "i": "int",
    "j": "unsigned int",
    "l": "long",
    "m": "unsigned long",
    "x": "long long",
    "y": "unsigned long long",
    "n": "__int128",
    "o": "unsigned __int128",
    "f": "float",
    "d": "double",
    "e": "long double",
    "g": "__float128",
    "z": "...",
    "Dn": "std::nullptr_t",
}

#: The well-known substitution abbreviations (Itanium ABI Â§5.1.7.3). ``S_``
#: and ``S<n>_`` index the substitution table itself; these spell fixed
#: ``std::``-namespace entities regardless of the table's state.
_ITANIUM_WELLKNOWN: dict[str, str] = {
    "a": "std::allocator",
    "b": "std::basic_string",
    "s": "std::string",
    "i": "std::istream",
    "o": "std::ostream",
    "d": "std::iostream",
    "t": "std::",
}

#: Operator-name codes decoded as plain names (Itanium ABI Â§5.1.5.1).
_ITANIUM_OPERATORS: dict[str, str] = {
    "nw": "operator new",
    "na": "operator new[]",
    "dl": "operator delete",
    "da": "operator delete[]",
    "ps": "operator+",
    "ng": "operator-",
    "ad": "operator&",
    "de": "operator*",
    "co": "operator~",
    "pl": "operator+",
    "mi": "operator-",
    "ml": "operator*",
    "dv": "operator/",
    "rm": "operator%",
    "an": "operator&",
    "or": "operator|",
    "eo": "operator^",
    "aS": "operator=",
    "pL": "operator+=",
    "mI": "operator-=",
    "mL": "operator*=",
    "dV": "operator/=",
    "rM": "operator%=",
    "aN": "operator&=",
    "oR": "operator|=",
    "eX": "operator^=",
    "aO": "operator<<=",
    "aR": "operator>>=",
    "ne": "operator!=",
    "eq": "operator==",
    "lt": "operator<",
    "gt": "operator>",
    "le": "operator<=",
    "ge": "operator>=",
    "ss": "operator<=>",
    "nt": "operator!",
    "aa": "operator&&",
    "oo": "operator||",
    "pp": "operator++",
    "mm": "operator--",
    "cm": "operator,",
    "pm": "operator->*",
    "pt": "operator->",
    "cl": "operator()",
    "ix": "operator[]",
    "qu": "operator?",
}


class _ItaniumParser:
    """Bounded recursive-descent decoder for ``_Z...`` (Itanium C++ ABI).

    Rendering follows the GNU ``c++filt`` conventions: ``::`` between name
    components, ``", "`` between template/argument types, ``const``/``&``/
    ``*`` suffixed onto the type text. The substitution table is kept per the
    ABI rules (prefixes of nested names, non-builtin types, template
    parameters); a reference the table cannot answer is an honest
    :class:`_UnsupportedError`, never a guess.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.depth = 0
        self.subs: list[str] = []
        self.template_args: list[str] | None = None
        self.partial = ""
        self.args_seen = 0

    # -- low-level cursor helpers

    def _eof(self) -> bool:
        return self.pos >= len(self.text)

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _peek_at(self, offset: int) -> str:
        position = self.pos + offset
        return self.text[position] if position < len(self.text) else ""

    def _take(self) -> str:
        char = self._peek()
        self.pos += 1
        return char

    def _expect(self, char: str) -> None:
        if self._take() != char:
            raise _MalformedError(f"expected {char!r} at position {self.pos - 1}")

    def _enter(self, what: str) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise _CapExceededError(f"{what} nesting deeper than the {MAX_DEPTH}-level cap")

    def _leave(self) -> None:
        self.depth -= 1

    # -- grammar

    def parse_encoding(self) -> str:
        """``<encoding> ::= <name> [<bare-function-type>]``."""
        name, had_template_args = self.parse_name()
        self.partial = name
        if self._eof():
            return name
        types = self.parse_type_list()
        if had_template_args:
            # Template functions mangle their return type first (ABI Â§5.1.8.1).
            ret, params = types[0], types[1:]
            head = f"{ret} " if ret else ""
        else:
            head, params = "", types
        # A lone void is the standard spelling of "no parameters".
        if params == ["void"]:
            params = []
        rendered = f"{head}{name}({', '.join(params)})"
        self.partial = rendered
        return rendered

    def parse_name(self) -> tuple[str, bool]:
        """``<name> ::= <nested-name> | <unscoped-name> [<template-args>]``.

        Returns ``(rendered name, had template args)`` -- the flag decides
        whether the following type list starts with the return type.
        """
        if self._peek() == "N":
            return self.parse_nested_name(), False
        if self._peek() == "Z":
            raise _UnsupportedError("local names (Z...E) are not decoded")
        if self.text.startswith("St", self.pos):
            self.pos += 2
            self.subs.append("std::")
            name = "std::" + self.parse_unqualified_name()
            self.partial = name
            had_args = False
            if self._peek() == "I":
                name = f"{name}<{self.parse_template_args()}>"
                had_args = True
            self.subs.append(name)
            return name, had_args
        name = self.parse_unqualified_name()
        self.partial = name
        if self._peek() == "I":
            name = f"{name}<{self.parse_template_args()}>"
            self.partial = name
            return name, True
        return name, False

    def parse_nested_name(self) -> str:
        """``N [<quals>] <prefix>* <unqualified-name> E``."""
        self._expect("N")
        self._enter("name")
        try:
            quals = ""
            while self._peek() in ("K", "V", "R", "O"):
                quals += self._take()
            if quals:
                self.partial = f"(name qualifiers {quals} not rendered)"
            acc = ""
            last_name: str | None = None
            components = 0
            while self._peek() != "E":
                if self._eof():
                    raise _MalformedError(f"unterminated nested name at position {self.pos}")
                components += 1
                if components > MAX_DEPTH:
                    raise _CapExceededError(
                        f"name nesting deeper than the {MAX_DEPTH}-level cap"
                    )
                char = self._peek()
                if char == "S":
                    acc = self._join(acc, self.parse_substitution())
                elif char == "T":
                    acc = self._join(acc, self.parse_template_param())
                elif char.isdigit():
                    comp = self.parse_source_name()
                    last_name = comp
                    acc = self._join(acc, comp)
                elif char == "I":
                    args = self.parse_template_args()
                    acc = f"{acc}<{args}>"
                    last_name = None
                elif char == "C" and self._peek_at(1) in ("1", "2"):
                    if last_name is None:
                        raise _MalformedError(
                            f"constructor with no enclosing class at position {self.pos}"
                        )
                    self.pos += 2
                    # The constructor replaces the last class component.
                    if acc == last_name:
                        prefix = ""
                    elif acc.endswith("::" + last_name):
                        prefix = acc[: -(len(last_name) + 2)]
                    else:
                        prefix = acc
                    acc = self._join(prefix, f"{last_name}::{last_name}")
                    last_name = None
                elif char == "D" and self._peek_at(1) in ("0", "1"):
                    if last_name is None:
                        raise _MalformedError(
                            f"destructor with no enclosing class at position {self.pos}"
                        )
                    self.pos += 2
                    if acc == last_name:
                        prefix = ""
                    elif acc.endswith("::" + last_name):
                        prefix = acc[: -(len(last_name) + 2)]
                    else:
                        prefix = acc
                    acc = self._join(prefix, f"{last_name}::~{last_name}")
                    last_name = None
                else:
                    acc = self._join(acc, self.parse_unqualified_name())
                self.partial = acc
                self.subs.append(acc)
            self._take()  # E
            return acc
        finally:
            self._leave()

    def parse_source_name(self) -> str:
        """``<source-name> ::= <length> <identifier>``."""
        start = self.pos
        while self._peek().isdigit():
            self.pos += 1
        if self.pos == start:
            raise _MalformedError(f"expected a length prefix at position {self.pos}")
        length = int(self.text[start : self.pos])
        if self.pos + length > len(self.text):
            raise _MalformedError(
                f"identifier length {length} overruns the input at position {start}"
            )
        name = self.text[self.pos : self.pos + length]
        self.pos += length
        return name

    def parse_unqualified_name(self) -> str:
        """``<unqualified-name> ::= <source-name> | <operator-name> | ...``."""
        char = self._peek()
        if char.isdigit():
            return self.parse_source_name()
        two = self.text[self.pos : self.pos + 2]
        if two in _ITANIUM_OPERATORS:
            self.pos += 2
            return _ITANIUM_OPERATORS[two]
        if two == "cv":
            raise _UnsupportedError("conversion operators (cv<type>) are not decoded")
        raise _MalformedError(f"unsupported unqualified-name at position {self.pos}")

    def _join(self, acc: str, comp: str) -> str:
        """Append ``comp`` to the rendered prefix, ``::``-separated."""
        if not acc:
            return comp
        if acc.endswith("::"):  # the well-known "std::" prefix
            return acc + comp
        return f"{acc}::{comp}"

    def parse_template_args(self) -> str:
        """``I <type>+ E`` rendered as ``<a, b>``, resolving ``T_`` refs."""
        self._expect("I")
        self._enter("template arguments")
        saved = self.template_args
        self.template_args = []
        try:
            args: list[str] = []
            while self._peek() != "E":
                if self._eof():
                    raise _MalformedError(
                        f"unterminated template arguments at position {self.pos}"
                    )
                if len(args) >= MAX_TEMPLATE_ARGS:
                    raise _CapExceededError(
                        f"more than the {MAX_TEMPLATE_ARGS} template arguments cap"
                    )
                text, builtin = self.parse_type()
                args.append(text)
                if not builtin:
                    self.subs.append(text)
        except BaseException:
            self.template_args = saved
            self.depth -= 1
            raise
        self._take()  # E
        # Keep the decoded args visible for T_ references that follow.
        self.template_args = args
        self.depth -= 1
        return ", ".join(args)

    def parse_template_param(self) -> str:
        """``T_`` / ``T<n>_`` resolved against the enclosing template args."""
        self._expect("T")
        if self._peek() == "_":
            self._take()
            index = 0
        else:
            start = self.pos
            while self._peek().isdigit():
                self.pos += 1
            if self.pos == start:
                raise _MalformedError(f"malformed template parameter at position {self.pos}")
            index = int(self.text[start : self.pos]) + 1
            self._expect("_")
        args = self.template_args
        if args is None or index >= len(args):
            raise _UnsupportedError(
                f"template parameter T{index} has no decoded template-args to answer it"
            )
        text = args[index]
        self.subs.append(text)
        return text

    def parse_substitution(self) -> str:
        """``S_``, ``S<n>_`` or a well-known ``S<a|b|s|i|o|d|t>``."""
        self._expect("S")
        char = self._peek()
        if char in _ITANIUM_WELLKNOWN:
            self.pos += 1
            return _ITANIUM_WELLKNOWN[char]
        if char == "_":
            self._take()
            if not self.subs:
                raise _UnsupportedError("substitution table is empty")
            return self.subs[-1]
        start = self.pos
        while self._peek().isdigit():
            self.pos += 1
        if self.pos == start:
            raise _MalformedError(f"malformed substitution at position {self.pos}")
        index = int(self.text[start : self.pos])
        self._expect("_")
        if index >= len(self.subs):
            raise _UnsupportedError(
                f"substitution S{index}_ is beyond the {len(self.subs)}-entry table"
            )
        return self.subs[index]

    # -- types

    def parse_type(self) -> tuple[str, bool]:
        """One ``<type>``; returns ``(rendered text, is bare builtin)``."""
        self._enter("type")
        try:
            char = self._peek()
            if char == "D" and self._peek_at(1) == "n":
                self.pos += 2
                return "std::nullptr_t", True
            if char in _ITANIUM_BUILTINS:
                self.pos += 1
                return _ITANIUM_BUILTINS[char], True
            if char in ("P", "R", "O", "K", "V"):
                self.pos += 1
                target, _ = self.parse_type()
                suffix = {
                    "P": "*",
                    "R": "&",
                    "O": "&&",
                    "K": " const",
                    "V": " volatile",
                }[char]
                text = target + suffix
                self.subs.append(text)
                return text, False
            if char == "A":
                self.pos += 1
                start = self.pos
                while self._peek().isdigit():
                    self.pos += 1
                count = self.text[start : self.pos]
                if not count:
                    raise _UnsupportedError(
                        "array bound expressions (A <expr> _) are not decoded"
                    )
                self._expect("_")
                target, _ = self.parse_type()
                text = f"{target}[{count}]"
                self.subs.append(text)
                return text, False
            if char == "F":
                raise _UnsupportedError("function types (F...E) are not decoded")
            if char == "M":
                raise _UnsupportedError("pointer-to-member types (M...) are not decoded")
            if char == "T":
                return self.parse_template_param(), False
            if char == "S":
                text = self.parse_maybe_template_args(self.parse_substitution())
                return text, False
            if char in ("N",) or char.isdigit():
                return self.parse_named_type(), False
            raise _MalformedError(
                f"unsupported type character {char!r} at position {self.pos}"
            )
        finally:
            self._leave()

    def parse_maybe_template_args(self, base: str) -> str:
        """Append ``<args>`` to a named base when ``I`` follows."""
        if self._peek() == "I":
            args = self.parse_template_args()
            text = f"{base}<{args}>"
            self.subs.append(text)
            return text
        return base

    def parse_named_type(self) -> str:
        """A class/enum type: nested name or source name plus template args."""
        if self._peek() == "N":
            return self.parse_nested_name()
        text = self.parse_unqualified_name()
        self.partial = text
        return self.parse_maybe_template_args(text)

    def parse_type_list(self) -> list[str]:
        """The types up to end of input, under the argument cap."""
        types: list[str] = []
        while not self._eof():
            if len(types) >= MAX_ARGS:
                raise _CapExceededError(f"more than the {MAX_ARGS}-argument cap; args truncated")
            types.append(self.parse_type()[0])
        return types


def _demangle_itanium(body: str) -> tuple[str | None, bool, str]:
    """Decode the text after ``_Z``; returns ``(demangled, complete, note)``.

    On failure the best sound prefix decoded so far is kept (``""`` becomes
    ``None``) and the reason is returned as the note.
    """
    parser = _ItaniumParser(body)
    try:
        demangled = parser.parse_encoding()
        if parser._eof():
            return demangled, True, ""
        rest = parser.text[parser.pos :]
        return demangled, False, f"{len(rest)} trailing character(s) not decoded: {rest!r}"
    except _UnsupportedError as exc:
        return parser.partial or None, False, str(exc)
    except _CapExceededError as exc:
        return parser.partial or None, False, str(exc)
    except _MalformedError as exc:
        return parser.partial or None, False, f"decode failed: {exc}"


# ---- MSVC decorated names --------------------------------------------------

#: Builtin type codes (MSDN "Format of a C++ decorated name"); ``_``-prefixed
#: two-letter codes are handled by :meth:`_MsvcParser._parse_type`.
_MSVC_BUILTINS: dict[str, str] = {
    "X": "void",
    "D": "char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
    "O": "long double",
    "W": "wchar_t",
    "_N": "bool",
    "_J": "__int64",
    "_K": "unsigned __int64",
}

#: Free-function calling-convention letters (the slot after ``Y``).
_MSVC_CC: dict[str, str] = {"A": "__cdecl", "G": "__stdcall", "I": "__fastcall"}

#: Member-function access letters (``Q`` ``R`` ``S``).
_MSVC_ACCESS: dict[str, str] = {
    "Q": "public:",
    "R": "protected:",
    "S": "private:",
}


class _MsvcParser:
    """Bounded decoder for ``?...@@`` MSVC decorated names.

    Deliberately narrow: qualified names, free/member functions, the common
    builtins, pointers/references and class-name types. Substitution codes,
    templates, throw specs and the exotic storage classes are *named* as
    unsupported instead of being guessed -- an MSVC symbol that needs them
    comes back partial with a note.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.partial = ""

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _peek_at(self, offset: int) -> str:
        position = self.pos + offset
        return self.text[position] if position < len(self.text) else ""

    def _take(self) -> str:
        char = self._peek()
        self.pos += 1
        return char

    def _eof(self) -> bool:
        return self.pos >= len(self.text)

    def parse_symbol(self) -> tuple[str, list[str]]:
        """``? [<special>] <qualified-name> <info> <return-type> <args> Z``."""
        if self._take() != "?":
            raise _MalformedError("MSVC decorated names start with '?'")
        ctor = False
        dtor = False
        if self._peek() == "?" and self._peek_at(1) in ("0", "1"):
            self._take()  # the special marker '?'
            code = self._take()  # '0' constructor, '1' destructor
            ctor = code == "0"
            dtor = not ctor
        names = self.parse_name_parts()
        rendered = "::".join(reversed(names))
        if ctor:
            rendered = f"{rendered}::{names[0]}"
        elif dtor:
            rendered = f"{rendered}::~{names[0]}"
        self.partial = rendered
        return self.parse_info(rendered)

    def parse_name_parts(self) -> list[str]:
        """``name@name@@`` -- parts innermost first, terminated by ``@@``."""
        parts: list[str] = []
        while True:
            end = self.text.find("@", self.pos)
            if end < 0:
                raise _MalformedError("unterminated name list (no '@')")
            parts.append(self.text[self.pos : end])
            self.pos = end + 1
            if self._peek() == "@":
                self._take()
                return parts
            if self.pos >= len(self.text):
                raise _MalformedError("unterminated name list")

    def parse_info(self, rendered: str) -> tuple[str, list[str]]:
        """The grouping letters plus return type and arguments.

        Returns ``(rendered symbol, notes)``; non-empty notes mark the symbol
        as honestly partial. Free functions carry ``Y <cc>``; non-static
        member functions carry four letters (access plus three attribute
        slots -- ``?foo@Bar@@QEAAXXZ``). Calling conventions and function
        attributes are consumed but deliberately not rendered; an exotic
        attribute letter is named in a note instead of silently dropped.
        """
        notes: list[str] = []
        char = self._take()
        if char == "Y":
            cc = _MSVC_CC.get(self._take())
            if cc is None:
                notes.append("calling convention of the free function not decoded")
            ret = self._parse_type(notes)
            args = self._parse_params(notes)
            if self._take() != "Z":
                notes.append("throw specification not decoded")
            head = f"{ret} {cc} " if cc else f"{ret} "
            return f"{head}{rendered}({args})", notes
        if char in _MSVC_ACCESS:
            access = _MSVC_ACCESS[char]
            self.partial = f"{access} {rendered}"
            attributes = self.text[self.pos : self.pos + 3]
            self.pos += 3
            for attribute in attributes:
                if attribute not in ("A", "E"):
                    notes.append(f"function attribute {attribute!r} not rendered")
            ret_char = self._peek()
            ret = ""
            if ret_char == "@":
                self._take()  # constructors have no return type
            else:
                ret = self._parse_type(notes) + " "
            args = self._parse_params(notes)
            if self._take() != "Z":
                notes.append("throw specification not decoded")
            return f"{access} {ret}{rendered}({args})", notes
        raise _UnsupportedError(f"symbol kind {char!r} is not decoded (name kept only)")

    def _parse_params(self, notes: list[str]) -> str:
        """Parameters up to ``@``/``Z``; a lone leading ``X`` is ``(void)``."""
        if self._peek() == "X" and self._peek_at(1) in ("@", "Z"):
            self._take()
            return "void"
        types: list[str] = []
        while self._peek() not in ("@", "Z"):
            if self._eof():
                raise _MalformedError("unterminated parameter list")
            if len(types) >= MAX_ARGS:
                raise _CapExceededError(f"more than the {MAX_ARGS}-argument cap")
            types.append(self._parse_type(notes))
        if self._peek() == "@":
            self._take()
        return ", ".join(types)

    def _parse_type(self, notes: list[str]) -> str:
        """One MSVC type; unsupported codes name themselves via ``notes``."""
        char = self._take()
        if char == "_":
            two = "_" + self._take()
            if two not in _MSVC_BUILTINS:
                raise _UnsupportedError(f"type code {two!r} is not decoded")
            return _MSVC_BUILTINS[two]
        if char in _MSVC_BUILTINS:
            return _MSVC_BUILTINS[char]
        if char in ("P", "A", "Q", "R"):
            # Pointer/reference: a pointee CV letter, an optional E (__ptr64),
            # then the target type.
            cv = self._take()
            if cv == "E":
                cv = self._take()
            target = self._parse_type(notes)
            if char == "P":
                return target + "*"
            if cv == "B":
                return target + " const&"
            if cv == "C":
                return target + " volatile&"
            return target + "&"
        if char == "V":
            names = self.parse_name_parts()
            if not names[0] or names[0].isdigit():
                raise _UnsupportedError(
                    f"substitution code {names[0]!r} in a class type is not decoded"
                )
            return "::".join(reversed(names))
        if char == "Z":
            notes.append("ellipsis argument (Z) not decoded")
            return "..."
        if char.isdigit():
            raise _UnsupportedError(
                f"substitution code {char!r} in the type stream is not decoded"
            )
        raise _UnsupportedError(f"type code {char!r} is not decoded")


def _demangle_msvc(text: str) -> tuple[str | None, bool, str]:
    """Decode an ``?...`` MSVC symbol; ``note`` names the gap on failure."""
    parser = _MsvcParser(text)
    try:
        demangled, notes = parser.parse_symbol()
        if notes:
            return demangled, False, "; ".join(notes)
        return demangled, True, ""
    except _UnsupportedError as exc:
        return parser.partial or None, False, str(exc)
    except _CapExceededError as exc:
        return parser.partial or None, False, str(exc)
    except _MalformedError as exc:
        return parser.partial or None, False, f"decode failed: {exc}"


# ---- Rust v0 (RFC 2603) ----------------------------------------------------

#: Namespace tags with a demangler-visible meaning (RFC 2603); lowercase tags
#: are implementation-internal and are never rendered.
_RUST_V0_NAMESPACES = {"C": "{closure}", "S": "{shim}"}


def _rust_v0_base62(text: str, pos: int) -> tuple[int, int]:
    """``<base-62-number>``: ``{0-9a-zA-Z}_``; ``_`` alone means 0."""
    digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    value = 0
    seen = False
    while pos < len(text) and text[pos] != "_":
        index = digits.find(text[pos])
        if index < 0:
            raise _MalformedError(f"invalid base-62 digit at position {pos}")
        value = value * 62 + index
        seen = True
        pos += 1
    if pos >= len(text):
        raise _MalformedError("unterminated base-62 number")
    return (value + 1 if seen else 0), pos + 1


class _RustV0Parser:
    """Bounded decoder for ``_R...`` (Rust v0, RFC 2603).

    Supports crate roots, nested paths (with namespace tags) and
    length-prefixed identifiers including disambiguator stripping. Generic
    arguments, impl paths and backref compression raise :class:`_UnsupportedError`
    with the decoded prefix kept -- the partial output is sound, never
    invented.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.partial = ""
        self.notes: list[str] = []

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _take(self) -> str:
        char = self._peek()
        self.pos += 1
        return char

    def _eof(self) -> bool:
        return self.pos >= len(self.text)

    def parse_symbol(self) -> str:
        """``_R [<version>] <path> [<instantiating-crate>] [<suffix>]``."""
        if self._peek().isdigit():
            start = self.pos
            while self._peek().isdigit():
                self.pos += 1
            if self._peek() in ("C", "M", "X", "Y", "N", "I", "B"):
                self.notes.append(
                    f"encoding version {self.text[start : self.pos]} declared"
                )
            else:
                self.pos = start
        path = self.parse_path()
        self.partial = path
        if self._eof():
            return path
        if self._peek() == "C":
            self.parse_path()  # instantiating crate; omitted from the output
            return path
        if self._peek() in (".", "$"):
            self.notes.append("vendor-specific suffix stripped")
            return path
        raise _UnsupportedError(
            f"{len(self.text) - self.pos} trailing character(s) not decoded"
        )

    def parse_path(self) -> str:
        """``C <ident>`` | ``N <tag> <path> <ident>`` | the honest rest."""
        char = self._take()
        if char == "C":
            return self.parse_identifier()
        if char == "N":
            tag = self._take()
            inner = self.parse_path()
            ident = self.parse_identifier()
            self.partial = f"{inner}::{ident}"
            if tag.islower():
                return f"{inner}::{ident}"
            label = _RUST_V0_NAMESPACES.get(tag, f"{{{tag}}}")
            return f"{inner}::{label}::{ident}"
        if char == "I":
            base = self.parse_path()  # keep the decoded base for the partial
            self.partial = base
            raise _UnsupportedError("generic arguments (I...E) are not decoded")
        if char == "M":
            self.partial = self.parse_path()  # the impl path itself is sound
            raise _UnsupportedError("inherent impl paths (M...) are not decoded")
        if char == "X":
            self.partial = self.parse_path()
            raise _UnsupportedError("trait impl paths (X...) are not decoded")
        if char == "Y":
            raise _UnsupportedError("trait definition paths (Y...) are not decoded")
        if char == "B":
            raise _UnsupportedError("backref compression (B...) is not decoded")
        raise _MalformedError(
            f"unsupported path character {char!r} at position {self.pos - 1}"
        )

    def parse_identifier(self) -> str:
        """``[s<base62>_] [u] <length> [_] <bytes>``; disambiguators dropped."""
        if self._peek() == "s":
            self.pos += 1
            _, self.pos = _rust_v0_base62(self.text, self.pos)
        punycode = False
        if self._peek() == "u":
            self._take()
            punycode = True
        start = self.pos
        while self._peek().isdigit():
            self.pos += 1
        if self.pos == start:
            raise _MalformedError(f"expected identifier length at position {self.pos}")
        length = int(self.text[start : self.pos])
        # The ``_`` separator is mandatory when the bytes start with a digit
        # or an underscore (RFC 2603 <undisambiguated-identifier>).
        after = self.text[self.pos + 1 : self.pos + 2]
        if self._peek() == "_" and (after.isdigit() or after == "_"):
            self.pos += 1
        if self.pos + length > len(self.text):
            raise _MalformedError(
                f"identifier length {length} overruns the input at position {start}"
            )
        name = self.text[self.pos : self.pos + length]
        self.pos += length
        if punycode:
            self.notes.append("Punycode identifier not decoded")
        return name


def _demangle_rust_v0(text: str) -> tuple[str | None, bool, str]:
    """Decode an ``_R...`` symbol; ``note`` names the gap on failure."""
    parser = _RustV0Parser(text[2:])
    try:
        demangled = parser.parse_symbol()
        notes = "; ".join(parser.notes)
        if notes:
            return demangled, False, notes
        return demangled, True, ""
    except _UnsupportedError as exc:
        notes = "; ".join(parser.notes + [str(exc)])
        return parser.partial or None, False, notes
    except _MalformedError as exc:
        return parser.partial or None, False, f"decode failed: {exc}"


# ---- Swift (best-effort) ---------------------------------------------------

#: Trailing entity-kind letters this decoder can name. Swift's full type
#: encoding is far richer; anything else stays in the note.
_SWIFT_KINDS: dict[str, str] = {
    "C": "class",
    "V": "struct",
    "O": "enum",
    "P": "protocol",
    "F": "function",
    "v": "variable",
}


def _demangle_swift(text: str, notes: list[str]) -> tuple[str | None, bool, str]:
    """Best-effort decode: leading identifiers plus the trailing kind letter.

    Swift identifiers are decimal-length prefixed like Rust's; word
    substitutions, Punycode and the type encoding stay undecoded and are
    named in ``notes``. A Swift decode is *always* partial -- that is the
    honest report, not a failure.
    """
    if text.startswith("__T"):
        body = text[3:]
        notes.append("legacy (pre-Swift 5) mangling prefix")
    else:
        body = text[3:]
    parts: list[str] = []
    pos = 0
    while pos < len(body) and body[pos].isdigit():
        start = pos
        while pos < len(body) and body[pos].isdigit():
            pos += 1
        length = int(body[start:pos])
        if pos + length > len(body):
            notes.append("truncated identifier")
            break
        parts.append(body[pos : pos + length])
        pos += length
    tail = body[pos:]
    if not parts:
        notes.append("identifier encoding (word substitution or type code) not decoded")
        return None, False, "; ".join(notes)
    rendered = ".".join(parts)
    if tail:
        kind = _SWIFT_KINDS.get(tail[-1])
        if kind is None:
            notes.append(f"type/kind encoding {tail!r} not decoded")
        elif len(tail) > 1:
            notes.append(f"{kind} ({tail[-1]}); type encoding {tail[:-1]!r} not decoded")
        else:
            notes.append(f"{kind} ({tail[-1]})")
    return rendered, False, "; ".join(notes)


# ---- public API ------------------------------------------------------------


def _validate_symbol(symbol: Any, index: int | None = None) -> str:
    """Return ``symbol`` when it is a bounded non-empty string, else raise."""
    where = f"symbol {index}" if index is not None else "symbol"
    if not isinstance(symbol, str):
        raise AnalysisError(f"{where} must be a string, got {type(symbol).__name__}")
    if not symbol:
        raise AnalysisError(f"{where} must not be empty")
    if len(symbol) > MAX_NAME_CHARS:
        raise AnalysisError(
            f"{where} too long ({len(symbol)} > {MAX_NAME_CHARS} characters)"
        )
    return symbol


def demangle_symbol(sym: str) -> DemangleResult:
    """Auto-detect and decode one mangled symbol.

    The scheme is chosen by prefix (``_Z``/``__Z``, ``?``, ``_ZN...17h<hash>E``,
    ``_R``, ``_$s``/``__T``); a symbol that matches a prefix but does not
    decode still reports that scheme with ``complete=False`` and the reason.
    Unknown or non-mangled input is a valid result (``scheme="unknown"``,
    ``demangled=None``), *not* an error.

    Raises:
        AnalysisError: If ``sym`` is not a string, is empty, or exceeds
            :data:`MAX_NAME_CHARS`.
    """
    _validate_symbol(sym)
    scheme = detect_scheme(sym)
    notes: list[str] = []
    demangled: str | None = None
    complete = False
    if scheme == "unknown":
        notes.append(
            "no known mangling prefix (_Z, ?, _R, _$s, __T); not a mangled symbol"
        )
    elif scheme in ("itanium", "rust-legacy"):
        if scheme == "rust-legacy":
            notes.append(
                "legacy Rust mangling (Itanium-style); h<hash> suffix decoded verbatim"
            )
        body = sym[1:] if sym.startswith("__Z") else sym[2:]
        demangled, complete, note = _demangle_itanium(body)
        if note:
            notes.append(note)
    elif scheme == "msvc":
        demangled, complete, note = _demangle_msvc(sym)
        if note:
            notes.append(note)
    elif scheme == "rust-v0":
        demangled, complete, note = _demangle_rust_v0(sym)
        if note:
            notes.append(note)
    else:  # swift
        # The notes list is the function's own output channel; nothing to add.
        demangled, complete, _ = _demangle_swift(sym, notes)
    if demangled is not None and len(demangled) > MAX_NAME_CHARS:
        demangled = demangled[:MAX_NAME_CHARS]
        complete = False
        notes.append(f"output truncated at the {MAX_NAME_CHARS}-character cap")
    if complete:
        confidence = Confidence.HIGH
        detail = f"scheme={scheme}; decoded deterministically by the bounded grammar"
    else:
        confidence = Confidence.LOW
        detail = f"scheme={scheme}; partial decode" if demangled else f"scheme={scheme}"
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=confidence,
        detail=detail,
        extra={"input_length": len(sym), "complete": complete},
    )
    return DemangleResult(
        input=sym,
        scheme=scheme,
        demangled=demangled,
        complete=complete,
        notes=tuple(notes),
        evidence=evidence,
    )


def demangle_symbols(
    symbols: Sequence[str], max_count: int = DEFAULT_MAX_SYMBOLS
) -> DemangleSummary:
    """Demangle a bounded batch of symbols.

    Results keep input order; ``counts`` reports how many landed in each
    scheme (including ``"unknown"``). A list longer than ``max_count`` is
    truncated with a warning, never an error.

    Raises:
        AnalysisError: If ``symbols`` is not a sequence of bounded non-empty
            strings, or ``max_count`` is outside ``1..MAX_SYMBOLS``.
    """
    if isinstance(symbols, (str, bytes)) or not isinstance(symbols, Sequence):
        raise AnalysisError(
            f"symbols must be a sequence of strings, got {type(symbols).__name__}"
        )
    if not symbols:
        raise AnalysisError("symbols must not be empty")
    if not isinstance(max_count, int) or isinstance(max_count, bool):
        raise AnalysisError(f"max_count must be an int, got {type(max_count).__name__}")
    if max_count < 1 or max_count > MAX_SYMBOLS:
        raise AnalysisError(
            f"max_count must be within 1..{MAX_SYMBOLS}, got {max_count}"
        )
    for index, symbol in enumerate(symbols):
        _validate_symbol(symbol, index)
    truncated = len(symbols) > max_count
    warnings: list[str] = []
    if truncated:
        warnings.append(
            f"{len(symbols)} symbol(s) cut to the max_count={max_count} budget; "
            "the rest were not demangled"
        )
    results = tuple(demangle_symbol(symbol) for symbol in symbols[:max_count])
    counts = dict(sorted(Counter(result.scheme for result in results).items()))
    complete_count = sum(1 for result in results if result.complete)
    if results and complete_count == len(results):
        confidence = Confidence.HIGH
    elif complete_count:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=confidence,
        detail=(
            f"{len(results)} symbol(s); {complete_count} complete; "
            + ", ".join(f"{name}={count}" for name, count in counts.items())
        ),
        extra={"total": len(results), "truncated": truncated},
    )
    return DemangleSummary(
        results=results,
        counts=counts,
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )
