"""A bounded subset of the YARA rule language, matched over raw file bytes.

Inspired by `VirusTotal/yara <https://github.com/VirusTotal/yara>`_. This
module parses a *subset* of real YARA rule syntax and evaluates it against
the raw bytes of any file -- not only binaries the loader understands -- so
analysts can interoperate with the rule corpus that already circulates,
inside CODEVANTA's evidence model. Pure standard library; nothing executes
and nothing beyond the rule text and the target file is read.

What is IN (the whole subset):

* ``rule NAME { meta: strings: condition: }`` with ``//`` and ``/* */``
  comments and multiple rules per file;
* text strings ``$a = "text"`` with the ``nocase`` and ``wide`` modifiers
  (``wide`` adds a UTF-16LE interleaved scan);
* hex strings ``{ AA BB ?? CC [4-8] }`` with ``??`` / nibble wildcards
  (``A?``, ``?5``) and bounded jumps ``[n-m]`` / ``[n]``;
* conditions built from ``and`` / ``or`` / ``not`` and parentheses, string
  truthiness (``$a``), match counts (``#a OP integer``), ``filesize OP
  integer`` with ``OP`` in ``> >= < <= == !=``, and the string-set
  quantifiers ``all of`` / ``any of`` / ``N of`` over wildcard sets
  ``($x*)``, explicit id lists ``($a, $b)`` and ``them``.

What is OUT -- rejected loudly with a typed
:class:`~codevanta.core.report.AnalysisError` that names the rule and the
offending token, never silently ignored:

* regex strings (``/re/``) and every string modifier except ``nocase`` and
  ``wide`` (``ascii``, ``fullword``, ``private``, ``xor``, ``base64``, ...);
* hex alternation ``( AA | BB )`` and unbounded jumps ``[*]`` / ``[n-]``;
* jump upper bounds above :data:`MAX_JUMP_SPAN`;
* module imports (``import "pe"``) and module conditions (``pe.*``,
  ``math.*``, ...), ``for .. of`` / ``for .. in`` loops, ``at`` / ``in``
  position operators, ``@a`` / ``!a`` occurrence syntax, integer
  arithmetic, boolean literals, rule tags, ``global`` / ``private`` rules,
  namespaces and ``include`` files;
* any other token outside the grammar above.

Matching semantics (deliberate deviations from stock YARA are marked):

* text strings are searched over the raw file bytes (the pattern encoded
  as UTF-8) and -- **deviation** -- ``wide`` adds the UTF-16LE form while
  the ASCII scan stays on, whereas stock YARA's bare ``wide`` searches
  UTF-16LE only (there it takes ``wide ascii`` to get both);
* ``nocase`` folds ASCII ``A-Z`` only, on both encodings;
* every occurrence is reported, including overlapping ones, with its file
  offset; hex strings match with wildcard and jump semantics over raw
  bytes;
* the file size seen by ``filesize`` is the byte length of the file.

Bounds: total match offsets recorded across the scan (``max_strings``),
offsets kept per string id (``max_matches_per_string`` -- counting
continues, so ``#a`` conditions stay truthful), the hex jump span, the
condition nesting depth, strings per rule and the warnings list are all
capped, and every cap that fires is reported through ``truncated`` flags
or warnings -- never silently.

Confidence follows the evidence model of the other lanes: a string match
at a raw file offset is *certain* (the bytes are provably in the file),
while the rule conclusion drawn from those matches is an inference and
carries *medium* confidence.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeAlias

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_MATCHES_PER_STRING",
    "DEFAULT_MAX_STRINGS",
    "EVIDENCE_SOURCE",
    "MAX_CONDITION_DEPTH",
    "MAX_JUMP_SPAN",
    "MAX_MATCHES_PER_STRING",
    "MAX_STRINGS_PER_RULE",
    "MAX_TOTAL_MATCHES",
    "MAX_WARNINGS",
    "AllOf",
    "And",
    "AnyOf",
    "Condition",
    "FileSize",
    "HexByte",
    "HexJump",
    "HexPattern",
    "NOf",
    "Not",
    "Or",
    "Pattern",
    "StrCount",
    "StrTruthy",
    "TextPattern",
    "YaraMatchReport",
    "YaraRule",
    "YaraRuleMatch",
    "YaraStringMatches",
    "load_rules_file",
    "match_rules",
    "parse_rules",
]

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "yara.subset"

#: Hard ceiling on the upper bound of a hex jump ``[n-m]`` (and on ``[n]``).
MAX_JUMP_SPAN = 64

#: Hard ceiling on condition nesting (parentheses / ``not`` chains).
MAX_CONDITION_DEPTH = 16

#: Hard ceiling on string entries per rule.
MAX_STRINGS_PER_RULE = 256

#: Default and hard ceiling for ``max_strings`` (total match offsets kept).
DEFAULT_MAX_STRINGS = 200_000
MAX_TOTAL_MATCHES = 200_000

#: Default and hard ceiling for ``max_matches_per_string``.
DEFAULT_MAX_MATCHES_PER_STRING = 64
MAX_MATCHES_PER_STRING = 4096

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Comparison operators accepted in ``#a`` / ``filesize`` comparisons.
_CMP_OPS = frozenset({">", ">=", "<", "<=", "==", "!="})

#: YARA string modifiers this subset supports.
_SUPPORTED_MODIFIERS = frozenset({"nocase", "wide"})

#: YARA string modifiers recognised only so their rejection can name them.
_UNSUPPORTED_MODIFIERS = frozenset(
    {"ascii", "fullword", "private", "xor", "base64", "base64wide"}
)

#: Reserved words of the subset (anything else lexes as an identifier).
_KEYWORDS = frozenset(
    {
        "rule", "meta", "strings", "condition", "and", "or", "not",
        "all", "any", "of", "them", "filesize", "true", "false",
        "import", "include", "global", "private",
    }
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

#: ASCII A-Z -> a-z translation table for ``nocase`` byte scans.
_LOWER_TABLE = bytes.maketrans(bytes(range(0x41, 0x5B)), bytes(range(0x61, 0x7B)))


# ---- string patterns ------------------------------------------------------------


@dataclass(frozen=True)
class TextPattern:
    """A quoted text string with its supported modifiers.

    Attributes:
        text: The decoded pattern text (escapes resolved by the lexer).
        nocase: Match case-insensitively (ASCII ``A-Z`` folding only).
        wide: Also search the UTF-16LE interleaved form of the pattern.
    """

    text: str
    nocase: bool = False
    wide: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "text",
            "text": self.text,
            "nocase": self.nocase,
            "wide": self.wide,
        }


@dataclass(frozen=True)
class HexByte:
    """One hex-string byte: ``value`` is matched under ``mask``.

    ``mask`` says which bits are significant: ``0xFF`` for an exact byte,
    ``0xF0`` when only the high nibble is known (``A?``), ``0x0F`` when
    only the low nibble is known (``?5``), and ``0x00`` for ``??``
    (any byte; ``value`` is then 0).
    """

    value: int
    mask: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 0xFF or self.mask not in (0x00, 0x0F, 0xF0, 0xFF):
            raise AnalysisError(
                f"invalid hex byte (value={self.value:#x}, mask={self.mask:#x})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "byte", "text": _hex_byte_text(self)}


@dataclass(frozen=True)
class HexJump:
    """A bounded hex-string jump ``[n-m]`` (``[n]`` means ``n == m``)."""

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if self.minimum < 0 or self.maximum < self.minimum:
            raise AnalysisError(f"invalid jump range [{self.minimum}-{self.maximum}]")
        if self.maximum > MAX_JUMP_SPAN:
            raise AnalysisError(
                f"jump [{self.minimum}-{self.maximum}] exceeds the maximum jump "
                f"span of {MAX_JUMP_SPAN}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "jump", "text": f"[{self.minimum}-{self.maximum}]"}


@dataclass(frozen=True)
class HexPattern:
    """A hex string: an ordered token stream of bytes and bounded jumps."""

    tokens: tuple[HexByte | HexJump, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tokens", tuple(self.tokens))
        if not self.tokens:
            raise AnalysisError("hex string needs at least one byte or jump")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "hex",
            "tokens": [_hex_token_text(token) for token in self.tokens],
        }


#: Any string pattern of a rule.
Pattern: TypeAlias = TextPattern | HexPattern


def _hex_byte_text(token: HexByte) -> str:
    """Regenerate the source form of one hex byte token."""
    if token.mask == 0x00:
        return "??"
    if token.mask == 0xFF:
        return f"{token.value:02X}"
    if token.mask == 0xF0:
        return f"{token.value >> 4:X}?"
    return f"?{token.value & 0x0F:X}"


def _hex_token_text(token: HexByte | HexJump) -> str:
    """Regenerate the source form of one hex token."""
    if isinstance(token, HexJump):
        return f"[{token.minimum}-{token.maximum}]"
    return _hex_byte_text(token)


# ---- condition AST --------------------------------------------------------------


@dataclass(frozen=True)
class And:
    """Conjunction: true when every child is true."""

    children: tuple[Condition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children))
        if not self.children:
            raise AnalysisError("and-condition needs at least one child")

    def to_dict(self) -> dict[str, Any]:
        return {"op": "and", "children": [child.to_dict() for child in self.children]}


@dataclass(frozen=True)
class Or:
    """Disjunction: true when at least one child is true."""

    children: tuple[Condition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children))
        if not self.children:
            raise AnalysisError("or-condition needs at least one child")

    def to_dict(self) -> dict[str, Any]:
        return {"op": "or", "children": [child.to_dict() for child in self.children]}


@dataclass(frozen=True)
class Not:
    """Negation: true when the child is false."""

    child: Condition

    def to_dict(self) -> dict[str, Any]:
        return {"op": "not", "child": self.child.to_dict()}


@dataclass(frozen=True)
class StrTruthy:
    """``$a``: true when the string matched at least once."""

    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"op": "string", "id": f"${self.name}"}


@dataclass(frozen=True)
class StrCount:
    """``#a OP n``: compare the match count of ``$a`` against ``n``."""

    name: str
    op: str
    value: int

    def __post_init__(self) -> None:
        if self.op not in _CMP_OPS:
            raise AnalysisError(f"unknown comparison operator {self.op!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "op": "count",
            "id": f"${self.name}",
            "compare": self.op,
            "value": self.value,
        }


@dataclass(frozen=True)
class FileSize:
    """``filesize OP n``: compare the file size in bytes against ``n``."""

    op: str
    value: int

    def __post_init__(self) -> None:
        if self.op not in _CMP_OPS:
            raise AnalysisError(f"unknown comparison operator {self.op!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"op": "filesize", "compare": self.op, "value": self.value}


@dataclass(frozen=True)
class AllOf:
    """``all of (...)``: true when every string in the set matched."""

    items: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        if not self.items:
            raise AnalysisError("all-of needs a non-empty string set")

    def to_dict(self) -> dict[str, Any]:
        return {"op": "all_of", "items": [f"${name}" for name in self.items]}


@dataclass(frozen=True)
class AnyOf:
    """``any of (...)``: true when at least one string in the set matched."""

    items: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        if not self.items:
            raise AnalysisError("any-of needs a non-empty string set")

    def to_dict(self) -> dict[str, Any]:
        return {"op": "any_of", "items": [f"${name}" for name in self.items]}


@dataclass(frozen=True)
class NOf:
    """``N of (...)``: true when at least ``count`` strings matched."""

    count: int
    items: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        if not self.items:
            raise AnalysisError("n-of needs a non-empty string set")
        if self.count < 0:
            raise AnalysisError("n-of count must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "op": "n_of",
            "count": self.count,
            "items": [f"${name}" for name in self.items],
        }


#: Any node of a parsed condition.
Condition: TypeAlias = (
    And
    | Or
    | Not
    | StrTruthy
    | StrCount
    | FileSize
    | AllOf
    | AnyOf
    | NOf
)


# ---- rule model -----------------------------------------------------------------


@dataclass(frozen=True)
class YaraRule:
    """One parsed YARA-subset rule.

    Attributes:
        name: Rule name (unique within one rules source).
        strings: String id (without ``$``) to :data:`Pattern`.
        condition: The parsed condition tree.
        meta: Metadata block preserved as a plain dict (ignored by
            matching, kept for report fidelity).
    """

    name: str
    strings: dict[str, Pattern]
    condition: Condition
    meta: dict[str, str | int | bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "meta": dict(self.meta),
            "strings": {
                f"${sid}": pattern.to_dict() for sid, pattern in sorted(self.strings.items())
            },
            "condition": self.condition.to_dict(),
        }


# ---- lexer ----------------------------------------------------------------------


@dataclass(frozen=True)
class _Tok:
    """One lexical token; ``text``/``number`` carry the payload by kind."""

    kind: str  # ident|keyword|string|hexstring|int|op|punct|dollar|hash|eof
    text: str = ""
    number: int = 0
    pos: int = 0


def _describe(token: _Tok) -> str:
    """Human-readable token description for error messages."""
    if token.kind == "int":
        return f"integer {token.number}"
    if token.kind == "eof":
        return "end of input"
    if token.kind == "string":
        return f"string literal {token.text!r}"
    if token.kind == "hexstring":
        return "hex string"
    return f"{token.text!r}"


def _lex(text: str, source: str) -> list[_Tok]:
    """Tokenize rule text; comments are stripped, errors name the offset."""
    tokens: list[_Tok] = []
    i = 0
    length = len(text)

    def fail(message: str, pos: int) -> AnalysisError:
        return AnalysisError(f"{source}: {message} at offset {pos}")

    while i < length:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "/" and text[i + 1 : i + 2] == "/":
            end = text.find("\n", i)
            i = length if end == -1 else end + 1
            continue
        if ch == "/" and text[i + 1 : i + 2] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise fail("unterminated /* comment", i)
            i = end + 2
            continue
        if ch == '"':
            start = i
            decoded, i = _lex_quoted(text, i, source)
            tokens.append(_Tok("string", text=decoded, pos=start))
            continue
        after_equals = (
            bool(tokens) and tokens[-1].kind == "op" and tokens[-1].text == "="
        )
        if ch == "{" and after_equals:
            end = text.find("}", i + 1)
            if end == -1:
                raise fail("unterminated hex string", i)
            tokens.append(_Tok("hexstring", text=text[i + 1 : end], pos=i))
            i = end + 1
            continue
        if ch.isdigit():
            start = i
            value, i = _lex_number(text, i, source)
            tokens.append(_Tok("int", number=value, pos=start))
            continue
        if ch.isalpha() or ch == "_":
            end = i + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            word = text[i:end]
            kind = "keyword" if word in _KEYWORDS else "ident"
            tokens.append(_Tok(kind, text=word, pos=i))
            i = end
            continue
        if ch in "$#":
            end = i + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            if end == i + 1:
                raise fail(f"expected an identifier after {ch!r}", i)
            kind = "dollar" if ch == "$" else "hash"
            tokens.append(_Tok(kind, text=text[i + 1 : end], pos=i))
            i = end
            continue
        pair = text[i : i + 2]
        if pair in (">=", "<=", "==", "!="):
            tokens.append(_Tok("op", text=pair, pos=i))
            i += 2
            continue
        if ch in "><=":
            tokens.append(_Tok("op", text=ch, pos=i))
            i += 1
            continue
        if ch in "()[]{},*:/.":
            tokens.append(_Tok("punct", text=ch, pos=i))
            i += 1
            continue
        if ch == "!":
            raise fail("unexpected '!' (negation is spelled 'not')", i)
        raise fail(f"unexpected character {ch!r}", i)
    tokens.append(_Tok("eof", pos=length))
    return tokens


def _lex_quoted(text: str, start: int, source: str) -> tuple[str, int]:
    """Decode one double-quoted string literal starting at ``start``."""
    buf: list[str] = []
    i = start + 1
    length = len(text)
    while True:
        if i >= length:
            raise AnalysisError(f"{source}: unterminated string literal at offset {start}")
        ch = text[i]
        if ch == '"':
            return "".join(buf), i + 1
        if ch == "\\":
            i += 1
            if i >= length:
                raise AnalysisError(
                    f"{source}: unterminated string literal at offset {start}"
                )
            esc = text[i]
            if esc == "x":
                digits = text[i + 1 : i + 3]
                if len(digits) != 2 or any(d not in _HEX_DIGITS for d in digits):
                    raise AnalysisError(
                        f"{source}: \\x escape needs two hex digits at offset {i}"
                    )
                buf.append(chr(int(digits, 16)))
                i += 3
                continue
            mapped = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}.get(esc)
            if mapped is None:
                raise AnalysisError(f"{source}: unsupported escape '\\{esc}' at offset {i}")
            buf.append(mapped)
            i += 1
            continue
        buf.append(ch)
        i += 1


def _lex_number(text: str, start: int, source: str) -> tuple[int, int]:
    """Decode one integer literal (decimal or ``0x`` hex)."""
    length = len(text)
    if text[start : start + 2].lower() == "0x":
        end = start + 2
        while end < length and text[end] in _HEX_DIGITS:
            end += 1
        digits = text[start + 2 : end]
        if not digits:
            raise AnalysisError(f"{source}: '0x' literal needs hex digits at offset {start}")
        return int(digits, 16), end
    end = start
    while end < length and text[end].isdigit():
        end += 1
    return int(text[start:end]), end


# ---- hex payload parsing ---------------------------------------------------------


def _parse_hex(payload: str) -> HexPattern:
    """Parse the payload between ``{`` and ``}`` of one hex string."""
    if any(ch in payload for ch in "()|"):
        raise AnalysisError(
            "hex alternation '( AA | BB )' is not supported by the yara subset "
            f"(payload {payload.strip()!r})"
        )
    parts = payload.split()
    if not parts:
        raise AnalysisError("empty hex string")
    tokens: list[HexByte | HexJump] = []
    for part in parts:
        if part.startswith("["):
            tokens.append(_parse_jump(part))
            continue
        if len(part) % 2 != 0:
            raise AnalysisError(
                f"odd number of hex digits in {part!r} (hex strings use byte pairs)"
            )
        for k in range(0, len(part), 2):
            tokens.append(_parse_hex_byte(part[k], part[k + 1], part))
    return HexPattern(tuple(tokens))


def _parse_jump(part: str) -> HexJump:
    """Parse one ``[n-m]`` / ``[n]`` jump token; unbounded forms are errors."""
    if not part.endswith("]"):
        raise AnalysisError(f"malformed jump {part!r} (missing ']')")
    inner = part[1:-1].strip()
    if inner in ("*", "-", "") or inner.endswith("-"):
        raise AnalysisError(
            f"unbounded jump {part!r} is not supported by the yara subset "
            f"(use [n-m] with m <= {MAX_JUMP_SPAN})"
        )
    if "-" in inner:
        low_text, _, high_text = inner.partition("-")
        low, high = _jump_bound(low_text, part), _jump_bound(high_text, part)
    else:
        low = high = _jump_bound(inner, part)
    if low > high:
        raise AnalysisError(f"jump {part!r} has an inverted range")
    if high > MAX_JUMP_SPAN:
        raise AnalysisError(f"jump {part!r} exceeds the maximum jump span of {MAX_JUMP_SPAN}")
    return HexJump(low, high)


def _jump_bound(raw: str, part: str) -> int:
    """Decode one decimal jump bound, rejecting junk."""
    if not raw.isdigit():
        raise AnalysisError(f"malformed jump {part!r} (bounds must be decimal integers)")
    return int(raw)


def _parse_hex_byte(high: str, low: str, part: str) -> HexByte:
    """Decode one byte pair where each nibble is a hex digit or ``?``."""
    high_value = _nibble(high, part)
    low_value = _nibble(low, part)
    if high_value is None:
        if low_value is None:
            return HexByte(0x00, 0x00)
        return HexByte(low_value, 0x0F)
    if low_value is None:
        return HexByte(high_value << 4, 0xF0)
    return HexByte((high_value << 4) | low_value, 0xFF)


def _nibble(ch: str, part: str) -> int | None:
    """Decode one hex nibble; ``?`` (``None``) is a wildcard."""
    if ch == "?":
        return None
    if ch in _HEX_DIGITS:
        return int(ch, 16)
    raise AnalysisError(f"invalid hex character {ch!r} in {part!r}")


# ---- parser ----------------------------------------------------------------------


class _Parser:
    """Recursive-descent parser over the token stream of one rules file."""

    def __init__(self, tokens: Sequence[_Tok], source: str) -> None:
        self._tokens = list(tokens)
        self._index = 0
        self._source = source
        self._rule = "<toplevel>"
        self._strings: dict[str, Pattern] = {}

    # -- token plumbing ----------------------------------------------------------

    def _peek(self) -> _Tok:
        return self._tokens[self._index]

    def _next(self) -> _Tok:
        token = self._tokens[self._index]
        if token.kind != "eof":
            self._index += 1
        return token

    def _at_keyword(self, word: str) -> bool:
        token = self._peek()
        return token.kind == "keyword" and token.text == word

    def _expect_keyword(self, word: str) -> _Tok:
        if not self._at_keyword(word):
            raise self._err(f"expected {word!r}, got {_describe(self._peek())}")
        return self._next()

    def _expect_punct(self, char: str) -> _Tok:
        token = self._peek()
        if token.kind != "punct" or token.text != char:
            raise self._err(f"expected {char!r}, got {_describe(token)}")
        return self._next()

    def _at_punct(self, char: str) -> bool:
        token = self._peek()
        return token.kind == "punct" and token.text == char

    def _expect_op(self, op: str) -> _Tok:
        token = self._peek()
        if token.kind != "op" or token.text != op:
            raise self._err(f"expected {op!r}, got {_describe(token)}", token)
        return self._next()

    def _err(self, message: str, token: _Tok | None = None) -> AnalysisError:
        token = token if token is not None else self._peek()
        return AnalysisError(
            f"{self._source}: rule {self._rule!r}: {message} (at offset {token.pos})"
        )

    # -- top level ------------------------------------------------------------------

    def parse_all(self) -> tuple[YaraRule, ...]:
        """Parse the whole file: a sequence of rule declarations."""
        rules: list[YaraRule] = []
        seen: set[str] = set()
        while self._peek().kind != "eof":
            token = self._peek()
            if token.kind == "keyword" and token.text in ("import", "include"):
                raise AnalysisError(
                    f"{self._source}: {token.text} statements are not supported by "
                    f"the yara subset (module conditions and includes are out of "
                    f"scope) at offset {token.pos}"
                )
            if token.kind == "keyword" and token.text in ("global", "private"):
                raise AnalysisError(
                    f"{self._source}: {token.text!r} rules are not supported by the "
                    f"yara subset at offset {token.pos}"
                )
            if not (token.kind == "keyword" and token.text == "rule"):
                raise AnalysisError(
                    f"{self._source}: expected 'rule', got {_describe(token)} at "
                    f"offset {token.pos}"
                )
            rules.append(self.parse_rule(seen))
        if not rules:
            raise AnalysisError(f"{self._source}: no rules found (empty rules input)")
        return tuple(rules)

    # -- rule and sections ------------------------------------------------------------

    def parse_rule(self, seen: set[str]) -> YaraRule:
        """Parse one ``rule NAME { ... }`` declaration."""
        self._next()  # 'rule'
        name_tok = self._peek()
        if name_tok.kind != "ident":
            raise self._err(f"expected a rule name, got {_describe(name_tok)}", name_tok)
        self._rule = name_tok.text
        self._next()
        if name_tok.text in seen:
            raise self._err(f"duplicate rule name {name_tok.text!r}", name_tok)
        seen.add(name_tok.text)
        self._expect_punct("{")
        meta = self._parse_meta() if self._at_keyword("meta") else {}
        self._strings = (
            self._parse_strings() if self._at_keyword("strings") else {}
        )
        self._expect_keyword("condition")
        self._expect_punct(":")
        condition = self._parse_expr(0)
        self._expect_punct("}")
        return YaraRule(
            name=name_tok.text, strings=self._strings, condition=condition, meta=meta
        )

    def _parse_meta(self) -> dict[str, str | int | bool]:
        """Parse one ``meta:`` section (preserved verbatim, ignored by matching)."""
        self._next()  # 'meta'
        self._expect_punct(":")
        meta: dict[str, str | int | bool] = {}
        while self._peek().kind == "ident":
            key = self._next().text
            self._expect_op("=")
            value_tok = self._peek()
            if value_tok.kind == "string":
                value: str | int | bool = self._next().text
            elif value_tok.kind == "int":
                value = self._next().number
            elif value_tok.kind == "keyword" and value_tok.text in ("true", "false"):
                value = self._next().text == "true"
            else:
                raise self._err(
                    f"invalid meta value for {key!r}: expected a string, integer "
                    f"or boolean, got {_describe(value_tok)}",
                    value_tok,
                )
            meta[key] = value
        if not meta:
            raise self._err("meta section needs at least one entry")
        return meta

    def _parse_strings(self) -> dict[str, Pattern]:
        """Parse one ``strings:`` section into id -> pattern (in file order)."""
        self._next()  # 'strings'
        self._expect_punct(":")
        strings: dict[str, Pattern] = {}
        while self._peek().kind == "dollar":
            id_tok = self._next()
            sid = id_tok.text
            if sid in strings:
                raise self._err(f"duplicate string identifier '${sid}'", id_tok)
            if len(strings) >= MAX_STRINGS_PER_RULE:
                raise self._err(
                    f"more than {MAX_STRINGS_PER_RULE} strings in one rule", id_tok
                )
            self._expect_op("=")
            value = self._peek()
            if value.kind == "string":
                self._next()
                strings[sid] = self._finish_text_string(value.text)
                continue
            if value.kind == "hexstring":
                self._next()
                self._reject_hex_modifiers()
                try:
                    strings[sid] = _parse_hex(value.text)
                except AnalysisError as exc:
                    raise self._err(
                        f"${sid} = {{ {value.text.strip()} }}: {exc}", value
                    ) from exc
                continue
            if value.kind == "punct" and value.text == "/":
                raise self._err(
                    "regex strings (/.../) are not supported by the yara subset", value
                )
            raise self._err(
                f"expected a quoted string or hex string for '${sid}', got "
                f"{_describe(value)}",
                value,
            )
        if not strings:
            raise self._err("strings section needs at least one string")
        return strings

    def _finish_text_string(self, text: str) -> TextPattern:
        """Consume the modifiers after one quoted string and build the pattern."""
        nocase = False
        wide = False
        while self._peek().kind == "ident":
            mod_tok = self._next()
            modifier = mod_tok.text
            if modifier in _SUPPORTED_MODIFIERS:
                if (modifier == "nocase" and nocase) or (modifier == "wide" and wide):
                    raise self._err(f"duplicate modifier {modifier!r}", mod_tok)
                if modifier == "nocase":
                    nocase = True
                else:
                    wide = True
            elif modifier in _UNSUPPORTED_MODIFIERS:
                raise self._err(
                    f"string modifier {modifier!r} is not supported by the yara "
                    f"subset (supported: nocase, wide)",
                    mod_tok,
                )
            else:
                raise self._err(
                    f"unexpected identifier {modifier!r} after a string (supported "
                    f"modifiers: nocase, wide)",
                    mod_tok,
                )
        if not text:
            raise self._err("empty text string is not allowed")
        return TextPattern(text=text, nocase=nocase, wide=wide)

    def _reject_hex_modifiers(self) -> None:
        """Reject modifiers after a hex string with a precise message."""
        token = self._peek()
        known = _SUPPORTED_MODIFIERS | _UNSUPPORTED_MODIFIERS
        if token.kind == "ident" and token.text in known:
            raise self._err(f"hex strings do not take modifiers ({token.text!r})", token)

    # -- condition grammar ------------------------------------------------------------

    def _parse_expr(self, depth: int) -> Condition:
        """``or`` level (lowest precedence); same-level operands stay flat."""
        if depth > MAX_CONDITION_DEPTH:
            raise self._err(f"condition nests deeper than {MAX_CONDITION_DEPTH} levels")
        operands = [self._parse_and(depth)]
        while self._at_keyword("or"):
            self._next()
            operands.append(self._parse_and(depth))
        return operands[0] if len(operands) == 1 else Or(tuple(operands))

    def _parse_and(self, depth: int) -> Condition:
        """``and`` level; same-level operands stay flat."""
        operands = [self._parse_not(depth)]
        while self._at_keyword("and"):
            self._next()
            operands.append(self._parse_not(depth))
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def _parse_not(self, depth: int) -> Condition:
        """``not`` level (highest-precedence prefix)."""
        if self._at_keyword("not"):
            self._next()
            return Not(self._parse_not(depth + 1))
        return self._parse_primary(depth + 1)

    def _parse_primary(self, depth: int) -> Condition:
        """Atoms: parentheses, quantifiers, comparisons, string truthiness."""
        token = self._peek()
        if self._at_punct("("):
            self._next()
            node = self._parse_expr(depth + 1)
            self._expect_punct(")")
            return node
        if token.kind == "keyword" and token.text in ("all", "any"):
            self._next()
            self._expect_keyword("of")
            items = self._parse_string_set()
            return AllOf(items) if token.text == "all" else AnyOf(items)
        if token.kind == "int":
            self._next()
            self._expect_keyword("of")
            items = self._parse_string_set()
            return NOf(count=token.number, items=items)
        if token.kind == "dollar":
            self._next()
            self._require_string(token.text, token)
            return StrTruthy(name=token.text)
        if token.kind == "hash":
            self._next()
            op = self._expect_cmp(f"string count '#{token.text}'")
            value = self._expect_int_after_cmp()
            self._require_string(token.text, token)
            return StrCount(name=token.text, op=op, value=value)
        if token.kind == "keyword" and token.text == "filesize":
            self._next()
            op = self._expect_cmp("filesize")
            value = self._expect_int_after_cmp()
            return FileSize(op=op, value=value)
        if token.kind == "keyword" and token.text in ("true", "false"):
            raise self._err(
                f"boolean literal {token.text!r} is not supported by the yara subset",
                token,
            )
        raise self._err(f"unexpected {_describe(token)} in condition", token)

    def _parse_string_set(self) -> tuple[str, ...]:
        """Parse ``them`` or ``( $a, $x*, ... )`` and expand it to concrete ids."""
        if self._at_keyword("them"):
            self._next()
            if not self._strings:
                raise self._err("'them' selects no strings (no strings section)")
            return tuple(sorted(self._strings))
        self._expect_punct("(")
        names: list[str] = []
        prefixes: list[str] = []
        while True:
            token = self._peek()
            if token.kind != "dollar":
                raise self._err(
                    f"expected a string identifier like '$a' in the set, got "
                    f"{_describe(token)}",
                    token,
                )
            self._next()
            if self._at_punct("*"):
                self._next()
                prefixes.append(token.text)
            else:
                names.append(token.text)
            if self._at_punct(","):
                self._next()
                continue
            break
        self._expect_punct(")")
        items: set[str] = set()
        for name in names:
            if name not in self._strings:
                raise self._err(f"undefined string '${name}' in string set")
            items.add(name)
        for prefix in prefixes:
            matched = [sid for sid in self._strings if sid.startswith(prefix)]
            if not matched:
                raise self._err(f"string set (${prefix}*) selects no strings")
            items.update(matched)
        return tuple(sorted(items))

    def _expect_cmp(self, what: str) -> str:
        """Consume one comparison operator for ``what``."""
        token = self._peek()
        if token.kind != "op" or token.text not in _CMP_OPS:
            raise self._err(
                f"expected a comparison operator (> >= < <= == !=) after {what}, "
                f"got {_describe(token)}",
                token,
            )
        self._next()
        return token.text

    def _expect_int_after_cmp(self) -> int:
        """Consume the integer literal on the right of a comparison."""
        token = self._peek()
        if token.kind != "int":
            raise self._err(
                f"expected an integer literal after the comparison, got "
                f"{_describe(token)}",
                token,
            )
        self._next()
        return token.number

    def _require_string(self, name: str, token: _Tok) -> None:
        """Reject condition references to strings the rule never declared."""
        if name not in self._strings:
            raise self._err(f"undefined string '${name}' in condition", token)


# ---- matching --------------------------------------------------------------------


def _find_all(data: bytes, needle: bytes) -> Iterator[int]:
    """Yield every occurrence of ``needle`` in ``data``, overlapping included."""
    if not needle:
        return
    pos = data.find(needle)
    while pos != -1:
        yield pos
        pos = data.find(needle, pos + 1)


def _ascii_lower(text: str) -> str:
    """Fold ASCII ``A-Z`` only (YARA ``nocase`` semantics)."""
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def _scan_text(data: bytes, lowered: bytes | None, pattern: TextPattern) -> tuple[int, ...]:
    """Find all offsets of one text pattern (ASCII, plus UTF-16LE when wide)."""
    found: set[int] = set()
    needle = pattern.text.encode("utf-8")
    if pattern.nocase:
        if lowered is None:
            raise AnalysisError("internal error: nocase scan without lowered buffer")
        found.update(_find_all(lowered, needle.translate(_LOWER_TABLE)))
        if pattern.wide:
            wide_needle = _ascii_lower(pattern.text).encode("utf-16-le")
            found.update(_find_all(lowered, wide_needle))
    else:
        found.update(_find_all(data, needle))
        if pattern.wide:
            found.update(_find_all(data, pattern.text.encode("utf-16-le")))
    return tuple(sorted(found))


def _scan_hex(data: bytes, pattern: HexPattern) -> tuple[int, ...]:
    """Find all start offsets of one hex pattern (wildcards and jumps).

    Uses a position-set sweep per candidate offset: after each token the
    set holds every relative end position still consistent with the
    pattern, so backtracking jumps never explode.
    """
    minimum = sum(
        1 if isinstance(token, HexByte) else token.minimum for token in pattern.tokens
    )
    matches: list[int] = []
    length = len(data)
    for start in range(length - minimum + 1):
        positions: set[int] = {0}
        alive = True
        for token in pattern.tokens:
            if isinstance(token, HexByte):
                following: set[int] = set()
                for pos in positions:
                    offset = start + pos
                    if offset < length and (
                        token.mask == 0x00 or (data[offset] & token.mask) == token.value
                    ):
                        following.add(pos + 1)
                positions = following
            else:
                positions = {
                    pos + skip
                    for pos in positions
                    for skip in range(token.minimum, token.maximum + 1)
                    if start + pos + skip <= length
                }
            if not positions:
                alive = False
                break
        if alive:
            matches.append(start)
    return tuple(matches)


def _compare(left: int, op: str, right: int) -> bool:
    """Evaluate one integer comparison."""
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == "==":
        return left == right
    return left != right


def _evaluate(node: Condition, counts: Mapping[str, int], filesize: int) -> bool:
    """Evaluate a condition tree against match counts and the file size."""
    if isinstance(node, And):
        return all(_evaluate(child, counts, filesize) for child in node.children)
    if isinstance(node, Or):
        return any(_evaluate(child, counts, filesize) for child in node.children)
    if isinstance(node, Not):
        return not _evaluate(node.child, counts, filesize)
    if isinstance(node, StrTruthy):
        return counts.get(node.name, 0) > 0
    if isinstance(node, StrCount):
        return _compare(counts.get(node.name, 0), node.op, node.value)
    if isinstance(node, FileSize):
        return _compare(filesize, node.op, node.value)
    if isinstance(node, AllOf):
        return all(counts.get(name, 0) > 0 for name in node.items)
    if isinstance(node, AnyOf):
        return any(counts.get(name, 0) > 0 for name in node.items)
    if isinstance(node, NOf):
        return sum(1 for name in node.items if counts.get(name, 0) > 0) >= node.count
    raise AnalysisError(f"unsupported condition node {type(node).__name__}")


# ---- report model -----------------------------------------------------------------


@dataclass(frozen=True)
class YaraStringMatches:
    """Bounded match offsets for one string id of one rule.

    Attributes:
        string_id: The id with its ``$`` (e.g. ``"$a"``).
        offsets: Kept match offsets (capped by ``max_matches_per_string``
            and the global budget); ``total`` stays truthful.
        total: Total number of matches found (counting never stops).
        truncated: True when ``offsets`` holds fewer than ``total``.
        evidence: Certain-confidence record for these byte matches.
    """

    string_id: str
    offsets: tuple[int, ...]
    total: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "string_id": self.string_id,
            "offsets": [f"0x{offset:x}" for offset in self.offsets],
            "count": self.total,
            "kept": len(self.offsets),
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class YaraRuleMatch:
    """One evaluated rule: its fired strings and the condition verdict.

    Attributes:
        rule_name: The rule that was evaluated.
        string_matches: One row per string id that matched at least once,
            sorted by id; ids that never matched are simply absent.
        condition_satisfied: The condition verdict.
        meta: The rule's preserved metadata block.
        evidence: Medium-confidence record for the rule conclusion.
    """

    rule_name: str
    string_matches: tuple[YaraStringMatches, ...]
    condition_satisfied: bool
    meta: dict[str, str | int | bool]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name,
            "condition_satisfied": self.condition_satisfied,
            "meta": dict(self.meta),
            "string_matches": [match.to_dict() for match in self.string_matches],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class YaraMatchReport:
    """The YARA-subset matching result for one file.

    Attributes:
        path: Analysed file path.
        sha256: SHA-256 of the file bytes.
        rule_count: Number of rules evaluated.
        matches: Rules whose condition was satisfied, sorted by rule name.
        evaluations: Every rule (matched or not) sorted by rule name, each
            carrying its ``condition_satisfied`` verdict.
        warnings: Bounded human-readable warnings.
        truncated: True when any cap cut the recorded offsets.
        evidence: Report-level evidence record (medium confidence).
    """

    path: str
    sha256: str
    rule_count: int
    matches: tuple[YaraRuleMatch, ...]
    evaluations: tuple[YaraRuleMatch, ...]
    warnings: tuple[str, ...] = ()
    truncated: bool = False
    evidence: Evidence = field(
        default_factory=lambda: Evidence(source=EVIDENCE_SOURCE, method="byte_pattern_scan")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "rule_count": self.rule_count,
            "match_count": len(self.matches),
            "matches": [match.to_dict() for match in self.matches],
            "evaluations": [row.to_dict() for row in self.evaluations],
            "warnings": list(self.warnings),
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


# ---- evaluation driver -------------------------------------------------------------


def _match(
    rules: tuple[YaraRule, ...],
    data: bytes,
    path: str,
    max_strings: int,
    max_matches_per_string: int,
) -> YaraMatchReport:
    """Scan ``data`` with every rule and build the report (deterministic order)."""
    filesize = len(data)
    sha256 = hashlib.sha256(data).hexdigest()
    lowered: bytes | None = None
    if any(
        isinstance(pattern, TextPattern) and pattern.nocase
        for rule in rules
        for pattern in rule.strings.values()
    ):
        lowered = data.translate(_LOWER_TABLE)

    raw_warnings: list[str] = []
    truncated = False
    budget = max_strings
    budget_warned = False
    evaluations: list[YaraRuleMatch] = []

    for rule in sorted(rules, key=lambda item: item.name):
        counts: dict[str, int] = {}
        string_matches: list[YaraStringMatches] = []
        for sid in sorted(rule.strings):
            pattern = rule.strings[sid]
            if isinstance(pattern, TextPattern):
                offsets = _scan_text(data, lowered, pattern)
            else:
                offsets = _scan_hex(data, pattern)
            total = len(offsets)
            counts[sid] = total
            if total == 0:
                continue
            kept_len = min(total, max_matches_per_string, budget)
            kept = offsets[:kept_len]
            budget -= kept_len
            row_truncated = kept_len < total
            if row_truncated:
                truncated = True
                raw_warnings.append(
                    f"rule {rule.name!r}: ${sid} kept {kept_len} of {total} match offsets"
                )
                if kept_len < min(total, max_matches_per_string) and not budget_warned:
                    budget_warned = True
                    raw_warnings.append(
                        f"global match budget of {max_strings} recorded offsets "
                        f"reached; counting continues but offsets are no longer recorded"
                    )
            string_matches.append(
                YaraStringMatches(
                    string_id=f"${sid}",
                    offsets=kept,
                    total=total,
                    truncated=row_truncated,
                    evidence=Evidence(
                        source=EVIDENCE_SOURCE,
                        method="byte_pattern_scan",
                        confidence=Confidence.CERTAIN,
                        detail=f"${sid} matched {total} time(s) in the raw file bytes",
                        extra={"string_id": f"${sid}", "total": total, "kept": len(kept)},
                    ),
                )
            )
        satisfied = _evaluate(rule.condition, counts, filesize)
        fired = {f"${sid}": counts[sid] for sid in sorted(counts) if counts[sid] > 0}
        evaluations.append(
            YaraRuleMatch(
                rule_name=rule.name,
                string_matches=tuple(string_matches),
                condition_satisfied=satisfied,
                meta=dict(rule.meta),
                evidence=Evidence(
                    source=EVIDENCE_SOURCE,
                    method="byte_pattern_scan",
                    confidence=Confidence.MEDIUM,
                    detail=(
                        "string matches are certain (raw byte offsets); the rule "
                        "conclusion is an inference"
                    ),
                    extra={"rule": rule.name, "fired": fired},
                ),
            )
        )

    matches = tuple(row for row in evaluations if row.condition_satisfied)
    if len(raw_warnings) > MAX_WARNINGS:
        warnings = raw_warnings[:MAX_WARNINGS]
        warnings.append(f"{len(raw_warnings) - MAX_WARNINGS} more warning(s) suppressed")
    else:
        warnings = raw_warnings
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="byte_pattern_scan",
        confidence=Confidence.MEDIUM,
        detail=(
            "every string match is a provable raw-byte offset (certain); each "
            "rule conclusion drawn from them is an inference (medium)"
        ),
        extra={"rules": len(rules), "matched": len(matches), "filesize": filesize},
    )
    return YaraMatchReport(
        path=path,
        sha256=sha256,
        rule_count=len(rules),
        matches=matches,
        evaluations=tuple(evaluations),
        warnings=tuple(warnings),
        truncated=truncated,
        evidence=evidence,
    )


# ---- public API --------------------------------------------------------------------


def parse_rules(text: str, *, source_name: str = "rules.yar") -> tuple[YaraRule, ...]:
    """Parse rule text and return the rules in file order.

    Args:
        text: The full text of a YARA rules file (comments allowed).
        source_name: Name used in error messages.

    Returns:
        The parsed :class:`YaraRule` tuple, in file order.

    Raises:
        AnalysisError: The text is empty (or comment-only), or anything in
            it falls outside the supported subset -- the message names the
            rule and the offending token. See the module docstring for the
            exact subset.
    """
    tokens = _lex(text, source_name)
    return _Parser(tokens, source_name).parse_all()


def load_rules_file(path: Path) -> tuple[YaraRule, ...]:
    """Read and parse a YARA-subset rules file from disk.

    Args:
        path: Path to the rules file (UTF-8 text).

    Returns:
        The parsed :class:`YaraRule` tuple, in file order.

    Raises:
        AnalysisError: The file cannot be read, or its content falls
            outside the supported subset (the message names the file, the
            rule and the offending token).
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"cannot read rules file {file_path}: {exc}") from exc
    return parse_rules(text, source_name=str(file_path))


def match_rules(
    path: Path,
    *,
    rules_text: str | None = None,
    rules_path: Path | None = None,
    max_strings: int = DEFAULT_MAX_STRINGS,
    max_matches_per_string: int = DEFAULT_MAX_MATCHES_PER_STRING,
) -> YaraMatchReport:
    """Match YARA-subset rules against the raw bytes of one file.

    Exactly one of ``rules_text`` / ``rules_path`` must be supplied. The
    target file is read as raw bytes -- any file scans, not only binaries
    the loader understands -- and every rule is evaluated with its string
    patterns searched over those bytes (ASCII, plus UTF-16LE for ``wide``
    text strings; wildcards and jumps for hex strings). Results are
    deterministic: rows are sorted by rule name, string ids within a rule
    by id.

    Args:
        path: File to scan.
        rules_text: Rule source text (mutually exclusive with
            ``rules_path``).
        rules_path: Rule file path (mutually exclusive with
            ``rules_text``).
        max_strings: Cap on the total match offsets recorded across the
            whole scan (``1 .. MAX_TOTAL_MATCHES``); counting continues,
            so ``#a`` conditions stay truthful.
        max_matches_per_string: Cap on offsets kept per string id
            (``1 .. MAX_MATCHES_PER_STRING``); counting continues.

    Returns:
        The :class:`YaraMatchReport` for ``path``.

    Raises:
        AnalysisError: Arguments are out of range or mutually exclusive,
            ``path`` does not exist, the rules cannot be parsed, or the
            file cannot be read.
    """
    if (rules_text is None) == (rules_path is None):
        raise AnalysisError("exactly one of rules_text or rules_path must be supplied")
    if not 1 <= max_strings <= MAX_TOTAL_MATCHES:
        raise AnalysisError(f"max_strings must be between 1 and {MAX_TOTAL_MATCHES}")
    if not 1 <= max_matches_per_string <= MAX_MATCHES_PER_STRING:
        raise AnalysisError(
            f"max_matches_per_string must be between 1 and {MAX_MATCHES_PER_STRING}"
        )
    if rules_text is not None:
        rules = parse_rules(rules_text, source_name="<rules text>")
    else:
        assert rules_path is not None
        rules = load_rules_file(rules_path)
    file_path = Path(path)
    if not file_path.is_file():
        raise AnalysisError(f"no such file: {file_path}")
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {file_path}: {exc}") from exc
    return _match(rules, data, str(file_path), max_strings, max_matches_per_string)
