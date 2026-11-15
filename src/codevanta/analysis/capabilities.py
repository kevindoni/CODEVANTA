"""File-scope capability detection rules for binaries (offline, pure Python).

Inspired by `mandiant/capa <https://github.com/mandiant/capa>`_, which maps
API imports, constants and strings to capabilities ("creates a reverse
shell", "installs a service", ...) with ATT&CK technique tags. This module is
a deliberately **small subset** of capa:

* **File scope only.** A rule sees the import table, extracted strings,
  exports and section names of *one file* -- nothing else. There is no
  function-level attribution: a match never says *where* in the code a
  capability lives, only that the features are present in the binary.
* **No YAML, no new dependencies.** Built-in rules are frozen dataclasses;
  user-supplied rules are JSON loaded with the standard library.
* **Bounded by construction.** Feature trees are capped in depth and width,
  string extraction is capped by ``string_limit``, and evidence rows are
  capped per feature -- every cap that fires is reported, never silent.

Semantics follow the evidence model of the other lanes: the *features* are
certain (an import-table entry, a string at a file offset are provably in
the file), but the *capability conclusion* is an inference -- so every match
carries ``medium`` confidence. Each match lists exactly which features fired
and where (import table entry, string offset, export or section name), so
the "why" behind every conclusion is inspectable.

Nothing here executes, writes, or talks to the network; the only inputs are
the binary bytes and an optional JSON rule file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeAlias

from codevanta.core.loader import BinaryInfo, BinaryLoadError
from codevanta.core.report import AnalysisError, load_binary
from codevanta.core.strings import StringExtractor, StringResult
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "BUILTIN_RULES",
    "BinaryFeatureSet",
    "CapabilityMatch",
    "CapabilityReport",
    "DEFAULT_STRING_LIMIT",
    "Feature",
    "FeatureAnd",
    "FeatureExport",
    "FeatureImport",
    "FeatureOr",
    "FeatureSection",
    "FeatureString",
    "FiredFeature",
    "ImportRef",
    "MAX_CHILDREN",
    "MAX_LOCATIONS_PER_FEATURE",
    "MAX_STRING_LIMIT",
    "MAX_TREE_DEPTH",
    "MIN_STRING_LIMIT",
    "Rule",
    "SEVERITIES",
    "StringRef",
    "detect_capabilities",
    "evaluate_feature",
    "load_rules",
]

#: Allowed rule severities, ordered most to least severe.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Sort rank of each severity (lower sorts first).
SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

#: Hard ceiling on feature-tree depth. A lone leaf is depth 1; every level
#: of ``FeatureOr`` / ``FeatureAnd`` nesting adds one.
MAX_TREE_DEPTH = 8

#: Hard ceiling on children per composite feature node.
MAX_CHILDREN = 16

#: Hard ceiling on string rows kept for matching (the ``string_limit`` range).
MIN_STRING_LIMIT = 1
MAX_STRING_LIMIT = 50_000

#: Default (and only) ceiling accepted for ``string_limit``.
DEFAULT_STRING_LIMIT = 5000

#: Locations kept per fired leaf feature; the true total is reported too.
MAX_LOCATIONS_PER_FEATURE = 4

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "capabilities.static"

#: ATT&CK technique ids accepted by the validating loader (``T1059.003``).
_ATTCK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

#: JSON feature kinds understood by :func:`load_rules`.
_FEATURE_KINDS = frozenset({"or", "and", "import", "string", "export", "section"})


# ---- feature tree -------------------------------------------------------------


@dataclass(frozen=True)
class FeatureImport:
    """An import-table leaf: any import from ``library``, or one named symbol.

    Attributes:
        library: DLL / object name matched case-insensitively with a ``.dll``
            suffix ignored (``kernel32`` matches ``KERNEL32.dll``).
        name: Import name matched case-insensitively; ``None`` means *any*
            import from the library counts.
    """

    library: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": "import", "library": self.library}
        if self.name is not None:
            data["name"] = self.name
        return data


@dataclass(frozen=True)
class FeatureString:
    """A substring leaf over the extracted strings (case-insensitive)."""

    value: str
    kind: str = "substring"

    def __post_init__(self) -> None:
        if self.kind != "substring":
            raise AnalysisError(f"string feature kind must be 'substring', got {self.kind!r}")
        if not self.value:
            raise AnalysisError("string feature needs a non-empty value")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "string", "value": self.value, "match": self.kind}


@dataclass(frozen=True)
class FeatureExport:
    """An export-table leaf, matched by exact name (case-insensitive)."""

    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "export", "name": self.name}


@dataclass(frozen=True)
class FeatureSection:
    """A section-table leaf, matched by exact section name (case-insensitive)."""

    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "section", "name": self.name}


@dataclass(frozen=True)
class FeatureOr:
    """Disjunction: true when at least one child is true (first child that
    proves the node provides its evidence; the rest are not evaluated)."""

    children: tuple[Feature, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children))
        if not self.children:
            raise AnalysisError("or-feature needs at least one child")
        if len(self.children) > MAX_CHILDREN:
            raise AnalysisError(
                f"or-feature has {len(self.children)} children; the cap is {MAX_CHILDREN}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "or", "children": [child.to_dict() for child in self.children]}


@dataclass(frozen=True)
class FeatureAnd:
    """Conjunction: true when every child is true; the evidence of a true
    node is the union of its children's evidence."""

    children: tuple[Feature, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children))
        if not self.children:
            raise AnalysisError("and-feature needs at least one child")
        if len(self.children) > MAX_CHILDREN:
            raise AnalysisError(
                f"and-feature has {len(self.children)} children; the cap is {MAX_CHILDREN}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "and", "children": [child.to_dict() for child in self.children]}


#: Any node of the feature tree.
Feature: TypeAlias = (
    FeatureOr
    | FeatureAnd
    | FeatureImport
    | FeatureString
    | FeatureExport
    | FeatureSection
)


@dataclass(frozen=True)
class Rule:
    """One capability rule: metadata plus a feature tree.

    Attributes:
        id: Stable rule identifier, e.g. ``"CV-HTTP-COMM"``.
        name: Human-readable capability name.
        namespace: Dot-separated namespace, e.g. ``"communication/http"``.
        severity: One of :data:`SEVERITIES`.
        attck: MITRE ATT&CK technique ids (may be empty; never invented).
        description: What the rule means and what it does *not* prove.
        features: The feature tree that must evaluate true to match.
    """

    id: str
    name: str
    namespace: str
    severity: str
    attck: tuple[str, ...]
    description: str
    features: Feature

    def __post_init__(self) -> None:
        object.__setattr__(self, "attck", tuple(self.attck))
        if not self.id:
            raise AnalysisError("rule needs a non-empty id")
        if self.severity not in SEVERITY_RANK:
            raise AnalysisError(
                f"rule {self.id!r}: severity must be one of {', '.join(SEVERITIES)}"
            )
        for technique in self.attck:
            if not _ATTCK_RE.match(technique):
                raise AnalysisError(
                    f"rule {self.id!r}: invalid ATT&CK technique id {technique!r}"
                )
        depth = _tree_depth(self.features)
        if depth > MAX_TREE_DEPTH:
            raise AnalysisError(
                f"rule {self.id!r}: feature tree depth {depth} exceeds the cap "
                f"of {MAX_TREE_DEPTH}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "namespace": self.namespace,
            "severity": self.severity,
            "attck": list(self.attck),
            "description": self.description,
            "features": self.features.to_dict(),
        }


def _tree_depth(feature: Feature) -> int:
    """Depth of a feature tree (a lone leaf is 1)."""
    if isinstance(feature, FeatureOr | FeatureAnd):
        return 1 + max(_tree_depth(child) for child in feature.children)
    return 1


def _leaf_kinds(feature: Feature) -> set[str]:
    """Leaf kinds referenced anywhere in a feature tree."""
    if isinstance(feature, FeatureOr | FeatureAnd):
        kinds: set[str] = set()
        for child in feature.children:
            kinds |= _leaf_kinds(child)
        return kinds
    if isinstance(feature, FeatureImport):
        return {"import"}
    if isinstance(feature, FeatureString):
        return {"string"}
    if isinstance(feature, FeatureExport):
        return {"export"}
    return {"section"}


# ---- feature collection -------------------------------------------------------


@dataclass(frozen=True)
class ImportRef:
    """One normalized import-table row used for matching."""

    library: str | None
    name: str


@dataclass(frozen=True)
class StringRef:
    """One extracted string used for matching."""

    text: str
    offset: int
    encoding: str


@dataclass(frozen=True)
class BinaryFeatureSet:
    """Everything a feature tree may look at, collected from one binary.

    This is the whole world a rule can see: file scope only, no function
    boundaries, no cross-binary context.
    """

    imports: tuple[ImportRef, ...] = ()
    strings: tuple[StringRef, ...] = ()
    exports: tuple[str, ...] = ()
    sections: tuple[str, ...] = ()

    @classmethod
    def from_binary(
        cls, info: BinaryInfo, strings: Sequence[StringResult]
    ) -> BinaryFeatureSet:
        """Collect the matchable surface of ``info`` plus bounded strings."""
        return cls(
            imports=tuple(ImportRef(imp.library, imp.name) for imp in info.imports),
            strings=tuple(
                StringRef(item.text, item.offset, item.encoding) for item in strings
            ),
            exports=tuple(exp.name for exp in info.exports),
            sections=tuple(section.name for section in info.sections),
        )

    def unavailable_kinds(self) -> tuple[tuple[str, str], ...]:
        """Map each empty collection to the leaf kind it starves.

        Returns ``(leaf_kind, skip_reason)`` pairs so a report can explain a
        non-match as "the data this rule needs is not present" instead of
        "the feature was looked for and absent" -- the loader does not
        distinguish an empty import table from a statically linked binary.
        """
        pairs: list[tuple[str, str]] = []
        if not self.imports:
            pairs.append(("import", "imports_unavailable"))
        if not self.strings:
            pairs.append(("string", "strings_unavailable"))
        if not self.exports:
            pairs.append(("export", "exports_unavailable"))
        if not self.sections:
            pairs.append(("section", "sections_unavailable"))
        return tuple(pairs)


@dataclass(frozen=True)
class FiredFeature:
    """One leaf feature that fired, with the locations that proved it.

    Attributes:
        description: What matched, e.g. ``import kernel32.CreateProcessW``.
        locations: Up to :data:`MAX_LOCATIONS_PER_FEATURE` location strings,
            e.g. ``import:KERNEL32.dll!CreateProcessW`` or ``string@0x2a4/ascii``.
        total: Total number of locations that fired (may exceed the cap).
    """

    description: str
    locations: tuple[str, ...]
    total: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "locations": list(self.locations),
            "total": self.total,
        }


def _norm_library(library: str | None) -> str | None:
    """Normalize a library name for matching (lowercase, ``.dll`` ignored)."""
    if not library:
        return None
    return library.lower().removesuffix(".dll")


def _eval_leaf(feature: Feature, features: BinaryFeatureSet) -> FiredFeature | None:
    """Match one leaf feature; ``None`` when it did not fire."""
    if isinstance(feature, FeatureImport):
        wanted = _norm_library(feature.library)
        locations: list[str] = []
        total = 0
        for ref in features.imports:
            if _norm_library(ref.library) != wanted:
                continue
            if feature.name is not None and ref.name.lower() != feature.name.lower():
                continue
            total += 1
            if len(locations) < MAX_LOCATIONS_PER_FEATURE:
                source = ref.library if ref.library else "unknown-library"
                locations.append(f"import:{source}!{ref.name}")
        if not total:
            return None
        target = feature.name if feature.name is not None else "(any import)"
        return FiredFeature(
            description=f"import {feature.library.lower()}.{target}",
            locations=tuple(locations),
            total=total,
        )
    if isinstance(feature, FeatureString):
        wanted = feature.value.lower()
        locations = []
        total = 0
        for string_ref in features.strings:
            if wanted not in string_ref.text.lower():
                continue
            total += 1
            if len(locations) < MAX_LOCATIONS_PER_FEATURE:
                locations.append(
                    f"string@{string_ref.offset:#x}/{string_ref.encoding}"
                )
        if not total:
            return None
        return FiredFeature(
            description=f"string contains {feature.value!r}",
            locations=tuple(locations),
            total=total,
        )
    if isinstance(feature, FeatureExport):
        locations = []
        total = 0
        for name in features.exports:
            if name.lower() != feature.name.lower():
                continue
            total += 1
            if len(locations) < MAX_LOCATIONS_PER_FEATURE:
                locations.append(f"export:{name}")
        if not total:
            return None
        return FiredFeature(
            description=f"export {feature.name}", locations=tuple(locations), total=total
        )
    if isinstance(feature, FeatureSection):
        locations = []
        total = 0
        for name in features.sections:
            if name.lower() != feature.name.lower():
                continue
            total += 1
            if len(locations) < MAX_LOCATIONS_PER_FEATURE:
                locations.append(f"section:{name}")
        if not total:
            return None
        return FiredFeature(
            description=f"section {feature.name}", locations=tuple(locations), total=total
        )
    return None


def evaluate_feature(feature: Feature, features: BinaryFeatureSet) -> tuple[FiredFeature, ...] | None:
    """Evaluate a feature tree; ``None`` means the tree is false.

    ``FeatureOr`` short-circuits on the first child that proves it and
    returns only that child's evidence; ``FeatureAnd`` requires every child
    and returns the union of their evidence. The recursion depth is bounded
    by :data:`MAX_TREE_DEPTH` and the width by :data:`MAX_CHILDREN`, both
    enforced when the tree is built.
    """
    if isinstance(feature, FeatureOr):
        for child in feature.children:
            hits = evaluate_feature(child, features)
            if hits is not None:
                return hits
        return None
    if isinstance(feature, FeatureAnd):
        collected: list[FiredFeature] = []
        for child in feature.children:
            hits = evaluate_feature(child, features)
            if hits is None:
                return None
            collected.extend(hits)
        return tuple(collected)
    return (hit,) if (hit := _eval_leaf(feature, features)) is not None else None


# ---- built-in rule pack -------------------------------------------------------


def _or(*children: Feature) -> Feature:
    """Build a :class:`FeatureOr`, passing a lone child through unchanged."""
    return children[0] if len(children) == 1 else FeatureOr(children)


def _imports(library: str, *names: str) -> Feature:
    """Build an or-tree over named imports from one library."""
    return _or(*[FeatureImport(library, name) for name in names])


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        id="CV-HTTP-COMM",
        name="HTTP client communication",
        namespace="communication/http",
        severity="low",
        attck=("T1071.001",),
        description=(
            "Imports a Windows web stack (wininet/winhttp/ws2_32) or carries an "
            "'http' string; proves web-facing surface, not what is sent or to whom."
        ),
        features=_or(
            FeatureImport("wininet"),
            FeatureImport("winhttp"),
            FeatureImport("ws2_32"),
            FeatureString("http"),
        ),
    ),
    Rule(
        id="CV-TCP-SOCKET",
        name="TCP socket creation",
        namespace="communication/socket",
        severity="medium",
        attck=("T1095",),
        description=(
            "Winsock socket setup imports or classic socket strings; the binary "
            "can create network connections, intent unknown."
        ),
        features=_or(
            FeatureImport("ws2_32", "socket"),
            FeatureImport("ws2_32", "WSAStartup"),
            FeatureString("htons"),
            FeatureString("socket"),
        ),
    ),
    Rule(
        id="CV-CREATE-PROCESS",
        name="CreateProcess / command execution",
        namespace="execution/process",
        severity="high",
        attck=("T1059",),
        description=(
            "CreateProcess-family imports or shell strings; the binary can spawn "
            "processes, which is also common in benign installers and launchers."
        ),
        features=_or(
            _imports(
                "kernel32",
                "CreateProcessA",
                "CreateProcessW",
                "CreateProcessAsUserA",
                "CreateProcessAsUserW",
            ),
            FeatureString("cmd.exe"),
            FeatureString("/bin/sh"),
            FeatureString("/bin/bash"),
        ),
    ),
    Rule(
        id="CV-REGISTRY-WRITE",
        name="Registry write or persistence keys",
        namespace="persistence/registry",
        severity="high",
        attck=("T1112",),
        description=(
            "advapi32 registry-write imports; the binary can create or modify "
            "registry values, a persistence mechanism and also ordinary setup."
        ),
        features=_imports(
            "advapi32",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
        ),
    ),
    Rule(
        id="CV-SERVICE-INSTALL",
        name="Windows service installation",
        namespace="persistence/service",
        severity="high",
        attck=("T1543.003",),
        description=(
            "advapi32 service-creation imports; the binary can register a "
            "service, which persists execution across reboots."
        ),
        features=_imports("advapi32", "CreateServiceA", "CreateServiceW"),
    ),
    Rule(
        id="CV-KEYLOG",
        name="Keyboard input capture",
        namespace="collection/keylog",
        severity="high",
        attck=("T1056.001",),
        description=(
            "user32 keyboard-hook or async key-state imports; the binary can "
            "capture keystrokes. SetWindowsHookEx also serves legitimate "
            "global-shortcut and accessibility software."
        ),
        features=_imports(
            "user32",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "GetKeyboardState",
        ),
    ),
    Rule(
        id="CV-SCREENSHOT",
        name="Screen capture",
        namespace="collection/screenshot",
        severity="medium",
        attck=("T1113",),
        description=(
            "gdi32 bitmap-copy / user32 device-context imports; the binary can "
            "read screen pixels, as screen recorders and remote support also do."
        ),
        features=_or(
            _imports("gdi32", "GetDIBits", "BitBlt", "StretchBlt"),
            _imports("user32", "GetDC", "GetForegroundWindow"),
        ),
    ),
    Rule(
        id="CV-REVERSE-SHELL",
        name="Reverse shell candidate",
        namespace="execution/reverse-shell",
        severity="critical",
        attck=("T1059.003",),
        description=(
            "Socket setup AND a cmd.exe string AND process creation together; "
            "the classic reverse-shell shape. File-scope evidence cannot prove "
            "the three features are connected, hence 'candidate'."
        ),
        features=FeatureAnd(
            (
                _or(
                    FeatureImport("ws2_32", "socket"),
                    FeatureImport("ws2_32", "WSAStartup"),
                    FeatureString("socket"),
                    FeatureString("htons"),
                ),
                FeatureString("cmd.exe"),
                _imports("kernel32", "CreateProcessA", "CreateProcessW"),
            )
        ),
    ),
    Rule(
        id="CV-UPX",
        name="Packed with UPX (section names)",
        namespace="anti-analysis/packing",
        severity="medium",
        attck=("T1027.002",),
        description=(
            "UPX0/UPX1/UPX2 section names; the binary was packed with UPX, "
            "which hides its real code from static analysis."
        ),
        features=_or(
            FeatureSection("UPX0"),
            FeatureSection("UPX1"),
            FeatureSection("UPX2"),
        ),
    ),
    Rule(
        id="CV-DYNAMIC-LOADING",
        name="Dynamic library loading",
        namespace="execution/loading",
        severity="low",
        attck=("T1129",),
        description=(
            "LoadLibrary/GetProcAddress imports; the binary resolves APIs at "
            "run time, used by plugins and analysis evasion alike."
        ),
        features=_imports(
            "kernel32",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
        ),
    ),
    Rule(
        id="CV-INJECTION",
        name="Process injection hint",
        namespace="defense-evasion/injection",
        severity="critical",
        attck=("T1055",),
        description=(
            "Memory allocation plus write plus remote-thread imports together; "
            "the classic injection triad, also used by debuggers."
        ),
        features=FeatureAnd(
            (
                _imports("kernel32", "VirtualAlloc", "VirtualAllocEx"),
                FeatureImport("kernel32", "WriteProcessMemory"),
                _imports("kernel32", "CreateRemoteThread", "CreateRemoteThreadEx"),
            )
        ),
    ),
    Rule(
        id="CV-FILE-ENUM",
        name="File and directory enumeration",
        namespace="discovery/file",
        severity="low",
        attck=("T1083",),
        description=(
            "FindFirstFile/FindNextFile imports; the binary walks the "
            "filesystem, as search tools and infectors both do."
        ),
        features=_imports(
            "kernel32",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
        ),
    ),
    Rule(
        id="CV-CRED-DUMP",
        name="Credential dumping hint",
        namespace="credential-access/dumping",
        severity="high",
        attck=("T1003.001",),
        description=(
            "An 'lsass' string, a debug-attach import, or MiniDumpWriteDump "
            "from dbghelp; individually these also appear in crash handlers "
            "and admin tools, so this is a hint, not a verdict."
        ),
        features=_or(
            FeatureString("lsass"),
            FeatureImport("dbghelp", "MiniDumpWriteDump"),
            FeatureImport("kernel32", "DebugActiveProcess"),
        ),
    ),
    Rule(
        id="CV-SELF-DELETE",
        name="Self-deletion",
        namespace="defense-evasion/self-delete",
        severity="medium",
        attck=("T1070.004",),
        description=(
            "Command-shell deletion strings or SHDeleteKey imports; the binary "
            "may remove traces of itself after running."
        ),
        features=_or(
            FeatureString("cmd.exe /c del"),
            FeatureString("cmd /c del"),
            FeatureString("del /f"),
            _imports("shlwapi", "SHDeleteKeyA", "SHDeleteKeyW"),
        ),
    ),
)


# ---- JSON rule loading --------------------------------------------------------


def load_rules(json_path: Path) -> tuple[Rule, ...]:
    """Load and validate a user-supplied JSON rule file.

    The file is either a JSON object with a ``"rules"`` list or a bare
    top-level list. Every entry is validated (required fields, severity,
    ATT&CK id shape, feature kinds, tree depth and width) before any
    :class:`Rule` is built; the first defect raises. Rule ids may repeat --
    the later entry wins, mirroring the merge semantics of
    :func:`detect_capabilities`.

    Args:
        json_path: Path to the JSON rule file.

    Returns:
        The validated rules, deduplicated by id (later wins).

    Raises:
        AnalysisError: The file cannot be read, is not valid JSON, or any
            rule entry is malformed -- the message names the file and the
            defect.
    """
    file_path = Path(json_path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"cannot read rules file {file_path}: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"{file_path}: not valid JSON: {exc}") from exc
    if isinstance(payload, dict):
        entries = payload.get("rules")
        if not isinstance(entries, list):
            raise AnalysisError(
                f"{file_path}: expected a JSON object with a 'rules' list or a "
                f"top-level list of rule objects"
            )
    elif isinstance(payload, list):
        entries = payload
    else:
        raise AnalysisError(
            f"{file_path}: expected a JSON object with a 'rules' list or a "
            f"top-level list of rule objects"
        )
    by_id: dict[str, Rule] = {}
    for index, entry in enumerate(entries):
        rule = _parse_rule_entry(entry, file_path, f"rules[{index}]")
        by_id[rule.id] = rule
    return tuple(by_id.values())


def _parse_rule_entry(entry: Any, file_path: Path, where: str) -> Rule:
    """Validate one JSON rule object; every defect names file and location."""
    if not isinstance(entry, dict):
        raise AnalysisError(f"{file_path}: {where}: rule entry must be a JSON object")
    for key in ("id", "name", "namespace", "severity", "description"):
        value = entry.get(key)
        if not isinstance(value, str) or not value:
            raise AnalysisError(f"{file_path}: {where}: field {key!r} must be a non-empty string")
    if entry["severity"] not in SEVERITY_RANK:
        raise AnalysisError(
            f"{file_path}: {where}: severity must be one of {', '.join(SEVERITIES)}"
        )
    attck_raw = entry.get("attck", [])
    if not isinstance(attck_raw, list) or not all(
        isinstance(item, str) and _ATTCK_RE.match(item) for item in attck_raw
    ):
        raise AnalysisError(
            f"{file_path}: {where}: 'attck' must be a list of technique ids like 'T1059.003'"
        )
    if "features" not in entry:
        raise AnalysisError(f"{file_path}: {where}: missing required field 'features'")
    features = _parse_feature_node(entry["features"], file_path, f"{where}.features", 1)
    try:
        return Rule(
            id=entry["id"],
            name=entry["name"],
            namespace=entry["namespace"],
            severity=entry["severity"],
            attck=tuple(attck_raw),
            description=entry["description"],
            features=features,
        )
    except AnalysisError as exc:
        raise AnalysisError(f"{file_path}: {where}: {exc}") from exc


def _parse_feature_node(node: Any, file_path: Path, where: str, depth: int) -> Feature:
    """Parse one JSON feature node with depth/width enforcement."""
    if depth > MAX_TREE_DEPTH:
        raise AnalysisError(
            f"{file_path}: {where}: feature tree deeper than {MAX_TREE_DEPTH} levels"
        )
    if not isinstance(node, dict):
        raise AnalysisError(f"{file_path}: {where}: feature node must be a JSON object")
    kind = node.get("kind")
    if not isinstance(kind, str) or kind not in _FEATURE_KINDS:
        raise AnalysisError(
            f"{file_path}: {where}: unknown feature kind {kind!r} "
            f"(expected one of {', '.join(sorted(_FEATURE_KINDS))})"
        )
    if kind in ("or", "and"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise AnalysisError(
                f"{file_path}: {where}: {kind}-feature needs a non-empty 'children' list"
            )
        if len(children) > MAX_CHILDREN:
            raise AnalysisError(
                f"{file_path}: {where}: {kind}-feature has {len(children)} children; "
                f"the cap is {MAX_CHILDREN}"
            )
        parsed = tuple(
            _parse_feature_node(child, file_path, f"{where}.children[{index}]", depth + 1)
            for index, child in enumerate(children)
        )
        return FeatureOr(parsed) if kind == "or" else FeatureAnd(parsed)
    if kind == "import":
        library = node.get("library")
        if not isinstance(library, str) or not library:
            raise AnalysisError(
                f"{file_path}: {where}: import-feature needs a non-empty 'library'"
            )
        name = node.get("name")
        if name is not None and not isinstance(name, str):
            raise AnalysisError(f"{file_path}: {where}: import-feature 'name' must be a string")
        return FeatureImport(library, name)
    if kind == "string":
        value = node.get("value")
        if not isinstance(value, str) or not value:
            raise AnalysisError(
                f"{file_path}: {where}: string-feature needs a non-empty 'value'"
            )
        match = node.get("match", "substring")
        if match != "substring":
            raise AnalysisError(
                f"{file_path}: {where}: string-feature 'match' must be 'substring'"
            )
        return FeatureString(value)
    name = node.get("name")
    if not isinstance(name, str) or not name:
        raise AnalysisError(f"{file_path}: {where}: {kind}-feature needs a non-empty 'name'")
    return FeatureExport(name) if kind == "export" else FeatureSection(name)


# ---- report model -------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityMatch:
    """One rule that matched, with the evidence that fired it."""

    rule_id: str
    name: str
    namespace: str
    severity: str
    attck: tuple[str, ...]
    fired_features: tuple[FiredFeature, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "namespace": self.namespace,
            "severity": self.severity,
            "attck": list(self.attck),
            "fired_features": [feature.to_dict() for feature in self.fired_features],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class CapabilityReport:
    """The capability-detection result for one binary (file scope only).

    Attributes:
        path: Analysed file path.
        sha256: SHA-256 of the file bytes (from the loader).
        format: Binary format name (``PE`` / ``ELF`` / ``MachO`` / ``DEX``).
        architecture: Architecture name.
        bitness: 32 / 64 / 0 when unknown.
        endianness: ``little`` or ``big``.
        matches: Matched rules, sorted by (severity rank, rule id).
        rule_count: Number of rules evaluated.
        skipped_counts: How many non-matching rules needed a data kind the
            binary does not have (e.g. ``{"imports_unavailable": 9}``).
        warnings: Bounded human-readable warnings.
        truncated: True when string extraction was cut by ``string_limit``.
        evidence: Report-level evidence record (medium confidence).
    """

    path: str
    sha256: str
    format: str
    architecture: str
    bitness: int
    endianness: str
    matches: tuple[CapabilityMatch, ...]
    rule_count: int
    skipped_counts: dict[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    truncated: bool = False
    evidence: Evidence = field(
        default_factory=lambda: Evidence(source=EVIDENCE_SOURCE, method="rule_evaluation")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "format": self.format,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "endianness": self.endianness,
            "match_count": len(self.matches),
            "matches": [match.to_dict() for match in self.matches],
            "rule_count": self.rule_count,
            "skipped_counts": dict(sorted(self.skipped_counts.items())),
            "warnings": list(self.warnings),
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


# ---- entry point --------------------------------------------------------------


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


def _match_for(rule: Rule, fired: tuple[FiredFeature, ...]) -> CapabilityMatch:
    """Build the report row for one matched rule."""
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=f"rule:{rule.id}",
        confidence=Confidence.MEDIUM,
        detail=(
            f"{len(fired)} matched feature(s); the features are certain, "
            f"the capability conclusion is an inference"
        ),
        extra={"rule": rule.id, "fired": len(fired)},
    )
    return CapabilityMatch(
        rule_id=rule.id,
        name=rule.name,
        namespace=rule.namespace,
        severity=rule.severity,
        attck=rule.attck,
        fired_features=fired,
        evidence=evidence,
    )


def _combine_rules(extra_rules: Path | None) -> tuple[Rule, ...]:
    """Merge built-in and user rules: user rules are appended, ids dedupe
    with the later entry winning."""
    by_id: dict[str, Rule] = {rule.id: rule for rule in BUILTIN_RULES}
    if extra_rules is not None:
        for rule in load_rules(extra_rules):
            by_id[rule.id] = rule
    return tuple(by_id.values())


def detect_capabilities(
    path: Path,
    *,
    extra_rules: Path | None = None,
    string_limit: int = DEFAULT_STRING_LIMIT,
) -> CapabilityReport:
    """Detect file-scope capabilities in one binary.

    Loads the binary, extracts bounded strings, evaluates the built-in rule
    pack (plus optional user rules) against the binary's feature set and
    returns the matches sorted by (severity, rule id). Nothing is executed
    and nothing beyond ``path`` and ``extra_rules`` is read.

    Args:
        path: Binary file to analyse.
        extra_rules: Optional JSON rule file appended to the built-in pack;
            duplicate rule ids are overridden by the user's rule.
        string_limit: Cap on strings used for matching
            (``1 .. MAX_STRING_LIMIT``); reaching it sets ``truncated``.

    Returns:
        The :class:`CapabilityReport` for ``path``.

    Raises:
        AnalysisError: ``string_limit`` is out of range, ``path`` does not
            exist or is not a file, the binary cannot be loaded, or the
            rules file is malformed.
    """
    if not MIN_STRING_LIMIT <= string_limit <= MAX_STRING_LIMIT:
        raise AnalysisError(
            f"string_limit must be between {MIN_STRING_LIMIT} and {MAX_STRING_LIMIT}"
        )
    file_path = Path(path)
    if not file_path.is_file():
        raise AnalysisError(f"no such binary file: {file_path}")
    try:
        info = load_binary(file_path)
    except BinaryLoadError as exc:
        raise AnalysisError(f"cannot load {file_path}: {exc}") from exc
    rules = _combine_rules(extra_rules)

    extracted = StringExtractor(min_length=4).extract(file_path, info=info)
    kept = extracted[:string_limit]
    warnings: list[str] = []
    truncated = len(extracted) > string_limit
    if truncated:
        _warn(
            warnings,
            f"string extraction truncated to {string_limit} of {len(extracted)} strings",
        )

    features = BinaryFeatureSet.from_binary(info, kept)
    unavailable = features.unavailable_kinds()
    matches: list[CapabilityMatch] = []
    skipped_counts: dict[str, int] = {}
    for rule in rules:
        fired = evaluate_feature(rule.features, features)
        if fired is not None:
            matches.append(_match_for(rule, fired))
            continue
        needed = _leaf_kinds(rule.features)
        for leaf_kind, reason in unavailable:
            if leaf_kind in needed:
                skipped_counts[reason] = skipped_counts.get(reason, 0) + 1
    matches.sort(key=lambda match: (SEVERITY_RANK[match.severity], match.rule_id))

    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="rule_evaluation",
        confidence=Confidence.MEDIUM,
        detail=(
            "matched features are certain and listed with locations; each "
            "capability conclusion is an inference from file-scope evidence"
        ),
        extra={
            "rules": len(rules),
            "strings_kept": len(kept),
            "strings_total": len(extracted),
            "imports": len(features.imports),
            "exports": len(features.exports),
            "sections": len(features.sections),
        },
    )
    return CapabilityReport(
        path=str(file_path),
        sha256=info.sha256,
        format=info.format,
        architecture=info.architecture,
        bitness=info.bitness,
        endianness=info.endianness,
        matches=tuple(matches),
        rule_count=len(rules),
        skipped_counts=skipped_counts,
        warnings=tuple(warnings),
        truncated=truncated,
        evidence=evidence,
    )
