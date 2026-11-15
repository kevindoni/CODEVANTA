"""Static Electron security audit (offline, pure Python, regex rules).

Inspired by doyensec/electronegativity and gyugyu86/electron-audit, this
module flags the security anti-patterns that make Electron applications
dangerous -- ``nodeIntegration: true``, ``contextIsolation: false``,
disabled sandbox / webSecurity, a missing or weakened Content-Security-Policy,
``shell.openExternal`` on caller-controlled targets, ``child_process`` calls
with non-literal commands, and friends -- without executing anything.

How it works:

* The JavaScript inventory
  (:func:`codevanta.analysis.javascript.analyze_javascript_app`) runs first:
  its package facts and per-file heuristic process roles (``main`` /
  ``renderer`` / ``preload`` / ``mixed``) become report context, and EA-042
  only trusts a remote ``loadURL``/``loadFile`` in a file the inventory
  called ``main``.
* The audit then does its own bounded walk of ``.js`` / ``.cjs`` / ``.mjs``
  **and** ``.html`` files (same skip rules, per-file cap and whole-scan byte
  budget as the JavaScript lane) and applies regex rules with 1-based line
  numbers. ``.asar`` archives go through the bounded
  :mod:`codevanta.analysis.asar` parser, one ``extract_file`` per entry.

Guarantees:

* Nothing here executes, writes, or follows symlinks; directory walks use
  ``os.walk(..., followlinks=False)``.
* Bounded work: findings kept, findings per file, file rows, depth, per-file
  bytes, total bytes and warnings all carry hard caps, and every cap that
  fires is reported through ``truncated`` flags, honest counts or warnings --
  never silently.
* Literal option findings (``nodeIntegration: true`` and friends) are
  *certain*: the text is provably in the file at that line. Shape-based
  findings (non-literal arguments, fuzzy CSP parsing, absence checks,
  role-dependent rules) are *heuristic* and say so in their evidence.
* Regex scan caveats, stated up front: comments and strings count as text,
  and "non-literal argument" means the argument does not start with a plain
  quote -- whether the value is actually attacker-controlled is not decided
  here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from codevanta.analysis.asar import extract_file, list_archive
from codevanta.analysis.javascript import (
    DEFAULT_MAX_FILES,
    MAX_DEPTH,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    SKIP_DIRS,
    JsAppReport,
    PackageFacts,
    analyze_javascript_app,
)
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_FILES",
    "EVIDENCE_SOURCE",
    "ElectronAuditReport",
    "ElectronFinding",
    "MAX_FILE_BYTES",
    "MAX_FILES",
    "MAX_FINDINGS",
    "MAX_FINDINGS_PER_FILE",
    "MAX_TOTAL_BYTES",
    "MAX_WARNINGS",
    "RULES",
    "RULES_BY_ID",
    "AuditRule",
    "SKIP_DIRS",
    "SNIPPET_MAX_CHARS",
    "audit_electron_app",
    "build_audit_result",
    "ElectronAuditResult",
    "ElectronCheck",
    "CheckStatus",
    "OverallSecurity",
]

#: Hard ceiling on findings kept in one report. Counting continues beyond it
#: (``finding_count`` stays honest) and ``truncated`` is set.
MAX_FINDINGS = 256

#: Hard ceiling on findings kept per file (counting continues past it).
MAX_FINDINGS_PER_FILE = 64

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Hard ceiling on the matched-text snippet stored in one finding.
SNIPPET_MAX_CHARS = 200

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "electron.audit"

#: Severity ranking used to order findings (critical > high > medium > low > info).
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_SEVERITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}

_SCAN_SUFFIXES = frozenset({".js", ".cjs", ".mjs", ".html"})

#: ``webPreferences`` option literals (certain: the text is in the file).
_LITERAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EA-001", re.compile(r"\bnodeIntegration\s*:\s*true\b")),
    ("EA-002", re.compile(r"\bcontextIsolation\s*:\s*false\b")),
    ("EA-003", re.compile(r"\bsandbox\s*:\s*false\b")),
    ("EA-004", re.compile(r"\bwebSecurity\s*:\s*false\b")),
    ("EA-005", re.compile(r"\ballowRunningInsecureContent\s*:\s*true\b")),
)

#: ``exec`` / ``execSync`` / ``spawn`` whose first argument is a template
#: literal or an interpolation (shape-based, not data-flow aware).
_EXEC_NONLITERAL_RE = re.compile(r"\b(?:execSync|exec|spawn)\s*\(\s*(?:`|\$\{)")

#: ``shell.openExternal(...)`` whose argument does not start with a plain
#: quote (variable, template literal, expression).
_OPEN_EXTERNAL_RE = re.compile(r"\bshell\.openExternal\s*\(\s*(?![)'\"])")

#: ``loadURL`` / ``loadFile`` with a remote (http/https) string literal.
_LOAD_REMOTE_RE = re.compile(r"\.(?:loadURL|loadFile)\s*\(\s*(['\"])https?://[^'\"]*\1")

#: ``contextBridge.exposeInMainWorld`` marker gating the EA-031 rule.
_EXPOSE_IN_MAIN_WORLD_RE = re.compile(r"\bexposeInMainWorld\b")

#: ``ipcRenderer.*`` call whose channel argument is not a plain string literal.
_IPC_VARIABLE_CHANNEL_RE = re.compile(
    r"\bipcRenderer\.(?:on|once|send|sendSync|invoke)\s*\(\s*(?![)'\"])"
)

#: ``script-src`` directive containing ``unsafe-eval`` / ``unsafe-inline``.
#: Bounded, stops at the ``;`` that ends the directive; heuristic parsing.
_SCRIPT_SRC_UNSAFE_RE = re.compile(r"script-src[^;\n]{0,400}?unsafe-(?:eval|inline)", re.IGNORECASE)

#: CSP delivered via a ``<meta http-equiv="Content-Security-Policy">`` tag.
_META_CSP_RE = re.compile(
    r"<meta[^>]*http-equiv\s*=\s*['\"]?\s*Content-Security-Policy", re.IGNORECASE
)

#: CSP delivered from JS (``onHeadersReceived`` / ``webRequest`` header names).
_CSP_HEADER_RE = re.compile(r"Content-Security-Policy", re.IGNORECASE)


@dataclass(frozen=True)
class AuditRule:
    """One static rule: identity, severity, confidence and recommended fix.

    Attributes:
        rule_id: Stable identifier (``EA-001`` ...).
        title: One-line description of what the rule detects.
        severity: ``critical`` / ``high`` / ``medium`` / ``low`` / ``info``.
        confidence: ``high`` (the matched literal is certainly present) or
            ``heuristic`` (shape-based inference).
        recommendation: Short fix string shown with every finding.
    """

    rule_id: str
    title: str
    severity: str
    confidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
        }


#: The rule catalog, sorted by id.
RULES: tuple[AuditRule, ...] = (
    AuditRule(
        rule_id="EA-001",
        title="nodeIntegration enabled in webPreferences",
        severity="critical",
        confidence="high",
        recommendation="Set nodeIntegration: false and expose capabilities "
        "through a contextBridge preload script.",
    ),
    AuditRule(
        rule_id="EA-002",
        title="contextIsolation disabled",
        severity="critical",
        confidence="high",
        recommendation="Remove contextIsolation: false so renderer code cannot "
        "reach Electron and Node primitives directly.",
    ),
    AuditRule(
        rule_id="EA-003",
        title="renderer sandbox disabled",
        severity="high",
        confidence="high",
        recommendation="Remove sandbox: false so renderers stay sandboxed.",
    ),
    AuditRule(
        rule_id="EA-004",
        title="webSecurity disabled",
        severity="high",
        confidence="high",
        recommendation="Remove webSecurity: false; the same-origin policy must "
        "stay enforced.",
    ),
    AuditRule(
        rule_id="EA-005",
        title="allowRunningInsecureContent enabled",
        severity="medium",
        confidence="high",
        recommendation="Remove allowRunningInsecureContent: true and load all "
        "subresources over HTTPS.",
    ),
    AuditRule(
        rule_id="EA-010",
        title="no Content-Security-Policy found",
        severity="high",
        confidence="heuristic",
        recommendation="Ship a CSP: a meta http-equiv tag in the HTML and/or "
        "CSP response headers set via onHeadersReceived.",
    ),
    AuditRule(
        rule_id="EA-011",
        title="script-src allows unsafe-eval or unsafe-inline",
        severity="high",
        confidence="heuristic",
        recommendation="Drop unsafe-eval and unsafe-inline from script-src; "
        "use nonces or hashes instead.",
    ),
    AuditRule(
        rule_id="EA-020",
        title="child_process exec/execSync/spawn with non-literal command",
        severity="critical",
        confidence="heuristic",
        recommendation="Avoid shell strings built from variables; use "
        "execFile with fixed argv and validated input.",
    ),
    AuditRule(
        rule_id="EA-031",
        title="contextBridge API with caller-chosen IPC channel",
        severity="medium",
        confidence="heuristic",
        recommendation="Use fixed literal channel names inside the exposed "
        "function instead of a caller-supplied channel.",
    ),
    AuditRule(
        rule_id="EA-040",
        title="shell.openExternal with non-literal target",
        severity="high",
        confidence="heuristic",
        recommendation="Validate and allow-list the URL (scheme and host) "
        "before openExternal, or reject user-supplied URLs.",
    ),
    AuditRule(
        rule_id="EA-042",
        title="remote URL loaded in a main-process file",
        severity="medium",
        confidence="high",
        recommendation="Load bundled local content; remote URLs in the main "
        "process should be allow-listed.",
    ),
)

RULES_BY_ID: dict[str, AuditRule] = {rule.rule_id: rule for rule in RULES}


@dataclass(frozen=True)
class ElectronFinding:
    """One rule hit in one file at one line.

    Attributes:
        rule_id: Matching :class:`AuditRule` identifier.
        title: The rule's title.
        severity: The rule's severity.
        confidence: ``high`` or ``heuristic``.
        file: Posix-style path relative to the scan root (``.`` for the
            app-wide absence finding EA-010).
        line: 1-based line number (``0`` for EA-010).
        snippet: The source line containing the match, trimmed and capped
            at :data:`SNIPPET_MAX_CHARS` characters (empty for EA-010).
        recommendation: The rule's recommended fix.
        evidence: Justification record for this finding.
    """

    rule_id: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    snippet: str
    recommendation: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class ElectronAuditReport:
    """The bounded security audit of one Electron application.

    Attributes:
        root: The scanned path as given.
        kind: ``directory`` or ``asar``.
        findings: Kept findings sorted by (severity rank, file, line, rule id).
        evidence: Report-level evidence record.
        summary: True finding counts per severity (kept + cut); every
            severity key is always present.
        finding_count: Total findings counted (kept + cut).
        scanned_files: Files actually read and scanned (JS + HTML).
        file_count: Candidate JS/HTML files seen (scanned + cut by caps).
        total_scanned_bytes: Bytes actually read by this audit.
        truncated: True when any cap (files, findings, bytes, depth) fired.
        warnings: Capped human-readable warnings.
        package: Package facts from the JavaScript inventory.
        role_counts: Inventory file counts per heuristic process role.
        js_file_count: Inventory JS file count (kept + cut).
        js_truncated: Truncation flag of the underlying inventory.
    """

    root: str
    kind: str
    findings: tuple[ElectronFinding, ...]
    evidence: Evidence
    summary: dict[str, int] = field(default_factory=dict)
    finding_count: int = 0
    scanned_files: int = 0
    file_count: int = 0
    skipped_dirs: int = 0
    skipped_large_files: int = 0
    skipped_unpacked: int = 0
    skipped_unreadable: int = 0
    total_scanned_bytes: int = 0
    truncated: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)
    package: PackageFacts | None = None
    role_counts: dict[str, int] = field(default_factory=dict)
    js_file_count: int = 0
    js_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "kind": self.kind,
            "findings": [finding.to_dict() for finding in self.findings],
            "finding_count": self.finding_count,
            "findings_kept": len(self.findings),
            "summary": dict(self.summary),
            "scanned_files": self.scanned_files,
            "file_count": self.file_count,
            "skipped": {
                "directories": self.skipped_dirs,
                "large_files": self.skipped_large_files,
                "unpacked": self.skipped_unpacked,
                "unreadable": self.skipped_unreadable,
            },
            "total_scanned_bytes": self.total_scanned_bytes,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "context": {
                "package": self.package.to_dict() if self.package else None,
                "role_counts": dict(sorted(self.role_counts.items())),
                "js_file_count": self.js_file_count,
                "js_truncated": self.js_truncated,
            },
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class _Candidate:
    """One rule hit waiting to be counted / kept."""

    rule_id: str
    confidence: str
    line: int
    snippet: str
    role: str | None = None


def _line_of(text: str, index: int) -> int:
    """1-based line number of ``index`` within ``text``."""
    return text.count("\n", 0, index) + 1


def _snippet(text: str, index: int) -> str:
    """The source line holding ``index``, trimmed and capped."""
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:SNIPPET_MAX_CHARS]


def _decode(data: bytes, path: str) -> str:
    """Decode source bytes as UTF-8 (a BOM is tolerated), or raise typed."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"electron audit file {path!r} is not valid UTF-8: {exc}") from exc


def _has_csp(text: str, is_html: bool) -> bool:
    """True when the text carries a CSP marker for its file kind."""
    if is_html:
        return _META_CSP_RE.search(text) is not None
    return _CSP_HEADER_RE.search(text) is not None


def _file_candidates(
    text: str,
    is_html: bool,
    role: str | None,
) -> tuple[list[_Candidate], bool]:
    """Apply every rule to one file's text (bounded per file).

    Returns the deduplicated candidates sorted by (line, rule id) plus a
    per-file truncation flag. EA-042 confidence depends on the inventory
    role: ``main`` is high confidence, anything else is heuristic.
    """
    candidates: list[_Candidate] = []
    seen: set[tuple[str, int, str]] = set()

    def add(rule_id: str, match: re.Match[str], confidence: str | None = None) -> None:
        rule = RULES_BY_ID[rule_id]
        line = _line_of(text, match.start())
        snippet = _snippet(text, match.start())
        key = (rule_id, line, snippet)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            _Candidate(
                rule_id=rule_id,
                confidence=confidence if confidence is not None else rule.confidence,
                line=line,
                snippet=snippet,
                role=role if rule_id == "EA-042" else None,
            )
        )

    if not is_html:
        for rule_id, pattern in _LITERAL_PATTERNS:
            for match in pattern.finditer(text):
                add(rule_id, match)
        for match in _EXEC_NONLITERAL_RE.finditer(text):
            add("EA-020", match)
        for match in _OPEN_EXTERNAL_RE.finditer(text):
            add("EA-040", match)
        for match in _LOAD_REMOTE_RE.finditer(text):
            add("EA-042", match, "high" if role == "main" else "heuristic")
        if _EXPOSE_IN_MAIN_WORLD_RE.search(text) is not None:
            for match in _IPC_VARIABLE_CHANNEL_RE.finditer(text):
                add("EA-031", match)
    for match in _SCRIPT_SRC_UNSAFE_RE.finditer(text):
        add("EA-011", match)

    candidates.sort(key=lambda cand: (cand.line, cand.rule_id))
    return candidates, len(candidates) > MAX_FINDINGS_PER_FILE


class _Scan:
    """Mutable accumulator shared by the directory and ASAR audit lanes."""

    def __init__(self, roles: dict[str, str], max_files: int) -> None:
        self.roles = roles
        self.max_files = max_files
        self.findings: list[ElectronFinding] = []
        self.severity_counts: dict[str, int] = {name: 0 for name in SEVERITY_ORDER}
        self.finding_count = 0
        self.scanned = 0
        self.candidates = 0
        self.skipped_dirs = 0
        self.skipped_large = 0
        self.skipped_unpacked = 0
        self.skipped_unreadable = 0
        self.bytes_read = 0
        self.truncated = False
        self.csp_found = False
        self.warnings: list[str] = []

    def warn(self, message: str) -> None:
        """Append one warning unless the cap has been reached."""
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)

    def prune(self, dirname: str) -> bool:
        """Count and prune skipped directory names."""
        if dirname in SKIP_DIRS:
            self.skipped_dirs += 1
            return True
        return False

    def candidate(self) -> bool:
        """Count one candidate file; False when the file cap is reached."""
        self.candidates += 1
        if self.scanned >= self.max_files:
            self.truncated = True
            return False
        return True

    def skip_large(self, rel: str, size: int) -> bool:
        """True (and counted + warned) when the file exceeds the per-file cap."""
        if size > MAX_FILE_BYTES:
            self.skipped_large += 1
            self.warn(
                f"skipped {rel!r}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte per-file cap"
            )
            return True
        return False

    def over_budget(self, rel: str, size: int) -> bool:
        """True when reading ``size`` bytes would exceed the whole-scan budget."""
        if self.bytes_read + size > MAX_TOTAL_BYTES:
            self.truncated = True
            self.warn(f"stopped at {rel!r}: whole-scan byte budget {MAX_TOTAL_BYTES} reached")
            return True
        return False

    def unreadable(self, rel: str, reason: str) -> None:
        """Count and warn one unreadable / undecodable file."""
        self.skipped_unreadable += 1
        self.warn(f"cannot read {rel!r}: {reason}")

    def load(self, rel: str, data: bytes, size: int) -> bool:
        """Decode and scan one file; returns True when it was scanned."""
        try:
            text = _decode(data, rel)
        except AnalysisError as exc:
            self.unreadable(rel, str(exc))
            return False
        self.bytes_read += size
        self.scanned += 1
        is_html = PurePosixPath(rel).suffix.lower() == ".html"
        if not self.csp_found and _has_csp(text, is_html):
            self.csp_found = True
        role = self.roles.get(rel)
        candidates, file_truncated = _file_candidates(text, is_html, role)
        if file_truncated:
            self.truncated = True
        kept_here = 0
        for cand in candidates:
            if self._count_and_maybe_keep(cand, rel, kept_here):
                kept_here += 1
        return True

    def _count_and_maybe_keep(self, cand: _Candidate, rel: str, kept_here: int) -> bool:
        """Count one candidate always; keep it while both caps allow."""
        rule = RULES_BY_ID[cand.rule_id]
        self.finding_count += 1
        self.severity_counts[rule.severity] += 1
        if len(self.findings) >= MAX_FINDINGS or kept_here >= MAX_FINDINGS_PER_FILE:
            return False
        extra: dict[str, Any] = {
            "rule_id": cand.rule_id,
            "file": rel,
            "line": cand.line,
            "severity": rule.severity,
        }
        if cand.role is not None:
            extra["role"] = cand.role
        self.findings.append(
            ElectronFinding(
                rule_id=cand.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=cand.confidence,
                file=rel,
                line=cand.line,
                snippet=cand.snippet,
                recommendation=rule.recommendation,
                evidence=Evidence(
                    source=EVIDENCE_SOURCE,
                    method="regex_rule_scan",
                    confidence=(
                        Confidence.CERTAIN if cand.confidence == "high" else Confidence.MEDIUM
                    ),
                    detail=f"{cand.rule_id} matched at {rel}:{cand.line}",
                    extra=extra,
                ),
            )
        )
        return True

    def append_absence_finding(self) -> None:
        """Add the app-wide EA-010 finding when no CSP marker was seen."""
        if self.scanned < 1 or self.csp_found:
            return
        rule = RULES_BY_ID["EA-010"]
        self.finding_count += 1
        self.severity_counts[rule.severity] += 1
        if len(self.findings) >= MAX_FINDINGS:
            return
        self.findings.append(
            ElectronFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                file=".",
                line=0,
                snippet="",
                recommendation=rule.recommendation,
                evidence=Evidence(
                    source=EVIDENCE_SOURCE,
                    method="absence_check",
                    confidence=Confidence.MEDIUM,
                    detail="no CSP marker found in any scanned HTML or JS file",
                    extra={
                        "rule_id": rule.rule_id,
                        "file": ".",
                        "line": 0,
                        "severity": rule.severity,
                        "files_scanned": self.scanned,
                    },
                ),
            )
        )


def audit_electron_app(path: Path, *, max_files: int = DEFAULT_MAX_FILES) -> ElectronAuditReport:
    """Statically audit one Electron application for security anti-patterns.

    Args:
        path: Application root directory, or a path to an ``.asar`` archive.
        max_files: Ceiling on files scanned (1..MAX_FILES); the walk keeps
            counting beyond it so the totals stay honest.

    Returns:
        The bounded audit report; ``to_dict()`` is fully JSON-safe.

    Raises:
        AnalysisError: ``path`` does not exist, is neither a directory nor an
            ``.asar`` file, the ``.asar`` header is malformed, or the
            JavaScript inventory that runs first cannot be built.
    """
    if not 1 <= max_files <= MAX_FILES:
        raise AnalysisError(f"max_files must be between 1 and {MAX_FILES}")
    try:
        path.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {path}: {exc}") from exc
    if path.is_dir():
        kind = "directory"
    elif path.is_file() and path.suffix.lower() == ".asar":
        kind = "asar"
    else:
        raise AnalysisError(
            f"not an electron application root: {path} is neither a directory nor an .asar archive"
        )
    inventory = analyze_javascript_app(path, max_files=max_files)
    roles = {js_file.path: js_file.role for js_file in inventory.files}
    role_counts: dict[str, int] = {}
    for js_file in inventory.files:
        role_counts[js_file.role] = role_counts.get(js_file.role, 0) + 1
    if kind == "directory":
        return _audit_directory(path, max_files, roles, inventory, role_counts)
    return _audit_asar(path, max_files, roles, inventory, role_counts)


def _audit_directory(
    root: Path,
    max_files: int,
    roles: dict[str, str],
    inventory: JsAppReport,
    role_counts: dict[str, int],
) -> ElectronAuditReport:
    """Walk an extracted application directory (bounded, symlink-free)."""
    scan = _Scan(roles, max_files)
    stop = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = PurePosixPath(Path(dirpath).relative_to(root).as_posix())
        depth = 0 if rel_dir.as_posix() == "." else len(rel_dir.parts)
        if depth >= MAX_DEPTH:
            dirnames[:] = []
            scan.truncated = True
            scan.warn(f"directory depth cap {MAX_DEPTH} reached at {rel_dir.as_posix()!r}")
        dirnames[:] = sorted(d for d in dirnames if not scan.prune(d))
        for name in sorted(filenames):
            if PurePosixPath(name).suffix.lower() not in _SCAN_SUFFIXES:
                continue
            rel = (rel_dir / name).as_posix() if rel_dir.as_posix() != "." else name
            if not scan.candidate():
                continue
            absolute = Path(dirpath) / name
            try:
                size = absolute.stat().st_size
            except OSError as exc:
                scan.unreadable(rel, str(exc))
                continue
            if scan.skip_large(rel, size):
                continue
            if scan.over_budget(rel, size):
                stop = True
                break
            try:
                data = absolute.read_bytes()
            except OSError as exc:
                scan.unreadable(rel, str(exc))
                continue
            scan.load(rel, data, size)
        if stop:
            break
    return _finish(str(root), "directory", scan, inventory, role_counts)


def _audit_asar(
    root: Path,
    max_files: int,
    roles: dict[str, str],
    inventory: JsAppReport,
    role_counts: dict[str, int],
) -> ElectronAuditReport:
    """Audit the JS/HTML files inside one ``.asar`` archive."""
    scan = _Scan(roles, max_files)
    listing = list_archive(root)
    if listing.truncated:
        scan.truncated = True
        scan.warn("asar listing truncated; totals may be incomplete")
    for entry in listing.files:
        if PurePosixPath(entry.path).suffix.lower() not in _SCAN_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in PurePosixPath(entry.path).parts[:-1]):
            scan.skipped_dirs += 1
            continue
        if not scan.candidate():
            continue
        if entry.unpacked:
            scan.skipped_unpacked += 1
            scan.warn(f"skipped {entry.path!r}: unpacked entries live outside the archive")
            continue
        if scan.skip_large(entry.path, entry.size):
            continue
        if scan.over_budget(entry.path, entry.size):
            break
        try:
            extracted = extract_file(root, entry.path, max_bytes=MAX_FILE_BYTES)
        except AnalysisError as exc:
            scan.unreadable(entry.path, str(exc))
            continue
        scan.load(entry.path, extracted.data, entry.size)
    return _finish(str(root), "asar", scan, inventory, role_counts)


def _finish(
    root: str,
    kind: str,
    scan: _Scan,
    inventory: JsAppReport,
    role_counts: dict[str, int],
) -> ElectronAuditReport:
    """Add the absence finding, sort, and assemble the report."""
    scan.append_absence_finding()
    ordered = sorted(
        scan.findings,
        key=lambda f: (_SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id),
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="bounded_walk" if kind == "directory" else "asar_listing",
        confidence=Confidence.CERTAIN,
        detail="regex rules over decoded text; every cap that fired is reported",
        extra={"kind": kind, "files": scan.scanned, "findings": scan.finding_count},
    )
    return ElectronAuditReport(
        root=root,
        kind=kind,
        findings=tuple(ordered),
        evidence=evidence,
        summary=scan.severity_counts,
        finding_count=scan.finding_count,
        scanned_files=scan.scanned,
        file_count=scan.candidates,
        skipped_dirs=scan.skipped_dirs,
        skipped_large_files=scan.skipped_large,
        skipped_unpacked=scan.skipped_unpacked,
        skipped_unreadable=scan.skipped_unreadable,
        total_scanned_bytes=scan.bytes_read,
        truncated=scan.truncated or len(ordered) < scan.finding_count,
        warnings=tuple(scan.warnings),
        package=inventory.package,
        role_counts=role_counts,
        js_file_count=inventory.file_count,
        js_truncated=inventory.truncated,
    )


# ---- the typed audit result (checks + overall verdict) ------------------------
#
# The finding list above is forensic (one row per rule hit per file line).
# Consumers that need a verdict get the rollup below: named checks in a fixed
# order (the BrowserWindow security knobs, CSP, preload) plus one check per
# additional rule that fired, and an overall ``good`` / ``warning`` / ``bad``.

#: Per-check status.
CheckStatus = Literal["pass", "warning", "fail"]

#: Overall security verdict of an :class:`ElectronAuditResult`.
OverallSecurity = Literal["good", "warning", "bad"]

#: Checks kept in one :class:`ElectronAuditResult` (hard bound).
MAX_AUDIT_CHECKS = 16

#: Fixed check order: the BrowserWindow security knobs first, then CSP.
_CORE_CHECKS: tuple[tuple[str, str], ...] = (
    ("nodeIntegration", "EA-001"),
    ("contextIsolation", "EA-002"),
    ("sandbox", "EA-003"),
    ("webSecurity", "EA-004"),
    ("csp", "EA-010"),
)


@dataclass(frozen=True)
class ElectronCheck:
    """One named security check rolled up from the finding list.

    Attributes:
        name: Stable check name (``nodeIntegration``, ``csp``, a rule id for
            non-core rules, ...).
        status: ``pass`` (no findings), ``fail`` (the check's rule fired) or
            ``warning`` (present-but-weak signal, e.g. no preload script).
        detail: One-line human explanation.
        evidence: Provenance for the rollup decision.
    """

    name: str
    status: CheckStatus
    detail: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class ElectronAuditResult:
    """The bounded, typed verdict over one Electron audit.

    Attributes:
        checks: Named checks, bounded by :data:`MAX_AUDIT_CHECKS`; the core
            BrowserWindow/CSP checks come first, then preload, then extra
            fired rules in rule-id order. The cut is reported, never silent.
        overall_security: ``bad`` when any check failed, ``warning`` when
            only warnings or medium+ findings remain, ``good`` otherwise.
        truncated: True when more checks matched than the cap kept.
        evidence: Provenance for the whole result.
    """

    checks: tuple[ElectronCheck, ...]
    overall_security: OverallSecurity
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "checks": [check.to_dict() for check in self.checks],
            "check_count": len(self.checks),
            "overall_security": self.overall_security,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


def _check(
    name: str,
    status: CheckStatus,
    detail: str,
    extra: dict[str, Any] | None = None,
) -> ElectronCheck:
    """Build one rollup check with its evidence record."""
    return ElectronCheck(
        name=name,
        status=status,
        detail=detail,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="finding_rollup",
            confidence=Confidence.HIGH,
            detail=detail,
            extra=extra or {},
        ),
    )


def build_audit_result(report: ElectronAuditReport) -> ElectronAuditResult:
    """Roll a report's findings up into named checks and one verdict.

    The fixed core checks read the finding set (a check fails when its rule
    fired anywhere in the app); the ``csp`` check passes when EA-010 (missing
    CSP) did not fire. The ``preload`` check uses the inventory context: it
    passes when at least one file was classified as a preload/mixed script
    and warns otherwise -- a missing preload is not a vulnerability by
    itself, but it usually means capabilities reach the renderer through
    ``nodeIntegration`` or broad IPC. Every additional rule that fired
    becomes one ``fail`` check in rule-id order, capped at
    :data:`MAX_AUDIT_CHECKS`.
    """
    fired: set[str] = {finding.rule_id for finding in report.findings}
    checks: list[ElectronCheck] = []
    for name, rule_id in _CORE_CHECKS:
        if rule_id in fired:
            severity = next(
                (
                    finding.severity
                    for finding in report.findings
                    if finding.rule_id == rule_id
                ),
                "unknown",
            )
            checks.append(
                _check(
                    name,
                    "fail",
                    f"{rule_id}: misconfiguration literal in the sources "
                    f"(severity {severity})",
                    {"rule_id": rule_id},
                )
            )
        elif name == "csp":
            checks.append(_check(name, "pass", "a CSP marker was found in the app"))
        else:
            checks.append(
                _check(name, "pass", f"{rule_id} not found: setting not weakened")
            )
    preload_files = report.role_counts.get("preload", 0) + report.role_counts.get(
        "mixed", 0
    )
    if preload_files:
        checks.append(
            _check(
                "preload",
                "pass",
                f"{preload_files} preload/mixed script(s) detected by the "
                "inventory roles",
                {"preload_files": preload_files},
            )
        )
    else:
        checks.append(
            _check(
                "preload",
                "warning",
                "no preload script detected: renderer capabilities likely come "
                "from nodeIntegration or direct ipcRenderer use",
            )
        )
    core_rule_ids = {rule_id for _name, rule_id in _CORE_CHECKS}
    for rule_id in sorted(fired - core_rule_ids):
        checks.append(
            _check(
                rule_id,
                "fail",
                f"{rule_id}: {RULES_BY_ID[rule_id].title.lower()}",
                {"rule_id": rule_id},
            )
        )
    truncated = len(checks) > MAX_AUDIT_CHECKS
    kept = checks[:MAX_AUDIT_CHECKS]
    any_fail = any(check.status == "fail" for check in kept)
    if any_fail:
        overall: OverallSecurity = "bad"
    elif any(check.status == "warning" for check in kept) or report.summary.get(
        "medium", 0
    ) or report.summary.get("high", 0):
        overall = "warning"
    else:
        overall = "good"
    return ElectronAuditResult(
        checks=tuple(kept),
        overall_security=overall,
        truncated=truncated,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="finding_rollup",
            confidence=Confidence.HIGH,
            detail=(
                f"{len(report.findings)} finding(s) rolled up into {len(kept)} "
                f"check(s); verdict {overall}"
                + (" (check list cut)" if truncated else "")
            ),
            extra={
                "finding_count": report.finding_count,
                "summary": dict(sorted(report.summary.items())),
            },
        ),
    )
