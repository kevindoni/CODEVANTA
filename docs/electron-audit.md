# Electron security audit

`codevanta.analysis.electron_audit.audit_electron_app` statically flags the
Electron security anti-patterns canonized by
[electronegativity](https://github.com/doyensec/electronegativity) (doyensec)
and [electron-audit](https://github.com/gyugyu86/electron-audit) — read-only,
offline, bounded, pure Python regex rules, and an evidence record behind every
finding. Nothing is executed.

## Usage (Python)

```python
from pathlib import Path

from codevanta.analysis.electron_audit import audit_electron_app

report = audit_electron_app(Path("path/to/app"))         # extracted directory
report = audit_electron_app(Path("app.asar"))            # Electron archive
report = audit_electron_app(Path("app"), max_files=100)  # lower file ceiling

payload = report.to_dict()   # fully JSON-safe
payload["summary"]           # {"critical": 3, "high": 4, "medium": 2, ...}
payload["findings"][0]       # rule id, title, severity, confidence, file,
                            # line, snippet, recommendation, evidence
```

The engine runs the JavaScript inventory
(`codevanta.analysis.javascript.analyze_javascript_app`) first and reuses its
package facts and per-file heuristic process roles: EA-042 only trusts a
remote `loadURL`/`loadFile` literal in a file the inventory called `main`
(unknown role → heuristic confidence). The audit then walks `.js` / `.cjs` /
`.mjs` **and** `.html` files itself, under the same skip rules
(`node_modules`, `.git`, `__pycache__`, `.cache` pruned, never entered) and
byte caps as the JavaScript lane. `.asar` archives go through the bounded
`codevanta.analysis.asar` parser, one extraction per entry.

## Rules

| Rule | Severity | Confidence | Detects |
|------|----------|------------|---------|
| EA-001 | critical | high | `nodeIntegration: true` in a `webPreferences` block |
| EA-002 | critical | high | `contextIsolation: false` |
| EA-003 | high | high | `sandbox: false` |
| EA-004 | high | high | `webSecurity: false` |
| EA-005 | medium | high | `allowRunningInsecureContent: true` |
| EA-010 | high | heuristic | no CSP anywhere (no meta `http-equiv` tag in HTML, no `Content-Security-Policy` in JS); reported once per app with `file: "."`, `line: 0`, only when at least one HTML/JS file was scanned |
| EA-011 | high | heuristic | a `script-src` directive containing `unsafe-eval` or `unsafe-inline` (bounded, stops at the `;` ending the directive) |
| EA-020 | critical | heuristic | `exec` / `execSync` / `spawn` whose first argument is a template literal or `${…}` interpolation |
| EA-031 | medium | heuristic | `contextBridge.exposeInMainWorld` plus an `ipcRenderer.*` call whose channel argument is not a plain string literal |
| EA-040 | high | heuristic | `shell.openExternal(...)` whose argument does not start with a plain quote |
| EA-042 | medium | high (role `main`) / heuristic otherwise | `loadURL`/`loadFile` with a remote (`http`/`https`) string literal in a main-process file |

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| EA-001 … EA-005 literals, EA-042 in a `main` file | `certain` | the matched text is provably in the file at that line |
| EA-010 (absence), EA-011 (fuzzy CSP parsing) | `medium` | inference over what was *not* seen, or fuzzy directive parsing |
| EA-020 / EA-040 / EA-031 (shape matches) | `medium` | "non-literal argument" is a text shape, not a data-flow fact |
| EA-042 outside a `main` file | `medium` | the URL literal is certain, the process role is a heuristic |

Every finding carries an `Evidence(source="electron.audit",
method="regex_rule_scan" | "absence_check")` record; `high` maps to
`Confidence.CERTAIN` and `heuristic` to `Confidence.MEDIUM`. Regex caveats,
stated up front: comments and strings count as text, snippets are the matched
source line capped at 200 characters, and whether a non-literal value is
actually attacker-controlled is not decided here.

## Bounds

Every bound that fires is reported through `truncated`, honest counts
(`finding_count` vs `findings_kept`) or `warnings` — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Findings kept | 256 | counting continues; `truncated: true` |
| Findings per file | 64 | counting continues; `truncated: true` |
| File rows scanned | 512 (`max_files`) | counting continues; `truncated: true` |
| Directory depth | 64 | deeper subtrees cut with a warning |
| Per-file bytes | 1 MiB | larger files skipped and named |
| Whole-scan bytes | 32 MiB | scan stops with a warning |
| Warnings kept | 32 | further warnings dropped |
| Snippet length | 200 chars | snippet truncated |

Unreadable files and non-UTF-8 sources degrade to warnings; a missing path, a
wrong path kind, an out-of-range `max_files`, or a malformed `.asar` header
raises the typed `AnalysisError`.

## References

* doyensec/electronegativity — the rule taxonomy this lane is modeled on
* gyugyu86/electron-audit — the audit checklist (nodeIntegration,
  contextIsolation, CSP, openExternal, exec)
