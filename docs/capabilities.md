# Capability detection (file-scope rules)

`codevanta.analysis.capabilities` maps what a binary *can do* — network
communication, process creation, persistence, injection, packing — from
file-scope evidence: the import table, extracted strings, exports and section
names. It is inspired by
[mandiant/capa](https://github.com/mandiant/capa), which maps API imports,
constants and strings to capabilities with ATT&CK technique tags.

> **This is a deliberately small subset of capa.** File scope only, ~14
> built-in rules, no YAML, no new dependencies (rules are Python dataclasses
> or JSON loaded with the standard library). Nothing here replicates capa's
> function-level logic, its rule ecosystem, or its matching breadth.

## The file-scope-only limitation, stated loudly

A rule sees exactly one binary's **import table, extracted strings, exports
and section names**. Nothing else.

* **No function-level attribution.** A match never says *where* in the code a
  capability lives — only that the features are present somewhere in the
  file. Full capa reasons about individual instructions and function
  boundaries; this engine does not.
* **No connection proof.** `CV-REVERSE-SHELL` sees socket setup, a `cmd.exe`
  string and `CreateProcess` in the same file. It cannot prove the three are
  related — that is why it is called a *candidate*.
* **No behavioral verdict.** Every matched feature also appears in benign
  software (`FindFirstFile` in search tools, `MiniDumpWriteDump` in crash
  handlers). A match is a lead for an analyst, not a detection verdict.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| A matched feature (import entry, string at an offset, export, section) | `certain` | provably in the file; every location is listed |
| The capability conclusion of a matched rule | `medium` | inference from co-located features; intent is not observable from bytes |

Every match row lists exactly **which features fired and where** — e.g.
`import:KERNEL32.dll!CreateProcessW` or `string@0x2a4/ascii` — so the "why"
behind every conclusion is inspectable.

## Built-in rules

Matches are sorted by severity (`critical`, `high`, `medium`, `low`), then
rule id.

| ID | Name | Severity | ATT&CK | Features (any-of unless noted) |
|----|------|----------|--------|--------------------------------|
| `CV-HTTP-COMM` | HTTP client communication | low | T1071.001 | import `wininet` / `winhttp` / `ws2_32` (any), string `http` |
| `CV-TCP-SOCKET` | TCP socket creation | medium | T1095 | import `ws2_32.socket` / `ws2_32.WSAStartup`, string `htons` / `socket` |
| `CV-CREATE-PROCESS` | CreateProcess / command execution | high | T1059 | imports `kernel32.CreateProcess{A,W,AsUserA,AsUserW}`, strings `cmd.exe`, `/bin/sh`, `/bin/bash` |
| `CV-REGISTRY-WRITE` | Registry write or persistence keys | high | T1112 | imports `advapi32.RegSetValueEx{A,W}`, `RegCreateKey{A,W,ExA,ExW}` |
| `CV-SERVICE-INSTALL` | Windows service installation | high | T1543.003 | imports `advapi32.CreateService{A,W}` |
| `CV-KEYLOG` | Keyboard input capture | high | T1056.001 | imports `user32.SetWindowsHookEx{A,W}`, `GetAsyncKeyState`, `GetKeyboardState` |
| `CV-SCREENSHOT` | Screen capture | medium | T1113 | imports `gdi32.{GetDIBits,BitBlt,StretchBlt}`, `user32.{GetDC,GetForegroundWindow}` |
| `CV-REVERSE-SHELL` | Reverse shell candidate | critical | T1059.003 | **all-of**: (socket setup) AND string `cmd.exe` AND (`CreateProcessA/W`) |
| `CV-UPX` | Packed with UPX (section names) | medium | T1027.002 | sections `UPX0` / `UPX1` / `UPX2` |
| `CV-DYNAMIC-LOADING` | Dynamic library loading | low | T1129 | imports `kernel32.LoadLibrary{A,W,ExA,ExW}`, `GetProcAddress` |
| `CV-INJECTION` | Process injection hint | critical | T1055 | **all-of**: (`VirtualAlloc{,Ex}`) AND `WriteProcessMemory` AND (`CreateRemoteThread{,Ex}`) |
| `CV-FILE-ENUM` | File and directory enumeration | low | T1083 | imports `kernel32.FindFirstFile{A,W}`, `FindNextFile{A,W}` |
| `CV-CRED-DUMP` | Credential dumping hint | high | T1003.001 | string `lsass`, import `dbghelp.MiniDumpWriteDump` / `kernel32.DebugActiveProcess` |
| `CV-SELF-DELETE` | Self-deletion | medium | T1070.004 | strings `cmd.exe /c del`, `cmd /c del`, `del /f`; imports `shlwapi.SHDeleteKey{A,W}` |

ATT&CK ids are attached only where the mapping is well established; rules
without a confident mapping would carry an empty list rather than an
invented id.

## Supplying JSON rules

Pass a JSON rule file to `detect_capabilities(..., extra_rules=...)`. The
file is either an object with a `"rules"` list or a bare top-level list:

```json
{
  "rules": [
    {
      "id": "CV-SANDBOX-EVASION",
      "name": "Sandbox-evasion strings",
      "namespace": "defense-evasion/sandbox",
      "severity": "medium",
      "attck": ["T1497.001"],
      "description": "Classic sandbox/VM artefact strings",
      "features": {
        "kind": "or",
        "children": [
          {"kind": "string", "value": "vmware"},
          {"kind": "string", "value": "sandbox"},
          {"kind": "import", "library": "kernel32", "name": "IsDebuggerPresent"}
        ]
      }
    }
  ]
}
```

Feature node kinds:

| Kind | Required fields | Meaning |
|------|-----------------|---------|
| `or` | `children` (1..16) | true when any child is true (short-circuits) |
| `and` | `children` (1..16) | true when every child is true |
| `import` | `library`, optional `name` | import-table match; `name` omitted = any import from the library; `.dll` suffix and case are ignored |
| `string` | `value` (substring, case-insensitive) | any extracted string contains `value` |
| `export` | `name` | export-table name, case-insensitive |
| `section` | `name` | section name, case-insensitive |

Merge semantics: extra rules are **appended** to the built-in pack and the
whole set is deduplicated by id — a user rule with a built-in id replaces
it (later wins; within one file the same applies). Every entry is validated
before any rule is built; the first defect raises `AnalysisError` naming the
file and the defect (unknown feature kind, tree deeper than 8 levels, node
wider than 16 children, bad severity, malformed ATT&CK id, missing fields,
invalid JSON).

## Bounds

| Bound | Default | Effect |
|-------|---------|--------|
| Strings used for matching | 5000 (`string_limit`, range 1..50000) | extraction beyond the cap is dropped; `truncated: true` + warning |
| Feature tree depth | 8 | deeper JSON rules are rejected with `AnalysisError` |
| Children per `or`/`and` node | 16 | wider nodes are rejected (builtins and JSON alike) |
| Locations kept per fired feature | 4 | the true total is still reported per feature |
| Warnings kept | 32 | further warnings are dropped |

Tree size itself is bounded by the rule file (every node is a JSON object in
it), so evaluation work is bounded by construction: depth by the tree cap,
width by the children cap, string scans by `string_limit`.

`skipped_counts` explains non-matches that are not evidence of absence: when
the binary has no rows of a kind a rule needs (no imports, no strings, …),
the report counts the rule under `imports_unavailable` and friends instead of
letting a silent empty collection read as "feature looked for and absent".

## Usage

```python
from pathlib import Path
from codevanta.analysis.capabilities import detect_capabilities, load_rules

report = detect_capabilities(Path("malware.exe"))
print(report.to_dict()["match_count"])      # 3
for match in report.matches:                # sorted critical -> low
    print(match.severity, match.rule_id)
    for fired in match.fired_features:
        print("   ", fired.description, fired.locations)

# With your own rules:
report = detect_capabilities(
    Path("malware.exe"),
    extra_rules=Path("my_rules.json"),
    string_limit=10_000,
)

# Validate a rules file on its own:
rules = load_rules(Path("my_rules.json"))
```

Errors are typed `AnalysisError` throughout: nonexistent path, out-of-range
`string_limit`, unparseable binary, or a malformed rules file (the message
names the file and the defect). A binary with no matching features is **not**
an error — it returns zero matches with empty warnings.
