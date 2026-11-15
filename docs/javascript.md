# Static JavaScript / Electron application analysis

`codevanta js analyze` inventories a JavaScript or Electron application the
way the binary lanes inventory a PE or ELF: read-only, offline, bounded, and
with an evidence record behind every claim. It is pure Python — no Node.js,
no npm install, nothing executed.

```powershell
codevanta js analyze path\to\app            # extracted directory
codevanta js analyze app.asar --json        # Electron archive, JSON payload
codevanta js analyze path\to\app --max-files 100
```

Give it an extracted application directory or an `.asar` archive (the same
bounded parser behind `codevanta asar`). It returns:

* **Modules** — every `.js` / `.cjs` / `.mjs` file, with size and line-level
  findings. `node_modules`, `.git`, `__pycache__` and `.cache` are counted
  and pruned, never entered.
* **Imports** — `require("x")`, static `import ... from "x"`,
  `export ... from "x"`, and dynamic `import("x")`, each classified as
  `relative`, `bare` (npm package), or `builtin` (Node core module).
  Relative specifiers are resolved Node-style (`./util` → `util.js`,
  `lib/index.js`, …) against the scanned file set when the target is one of
  them.
* **External packages** — bare specifiers reduced to package names
  (`@scope/name` aware) with use counts.
* **Package facts** — `name`, `main`, and the declared `electron` version
  from the root `package.json`.
* **Electron boundaries** — files that import `electron` get a heuristic
  process role (`main` / `renderer` / `preload` / `mixed`) from the Electron
  APIs they reference, and every `ipcMain.*` / `ipcRenderer.*` call with a
  literal channel string is recorded with its line. Channels are then paired
  across sides by exact name — the report shows matched pairs plus
  `main_only` / `renderer_only` leftovers instead of inventing endpoints.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| An import / IPC / electron literal at a line | `certain` | the text is provably in the file at that line |
| `relative` / `bare` / `builtin` classification | `medium` | name-shape only; bundlers and aliases can lie |
| Process role (`main` / `renderer` / `preload`) | `medium` | inferred from which Electron APIs the text mentions |
| An IPC pair | `medium` | same channel string on both sides; endpoints not verified |
| Relative-spec resolution | `certain` when resolved | resolved only against files the scan itself read |

Regex scan caveats, stated up front: comments and strings count as text (a
`require` in a comment is a finding), and template-literal or variable
channel names are not IPC sites — only literal strings are reported.

## Bounds

Every bound that fires is reported through `truncated` flags, `skipped`
counters or `warnings` — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| File rows kept | 512 | counting continues; `truncated: true` |
| Directory depth | 64 | deeper subtrees are cut with a warning |
| Per-file bytes | 1 MiB | larger files are skipped and named |
| Whole-scan bytes | 32 MiB | scan stops with a warning |
| Imports per file | 256 | counting continues; `imports_truncated: true` |
| IPC sites per file | 128 | counting continues; `ipc_truncated: true` |
| Warnings kept | 32 | further warnings are dropped |

## Surfaces

The same engine is exposed everywhere:

* CLI — `codevanta js analyze <path> [--json] [--max-files N]`
* MCP — the `codevanta_javascript` tool (`path`, `max_files`)
* GUI — the read-only `/api/js?path=...&max_files=N` dashboard route
* Python — `codevanta.analysis.javascript.analyze_javascript_app(path)`

Unreadable files, non-UTF-8 sources, and a missing or broken `package.json`
degrade to warnings; a missing path, a wrong path kind, or an out-of-range
`max_files` raises the typed `AnalysisError` (exit 2 from the CLI, HTTP 400
from the GUI, `ToolError` over MCP).

Bundle *recovery* (un-minifying) stays where it was: `codevanta js recover`,
the bounded Wakaru bridge — this lane never runs Node.
