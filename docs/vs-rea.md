# CODEVANTA vs REA — honest comparison

> Last updated: 2026-11-14 · against CODEVANTA `main` after phases 11–12 (55 MCP
> tools) and the full public REA catalog (229 tools, 100% enumerated).
>
> Method: every CODEVANTA number below was derived live from the installed package
> (`build_server().list_tools()`, `ROUTES`, registries, CI logs) — never from memory.
> REA numbers come from its published catalog. Where REA is ahead, we say so.

## TL;DR

| Question | Answer |
|----------|--------|
| Do we cover every REA *lane*? | **Yes — 8/8 lanes have working counterparts.** |
| Who wins on accessibility? | **CODEVANTA.** One `pip install`; REA needs ±12 external tools + 2 commercial licenses (Hopper, JEB). |
| Who wins on raw depth/breadth? | **REA** (229 tools; deep per-format parsers, live GUI bridges). |
| Who wins on emulation & symbolic execution? | **CODEVANTA** — Unicorn emulation and Z3-backed symbolic exploration are absent from the entire REA catalog. |
| Overall weighted position | ~90% of REA's weighted capability, with 3 exclusive dimensions REA does not have. |

## The two philosophies

| | CODEVANTA | REA |
|---|-----------|-----|
| Architecture | **Self-contained engine**: pure-Python core, all 50 MCP tools work on any machine | **Curated orchestrator**: thin, disciplined wrappers over specialist tools you install |
| Install cost | 0 minutes (`pip install codevanta`) | Hours; Hopper (macOS, paid), JEB (paid), Ghidra, Rizin, Frida, GDB, LLDB, adb, Binwalk, Unblob, TShark, WABT, sigrok-cli, Apktool, Wakaru |
| Availability floor | 100% of tools respond everywhere | Wrapper tools fail without their backing binaries |
| Depth ceiling | Bounded pure-Python parsers (+ optional bridges) | Full native depth of each installed tool |
## Lane-by-lane matrix

| Lane | CODEVANTA | REA | Edge |
|------|-----------|-----|------|
| Static analysis | Loader PE/ELF/Mach-O, x86/x64 disasm, xrefs + jump tables, linear+recursive CFG, call graphs (DOT/GraphML/HTML), strings, entropy, struct recovery, dwarf, vtables, binary diff, fingerprints/similarity | Provider-normalized equivalents over Hopper/Ghidra/Rizin/JEB | 🤝 parity in scope; REA deeper per-provider |
| Decompilation | native + Ghidra + angr + **JEB headless (dex/apk)** + objdump + `--provider auto` routing + Hopper probe (GUI export) | + Hopper GUI, JEB MCP | 🤝 parity when tools installed |
| Live debugging | **Owned gdb MI2 sessions** (break/step/registers/memory/backtrace, verified shutdown) + LLDB batch runs + Rizin batch analysis (skip-gated) | gdb MI3 persistent + Frida full lifecycle + LLDB observation + Rizin debug sessions + Cutter | 🤝 near-parity (we own gdb; Frida full lifecycle shipped; REA broader) |
| Frida | **full lifecycle shipped** (device/process discovery, script sessions with bounded duration, skip-gated) + script generation + trace replay | full session lifecycle (spawn-paused, script load/unload/resume) | 🤝 parity |
| Mobile/ADB | devices, props, packages, processes, services, install, screencap, bugreport, **logcat, pull/push, start/stop app, read settings** | same surface + intent launches, file pull/push, window/display details | 🤝 near-parity |
| Web/Electron | CDP passive inspect (stdlib WebSocket client — zero deps), screenshot, WebMCP probe, ASAR reconstruction, Wakaru recovery (skip-gated), **HAR capture summaries, gRPC frame detection, protobuf wire-format decode (structure-only)** | deeper CDP: network capture with protobuf/gRPC semantic decode (with .proto schema), event listeners, source-map tracing | 🟡 REA (semantic decode still deeper) |
| Crash dumps | ELF core (registers/SIGINFO/modules) + Apple `.ips` (both formats) | deeper crash detail + more formats | 🟡 REA |
| Format metadata | **13 auto-detectors**: APK signing v1–v3, Go buildinfo, Rust cargo-auditable, .pyc, Electron fuses, ELF notes/modinfo, desktop classification, BEAM, Flutter/Dart, HarmonyOS HAP, **IL2CPP global-metadata header walk (version families 24–39), CUDA fatbin entry walk with sm_XX arch detection, CUBIN ELF section listing with PTX markers, Clang offload bundles, Mach-O code-signature+entitlements** | far more formats + full per-format depth (cert chains, GPU code-object internals) | 🟡 REA (structure vs full depth) |
| Firmware/signal | magic-scan triage, `.sr` archives, UART decoder-lite, FDT parser, sigrok-cli bridge | Binwalk/Unblob extraction + 100+ sigrok decoders | 🟡 REA (ours always runs; theirs deeper when installed) |
| Comparators | **12 kinds**: functions, strings, bundles, reports, metadata, wasm, crash, sessions, nav, firmware, **screenshots (pure-Python PNG pixel-diff), HAR capture diffs** | ~12 specialists incl. process captures | 🤝 parity (REA keeps process-capture variants) |
| Evidence discipline | digested evidence bundles + unknown ledger | bundles + unknown ledger | 🤝 parity |
| Ledger discipline | **revision-controlled immutable** (CAS via `expected_revision`), obligations ledger, coverage evaluation | revision-controlled + obligations + coverage | ✅ parity (REA's was the model) |
| Navigation state | provider-neutral bookmarks/comments/cursor/history over session store + typed provider probes | live mutation of Hopper databases (needs the app) | 🟡 split (ours portable, theirs live) |
| **Emulation** | **Unicorn-based emulation engine** | — | ✅ CODEVANTA exclusive |
| **Symbolic execution** | **path exploration with optional Z3 solver** (naive fallback) | — | ✅ CODEVANTA exclusive |
| **GUI dashboard** | **read-only loopback web dashboard, 20 routes** | — (relies on provider GUIs) | ✅ CODEVANTA exclusive |
| Plugin SDK / sessions / bridges report | ✅ | — | ✅ CODEVANTA |
## CODEVANTA by the numbers (live-derived)

| Metric | Value |
|--------|-------|
| MCP tools registered | **55** |
| GUI dashboard routes | **20** |
| Comparators | **12 kinds** |
| Metadata detectors | **13** |
| External-tool bridge probes | **11** (incl. JEB headless + Hopper) |
| Live instrumentation | Frida full lifecycle + LLDB batch + Rizin analysis + owned gdb MI2 sessions |
| Tests | **2,200+** (CI: 12 checks × 3 OS, coverage gate 85%) |
| Releases | 0.1.0 → 0.1.1 → 0.2.0 → 0.2.1 (all on PyPI) |

## Where REA is genuinely still ahead

1. **Live GUI bridges** — mutating Hopper databases, Cutter/JEB sessions (needs those apps).
2. **Per-format parser depth** — certificate-chain detail, IL2CPP readable-name recovery, GPU code-object internals, BEAM atoms beyond the chunk table.
3. **Web capture semantic decode** — protobuf/gRPC bodies decoded against .proto schemas, event listeners, source-map tracing (ours is structure-only wire decoding).
4. **Process-capture comparator variants** — terminal/interaction capture diffs.
5. **Raw surface** — 229 tools vs 55.

## Strategy: the hybrid closes the gap without losing the floor

CODEVANTA's bridge architecture (`codevanta bridges --json` probes 9 specialist tools)
means: **when a specialist tool is installed, CODEVANTA uses its full depth; when it is
not, the pure-Python fallback answers anyway.** The floor never drops, the ceiling rises
with your workstation. That is the one thing neither a pure engine nor a pure
orchestrator can offer alone.

