import pathlib
pp = pathlib.Path("pyproject.toml")
t = pp.read_text(encoding="utf-8")
assert 'version = "0.2.1"' in t
pp.write_text(t.replace('version = "0.2.1"', 'version = "0.3.0"', 1), encoding="utf-8", newline="\n")
cl = pathlib.Path("CHANGELOG.md")
c = cl.read_text(encoding="utf-8")
entry = """## [0.3.0] - 2026-11-14

### Added

- **Live instrumentation bridges** (phase 11/12): Frida full lifecycle
  (device/process discovery, bounded script sessions), LLDB batch runs
  (breakpoint -> registers -> backtrace, transcript-parsed), and Rizin batch
  analysis (function list + binary info) - all skip-gated with offline
  transcript parsers (`codevanta live`, MCP `codevanta_frida`,
  `codevanta_lldb_run`, `codevanta_rizin_functions`).
- **Ledger discipline v2**: revision-controlled immutable unknown records with
  CAS semantics (`expected_revision`), an obligations ledger
  (authority/confidence/environment/probes), and coverage evaluation
  (`codevanta obligations`, MCP `codevanta_obligations`, `codevanta_coverage`).
- **Comparator suite 12 kinds** (`codevanta compare`): plus reports, metadata,
  wasm, crash, sessions, nav, firmware, screenshots (pure-Python PNG
  pixel-diff, all five PNG filters), and HAR capture diffs.
- **Depth lanes** (phase 9/10/12): crash dumps (ELF core + Apple .ips), format
  metadata auto-detection (13 detectors: APK signing, Go buildinfo, Rust
  cargo-auditable, .pyc, Electron fuses, ELF notes/modinfo, desktop layouts,
  BEAM, IL2CPP header walk, Flutter/Dart, HarmonyOS HAP, CUDA fatbin,
  Mach-O code-signature), binary containers (WASM, EVM, GGUF, safetensors,
  pcap, firmware magic scan), a read-only SQLite viewer, the ADB mobile lane,
  the Web/Electron lane (stdlib CDP client, ASAR), depth bridges to
  binwalk/unblob/tshark/wabt/objdump/apktool/wakaru, signal lane (sigrok .sr,
  UART decoder-lite, devicetree FDT), provider-neutral navigation state, and
  pure-Python PE certificate-table parsing.

### Changed

- MCP server registers **55 tools** (from 22 at v0.1.0); dashboard grows to 20
  routes; `codevanta bridges --json` reports specialist-tool availability.

### Fixed

- v0.2.0 shipped 26 of the intended 38 MCP tools registered (fixed in 0.2.1);
  this release also fixes a 80-column-console test assertion and completes
  the webcap `_result_payload` helper.
"""
c = c.replace("## [0.2.1]", entry + "\n## [0.2.1]", 1)
cl.write_text(c, encoding="utf-8", newline="\n")
print("bumped 0.3.0 + changelog")
