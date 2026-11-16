# Tool depth audit (v0.5.0)

Objective audit of all registered MCP tools, generated from the
pinned tool list in `tests/test_mcp_tools.py` plus file metrics:
LOC of the backing `ext_*.py` plus its largest `codevanta.analysis`
engine module, and a subprocess/which/frida/gdb scan for external-
tool usage. Depth is a size proxy, not a quality verdict; the
per-tool quality signal remains its `tests/` coverage.

- Total tools: **126**
- Categories: **74** pure offline analysis,
  **9** external-tool bridges, **19**
  host-automation / live-process
- Depth by backing LOC: **51 deep** (>=400), 18 medium
  (150-399), 57 thin (<150)

## All tools

| tool | category | engine module | backing LOC | depth |
| --- | --- | --- | --- | --- |
| `codevanta_adb` | BRIDGE | adb | 2136 | Deep |
| `codevanta_analyze` | ANALYSIS | managed_meta | 2956 | Deep |
| `codevanta_apk_decode` | ANALYSIS | (ext only) | 126 | Thin |
| `codevanta_asar` | ANALYSIS | asar | 657 | Deep |
| `codevanta_binmeta` | ANALYSIS | containers | 1531 | Deep |
| `codevanta_bplist` | ANALYSIS | containers | 1519 | Deep |
| `codevanta_bridges` | BRIDGE | bridge | 427 | Deep |
| `codevanta_call_path` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_callgraph` | ? | ? | 0 | Thin |
| `codevanta_capabilities` | ANALYSIS | (ext only) | 59 | Thin |
| `codevanta_capability_profile` | ANALYSIS | (ext only) | 59 | Thin |
| `codevanta_certs` | ANALYSIS | (ext only) | 126 | Thin |
| `codevanta_cfg` | ? | ? | 0 | Thin |
| `codevanta_codesign` | ANALYSIS | codesign | 561 | Deep |
| `codevanta_compare` | ? | ? | 0 | Thin |
| `codevanta_containers` | BRIDGE | compare | 5261 | Deep |
| `codevanta_coverage` | ANALYSIS | compare | 3468 | Deep |
| `codevanta_crash` | ANALYSIS | crash_core | 756 | Deep |
| `codevanta_dataflow` | ? | ? | 0 | Thin |
| `codevanta_debug` | ? | ? | 0 | Thin |
| `codevanta_debug_close` | HOST | dynamic | 1143 | Deep |
| `codevanta_debug_sessions` | HOST | dynamic | 1143 | Deep |
| `codevanta_debug_start` | HOST | dynamic | 1143 | Deep |
| `codevanta_debug_status` | HOST | dynamic | 1143 | Deep |
| `codevanta_decompile` | ? | ? | 0 | Thin |
| `codevanta_delayload` | ANALYSIS | (ext only) | 35 | Thin |
| `codevanta_demangle` | ANALYSIS | (ext only) | 31 | Thin |
| `codevanta_dex` | ANALYSIS | (ext only) | 52 | Thin |
| `codevanta_dialog_decode` | ANALYSIS | (ext only) | 98 | Thin |
| `codevanta_diff` | ? | ? | 0 | Thin |
| `codevanta_disasm` | ? | ? | 0 | Thin |
| `codevanta_dtb` | ANALYSIS | fdt | 527 | Deep |
| `codevanta_dwarf` | ? | ? | 0 | Thin |
| `codevanta_electron_audit` | ANALYSIS | (ext only) | 126 | Thin |
| `codevanta_elf_macho` | ANALYSIS | (ext only) | 79 | Thin |
| `codevanta_emulate` | ANALYSIS | (ext only) | 267 | Medium |
| `codevanta_entropy` | ? | ? | 0 | Thin |
| `codevanta_firmware_extract` | BRIDGE | bridge | 427 | Deep |
| `codevanta_frida` | HOST | (ext only) | 91 | Thin |
| `codevanta_frida_close` | HOST | frida_bridge | 1587 | Deep |
| `codevanta_frida_load` | HOST | frida_bridge | 1587 | Deep |
| `codevanta_frida_sessions` | HOST | frida_bridge | 1587 | Deep |
| `codevanta_frida_start` | HOST | frida_bridge | 1587 | Deep |
| `codevanta_frida_status` | HOST | frida_bridge | 1587 | Deep |
| `codevanta_fs_diff` | ANALYSIS | (ext only) | 86 | Thin |
| `codevanta_fs_snapshot` | ANALYSIS | (ext only) | 86 | Thin |
| `codevanta_function_hash` | ? | ? | 0 | Thin |
| `codevanta_functions` | ? | ? | 0 | Thin |
| `codevanta_gosymbols` | ANALYSIS | (ext only) | 29 | Thin |
| `codevanta_gpu` | ANALYSIS | gpu_meta | 259 | Medium |
| `codevanta_graph_subset` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_il2cpp` | ANALYSIS | gpu_meta | 259 | Medium |
| `codevanta_info` | ? | ? | 0 | Thin |
| `codevanta_javascript` | ANALYSIS | (ext only) | 126 | Thin |
| `codevanta_js_recover` | ANALYSIS | (ext only) | 126 | Thin |
| `codevanta_jump_table` | ? | ? | 0 | Thin |
| `codevanta_lldb_run` | HOST | (ext only) | 91 | Thin |
| `codevanta_macho_symbols` | ANALYSIS | (ext only) | 32 | Thin |
| `codevanta_metadata` | ANALYSIS | (ext only) | 25 | Thin |
| `codevanta_nav` | ANALYSIS | nav | 918 | Deep |
| `codevanta_nav_providers` | ANALYSIS | nav | 918 | Deep |
| `codevanta_navigate` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_net_capture` | BRIDGE | net_capture | 719 | Deep |
| `codevanta_net_interfaces` | BRIDGE | net_capture | 719 | Deep |
| `codevanta_obligations` | ANALYSIS | compare | 3468 | Deep |
| `codevanta_pcap_fields` | BRIDGE | bridge | 427 | Deep |
| `codevanta_pdb` | ANALYSIS | (ext only) | 61 | Thin |
| `codevanta_pe_assets` | ANALYSIS | (ext only) | 36 | Thin |
| `codevanta_pe_deep` | ANALYSIS | (ext only) | 79 | Thin |
| `codevanta_png_diff` | BRIDGE | compare | 5261 | Deep |
| `codevanta_proc_compare` | HOST | proc_capture | 855 | Deep |
| `codevanta_proc_run` | HOST | proc_capture | 855 | Deep |
| `codevanta_proc_sessions` | HOST | proc_capture | 855 | Deep |
| `codevanta_proc_status` | HOST | proc_capture | 855 | Deep |
| `codevanta_proto_decode` | ANALYSIS | proto_wire | 582 | Deep |
| `codevanta_providers` | ANALYSIS | decompile_router | 424 | Deep |
| `codevanta_pseudo_c` | ANALYSIS | ir_ssa | 1729 | Deep |
| `codevanta_rebuild` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_build` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_build_auto` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_check` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_check_behavior` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_generate` | ANALYSIS | rebuild_codegen | 673 | Deep |
| `codevanta_rebuild_improve` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_list` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_ready` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_rebuild_show` | ANALYSIS | (ext only) | 242 | Medium |
| `codevanta_replay_fixture` | ANALYSIS | (ext only) | 35 | Thin |
| `codevanta_rich` | ANALYSIS | (ext only) | 30 | Thin |
| `codevanta_rizin_functions` | BRIDGE | (ext only) | 91 | Thin |
| `codevanta_sbom` | ANALYSIS | (ext only) | 72 | Thin |
| `codevanta_search_bytes` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_search_procs` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_search_strings` | ANALYSIS | callgraph | 735 | Deep |
| `codevanta_session_list` | ? | ? | 0 | Thin |
| `codevanta_session_save` | ? | ? | 0 | Thin |
| `codevanta_signal_sr` | ANALYSIS | fdt | 527 | Deep |
| `codevanta_similarity` | ? | ? | 0 | Thin |
| `codevanta_sourcemap` | ANALYSIS | containers | 1546 | Deep |
| `codevanta_sqlite` | ANALYSIS | containers | 1531 | Deep |
| `codevanta_ssa` | ANALYSIS | ir_ssa | 1734 | Deep |
| `codevanta_stackstrings` | ANALYSIS | (ext only) | 66 | Thin |
| `codevanta_strings` | ? | ? | 0 | Thin |
| `codevanta_struct` | ? | ? | 0 | Thin |
| `codevanta_symbolic` | ? | ? | 0 | Thin |
| `codevanta_symbolic_solve` | ANALYSIS | symbolic | 1939 | Deep |
| `codevanta_trace` | ? | ? | 0 | Thin |
| `codevanta_triage` | ANALYSIS | (ext only) | 35 | Thin |
| `codevanta_types` | ANALYSIS | (ext only) | 267 | Medium |
| `codevanta_uart_decode` | ANALYSIS | fdt | 527 | Deep |
| `codevanta_ui_preview` | ANALYSIS | (ext only) | 98 | Thin |
| `codevanta_unknowns` | ? | ? | 0 | Thin |
| `codevanta_unpack` | ANALYSIS | containers | 1546 | Deep |
| `codevanta_vtable` | ? | ? | 0 | Thin |
| `codevanta_wasm` | ANALYSIS | (ext only) | 267 | Medium |
| `codevanta_web_capture` | ANALYSIS | proto_wire | 582 | Deep |
| `codevanta_web_inspect` | ANALYSIS | asar | 657 | Deep |
| `codevanta_win_click` | HOST | (ext only) | 151 | Medium |
| `codevanta_win_key` | HOST | (ext only) | 151 | Medium |
| `codevanta_win_shot` | ANALYSIS | (ext only) | 93 | Thin |
| `codevanta_win_tree` | ANALYSIS | (ext only) | 93 | Thin |
| `codevanta_win_type` | HOST | (ext only) | 151 | Medium |
| `codevanta_win_visual_regression` | HOST | (ext only) | 151 | Medium |
| `codevanta_win_windows` | ANALYSIS | (ext only) | 93 | Thin |
| `codevanta_xrefs` | ? | ? | 0 | Thin |
| `codevanta_yara` | ANALYSIS | (ext only) | 41 | Thin |

## Reading the numbers

- **ANALYSIS** tools never leave the process: pure-Python engines
  over bytes the loader already read (offline by construction).
- **BRIDGE** tools shell out to an optional external tool (frida,
  gdb/lldb, rizin, adb/apktool, tshark, ...); they degrade with a
  typed error naming the missing binary when it is not installed.
- **HOST** tools deliberately act on the live machine (SendInput
  automation, process inspection, debugger/injection sessions).
- Thin tools are intentionally small wrappers around one bounded
  engine call, not incomplete engines.
