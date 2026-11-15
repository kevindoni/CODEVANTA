# Persistent analysis sessions (gdb / Frida / process captures)

Three session families share one shape: a bounded dynamic-analysis run
registered under a deterministic id (`dbg-001`, `frida-001`,
`proc-001`, …), a read-only `status` that reports exactly the stored
result, and a bounded listing. None of them is interactive plumbing —
each session wraps **one** bounded invocation, and every tool says so
in its description.

| Family | Tools | What it wraps |
|--------|-------|---------------|
| gdb (`dbg-NNN`) | `codevanta_debug_start` / `codevanta_debug_status` / `codevanta_debug_close` / `codevanta_debug_sessions` | one `gdb -batch` run to completion with breakpoint hits parsed |
| Frida (`frida-NNN`) | `codevanta_frida_start` / `codevanta_frida_load` / `codevanta_frida_status` / `codevanta_frida_close` / `codevanta_frida_sessions` | one bounded observation run (attach/spawn + script + `run_for` slice); `load` adds a script to a live module-backed session |
| process (`proc-NNN`) | `codevanta_proc_run` / `codevanta_proc_status` / `codevanta_proc_compare` / `codevanta_proc_sessions` | one owned bounded subprocess run with piped output captured |

Every family keeps at most **8 session records** in a module-level
registry; a full registry is a typed error telling you to close one
first (the proc lane has no close — see below). Raw captures are
persisted next to each session script and removed on `close`.

## Security, honest up front

The gdb and Frida starts **execute code**: `codevanta_debug_start`
runs the target binary under gdb to completion;
`codevanta_frida_start` attaches to (or spawns!) a live process and
injects your script; `codevanta_proc_run` executes the command you
pass as an owned child. All three descriptions state that this is
dynamic analysis: pass only targets and commands you intend to run.
`status`, `sessions` and `compare` never re-run anything.

## The gdb family

`codevanta_debug_start(path, addresses, max_hits=64, timeout=60.0)` —
breakpoint addresses (file virtual-address space) are validated, a gdb
batch script is generated with a hit ceiling and wall-clock budget,
executed once through `gdb -batch`, and the captured trace is parsed
into a summary: `total_hits`, distinct `hit_addresses`, backtrace
-attributed `function_coverage`, a bounded recent-hits preview and
warnings. Requires gdb on PATH; its absence is a typed error. State
lifecycle: `completed` after the run, `closed` after cleanup.
`codevanta_debug_close(session_id)` removes the session artifacts
(script, raw capture, directory) — the summary stays queryable through
`codevanta_debug_sessions`.

## The Frida family

`codevanta_frida_start(mode="attach", target="", pid=None,
script=None, script_path=None, device_id=None, duration=10.0)` —
attach to a pid or program name, or spawn a program (resumed after the
initial script loads). One initial script inline (`script`) or by file
(`script_path`, at most 64 KiB), then one bounded observation slice of
`duration` (1…60 s). The availability probe (`find_spec` + `which`,

## The proc family

`codevanta_proc_run(command, arguments=None, working_directory=None,
timeout=30.0, env=None, max_output_bytes=1048576)` — the command runs
in argv form (no shell) with output via pipes (no terminal emulation,
no PTY): stdout and stderr are kept up to 1 MiB per stream with the
sha256 of the **full raw bytes** recorded either way. At most 32
arguments and 16 extra env variables (merged over the inherited
environment). A wall-clock timeout is reported as an honest
`timed_out` state with the partial output and `exit_code: null` — not
an error. **This lane has no `close` step**: a full registry refuses
further runs until the server process restarts (ids stay monotonic).
`codevanta_proc_compare(left_session_id, right_session_id)` compares
two stored captures deterministically — exit-code match, duration
delta in milliseconds, per-stream sha256 digest match, and a bounded
difflib unified diff (200 lines per stream) — with a verdict of
`identical`, `exit-mismatch`, `output-mismatch` or `divergent`. It
never executes anything.

## Bounds and confidence

Every bound that fires is reported through `truncated` flags, counts
or warnings — never silently.

| Bound | Default | Ceiling | Effect |
|-------|---------|---------|--------|
| Session records (each family) | 8 | 8 | full registry is a typed error |
| gdb hit ceiling (`max_hits`) | 64 | 100 000 | the script stops the target at the ceiling |
| gdb wall clock (`timeout`) | 60 s | — | the run is killed; the record says so |
| Stored summary entries (addresses / coverage) | 64 | — | bounded preview in status |
| Recent hits / messages preview | 8 | — | bounded preview in status |
| Frida duration (`duration`) | 10 s | 60 s | out-of-range is a typed error |
| Frida script size | 64 KiB | 64 KiB | larger scripts are typed errors |
| Frida message capture | 200 | 200 | `dropped_messages` reports the rest |
| Proc wall clock (`timeout`) | 30 s | 120 s | `timed_out` state, partial output kept |
| Proc output | 1 MiB per stream | — | full raw sha256 recorded either way |
| Proc compare diff | 200 lines per stream | — | verdict is computed on the digests, not the diff |

| Finding | Confidence | Why |
|---------|------------|-----|
| gdb trace summary rows | reported as parsed | the summary is exactly what gdb printed, with `truncated` when the parser hit a bound |
| Frida message rows | `medium` | delivered by the instrumentation bridge at run time |
| Proc capture rows (argv, exit code, stream digests) | `high` | read back from the completed subprocess result |

## Limitations

* **No interactive sessions anywhere.** A gdb session is one batch
  run; a Frida session is attach/spawn plus bounded slices; a proc
  session is one completed run. `status` is a report, not a console.
* Closed records keep their bounded summaries but lose their
  artifacts — the raw captures are gone by design.
* Frida one-shot sessions cannot load more scripts; install the frida
  Python module for a live, loadable session.
* The proc lane's registry cannot be drained without a server restart;
  plan long-running sessions accordingly.
* Frida targets and gdb runs happen on this machine against local
  binaries/processes; no remote devices beyond `device_id` pass-through.

never an import) runs first and its absence is one honest typed error
naming what is missing. The session kind is data:

* with the **frida Python module**, the bridge handle stays live —
  `codevanta_frida_load(session_id, source=None, path=None,
  duration=10.0)` attaches further scripts (each followed by another
  bounded slice) until `codevanta_frida_close`;
* without the module, the bridge degrades to one bounded
  `frida -l <script>` CLI run: the record is a **one-shot**
  (`session_kind: "one-shot-cli"`), a script is required, and `load`
  refuses with the typed "not supported for this session kind" error.

Message captures are capped by the bridge (200 messages) —
`dropped_messages` reports what was summarised away. `status` reports
the stored capture, message counts, recent-messages preview, run
warnings and the probe snapshot taken at start.
