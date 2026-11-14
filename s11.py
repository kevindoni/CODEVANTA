import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", "feat(phase11): live frida/lldb/rizin bridges, ledger v2 (revisions+obligations+coverage), 10 comparators, format depth (BEAM/IL2CPP/Flutter/HAP/CUDA/Mach-O codesign), ADB ops, 6 dashboard routes"], capture_output=True, text=True)
print("carrier commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "feat/phase11", "origin/main"], capture_output=True, text=True)
r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "feat/lane-gui2"], capture_output=True, text=True)
print("merge", r.returncode)
if r.returncode:
    print(subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], capture_output=True, text=True).stdout)
else:
    r = subprocess.run(["git", "push", "-u", "origin", "feat/phase11"], capture_output=True, text=True)
    print("push", r.returncode)
    msg = "feat(phase11): live instrumentation bridges, ledger v2, 10 comparators, format depth, dashboard routes"
    body = "Closes the five remaining REA-ahead areas: real live bridges (Frida full lifecycle, LLDB batch runs, Rizin analysis - all skip-gated with offline transcript parsers), the ledger goes revision-controlled immutable with CAS semantics plus an obligations ledger and coverage evaluation (matching REA's discipline model), the comparator suite grows from 3 to 10 kinds (reports, wasm, metadata, crash, sessions, nav, firmware), format depth adds BEAM/IL2CPP/Flutter/HAP/CUDA detectors and a pure-Python Mach-O code-signature walker, ADB gains logcat/pull/push/start/stop/settings, and the dashboard grows from 14 to 20 routes exposing the new lanes. Registered MCP tools: 50."
    r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/phase11", "--title", msg, "--body", body], capture_output=True, text=True)
    print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
