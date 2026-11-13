import subprocess
msg = "feat(phase8): live gdb debug sessions with owned MI process and codevanta_debug MCP tool"
body = "DebugSession launches and owns a gdb --interpreter=mi2 process with bounded timeouts and verified shutdown, exposing break/continue/step/registers/memory/backtrace as typed evidence-backed results. CLI: codevanta debug; MCP: codevanta_debug (tool list 22 to 23). 45 new tests: canned-MI parser tests run everywhere, live gdb tests skip when gdb is absent. ruff and mypy clean; full suite green."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "feat/live-debugger"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/live-debugger", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
