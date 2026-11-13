import subprocess
msg = "feat(phase8): typed comparators and a residual-unknown ledger"
body = "compare.py adds typed comparators (function inventories matched by name and fingerprint, string sets, evidence-bundle membership) and core/unknowns.py adds a residual-unknown ledger (typed UnknownRecord, deterministic ids, open/resolve lifecycle) surfaced through the evidence bundle, the CLI (codevanta compare / codevanta unknowns) and two new MCP tools. Offline tests cover every path."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "feat/typed-compare"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/typed-compare", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
