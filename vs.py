import subprocess
msg = "docs: add the honest CODEVANTA vs REA comparison page"
body = "Lane-by-lane matrix against the fully enumerated 229-tool REA catalog: 8/8 lanes covered, parity in core comparators and ledger discipline, three CODEVANTA-exclusive dimensions (emulation, symbolic execution with Z3, self-contained GUI), and an honest list of where REA's specialist depth is still ahead. All CODEVANTA numbers derived live from the installed package."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "docs/vs-rea"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "docs/vs-rea", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
