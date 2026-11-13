import subprocess
msg = "release: v0.2.0"
body = "Bump version to 0.2.0 and cut the changelog: typed comparators, residual-unknown ledger, six REA-parity lanes (crash, metadata, containers+sqlite, mobile/ADB, web/CDP+ASAR, solver), the signal/firmware lane, and provider-neutral navigation."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "release/0.2.0"], capture_output=True, text=True)
r = subprocess.run(["git", "push", "-u", "origin", "release/0.2.0"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "release/0.2.0", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
