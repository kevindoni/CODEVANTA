import subprocess
msg = "release: v0.1.1"
body = "Bump version to 0.1.1 and cut the changelog: live gdb debug sessions (codevanta_debug, MCP tools 23), README de-hardcoded with real screenshots, PyPI-first installation."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "release/0.1.1"], capture_output=True, text=True)
r = subprocess.run(["git", "push", "-u", "origin", "release/0.1.1"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "release/0.1.1", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
