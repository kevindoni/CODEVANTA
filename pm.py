import subprocess
msg = "docs: desktop-app proposal + two UI mockups (dashboard, compare)"
body = "Answers the desktop-app question with real rendered mockups (headless-Edge screenshots of hand-built HTML, 1280x820) and a recommendation: pywebview wrapping the existing 20-route loopback dashboard as phase 13, with PySide6/Tauri alternatives documented."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "docs/desktop-mockups"], capture_output=True, text=True)
r = subprocess.run(["git", "push", "-u", "origin", "docs/desktop-mockups"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "docs/desktop-mockups", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
