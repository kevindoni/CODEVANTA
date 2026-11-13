import subprocess
msg = "docs: add real screenshots of the CLI, dashboard and call graph to the README"
body = "Three screenshots generated from the tool itself (no mockups): the CLI output of info/functions/xrefs against samples/pe64_text.bin, the read-only loopback dashboard served by codevanta gui, and the self-contained HTML call graph export of samples/shapes-vtable (97 nodes). Captured with headless Edge at 1440px and committed under docs/assets/."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "docs/readme-screenshots"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "docs/readme-screenshots", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-60:], r.stderr.strip()[:150])
