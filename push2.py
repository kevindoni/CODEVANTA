import subprocess
msg = "fix: track samples/report_bundle.json - the compare tests need it on every OS"
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "origin", "feat/typed-compare"], capture_output=True, text=True)
print("push", r.returncode)
