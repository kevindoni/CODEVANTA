import subprocess
msg = "test: bridges report - jeb/hopper probes have their own seams, not the which/runner one"
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "origin", "feat/lane-decompile"], capture_output=True, text=True)
print("push", r.returncode)
