import subprocess
msg = "test: wrap-tolerant assertion for the obligations write-error output (80-col CI console splits the phrase)"
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "origin", "feat/phase11"], capture_output=True, text=True)
print("push", r.returncode)
