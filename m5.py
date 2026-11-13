import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "--no-edit", "-m", "merge lane-solver: union of registrations"], capture_output=True, text=True)
print("solver-merge", c.returncode)
