import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "--no-edit", "-m", "merge lane-web: union of registrations"], capture_output=True, text=True)
print("web-merge", c.returncode)
r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "feat/lane-solver"], capture_output=True, text=True)
print("solver-merge", r.returncode)
if r.returncode:
    print(subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], capture_output=True, text=True).stdout)
