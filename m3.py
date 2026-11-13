import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "--no-edit", "-m", "merge lane-meta: union of registration imports"], capture_output=True, text=True)
print("meta-merge", c.returncode)
r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "feat/lane-web"], capture_output=True, text=True)
print("web-merge", r.returncode)
print(r.stdout[-200:] if r.returncode else "clean")
if r.returncode:
    print(subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], capture_output=True, text=True).stdout)
