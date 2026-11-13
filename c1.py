import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", "feat(phase9): crash dumps, binary containers, and the ADB lane"], capture_output=True, text=True)
print("mobile-carrier commit", c.returncode)
