import subprocess
msg = "test: lift coverage past the 85 gate - solver extras in CI and 128 offline lane tests"
body = "z3-solver>=4.13 joins dev extras (solver extra added) so CI exercises the solver lane for real; 128 targeted offline tests cover the term-missing paths of the phase9 lanes (ips variants, metadata malformed paths, container CLI renders, CDP/ASAR error paths). Local TOTAL: 86.57%."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "origin", "feat/phase9"], capture_output=True, text=True)
print("push", r.returncode)
