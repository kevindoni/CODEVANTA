import subprocess
msg = "docs: refresh the REA comparison after phases 11-12 (55 tools, 12 comparators, live bridges)"
body = "Frida moves to parity (full lifecycle shipped), ledger discipline to full parity (revisions/CAS/obligations/coverage), comparators to 12 kinds (screenshot pixel-diff + HAR diffs), format metadata rows updated with IL2CPP header walk and GPU containers, web capture structure decode noted, and the honest still-ahead list narrows to live GUI bridges, readable-name recovery, semantic .proto decode, and process-capture variants. Weighted position: ~90%."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "docs/vs-rea-refresh"], capture_output=True, text=True)
r = subprocess.run(["git", "push", "-u", "origin", "docs/vs-rea-refresh"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "docs/vs-rea-refresh", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
