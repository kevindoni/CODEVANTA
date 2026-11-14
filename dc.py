import subprocess
msg = "feat(decompile): provider auto-routing, JEB headless bridge, Hopper probe, codevanta providers"
body = "The decompile lane reaches REA parity: analysis/decompile_router.py picks the provider deterministically (jeb for dex/apk when installed, ghidra, angr, native as the floor; hopper is GUI-only and probed honestly), analysis/jeb_bridge.py wraps JEB headless script export with a canned-tested parser, analysis/hopper_bridge.py reports the macOS GUI contract honestly, `codevanta providers` / `codevanta_providers` print the typed capability report, and the bridges registry grows to 11 probes. docs/vs-rea.md decompilation row moves to parity-when-installed."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "feat/lane-decompile"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/lane-decompile", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
