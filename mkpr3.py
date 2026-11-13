import subprocess
msg = "docs: de-hardcode the README and align docs with the shipped CI"
body = """README is now free of values that rot with every release: exact tool/endpoint/command counts, file:line references, Windows-only example paths and invented session ids are gone. Installation starts from PyPI (pip install codevanta, with a version badge) since v0.1.0 is published, source install second. Every usage command was executed against the committed cross-platform samples, and cfg examples no longer use an invalid 0x hex address.

CONTRIBUTING.md and docs now describe the actual 11-job CI reality (fuzz smoke, informational benchmark, decompile/ghidra parity, py3.13 windows/macos platform runs), docs/install.md no longer gates PyPI install behind the first release, and the docs note that the branch-protection rule still requires the three legacy required checks while the workflow runs a broader set.

Every claim was executed: all usage commands, the reporter script, tool/route counts via script file, PyPI JSON + badge render, and doc-link resolution."""
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "docs/readme-polish", "--title", title, "--body", body], capture_output=True, text=True)
print("pr", r.returncode)
print(r.stdout.strip()[-60:])
print(r.stderr.strip()[:200])
