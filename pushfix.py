import subprocess
msg = "test: gate live gdb tests off Windows CI (MinGW gdb MI rejects exec/run and early register reads)"
body = "Windows runners ship gdb, so the live session tests ran there and MinGW gdb rejected -exec-run (no executable specified) and -data-list-register-values before a stop frame. Gate needs_gdb on sys.platform == win32 as well; parsers, scripted-transport session tests and CLI/MCP tests still run on every OS."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "origin", "feat/live-debugger"], capture_output=True, text=True)
print("push", r.returncode)
