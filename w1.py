import subprocess
msg = "fix(mcp): register the 12 ext tools that were imported but never wired into build_server"
body = "v0.2.0 shipped with only 26 of the intended 38 MCP tools registered: the ext lane tools had import lines in tools.py but no @server.tool wrappers in build_server. This adds the 12 wrappers (crash, binmeta, sqlite, adb, web_inspect, asar, symbolic_solve, signal_sr, uart_decode, dtb, nav, nav_providers) following the codevanta_metadata pattern, and asserts the full 38-name list in test_mcp_tools."
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", msg, "-m", body], capture_output=True, text=True)
print("commit", c.returncode)
r = subprocess.run(["git", "push", "-u", "origin", "feat/wire-mcp"], capture_output=True, text=True)
print("push", r.returncode)
r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/wire-mcp", "--title", msg, "--body", body], capture_output=True, text=True)
print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
