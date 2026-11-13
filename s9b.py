import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", "feat(phase9b): signal/firmware lane and provider-neutral navigation state"], capture_output=True, text=True)
print("carrier commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "feat/phase9c", "origin/main"], capture_output=True, text=True)
r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "feat/lane-nav"], capture_output=True, text=True)
print("merge", r.returncode)
if r.returncode:
    print(subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], capture_output=True, text=True).stdout)
else:
    r = subprocess.run(["git", "push", "-u", "origin", "feat/phase9c"], capture_output=True, text=True)
    print("push", r.returncode)
    msg = "feat(phase9b): signal lane (.sr/UART/FDT/sigrok gate) and provider-neutral navigation"
    body = "Signal: .sr session archives, UART decoder-lite with parity/stop validation, flattened devicetree (FDT) parser, skip-gated sigrok-cli wrapper. Nav: provider-neutral bookmarks/comments/cursor/goto-history over the session store plus typed external-GUI provider probes (Hopper/Cutter/Ghidra). New CLI sub-apps signal+nav; MCP tools codevanta_signal_sr, codevanta_uart_decode, codevanta_dtb, codevanta_nav, codevanta_nav_providers. Offline byte-level fixtures cover every path; new modules at >=92% coverage."
    r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/phase9c", "--title", msg, "--body", body], capture_output=True, text=True)
    print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
