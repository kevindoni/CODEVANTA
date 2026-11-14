import subprocess
subprocess.run(["git", "add", "-A"], check=True)
c = subprocess.run(["git", "commit", "-m", "feat(phase10): depth bridges - binwalk/unblob/tshark/wabt/objdump/apktool/wakaru + PE certificate walker"], capture_output=True, text=True)
print("carrier commit", c.returncode)
r = subprocess.run(["git", "checkout", "-b", "feat/phase10", "origin/main"], capture_output=True, text=True)
r = subprocess.run(["git", "merge", "--no-ff", "--no-edit", "feat/lane-bridge-a"], capture_output=True, text=True)
print("merge", r.returncode)
if r.returncode:
    print(subprocess.run(["git", "diff", "--name-only", "--diff-filter=U"], capture_output=True, text=True).stdout)
else:
    r = subprocess.run(["git", "push", "-u", "origin", "feat/phase10"], capture_output=True, text=True)
    print("push", r.returncode)
    msg = "feat(phase10): optional depth bridges to the specialist ecosystem"
    body = "The hybrid strategy: the zero-install floor stays, and when specialist tools are present CODEVANTA uses their full depth. New: a bridges capability report (codevanta bridges --json) probing binwalk/unblob/tshark/wabt/objdump/sigrok/adb/gdb/z3 with versions; skip-gated firmware extraction via binwalk/unblob with offline-tested output parsers; TShark field queries with canned-TSV parsing; WABT validation + wasm-objdump disassembly; objdump disassembly; apktool decode; Wakaru JS recovery; and a pure-Python PE certificate-table walker (minimal DER parse: signers, serials, signing-time, digest OIDs - no trust verification). New MCP tools: codevanta_bridges, codevanta_firmware_extract, codevanta_pcap_fields, codevanta_apk_decode, codevanta_js_recover, codevanta_certs - each with its @server.tool wrapper in build_server (the v0.2.0 registration lesson)."
    r = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", "feat/phase10", "--title", msg, "--body", body], capture_output=True, text=True)
    print("pr", r.returncode, r.stdout.strip()[-55:], r.stderr.strip()[:120])
