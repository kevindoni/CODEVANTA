import pathlib, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
p = pathlib.Path("src/codevanta/analysis/gpu_meta.py")
lines = p.read_text(encoding="utf-8").splitlines()
new_block = [
    '    window = payload[idx : idx + 16]',
    '    raw_token = window.split()[0] if window.split() else b""',
    '    raw_token = raw_token.rstrip(b\")\x00,;[]\")',
    '    token = raw_token.decode("ascii", "replace")',
    '    return token or None',
]
lines[92:96] = new_block
p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print("_find_arch rewritten")
