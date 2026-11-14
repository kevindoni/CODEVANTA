import pathlib, re, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
p = pathlib.Path("src/codevanta/analysis/gpu_meta.py")
t = p.read_text(encoding="utf-8")
lines_out = []
for line in t.splitlines(keepends=True):
    if 'b"COB' in line and "== " in line:
        line = re.sub(r'== b"COB[^"]*"', "== COB_MAGIC", line)
    lines_out.append(line)
p.write_text("".join(lines_out), encoding="utf-8", newline="\n")
print("COB_MAGIC line:", any("== COB_MAGIC" in l for l in lines_out))
