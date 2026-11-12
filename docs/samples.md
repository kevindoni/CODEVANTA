# Sample binaries

Small, self-contained binaries for trying CODEVANTA without pointing it at a
system executable. Everything here is checked in, so the commands below work
immediately after cloning on Windows, macOS and Linux.

Every binary sample is synthetic, contains no executable payload for any real
platform, and is reproducible byte for byte:

```powershell
python scripts/make_samples.py            # rewrite the samples in place
python scripts/make_samples.py --check    # verify the committed bytes are current
python scripts/make_samples.py --output-dir build/samples   # write elsewhere
```

`scripts/make_samples.py` uses the Python standard library only. It zeroes every
timestamp and uses fixed padding, so regenerating always produces identical
bytes — `--check` exits non-zero when a sample on disk is stale, and
`tests/test_samples.py` runs that check in CI. Everything it writes is
deterministic: the SHA-256 values in the tables below are the committed ones.

## At a glance

| File | Format | Arch | Bitness | Entry point (VA) | Size | One working command |
| --- | --- | --- | --- | --- | --- | --- |
| `pe64_text.bin` | PE32+ | x86_64 | 64 | `0x140001000` | 1024 B | `codevanta info samples/pe64_text.bin` |
| `macho64_text.bin` | Mach-O | x86_64 | 64 | `0x100000180` | 482 B | `codevanta disasm samples/macho64_text.bin --count 10` |
| `elf64_text.bin` | ELF | x86_64 | 64 | `0x401000` | 280 B | `codevanta disasm samples/elf64_text.bin` |
| `elf32_text.bin` | ELF | x86 | 32 | `0x8048000` | 196 B | `codevanta disasm samples/elf32_text.bin` |
| `elf64_min.bin` | ELF | x86_64 | 64 | `0x401000` | 64 B | `codevanta info samples/elf64_min.bin` |
| `elf32_min.bin` | ELF | x86 | 32 | `0x8048000` | 52 B | `codevanta info samples/elf32_min.bin` |

| File | SHA-256 |
| --- | --- |
| `pe64_text.bin` | `bb85cdc6d6994c8a72491cbee6d239833584e212ec62149eb37b5064c80d2500` |
| `macho64_text.bin` | `2aee827875188af6bcb6fbc37f7574820bd3f326ade8a97e37350e2f0f33c41e` |
| `elf64_text.bin` | `90484368acda3d151338987a32f89239863f589e1483256ac265c772129f6cc1` |
| `elf32_text.bin` | `e4a3b26b7d59fa1ee37b96d3343798725920cfb02041ac5437dd5114391a4875` |
| `elf64_min.bin` | `2c37481112bf6d7287e5716f86c7aa9bfa5423b89df6227393b3a73eba6be360` |
| `elf32_min.bin` | `abfb4323bd3e78e2459a6dd96c003f9b7933737730b8e87b6ad90cb7eb429a47` |

`codevanta info` abbreviates the hash to fit its table; the values above are full.


## `pe64_text.bin` — PE32+ / x86_64

A valid PE32+ image with one executable `.text` section (512 bytes at RVA
`0x1000`) holding the shared code body, the ASCII payload
`codevanta x64 sample`, and a one-entry export directory exporting
`codevanta_sample_main` at the entry point. This is the sample to use when you
need an export table (function discovery at `high` confidence) without touching a
real Windows binary.

| Property | Value |
| --- | --- |
| Format | PE (`PE32+`, `IMAGE_FILE_MACHINE_AMD64`) |
| Architecture / bitness | x86_64 / 64-bit, little-endian |
| Image base | `0x140000000` |
| Sections | `.text` (R;X) @ `0x140001000`, file offset `0x200` |
| Imports / exports | 0 imports, 1 export (`codevanta_sample_main`) |

```powershell
codevanta info samples/pe64_text.bin
```

```text
+-------------------------- CODEVANTA - binary info --------------------------+
| File          samples\pe64_text.bin                                         |
| Format        PE                                                            |
| Architecture  x86_64                                                        |
| Bitness       64                                                            |
| Endianness    little                                                        |
| Entry point   0x140001000                                                   |
| Image base    0x140000000                                                   |
| SHA-256       bb85cdc6d6994c8a72491cbee6d239833584e212ec62149eb37b5064c80d...|
| Stripped      no                                                            |
| Sections      1                                                             |
| Imports       0                                                             |
| Exports       1                                                             |
| Symbols       0                                                             |
+----------------------- Decode. Analyze. Understand. ------------------------+
```

`codevanta functions samples/pe64_text.bin` reports that export as a `high`
confidence candidate from `pe.export_table`.

## `macho64_text.bin` — Mach-O 64 / x86_64

A thin `MH_EXECUTE` Mach-O. The `__TEXT` segment holds one executable `__text`
section (58 bytes) with the same code body and ASCII payload; a `__LINKEDIT`
segment holds a symbol table exporting `_codevanta_sample_main` at the entry
point. `LC_MAIN` points at the first instruction.

| Property | Value |
| --- | --- |
| Format | Mach-O (thin, `MH_MAGIC_64`, `MH_EXECUTE`) |
| Architecture / bitness | x86_64 / 64-bit, little-endian |
| Image base | `0x100000000` |
| Sections | `__TEXT,__text` (r-x) @ `0x100000180`, file offset `0x180` |
| Imports / exports | 0 imports, symbol `_codevanta_sample_main` |

```powershell
codevanta disasm samples/macho64_text.bin --count 10
```

```text
               Disassembly at 0x100000180
+------------------------------------------------------+
|     Address | Bytes          | Instruction           |
|-------------+----------------+-----------------------|
| 0x100000180 | 4883ec28       | sub rsp, 0x28         |
| 0x100000184 | 31c0           | xor eax, eax          |
| 0x100000186 | 4989c1         | mov r9, rax           |
| 0x100000189 | 488d0d15000000 | lea rcx, [rip + 0x15] |
| 0x100000190 | ba01000000     | mov edx, 1            |
| 0x100000195 | e805000000     | call 0x10000019f      |
| 0x10000019a | 4883c428       | add rsp, 0x28         |
| 0x10000019e | c3             | ret                   |
| 0x10000019f | b82a000000     | mov eax, 0x2a         |
| 0x1000001a4 | c3             | ret                   |
+------------------------------------------------------+
```

The code body is exactly ten instructions: the ASCII payload starts at `0x1a5`,
so `--count 10` stops at the end of the real code. This is the only committed
Mach-O sample and it is **thin**, not a universal binary. To exercise the fat
container path documented in [`docs/api.md`](api.md#fat-universal-mach-o), wrap it
yourself:

```python
import pathlib
import struct
import tempfile

thin = pathlib.Path("samples/macho64_text.bin").read_bytes()
header = struct.pack(">II", 0xCAFEBABE, 1)                 # FAT_MAGIC, 1 slice
header += struct.pack(">iiIII", 0x01000007, 3, 0x1000, len(thin), 0)
blob = header + b"\x00" * (0x1000 - len(header)) + thin
path = pathlib.Path(tempfile.gettempdir()) / "codevanta_fat_probe.bin"
path.write_bytes(blob)

from codevanta.core.loader import BinaryLoader

info = BinaryLoader().load(path)
print(info.format, info.architecture, hex(info.entry_point))
print(info.evidence.extra["slice_index"], info.evidence.extra["selection_rule"])
```

```text
MachO x86_64 0x100000180
0 prefer_64bit
```

## The ELF samples

Four minimal ELF files: a header-only pair and a section-only pair. They are
stripped by design, so they also exercise the "no symbol table" path — the loader
emits `BinaryInfo.warnings` and `codevanta info` prints
`warning: Binary is stripped: no symbol table found.` and still succeeds.

| File | Kind | Sections | Purpose |
| --- | --- | --- | --- |
| `elf64_min.bin` | ELF64 header only | 0 | Smallest loadable ELF64; checks the "no sections" warning path. |
| `elf64_text.bin` | ELF64 + `.text` | 3 | `.text` at `0x401000` (5 bytes), `.shstrtab`; the fixture used by the report, xref, CFG and session docs. |
| `elf32_min.bin` | ELF32 header only | 0 | 32-bit counterpart of `elf64_min.bin`. |
| `elf32_text.bin` | ELF32 + `.text` | 3 | `.text` at `0x8048000`; the 32-bit disassembly path. |

`codevanta disasm samples/elf64_text.bin`:

```text
      Disassembly at 0x401000
+----------------------------------+
|  Address | Bytes  | Instruction  |
|----------+--------+--------------|
| 0x401000 | 55     | push rbp     |
| 0x401001 | 4889e5 | mov rbp, rsp |
| 0x401004 | c3     | ret          |
+----------------------------------+
```

`codevanta disasm samples/elf32_text.bin`:

```text
      Disassembly at 0x8048000
+----------------------------------+
|   Address | Bytes | Instruction  |
|-----------+-------+--------------|
| 0x8048000 | 55    | push ebp     |
| 0x8048001 | 89e5  | mov ebp, esp |
| 0x8048003 | c3    | ret          |
+----------------------------------+
```

`codevanta info` on the header-only pair reports `Sections 0` plus the same
stripped warning; both load successfully, which is the point of the pair. These
are the fixtures the phase-1 and phase-2 documentation quotes, because a five-byte
`.text` makes every payload small enough to read.

## Non-binary and generated files

| File | What it is |
| --- | --- |
| `note.txt` | A plain-text placeholder (14 bytes) used to check error handling. `codevanta info samples/note.txt` exits non-zero with `error: Unsupported or unreadable binary: samples\note.txt`. |
| `README.md` | The sample directory's own notes, including the shared code-body disassembly table. |
| `report_elf64.json` | 3 883 bytes of saved `codevanta analyze samples/elf64_text.bin` output: one function candidate, four strings, and the disassembly of the five-byte `.text`. |
| `report_notepad.json` | 642 809 bytes of saved `codevanta analyze` output for a full-size PE (`notepad.exe`, 360 448 bytes), useful as a large-payload fixture. |

Both reports are kept in the repository, so a fresh clone has the same bytes the
docs quote (they show as untracked additions until the next commit; the negations
below mean `git add` no longer skips them). Neither is regenerated by
`scripts/make_samples.py` and neither is asserted by the test suite — they are
recorded output for report and session tooling to load. `.gitignore` ignores
`samples/report_*.json` to keep new runs out of the tree, then negates these two
names:

```text
samples/report_*.json
!samples/report_elf64.json
!samples/report_notepad.json
```

A newly written `samples/report_<anything>.json` therefore stays untracked while
the two fixtures stay checked in. Only `report_elf64.json` describes a sample;
`report_notepad.json` is metadata, strings and disassembly *about* a real system
binary — it holds no executable bytes and is not synthetic.

## The shared code body

Both `pe64_text.bin` and `macho64_text.bin` execute the same hand-assembled
x86_64 sequence (`text_code()` in `scripts/make_samples.py`); only the container
format differs. The ELF samples use the shorter `push`/`mov`/`ret` prologue shown
above.

| Offset | Bytes | Instruction | Comment |
| --- | --- | --- | --- |
| `0x00` | `48 83 ec 28` | `sub rsp, 0x28` | shadow space |
| `0x04` | `31 c0` | `xor eax, eax` | |
| `0x06` | `49 89 c1` | `mov r9, rax` | |
| `0x09` | `48 8d 0d 15 00 00 00` | `lea rcx, [rip + 0x15]` | → ASCII payload |
| `0x10` | `ba 01 00 00 00` | `mov edx, 0x1` | |
| `0x15` | `e8 05 00 00 00` | `call 0x1f` | → helper |
| `0x1a` | `48 83 c4 28` | `add rsp, 0x28` | |
| `0x1e` | `c3` | `ret` | |
| `0x1f` | `b8 2a 00 00 00` | `mov eax, 0x2a` | helper |
| `0x24` | `c3` | `ret` | |
| `0x25` | … | `codevanta x64 sample\0` | ASCII payload (21 bytes) |

Because both files share it, the API reference uses the pair to demonstrate
cross-format shape comparison: `function_similarity` over the two entry points
scores `1.0`, while `codevanta diff samples/pe64_text.bin samples/macho64_text.bin`
still reports `Identical no` (1 function added, 1 removed, 1 section added,
1 removed, 1 export removed) because address and name matching cross the
container boundary not at all. See the [quick recipes](api.md#quick-recipes) in
[`docs/api.md`](api.md).
