# Sample binaries

Small, self-contained binaries for trying CODEVANTA commands without pointing at
a system executable such as `C:\Windows\System32\notepad.exe`. Everything here is
checked in, so the commands below work immediately after cloning, on Windows,
macOS and Linux.

All samples are synthetic, safe to inspect, and reproducible:

```powershell
python scripts/make_samples.py          # rewrite the samples
python scripts/make_samples.py --check  # verify the committed bytes are current
```

`scripts/make_samples.py` uses the Python standard library only. It zeroes every
timestamp and uses fixed padding, so regenerating always produces byte-identical
files (enforced by `tests/test_samples.py`).

## `pe64_text.bin` — PE32+ / x86_64

A valid PE32+ executable image with a single executable `.text` section
(512 bytes, RVA `0x1000`) that holds the code body, the ASCII payload
`codevanta x64 sample`, and a one-entry export directory exporting
`codevanta_sample_main` at the entry point.

| Property | Value |
| --- | --- |
| Format | PE (PE32+, `IMAGE_FILE_MACHINE_AMD64`) |
| Architecture / bitness | x86_64 / 64-bit, little-endian |
| Entry point (VA) | `0x140001000` |
| Image base | `0x140000000` |
| Sections | `.text` (R;X) @ `0x140001000`, file offset `0x200` |
| Imports / exports | 0 imports, 1 export (`codevanta_sample_main`) |
| Size | 1024 bytes |
| SHA-256 | `bb85cdc6d6994c8a72491cbee6d239833584e212ec62149eb37b5064c80d2500` |

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

`codevanta info` abbreviates the hash to fit its table; the table above lists the
full value. `codevanta functions samples/pe64_text.bin` reports the export as a
`high` confidence candidate from `pe.export_table`.

## `macho64_text.bin` — Mach-O 64 / x86_64

A thin `MH_EXECUTE` Mach-O. The `__TEXT` segment contains one executable
`__text` section (58 bytes) with the same code body and ASCII payload, and a
`__LINKEDIT` segment holds a symbol table exporting `_codevanta_sample_main` at
the entry point. `LC_MAIN` points at the first instruction.

| Property | Value |
| --- | --- |
| Format | Mach-O (thin, `MH_MAGIC_64`, `MH_EXECUTE`) |
| Architecture / bitness | x86_64 / 64-bit, little-endian |
| Entry point (VA) | `0x100000180` (`LC_MAIN` entry offset `0x180`) |
| Image base | `0x100000000` |
| Sections | `__TEXT,__text` (r-x) @ `0x100000180`, file offset `0x180` |
| Imports / exports | 0 imports, symbol `_codevanta_sample_main` |
| Size | 482 bytes |
| SHA-256 | `2aee827875188af6b6fbc37f7574820bd3f326ade8a97e37350e2f0f33c41e` |

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

The code body is intentionally ten instructions long: the ASCII payload starts
at `0x1a5`, so `--count 10` stops exactly at the end of the real code.

## `hello.dex` — Android DEX

A real 952-byte DEX 035 container built with the Android SDK's `d8` from a
two-method `Main.java` (`add`, `main`, plus the compiler-generated
`<init>`). Unlike the image formats, DEX has no virtual address space: method
addresses are **file offsets**, and the loader says so in a warning. Defined
methods become `high`-confidence function symbols from `dex.method_ids`;
referenced-but-undefined methods (here `println` and `Object.<init>`) become
imports with the defining class as their `library`.

| Property | Value |
| --- | --- |
| Format | DEX 035, little-endian |
| Architecture | `dalvik` (disassembly not supported yet) |
| Entry point / image base | none / `0x0` |
| Sections | none (bytecode container) |
| Symbols | `LMain;->add` @ `0x160`, `LMain;-><init>` @ `0x174`, `LMain;->main` @ `0x18c` |
| Imports | `Ljava/io/PrintStream;->println`, `Ljava/lang/Object;-><init>` |
| Size | 952 bytes |
| SHA-256 | `029c6933bcad5885b8015ce043c95a29a07049ac14ea5dc6f1f85d268c639c27` |

```powershell
codevanta functions samples/hello.dex
codevanta strings samples/hello.dex --min-length 6
```

## `hello-dwarf` — ELF aarch64 with DWARF debug info

A 7 752-byte aarch64 PIE executable built with the Android NDK's clang
(`-g -O0`) from a three-function `main.c` (`compute`, `scale_and_shift`,
`main`) with a `struct point`. It is the fixture for `codevanta dwarf`:
producer-grade symbol evidence with byte-exact extents and named type
layouts, only available when a build keeps its debug info.

| Property | Value |
| --- | --- |
| Format | ELF64, aarch64, little-endian, PIE, **not stripped** |
| DWARF functions | `compute` @ `0x708` (64 B, external), `scale_and_shift` @ `0x748` (52 B), `main` @ `0x77c` (64 B, external) |
| Named types | `struct point` — 8 bytes |
| Size | 7 752 bytes |

```powershell
codevanta dwarf samples/hello-dwarf
codevanta dwarf samples/hello-dwarf --json
```

## `shapes-vtable` — ELF aarch64 with C++ vtables

An 47 400-byte aarch64 PIE executable built with the Android NDK's clang++
(`-O0`) from two polymorphic classes (`Square`, `Circle` deriving from
`Shape`). It is the fixture for `codevanta vtable`: the `.data.rel.ro`
section holds the two class vtables — pointer slots that are **zero on disk**
(PIE) and filled through `R_AARCH64_RELATIVE` dynamic relocations, which the
discovery overlays so virtualized builds are visible to static analysis.

| Property | Value |
| --- | --- |
| Format | ELF64, aarch64, little-endian, PIE |
| Vtables | `Square` @ `0xb8f0` (4 slots), `Circle` @ `0xb948` (4 slots) in `.data.rel.ro` |
| Scan result | 3 candidate tables (the two class vtables plus one runtime table) |
| Size | 47 400 bytes |

```powershell
codevanta vtable samples/shapes-vtable --scan
codevanta vtable samples/shapes-vtable --address 0xb8f0
```

## Shared code body

Both samples execute the same hand-assembled x86_64 sequence
(`scripts/make_samples.py`, `text_code()`); only the container format differs.

| Offset | Bytes | Instruction | Comment |
| --- | --- | --- | --- |
| `0x00` | `48 83 ec 28` | `sub rsp, 0x28` | shadow space |
| `0x04` | `31 c0` | `xor eax, eax` | |
| `0x06` | `49 89 c1` | `mov r9, rax` | |
| `0x09` | `48 8d 0d 15 00 00 00` | `lea rcx, [rip + 0x15]` | -> ASCII payload |
| `0x10` | `ba 01 00 00 00` | `mov edx, 0x1` | |
| `0x15` | `e8 05 00 00 00` | `call 0x1f` | -> helper |
| `0x1a` | `48 83 c4 28` | `add rsp, 0x28` | |
| `0x1e` | `c3` | `ret` | |
| `0x1f` | `b8 2a 00 00 00` | `mov eax, 0x2a` | helper |
| `0x24` | `c3` | `ret` | |
| `0x25` | ... | `codevanta x64 sample\0` | ASCII payload (21 bytes) |

## Other files in this directory

* `elf32_min.bin`, `elf32_text.bin`, `elf64_min.bin`, `elf64_text.bin` — the
  original header-only and section-only ELF samples used by the test suite and
  the docs. `elf64_text.bin` SHA-256:
  `90484368acda3d151338987a32f89239863f589e1483256ac265c772129f6cc1`.
* `note.txt` — a non-binary placeholder used to check error handling.
* `report_elf64.json`, `report_notepad.json` — saved `codevanta analyze`
  reports (3 883 bytes about `elf64_text.bin`, 642 809 bytes about a full-size
  PE), useful as fixtures for `codevanta session` and report tooling. They are
  not produced by `scripts/make_samples.py`; `.gitignore` ignores
  `samples/report_*.json` and then negates these two names, so new reports stay
  untracked while these fixtures stay checked in.

