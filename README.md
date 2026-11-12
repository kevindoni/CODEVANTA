# CODEVANTA

**ADVANCED CODE INTELLIGENCE**

> Decode. Analyze. Understand.

AI-Powered Reverse Engineering & Binary Analysis Platform — a local-first,
vendor-agnostic analysis engine that reads, disassembles, and explains PE and
ELF binaries. Every finding carries its evidence source and a confidence level.

## Status

🚧 Phase 1 (foundation) in progress: binary loading, disassembly, string
extraction, function discovery, and JSON export.

## Installation

```powershell
cd D:\PALIKASIKU\CODEVANTA
python -m pip install -e ".[dev]"
```

## Usage

```powershell
codevanta info      samples\app.exe
codevanta functions samples\app.exe
codevanta strings   samples\app.exe --min-length 6
codevanta disasm    samples\app.exe --count 80
codevanta analyze   samples\app.exe --output report.json
```

All addresses in the report are absolute virtual addresses (VA). Function
candidates always state their detection source (`export`, `symbol`,
`entry_point`) and confidence (`high`, `medium`, `low`, `unknown`).

## Testing

```powershell
python -m pytest
ruff check src tests
```

## Documentation

- [Project specification](PROJECT_SPEC.md)
- [Architecture](docs/architecture.md)

## Responsible use

CODEVANTA is intended for authorized analysis only: software you own, systems
you have written permission to inspect, security research, interoperability,
and education. It performs static analysis and never executes the target.

## License

MIT (CODEVANTA-authored code). Third-party components keep their own licenses.
