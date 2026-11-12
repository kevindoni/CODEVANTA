# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

Pre-release builds older than the latest minor version are unsupported.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:

<https://github.com/kevindoni/CODEVANTA/security/advisories/new>

Please include:

- CODEVANTA version (`codevanta --version` or the commit SHA)
- Python version and operating system
- Target format/architecture (do **not** attach samples you are not authorized to share)
- Reproduction steps and the smallest input that triggers the problem
- Impact assessment and any suggested fix

We aim to acknowledge reports within 72 hours and to publish an advisory once a
fix is available. Credit is given unless you prefer to stay anonymous.

## In scope

CODEVANTA performs static analysis and never executes the analyzed binary.
Reports are especially relevant for:

- crashes, hangs, or unbounded memory/CPU use on malformed PE or ELF input
- incorrect address/offset mapping that could mislead an analyst
- unsafe configuration writes in `codevanta setup` (path traversal, symlink
  handling, JSON injection, world-writable output)
- MCP tool input validation issues (path handling, argument bounds)
- evidence or confidence values that misrepresent what the engine verified

## Out of scope

- vulnerabilities in third-party dependencies (LIEF, Capstone, `mcp`, Typer,
  Rich) — report those upstream
- issues that require analyzing software you are not authorized to inspect
- social-engineering or physical-access scenarios

## Safe use

Analyze only software you own or have written permission to inspect. Treat
samples as untrusted: use a virtual machine or sandbox, never a production host.
CODEVANTA reads files and computes metadata; it does not execute targets, but it
does parse untrusted input.
