# Installing CODEVANTA

## One-line install and connect

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.ps1 | iex
```

**macOS / Linux**

```bash
curl -fsSL https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.sh | bash
```

Both scripts install CODEVANTA (via `uv tool`, `pipx`, or `pip --user`), then run
`codevanta setup`. **Without `-Apply` / `--apply` they only print the plan.**

Apply the configuration and verify it:

```powershell
irm https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.ps1 -OutFile install.ps1
.\install.ps1 -Client claude -Apply
```

```bash
curl -fsSL https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.sh | bash -s -- --client claude --apply
```

## Manual install

```powershell
uv tool install git+https://github.com/kevindoni/CODEVANTA.git   # isolated
# or: pipx install git+https://github.com/kevindoni/CODEVANTA.git
# or: python -m pip install --user git+https://github.com/kevindoni/CODEVANTA.git
# from a local clone: python -m pip install -e ".[dev]"
```

## From PyPI (after the first release)

```powershell
uv tool install codevanta       # or: pipx install codevanta
codevanta setup --dry-run --client claude
```

Until the first PyPI release is published, use the GitHub one-liners above.

## Connect a coding agent

```powershell
codevanta setup --client claude --dry-run   # plan + diff, nothing written
codevanta setup --client claude --yes --verify
codevanta setup --client cursor --scope user
codevanta setup --client vscode --scope project --project .
codevanta uninstall --client claude --yes
```

Supported clients: `claude`, `cursor`, `cline`, `vscode`.

## What setup guarantees

1. A plan with a unified diff is printed before anything is written.
2. Nothing is written without `--yes` or an interactive confirmation.
3. Existing configuration is backed up as `*.codevanta.bak`.
4. Re-running is idempotent (`noop` when already configured).
5. `--verify` checks the written entry and runs one tool call on a synthetic ELF.
6. Only the `mcpServers` / `servers` key is touched; invalid JSON is refused.

## Agent prompt

> Install CODEVANTA and connect it to this coding agent. Show me the setup plan
> first, then verify the installation.
