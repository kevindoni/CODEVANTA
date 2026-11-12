<#
.SYNOPSIS
Install CODEVANTA and connect it to coding agents.

.DESCRIPTION
Installs CODEVANTA (pipx when available, otherwise pip --user), then runs
`codevanta setup`. Without -Apply only the setup plan is printed.

.PARAMETER Source
Package source. Defaults to the GitHub repository.

.PARAMETER Client
One or more clients: claude, cursor, cline, vscode. Defaults to auto-detection.

.PARAMETER Scope
user (default) or project.

.PARAMETER Apply
Write the configuration. Without it, setup runs as a dry run.

.PARAMETER SkipInstall
Skip package installation (useful when CODEVANTA is already installed).

.EXAMPLE
irm https://raw.githubusercontent.com/kevindoni/CODEVANTA/main/scripts/install.ps1 | iex

.EXAMPLE
.\scripts\install.ps1 -Client claude -Apply
#>
[CmdletBinding()]
param(
    [string]$Source = "git+https://github.com/kevindoni/CODEVANTA.git",
    [string[]]$Client = @(),
    [ValidateSet("user", "project")]
    [string]$Scope = "user",
    [switch]$Apply,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

Write-Step "Checking Python"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.10+ is required but 'python' was not found on PATH."
}
$version = & python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
if ([version]$version -lt [version]"3.10") {
    throw "Python 3.10+ is required (found $version)."
}
Write-Host "    Python $version"

if (-not $SkipInstall) {
    Write-Step "Installing CODEVANTA from $Source"
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        & uv tool install --force $Source
    }
    elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
        & pipx install --force $Source
    }
    else {
        & python -m pip install --user --upgrade $Source
    }
}

Write-Step "Locating codevanta"
if (-not (Get-Command codevanta -ErrorAction SilentlyContinue)) {
    throw "codevanta is not on PATH. Restart the terminal, then rerun with -SkipInstall."
}

$setupArgs = @("setup")
foreach ($name in $Client) { $setupArgs += @("--client", $name) }
$setupArgs += @("--scope", $Scope)
if ($Apply) {
    $setupArgs += @("--yes", "--verify")
}
else {
    $setupArgs += @("--dry-run")
}

Write-Step ("codevanta " + ($setupArgs -join " "))
& codevanta @setupArgs

if (-not $Apply) {
    Write-Host ""
    Write-Host "Plan only. Re-run with -Apply to write the configuration." -ForegroundColor Yellow
}
