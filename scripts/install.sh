#!/usr/bin/env bash
# Install CODEVANTA and connect it to coding agents.
set -euo pipefail

SOURCE="${CODEVANTA_SOURCE:-git+https://github.com/kevindoni/CODEVANTA.git}"
SCOPE="user"
APPLY=0
SKIP_INSTALL=0
CLIENTS=()

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --source <pkg>       Package source (default: GitHub repository)
  --client <name>      claude | cursor | cline | vscode (repeatable)
  --scope <scope>      user (default) | project
  --apply              Write the configuration (default: dry run)
  --skip-install       Do not install the package
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --client) CLIENTS+=("$2"); shift 2 ;;
        --scope) SCOPE="$2"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        --skip-install) SKIP_INSTALL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

echo "==> Checking Python"
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"Python 3.10+ is required (found {sys.version.split()[0]})")
print(f"    Python {sys.version.split()[0]}")
PY

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
    echo "==> Installing CODEVANTA from $SOURCE"
    if command -v uv >/dev/null 2>&1; then
        uv tool install --force "$SOURCE"
    elif command -v pipx >/dev/null 2>&1; then
        pipx install --force "$SOURCE"
    else
        python3 -m pip install --user --upgrade "$SOURCE"
    fi
fi

if ! command -v codevanta >/dev/null 2>&1; then
    echo "codevanta is not on PATH. Restart the shell, then rerun with --skip-install." >&2
    exit 3
fi

ARGS=(setup --scope "$SCOPE")
if [[ ${#CLIENTS[@]} -gt 0 ]]; then
    for client in "${CLIENTS[@]}"; do
        ARGS+=(--client "$client")
    done
fi

if [[ "$APPLY" -eq 1 ]]; then
    ARGS+=(--yes --verify)
else
    ARGS+=(--dry-run)
fi

echo "==> codevanta ${ARGS[*]}"
codevanta "${ARGS[@]}"

if [[ "$APPLY" -eq 0 ]]; then
    echo
    echo "Plan only. Re-run with --apply to write the configuration."
fi
