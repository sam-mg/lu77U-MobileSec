#!/usr/bin/env bash

# Runs the same four gates the pre-push hook runs, so you can check before pushing.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
    PY="${VIRTUAL_ENV}/bin/python"
elif [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
else
    PY="python3"
fi

failed=0
echo "[1/4] comment style"
"$PY" scripts/check_comment_style.py || failed=1
echo "[2/4] tests"
"$PY" -m pytest -q || failed=1
echo "[3/4] CodeQL"
./scripts/codeql_scan.sh || failed=1
echo "[4/4] clean install"
./scripts/verify_install.sh || failed=1

if [ "$failed" -ne 0 ]; then
    echo
    echo "preflight failed - a push would be refused."
    exit 1
fi
echo
echo "preflight passed."
