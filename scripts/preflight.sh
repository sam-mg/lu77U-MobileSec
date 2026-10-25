#!/usr/bin/env bash

# Runs the same five gates the pre-push hook runs, so you can check before pushing. Commit messages are checked for every commit on HEAD that no remote branch has yet.

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
echo "[1/5] commit messages"
"$PY" scripts/check_commit_message.py --unpushed || failed=1
echo "[2/5] comment style"
"$PY" scripts/check_comment_style.py || failed=1
echo "[3/5] tests"
"$PY" -m pytest -q || failed=1
echo "[4/5] CodeQL"
./scripts/codeql_scan.sh || failed=1
echo "[5/5] clean install"
./scripts/verify_install.sh || failed=1

if [ "$failed" -ne 0 ]; then
    echo
    echo "preflight failed - a push would be refused."
    exit 1
fi
echo
echo "preflight passed."
