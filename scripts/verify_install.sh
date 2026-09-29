#!/usr/bin/env bash

# Proves the package actually installs and runs cleanly for someone who has never touched this repo: a brand-new venv, `pip install -e .` against it (pulling every dependency from PyPI, not reusing anything already on the machine), then the two entry-point flags a real user would try first.

# -v/--version must print the same version pyproject.toml declares - a mismatch there means the packaging metadata has drifted from the source of truth. -V/--verbose starts the real web dashboard and blocks forever by design (see cli/parser.py's own docstring on why -v is version and -V is verbose), so this runs it with --port and --no-browser - both real, undocumented flags that exist for exactly this kind of embedding - and treats "still running after a few seconds, no traceback" as success rather than waiting for an exit that never comes on its own.

# This is the slowest of the push gates by far: a fresh install of this package's dependency list (WeasyPrint, Frida, Semgrep, androguard, uiautomator2, mitmproxy and the rest) from a cold venv takes real minutes, every single run, because the whole point is that nothing is reused.

# Exit 0: the version matches and the server started without error.
# Exit 1: any step failed.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
REPO_ROOT="$(pwd)"

if command -v python3.12 >/dev/null 2>&1; then
    SYSTEM_PY="python3.12"
else
    SYSTEM_PY="python3"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lu77u-install-check.XXXXXX")" || exit 1
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        sleep 1
        kill -9 "$SERVER_PID" 2>/dev/null
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

expected_version="$("$SYSTEM_PY" -c '
import tomllib
with open("pyproject.toml", "rb") as fh:
    print(tomllib.load(fh)["project"]["version"])
')" || { echo "verify_install: could not read the version from pyproject.toml" >&2; exit 1; }
echo "verify_install: pyproject.toml declares version $expected_version"

echo "verify_install: creating a fresh venv..."
if ! "$SYSTEM_PY" -m venv "$WORK_DIR/.venv" > "$WORK_DIR/venv.log" 2>&1; then
    echo "verify_install: could not create the venv" >&2
    cat "$WORK_DIR/venv.log" >&2
    exit 1
fi
VENV_PY="$WORK_DIR/.venv/bin/python"
VENV_BIN="$WORK_DIR/.venv/bin/lu77U-MobileSec"

echo "verify_install: installing the package into it (pulls every dependency fresh; this is the slow part)..."
if ! "$VENV_PY" -m pip install --upgrade pip -q > "$WORK_DIR/pip.log" 2>&1; then
    echo "verify_install: could not upgrade pip in the fresh venv" >&2
    tail -n 40 "$WORK_DIR/pip.log" >&2
    exit 1
fi
if ! "$VENV_PY" -m pip install -e "$REPO_ROOT" -q >> "$WORK_DIR/pip.log" 2>&1; then
    echo "verify_install: pip install -e . failed in the fresh venv" >&2
    tail -n 60 "$WORK_DIR/pip.log" >&2
    exit 1
fi

if ! [ -x "$VENV_BIN" ]; then
    echo "verify_install: the lu77U-MobileSec console script was not installed" >&2
    exit 1
fi

echo "verify_install: running lu77U-MobileSec -v..."
version_output="$("$VENV_BIN" -v 2>&1)"
version_status=$?
if [ "$version_status" -ne 0 ]; then
    echo "verify_install: 'lu77U-MobileSec -v' exited $version_status" >&2
    echo "$version_output" >&2
    exit 1
fi
if ! echo "$version_output" | grep -qF "$expected_version"; then
    echo "verify_install: 'lu77U-MobileSec -v' printed '$version_output', which does not contain the pyproject.toml version '$expected_version'" >&2
    exit 1
fi
echo "verify_install: -v ok ($version_output)"

echo "verify_install: running lu77U-MobileSec -V (starts the dashboard; checked for a clean startup, then stopped)..."
port="$("$VENV_PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
verbose_log="$WORK_DIR/verbose.log"
"$VENV_BIN" -V --no-browser --port "$port" > "$verbose_log" 2>&1 &
SERVER_PID=$!

started=0
for _ in $(seq 1 20); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    if grep -qi "traceback\|error" "$verbose_log" 2>/dev/null; then
        break
    fi
    started=1
    sleep 0.5
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    wait "$SERVER_PID" 2>/dev/null
    exit_status=$?
    echo "verify_install: 'lu77U-MobileSec -V' exited on its own (status $exit_status) instead of staying up" >&2
    cat "$verbose_log" >&2
    SERVER_PID=""
    exit 1
fi
if grep -qi "traceback" "$verbose_log" 2>/dev/null; then
    echo "verify_install: 'lu77U-MobileSec -V' logged a traceback while starting" >&2
    cat "$verbose_log" >&2
    exit 1
fi
if [ "$started" -ne 1 ]; then
    echo "verify_install: 'lu77U-MobileSec -V' never reported starting" >&2
    cat "$verbose_log" >&2
    exit 1
fi

echo "verify_install: -V ok (server started cleanly on port $port, stopping it now)"
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""

echo "verify_install: clean."
exit 0
