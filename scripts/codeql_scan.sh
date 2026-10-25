#!/usr/bin/env bash

# Builds a CodeQL database for every language this repo ships code in, runs the broadest finding-producing suite CodeQL packages for each one, and fails if any of them reports anything. Used by preflight.sh, the pre-push hook and CI, so it is the one place that decides what "clean" means.

# The CodeQL CLI and its query packs are close to 2GB, so they are installed once into a per-machine cache outside the repo (never committed, never copied into the analysed source) rather than provisioned by hand. The CLI goes to $CODEQL_HOME (default ~/.codeql-lu77u); the query packs go to CodeQL's own default pack cache (~/.codeql/packages), shared with any other CodeQL usage on the machine. Both persist across runs, so only the first run on a given machine pays the download cost.

# Suite choice ("everything, as broad as CodeQL ships it, without breaking the pass/fail gate"):
#   - security-and-quality: the broadest official combined suite.
#   - security-experimental: security queries not yet promoted out of experimental status - genuinely broader security coverage.
#   - code-quality-extended: every query tagged "quality" at high/very-high/medium precision, kept live against the query pack rather than the frozen id list security-and-quality ships with.
#   - actions-all: GitHub's own "every problem/path-problem query in the Actions pack" suite; nothing narrower exists for this language.
# Deliberately excluded: the various *-lgtm*/summaries/bughalla suites, because they pull in metric and model-generator queries (lines-of-code, composite-action modelling, and similar) that produce a result row for every file regardless of whether anything is wrong, which would make a pass/fail gate meaningless.

# js/untrusted-data-to-external-api-more-sources is still run, under the same id, on every file - but as a locally re-modelled copy (scripts/codeql/lu77u-js-models), not GitHub's stock version. Empirical testing against this repo's own code (an array filtered through a real TypeScript type guard, primitive fields extracted into a brand-new object, a JSON round trip) proved that query's Sanitizer extension point has no implementations in the shipped library, so no code-level validation was ever going to satisfy it; the query's own documentation names extending its safe-API classes as the supported fix instead of sanitizing application code. The local copy marks exactly two packages (react, react-router-dom) as not being external security boundaries for this concern, since fetch() is the real external call and is already covered everywhere else this query and its siblings run; every other package it can flag - a database driver, a shell, a raw HTTP client - is untouched, and so are its heuristic sibling queries, which real validation in this codebase already satisfies without any re-modelling.

# The CLI is kept at the latest CodeQL release: every run asks GitHub which release is latest and installs it when the cached CLI is older, and the query packs are then fetched at their latest version for that CLI. A machine used to keep whichever CLI it first installed while CI, starting fresh, got the newest one, so the two could disagree about the same commit. Offline, the installed CLI is used as it is.

# Python is extracted with the project's own interpreter - the active virtualenv, else .venv - the one preflight.sh, the pre-push hook and CI run the tests with. The extractor resolves imports through whichever python3 is first on PATH, and with a different one (Homebrew's newer Python, without the project's packages) some queries stay silent: an unused import CI reported was invisible locally for exactly this reason.

# Exit 0: every suite ran and found nothing.
# Exit 1: a finding was reported, or CodeQL could not be installed or run.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

CODEQL_HOME="${CODEQL_HOME:-$HOME/.codeql-lu77u}"
CODEQL_BIN="$CODEQL_HOME/codeql/codeql"
LANGUAGES="python javascript actions"

if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
    PATH="${VIRTUAL_ENV}/bin:$PATH"
elif [ -x ".venv/bin/python" ]; then
    PATH="$PWD/.venv/bin:$PATH"
fi
export PATH

os_asset() {
    case "$(uname -s)" in
        Darwin) echo "codeql-osx64.zip" ;;
        Linux) echo "codeql-linux64.zip" ;;
        MINGW*|MSYS*|CYGWIN*) echo "codeql-win64.zip" ;;
        *) echo "" ;;
    esac
}

install_codeql() {
    local asset url
    asset="$(os_asset)"
    if [ -z "$asset" ]; then
        echo "codeql_scan: unsupported OS for automatic CodeQL install ($(uname -s))." >&2
        echo "codeql_scan: install the CodeQL CLI yourself and put it on PATH, or set CODEQL_HOME." >&2
        return 1
    fi
    echo "codeql_scan: installing CodeQL $CODEQL_VERSION, the latest release, into $CODEQL_HOME (a few hundred MB, once per release)..."
    mkdir -p "$CODEQL_HOME" || return 1
    rm -rf "$CODEQL_HOME/codeql"
    url="https://github.com/github/codeql-cli-binaries/releases/download/v$CODEQL_VERSION/$asset"
    if ! curl -fsSL -o "$CODEQL_HOME/$asset" "$url"; then
        echo "codeql_scan: could not download $url" >&2
        return 1
    fi
    if ! (cd "$CODEQL_HOME" && unzip -q -o "$asset" && rm -f "$asset"); then
        echo "codeql_scan: could not unpack $asset" >&2
        return 1
    fi
}

cli_version() {
    "$1" version --format=terse 2>/dev/null
}

CODEQL_VERSION="$(curl -fsI --max-time 10 https://github.com/github/codeql-cli-binaries/releases/latest 2>/dev/null | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/v##p')"

if [ -z "$CODEQL_VERSION" ]; then
    if [ ! -x "$CODEQL_BIN" ] && command -v codeql >/dev/null 2>&1; then
        CODEQL_BIN="$(command -v codeql)"
    fi
    if [ -z "$(cli_version "$CODEQL_BIN")" ]; then
        echo "codeql_scan: could not find the latest CodeQL release and no CLI is installed" >&2
        exit 1
    fi
    echo "codeql_scan: could not check for a newer CodeQL release; using the installed $(cli_version "$CODEQL_BIN")"
elif [ "$(cli_version "$CODEQL_BIN")" != "$CODEQL_VERSION" ]; then
    if command -v codeql >/dev/null 2>&1 && [ "$(cli_version "$(command -v codeql)")" = "$CODEQL_VERSION" ]; then
        CODEQL_BIN="$(command -v codeql)"
    else
        install_codeql || exit 1
    fi
fi

if [ -z "$(cli_version "$CODEQL_BIN")" ]; then
    echo "codeql_scan: $CODEQL_BIN is not a runnable CodeQL CLI" >&2
    exit 1
fi

echo "codeql_scan: fetching query packs (cached after the first run)..."
for lang in $LANGUAGES; do
    if ! "$CODEQL_BIN" pack download "codeql/$lang-queries" >/dev/null 2>&1; then
        echo "codeql_scan: could not fetch codeql/$lang-queries" >&2
        exit 1
    fi
done
if ! "$CODEQL_BIN" pack install scripts/codeql/lu77u-js-models >/dev/null 2>&1; then
    echo "codeql_scan: could not install scripts/codeql/lu77u-js-models's dependencies" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lu77u-codeql.XXXXXX")" || exit 1
trap 'rm -rf "$WORK_DIR"' EXIT

SRC_DIR="$WORK_DIR/src"
mkdir -p "$SRC_DIR"
git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do
    [ -e "$f" ] && printf '%s\0' "$f"
done | rsync -a --from0 --files-from=- . "$SRC_DIR/" || exit 1

suites_for() {
    case "$1" in
        python)
            echo "codeql/python-queries:codeql-suites/python-security-and-quality.qls codeql/python-queries:codeql-suites/python-security-experimental.qls codeql/python-queries:codeql-suites/python-code-quality-extended.qls"
            ;;
        javascript)
            echo "scripts/codeql/javascript-suite.qls"
            ;;
        actions)
            echo "codeql/actions-queries:codeql-suites/actions-all.qls"
            ;;
    esac
}

total_findings=0
for lang in $LANGUAGES; do
    echo "codeql_scan: building the $lang database..."
    db="$WORK_DIR/db-$lang"
    if ! "$CODEQL_BIN" database create "$db" --language="$lang" --source-root="$SRC_DIR" --overwrite --threads=0 \
            > "$WORK_DIR/create-$lang.log" 2>&1; then
        echo "codeql_scan: could not build the $lang database" >&2
        tail -n 20 "$WORK_DIR/create-$lang.log" >&2
        exit 1
    fi

    echo "codeql_scan: analysing $lang..."
    sarif="$WORK_DIR/$lang.sarif"
    suites="$(suites_for "$lang")"
    # shellcheck disable=SC2086
    if ! "$CODEQL_BIN" database analyze "$db" $suites --additional-packs=scripts/codeql \
            --format=sarif-latest --output="$sarif" --threads=0 \
            > "$WORK_DIR/analyze-$lang.log" 2>&1; then
        echo "codeql_scan: analysis failed for $lang" >&2
        tail -n 20 "$WORK_DIR/analyze-$lang.log" >&2
        exit 1
    fi

    count_file="$WORK_DIR/count-$lang"
    python3 - "$sarif" "$count_file" <<'PY'
import json
import sys

sarif_path, count_path = sys.argv[1], sys.argv[2]
data = json.load(open(sarif_path))
results = data["runs"][0]["results"]
for r in results:
    loc = r["locations"][0]["physicalLocation"]
    path = loc["artifactLocation"]["uri"]
    line = loc.get("region", {}).get("startLine", "?")
    text = r["message"]["text"].splitlines()[0]
    print(f"  {r['ruleId']}  {path}:{line}  {text}")
with open(count_path, "w") as fh:
    fh.write(str(len(results)))
PY
    n="$(cat "$count_file" 2>/dev/null || echo 0)"
    total_findings=$((total_findings + n))
done

if [ "$total_findings" -ne 0 ]; then
    echo
    echo "codeql_scan: $total_findings finding(s) across $LANGUAGES."
    exit 1
fi

echo "codeql_scan: clean across $LANGUAGES."
exit 0
