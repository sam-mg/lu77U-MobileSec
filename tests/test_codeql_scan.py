#!/usr/bin/env python3
"""
Module: test_codeql_scan

Purpose:
    Pin the two things that keep a local CodeQL run and CI in agreement: the CLI follows the latest release rather than whatever was installed first, and Python is extracted with the project's own interpreter.

Implementation notes:
    Both failures were real: CI reported an unused import a local run could not see, because the local run extracted Python with Homebrew's newer python3 instead of the project's 3.12 virtualenv, on a CLI it had never updated.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN = (REPO_ROOT / "scripts" / "codeql_scan.sh").read_text(encoding="utf-8")
SUITE = (REPO_ROOT / "scripts" / "codeql" / "javascript-suite.qls").read_text(encoding="utf-8")


def test_the_cli_follows_the_latest_release():
    """
    Purpose:
        Pin that the scan asks for the latest CodeQL release, installs it by that release's tag, and hardcodes no version of its own.
    """
    assert "releases/latest" in SCAN
    assert "releases/download/v$CODEQL_VERSION/" in SCAN
    assert not re.search(r'CODEQL_VERSION="\d', SCAN)


def test_query_packs_follow_the_cli():
    """
    Purpose:
        Pin that no query pack is held at a fixed version, in the scan or in the JavaScript suite, so the packs move with the CLI.
    """
    assert not re.search(r"codeql/[a-z-]+-queries@\d", SCAN)
    assert not re.search(r"^\s*version:", SUITE, re.M)


def test_python_is_extracted_with_the_project_interpreter():
    """
    Purpose:
        Pin that the project's virtualenv is put first on PATH before any database is built.
    """
    venv = SCAN.index('PATH="$PWD/.venv/bin:$PATH"')
    active = SCAN.index('PATH="${VIRTUAL_ENV}/bin:$PATH"')
    assert max(venv, active) < SCAN.index("database create")
