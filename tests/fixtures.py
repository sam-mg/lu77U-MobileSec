#!/usr/bin/env python3
"""
Module: fixtures

Purpose:
    Locate the real vulnerable-app APKs cloned under the gitignored etc directory, so tests that need a genuine APK can use one when it is present.

Responsibilities:
    Declare the known sample APK locations and provide the two lookup helpers.

Dependencies:
    pytest, for the skip used when a fixture is absent.

Implementation notes:
    The deliberately-vulnerable sample apps are cloned into etc, which is gitignored, so they exist on a developer's checkout and not in CI. Tests therefore skip cleanly when a fixture is missing rather than failing, which keeps CI green without weakening the local runs. Only release and profile Flutter builds are listed, because a debug build ships no ahead-of-time compiled library and would not exercise the path under test.
"""

from pathlib import Path
from typing import Optional

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

DVHMA_CORDOVA_APKS = (
    "etc/vulnerable-apps/cordova-dvhma/releases/"
    "de.zertapps.dvhma.featherweight_1.0.0_6.3.0_debug.apk",
    "etc/vulnerable-apps/cordova-dvhma/releases/"
    "de.zertapps.dvhma.openui5_1.0.0_6.3.0_debug.apk",
)

DVFA_FLUTTER_APKS = (
    "etc/vulnerable-apps/flutter-dvfa-schmieman/build/app/outputs/flutter-apk/app-release.apk",
    "etc/vulnerable-apps/flutter-dvfa-sebsnyk/build/app/outputs/flutter-apk/app-release.apk",
)


def find_fixture(*rel_paths: str) -> Optional[Path]:
    """
    Purpose:
        Return the first sample APK that exists among the given locations.

    Parameters:
        rel_paths: Candidate paths, relative to the repository root.

    Returns:
        The first path that exists, or None when none of them do.
    """
    for rel in rel_paths:
        candidate = _REPO_ROOT / rel
        if candidate.is_file():
            return candidate
    return None


def require_fixture(*rel_paths: str) -> Path:
    """
    Purpose:
        Return the first sample APK that exists, skipping the test when none do.

    Parameters:
        rel_paths: Candidate paths, relative to the repository root.

    Returns:
        The first path that exists.

    Raises:
        Skipped: Raised by pytest when no candidate is present, so the absence of a local clone skips the test rather than failing it.
    """
    found = find_fixture(*rel_paths)
    if found is None:
        pytest.skip(f"sample APK fixture not present (looked for: {', '.join(rel_paths)})")
    return found
