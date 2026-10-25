#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.screen_capture

Purpose:
    Note when nothing in the app ever sets FLAG_SECURE, so every screen - logins, balances, card numbers - can be screenshotted, recorded and shown in the recent-apps preview.

Responsibilities:
    Search the decompiled code for any way of setting the flag and, when there is none, emit one informational note.

Dependencies:
    os, pathlib, the app-Java library filter.

Implementation notes:
    This is an absence, so it cannot be cited at a line and is reported against the manifest as one build note. Every way the flag is set counts, wherever it is set: the constant's name, its value 8192 passed to addFlags or setFlags (which is how R8 output and Hermes output show it), and the setters of the common Flutter and React Native screenshot plugins. A plugin setting it counts too, since that is how cross-platform apps usually set it; the framework embeddings do not, since they only pass the flag along. The note stays Informational: screenshots need the device or a screen-recording permission, and it is context for the storage and authentication findings rather than a flaw of its own.

Security considerations:
    Reads untrusted decompiled text as bytes; nothing is executed.
"""

import os
from pathlib import Path
from typing import List

from .app_java import is_library
from ..findings import SastFinding
from ....utils.verbose import verbose_print

_EXTENSIONS = (".java", ".kt", ".js", ".dart", ".smali")
_MARKERS = (b"FLAG_SECURE", b"addFlags(8192)", b"setFlags(8192", b"FlutterWindowManager",
            b"secure_application", b"preventScreenCapture", b"enableSecureView", b"setSecureFlag")
_MAX_FILE_BYTES = 4_000_000


def _sets_flag_secure(root: Path) -> bool:
    """
    Purpose:
        Tell whether any decompiled file sets FLAG_SECURE.

    Parameters:
        root: The analysis root.

    Returns:
        True at the first file that does.

    Implementation notes:
        Files are read as bytes and the walk stops at the first hit, so an app that does set the flag costs little. Framework code is skipped: React Native's Modal copies the flag from its parent window with setFlags(8192, 8192), which would otherwise count every React Native app as protected.
    """
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(_EXTENSIONS):
                continue
            path = Path(dirpath) / name
            if is_library(path.relative_to(root).as_posix()):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if any(marker in data for marker in _MARKERS):
                return True
    return False


def analyze_screen_capture(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report an app that never sets FLAG_SECURE.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the result.

    Returns:
        One informational finding, or none.
    """
    root = Path(source_root)
    if _sets_flag_secure(root):
        verbose_print("SAST screen capture: FLAG_SECURE is set somewhere", verbose)
        return []
    verbose_print("SAST screen capture: FLAG_SECURE is never set", verbose)
    return [SastFinding(
        title="No screenshot protection: FLAG_SECURE is never set",
        severity="Informational", vuln_class="PLATFORM-12", file="AndroidManifest.xml", detector="screen-capture",
        description=("Nothing in the app sets WindowManager.LayoutParams.FLAG_SECURE, so every screen can be "
                     "screenshotted or recorded and appears in the recent-apps snapshot."),
        impact=("Credentials, balances or personal data on screen end up in screenshots, screen recordings and "
                "the task-switcher preview."),
        recommendation="Set FLAG_SECURE on the windows of screens that show credentials or account data.",
        cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration")]
