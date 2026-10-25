#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.ghidra_checker

Purpose:
    Report whether Ghidra, which decompiles native libraries for the agent, is configured, resolve the configured path to its headless launcher, and produce the setup instructions shown when it is not.

Responsibilities:
    Resolve the configured path to analyzeHeadless, check it, and render the setup message.

Dependencies:
    os, pathlib, ..config.user_settings.

Implementation notes:
    This tool is optional. Without it a native library is still summarised from its symbol table and strings; only the decompiled C is missing. The configured path may be the install directory, ghidraRun, or analyzeHeadless itself, because users naturally paste whichever of the three they found first, and a package manager usually puts only ghidraRun on PATH while analyzeHeadless stays in the install's support directory.

Security considerations:
    Only the presence of files is checked; nothing is executed here. Whether the file is the tool it claims to be is established when it is invoked.
"""

import os
from pathlib import Path
from typing import List, Optional

from ..config import user_settings
from ..utils.verbose import verbose_print

_HEADLESS_NAMES = ("analyzeHeadless", "analyzeHeadless.bat")

def _headless_candidates(base: Path) -> List[Path]:
    """
    Purpose:
        List where analyzeHeadless can sit relative to a directory taken from the configured path.

    Parameters:
        base: The install directory, or the directory holding ghidraRun.

    Returns:
        The candidate launcher paths, most likely first.

    Implementation notes:
        Covers the release zip layout, where support/ sits beside ghidraRun, and the Homebrew layout, where bin/ghidraRun is a wrapper and the real install is libexec/ next to bin/.
    """
    roots = [base, base / "libexec", base.parent, base.parent / "libexec"]
    return [root / "support" / name for root in roots for name in _HEADLESS_NAMES]

def resolve_analyze_headless(path: Optional[str] = None) -> Optional[Path]:
    """
    Purpose:
        Turn the configured Ghidra path into the analyzeHeadless launcher that actually runs.

    Parameters:
        path: The path to resolve; the configured setting when None.

    Returns:
        The launcher, or None when nothing usable is found.

    Side effects:
        Reads user settings when no path is passed, and stats candidate files.

    Implementation notes:
        Symlinks are followed before the search because a package manager's bin entry is usually a link into the real install, and the launcher is found relative to the real file rather than the link. Both the link's own directory and the real file's directory are searched, so either install layout resolves.
    """
    raw = (user_settings.get_ghidra_path() if path is None else path) or ""
    raw = raw.strip()
    if not raw or raw == "path_goes_here":
        return None
    given = Path(raw).expanduser()
    if not given.exists():
        return None

    if given.is_dir():
        candidates = _headless_candidates(given)
    else:
        real = given.resolve()
        if real.name in _HEADLESS_NAMES:
            return real
        candidates = _headless_candidates(real.parent) + _headless_candidates(given.parent)

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None

def check_ghidra_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether Ghidra is configured and its headless launcher can be found.

    Parameters:
        verbose: Traces the resolved launcher when the check passes.

    Returns:
        True when the configured path resolves to an executable analyzeHeadless.

    Side effects:
        Reads user settings and stats candidate files.

    Implementation notes:
        Checking for the launcher rather than for the configured file is deliberate: a path to ghidraRun that exists but whose install has no support directory would otherwise report ready and then fail on the first native library.
    """
    launcher = resolve_analyze_headless()
    if launcher is None:
        return False
    if os.name != "nt" and not os.access(launcher, os.X_OK):
        return False
    verbose_print(f"Ghidra headless launcher: {launcher}", verbose)
    return True

def get_ghidra_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render the instructions for installing and configuring Ghidra.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        The message says plainly that Ghidra is optional and what is lost without it, so a user who does not want a JDK and a large install on their machine can make that choice knowingly.
    """
    message = """\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Ghidra Configuration (optional - native library decompilation)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To read the decompiled C of an app's native (.so) libraries, configure Ghidra.

Steps to configure:
  1. Install Ghidra 11 or later and a JDK 21 or later
     • macOS: brew install ghidra
     • Linux / Windows: https://github.com/NationalSecurityAgency/ghidra/releases
  2. In Settings, set the Ghidra path to any one of:
     • ghidraRun            e.g. /opt/homebrew/bin/ghidraRun
     • the install folder   e.g. /opt/ghidra_12.1_PUBLIC
     • analyzeHeadless      e.g. /opt/ghidra_12.1_PUBLIC/support/analyzeHeadless

Without Ghidra, native libraries are still summarised from their symbol
table and embedded strings - only the decompiled code is skipped.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    verbose_print(message, verbose)
    return message
