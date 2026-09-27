#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.blutter_checker

Purpose:
    Report whether Blutter, which reconstructs Dart source from a Flutter AOT snapshot, is configured, and produce the setup instructions shown when it is not.

Responsibilities:
    Check the configured path, and render the setup message.

Dependencies:
    os, ..config.user_settings.

Implementation notes:
    This tool is optional. An app of this kind is still detected and reported without it; only the deep static analysis of its decompiled output is skipped.

Security considerations:
    Only the presence of the path is checked; the file is never executed here. Whether it is the tool it claims to be is established when it is invoked.
"""

import os
from ..config import user_settings
from ..utils.verbose import verbose_print

def check_blutter_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether Blutter is configured and present on disk.

    Parameters:
        verbose: Traces the resolved path when the check passes.

    Returns:
        True when a path is configured and the file exists.

    Side effects:
        Reads user settings and stats the path.

    Implementation notes:
        Both conditions are required. A configured path that no longer exists is worse than no path at all: without the existence check the tool would report as ready and then fail mid-scan, after the APK had already been decompiled.
    """
    path = user_settings.get_blutter_path()
    if not path:
        return False
    if not os.path.exists(path):
        return False
    verbose_print(f"Blutter is configured at: {path}", verbose)
    return True

def get_blutter_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render the instructions for installing and configuring Blutter.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        The message warns that Blutter compiles a Dart-version-specific executable on first use, so that a first Flutter scan taking a long time reads as expected rather than as a hang. It also states plainly that Flutter apps are still detected and reported without it, so a user who does not want to build Blutter knows exactly what they lose.
    """
    message = f"""\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Blutter Configuration Required (Flutter analysis)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To analyze Flutter apps, you need Blutter installed.

Steps to configure:
  1. Clone and build Blutter: https://github.com/worawit/blutter
     (it compiles a Dart-version-specific executable on first run -
     the first Flutter scan can take a while)
  2. In Settings, set the Blutter path to blutter.py in that checkout
     • Example: /opt/blutter/blutter.py

Flutter apps are still detected and reported without Blutter configured -
only the deep static analysis (decompiled findings) is skipped.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    verbose_print(message, verbose)
    return message
