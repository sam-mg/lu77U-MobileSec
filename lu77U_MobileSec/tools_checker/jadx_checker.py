#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.jadx_checker

Purpose:
    Report whether JADX, the Java and Kotlin decompiler, is configured, and produce the setup instructions shown when it is not.

Responsibilities:
    Check the configured path, and render the setup message.

Dependencies:
    os, ..config.user_settings.

Implementation notes:
    Unlike the other tool checkers, JADX is not optional. It is the decompiler for a standard Android app, so a scan of one cannot proceed without it.

Security considerations:
    Only the presence of the path is checked; the file is never executed here.
"""

import os
from ..config import user_settings
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

def check_jadx_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether JADX is configured and present on disk.

    Parameters:
        verbose: Traces the resolved path when the check passes.

    Returns:
        True when a usable path is configured.

    Side effects:
        Reads user settings and stats the path.

    Implementation notes:
        The literal "path_goes_here" is rejected explicitly. It is the placeholder the legacy settings module shipped with, and treating it as configured would produce a confusing failure deep inside decompilation rather than a clear one here. The existence check matters for the same reason: a stale path would otherwise report ready and fail later.
    """
    jadx_path = user_settings.get_jadx_path()
    if not jadx_path or jadx_path == "path_goes_here":
        return False

    if not os.path.exists(jadx_path):
        return False

    verbose_print(f"JADX is configured at: {jadx_path}", verbose)

    return True

def get_jadx_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render the instructions for installing and configuring JADX.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        Returned as well as optionally traced, so the caller decides where it goes -- the terminal, the dashboard, or nowhere. The message names concrete install commands and example paths per platform, because "configure the tool" leaves a new user with nothing to act on.
    """
    message = f"""\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  JADX Configuration Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To use APK Analysis features, you need to configure JADX.

Steps to configure:
  1. Install JADX on your system
     • macOS: brew install jadx
     • Linux: Download from https://github.com/skylot/jadx
     • Windows: Download from https://github.com/skylot/jadx
     
  2. Use option 4. Edit Settings from the main menu
  
  3. Set JADX_PATH to your JADX executable location
     • Example (macOS): /opt/homebrew/bin/jadx
     • Example (Linux): /usr/local/bin/jadx
     • Example (Windows): C:\\Program Files\\jadx\\bin\\jadx.bat

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
    
    verbose_print(message, verbose)
    return message
