#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.rn_decompiler_checker

Purpose:
    Report whether react-native-decompiler, which unbundles a plain-JavaScript React Native bundle, is configured, and produce the setup instructions shown when it is not.

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

def check_rn_decompiler_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether react-native-decompiler is configured and present on disk.

    Parameters:
        verbose: Traces the resolved path when the check passes.

    Returns:
        True when a path is configured and the file exists.

    Side effects:
        Reads user settings and stats the path.

    Implementation notes:
        Both conditions are required. A configured path that no longer exists is worse than no path at all: without the existence check the tool would report as ready and then fail mid-scan, after the APK had already been decompiled.
    """
    path = user_settings.get_rn_decompiler_path()
    if not path:
        return False
    if not os.path.exists(path):
        return False
    verbose_print(f"react-native-decompiler is configured at: {path}", verbose)
    return True

def get_rn_decompiler_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render the instructions for installing and configuring react-native-decompiler.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        The message covers the locally-installed case as well as the global one, since an npm tool is frequently installed as a project dependency where the executable lives under node_modules rather than on PATH. It also points at the Hermes tool, because the two cover the two bundle formats and choosing the wrong one is the common mistake.
    """
    message = f"""\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  react-native-decompiler Configuration Required (React Native - plain JS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To analyze React Native apps whose bundle is plain JavaScript (not Hermes
bytecode), you need react-native-decompiler installed.

Steps to configure:
  1. npm install -g react-native-decompiler
  2. In Settings, set the RN decompiler path to its executable
     • Example: /usr/local/bin/react-native-decompiler
     • Or, if installed as a local project dependency, the path to its
       bin script (e.g. node_modules/.bin/react-native-decompiler)

A Hermes-compiled React Native bundle uses a different tool - see the
hermes_decomp_path setting instead. React Native apps are still detected
and reported without either configured - only the deep static analysis is
skipped.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    verbose_print(message, verbose)
    return message
