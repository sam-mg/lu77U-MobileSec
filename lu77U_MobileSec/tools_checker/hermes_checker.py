#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.hermes_checker

Purpose:
    Report whether hermes-decomp, which decompiles Hermes bytecode from a React Native bundle, is configured, and produce the setup instructions shown when it is not.

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

def check_hermes_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether hermes-decomp is configured and present on disk.

    Parameters:
        verbose: Traces the resolved path when the check passes.

    Returns:
        True when a path is configured and the file exists.

    Side effects:
        Reads user settings and stats the path.

    Implementation notes:
        Both conditions are required. A configured path that no longer exists is worse than no path at all: without the existence check the tool would report as ready and then fail mid-scan, after the APK had already been decompiled.
    """
    path = user_settings.get_hermes_decomp_path()
    if not path:
        return False
    if not os.path.exists(path):
        return False
    verbose_print(f"hermes-decomp is configured at: {path}", verbose)
    return True

def get_hermes_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render the instructions for installing and configuring hermes-decomp.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        The message distinguishes this tool from the plain-JavaScript React Native decompiler, because React Native ships bundles in two forms and configuring the wrong tool leaves the scan silently unable to analyse the app.
    """
    message = f"""\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  hermes-decomp Configuration Required (React Native - Hermes bundles)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To analyze React Native apps whose bundle is compiled to Hermes bytecode,
you need hermes-decomp installed.

Steps to configure:
  1. Download a build or build from source:
     https://github.com/SymbioticSec/hermes-decomp
  2. In Settings, set the hermes-decomp path to that executable
     • Example: /usr/local/bin/hermes-decomp

A plain-JavaScript React Native bundle (not Hermes) uses a different tool -
see the rn_decompiler_path setting instead. React Native apps are still
detected and reported without either configured - only the deep static
analysis is skipped.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    verbose_print(message, verbose)
    return message
