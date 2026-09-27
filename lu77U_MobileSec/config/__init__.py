#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config

Purpose:
    Namespace for constants, filesystem paths, prompts, user settings and credential storage.

Responsibilities:
    None beyond marking the directory as a package. Nothing is re-exported because .credentials touches the keyring and .paths touches the home directory; callers import the specific submodule they need so those side effects stay opt-in.

Dependencies:
    None at import time.

Security considerations:
    Keeping this file empty is deliberate: importing lu77U_MobileSec.config must never trigger a credential read.
"""
