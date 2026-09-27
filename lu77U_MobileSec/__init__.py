#!/usr/bin/env python3
"""
Module: lu77U_MobileSec

Purpose:
    Package facade. Re-exports the version metadata and the single application object so that embedders can `from lu77U_MobileSec import MobileSecApp` without knowing the internal module layout.

Responsibilities:
    Bind the dunder metadata names PEP 396 tooling expects, and expose MobileSecApp as the only public symbol.

Dependencies:
    ._metadata for identity resolved from packaging data, .core.app for the application object.

Security considerations:
    Importing this package must stay side-effect free beyond metadata lookup; no APK is touched and no network or subprocess is started until an explicit call is made.
"""

from ._metadata import (
    AUTHOR as __author__,
    DESCRIPTION as __description__,
    EMAIL as __email__,
    NAME as __title__,
    VERSION as __version__,
)

from .core.app import MobileSecApp

__all__ = ["MobileSecApp"]
