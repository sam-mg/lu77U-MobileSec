#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.__main__

Purpose:
    Support `python -m lu77U_MobileSec` as an equivalent to the installed console script, so the tool stays runnable from a source checkout or a virtualenv where the script shim is missing.

Responsibilities:
    Enable ANSI colour on Windows, emit two verbose trace lines, and delegate to cli.main.main.

Dependencies:
    colorama on Windows only, .cli.main for the real entry point, .utils.verbose for tracing.

Implementation notes:
    Verbosity is sniffed straight from sys.argv rather than parsed, because the trace lines must fire before argparse runs. The sniff is intentionally permissive; argparse remains the authority on the flag. colorama is optional: when it is not installed the ImportError is suppressed and Windows output simply keeps raw ANSI sequences, which is cosmetic and never stops the tool starting.

Security considerations:
    No argument is executed or interpolated into a shell here; sys.argv is only scanned for a literal flag and echoed under --verbose.
"""

import contextlib
import sys
import platform

if platform.system() == "Windows":
    with contextlib.suppress(ImportError):
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)

from lu77U_MobileSec._metadata import NAME
from lu77U_MobileSec.cli.main import main
from lu77U_MobileSec.utils import verbose_print

if __name__ == "__main__":
    debug_verbose = "-V" in sys.argv or "--verbose" in sys.argv
    verbose_print(f"Starting {NAME} from __main__.py", debug_verbose)
    verbose_print(f"Python arguments: {sys.argv}", debug_verbose)
    main()
