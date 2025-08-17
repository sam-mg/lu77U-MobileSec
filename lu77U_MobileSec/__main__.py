#!/usr/bin/env python3
"""
lu77U-MobileSec CLI entry point
Main entry point for the lu77U-MobileSec package when run as a module.
"""

import sys
import platform

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
    except ImportError:
        pass

from lu77U_MobileSec.cli.main import main
from lu77U_MobileSec.utils import verbose_print

if __name__ == "__main__":
    debug_verbose = "-V" in sys.argv or "--verbose" in sys.argv
    verbose_print("Starting lu77U-MobileSec from __main__.py", debug_verbose)
    verbose_print(f"Python arguments: {sys.argv}", debug_verbose)
    main()