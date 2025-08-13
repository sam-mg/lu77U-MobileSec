#!/usr/bin/env python3
"""
lu77U-MobileSec CLI entry point
Main entry point for the lu77U-MobileSec package when run as a module.
"""

from lu77U_MobileSec.cli.main import main
from lu77U_MobileSec.utils import debug_print
import sys

if __name__ == "__main__":
    debug_verbose = "-V" in sys.argv or "--verbose" in sys.argv
    debug_print("Starting lu77U-MobileSec from __main__.py", debug_verbose)
    debug_print(f"Python arguments: {sys.argv}", debug_verbose)
    main()