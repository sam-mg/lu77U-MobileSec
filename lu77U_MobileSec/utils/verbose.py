"""Verbose utilities for lu77U-MobileSec"""

from ..ui.colors import Colors

def verbose_print(message: str, verbose: bool = False):
    """Print verbose message in yellow color"""
    if verbose:
        print(f"{Colors.YELLOW}[VERBOSE] {message}{Colors.RESET}")