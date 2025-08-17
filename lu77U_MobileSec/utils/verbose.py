"""
Debug utilities for lu77U-MobileSec
"""

from ..ui.colors import Colors

def verbose_print(message: str, verbose: bool = False):
    """Print debug message in yellow color if verbose mode is enabled"""
    if verbose:
        print(f"{Colors.YELLOW}[VERBOSE] {message}{Colors.RESET}")