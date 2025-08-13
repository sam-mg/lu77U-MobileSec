"""
Debug utilities for lu77U-MobileSec
"""

from ..ui.colors import Colors


def debug_print(message: str, verbose: bool = False):
    """Print debug message in yellow color if verbose mode is enabled"""
    if verbose:
        print(f"{Colors.YELLOW}[DEBUG] {message}{Colors.RESET}")
