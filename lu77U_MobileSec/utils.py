"""
Utility functions for lu77U-MobileSec
"""

import sys
import os
import platform
from typing import Optional
from .ui.colors import Colors
from .utils.verbose import verbose_print
from .utils.screen import clear_screen, safe_input

def get_python_version():
    """Get current Python version string"""
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

def check_python_compatibility():
    """Check if current Python version is compatible"""
    return sys.version_info >= (3, 12)