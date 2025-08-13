"""
Color constants and utilities for console output
"""

import sys
import platform

try:
    if platform.system() == "Windows":
        import colorama
        colorama.init(autoreset=True)
except ImportError:
    pass

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[35m'
    
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = PURPLE  
    INFO = CYAN
    HEADER = PURPLE
    DEBUG = YELLOW
