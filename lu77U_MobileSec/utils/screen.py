"""
Screen and terminal utilities for lu77U-MobileSec
"""

import os
import platform
from typing import Optional


def clear_screen():
    """Clear the terminal screen and scrollback buffer completely using reset"""
    try:
        if platform.system() != "Windows":
            import subprocess
            subprocess.run(['reset'], check=True, timeout=2.0)
        else:
            os.system('cls')
            try:
                import subprocess
                subprocess.run(['cmd', '/c', 'cls'], check=True, timeout=1.0)
            except:
                pass
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        try:
            print("\033c", end="", flush=True)
        except:
            if platform.system() != "Windows":
                os.system('clear')
            else:
                os.system('cls')


def safe_input(prompt: str, default: Optional[str] = None) -> str:
    """Safe input with default value handling"""
    try:
        result = input(prompt).strip()
        return result if result else (default or "")
    except (KeyboardInterrupt, EOFError):
        if default is not None:
            return default
        return "0"
