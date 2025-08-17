"""
Screen and terminal utilities for lu77U-MobileSec
"""

import os
import subprocess
import platform
from typing import Optional

def clear_screen():
    """Clear the terminal screen and scrollback buffer completely across all platforms"""
    system = platform.system()
    try:
        if system == "Windows":
            try:
                subprocess.run(['powershell', '-Command', 'Clear-Host'], check=True, timeout=2.0, capture_output=True)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    subprocess.run(['cmd', '/c', 'cls'], check=True, timeout=1.0)
                except:
                    os.system('cls')
        
        elif system == "Darwin":
            try:
                subprocess.run(['reset'], check=True, timeout=2.0)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    print("\033[2J\033[3J\033[H", end="", flush=True)
                except:
                    os.system('clear')
        
        else:
            try:
                subprocess.run(['sh', '-c', 'clear && printf "\\033[3J"'], check=True, timeout=2.0)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    print("\033[2J\033[3J\033[H", end="", flush=True)
                except:
                    os.system('clear')
    
    except Exception:
        if system == "Windows":
            os.system('cls')
        else:
            os.system('clear')

def _fallback_input(prompt: str, default: Optional[str] = None) -> str:
    """Fallback input method for when termios is not available"""
    try:
        result = input(prompt).strip()
        return result if result else (default or "")
    except (KeyboardInterrupt, EOFError):
        return default or "0"


def safe_input(prompt: str, default: Optional[str] = None) -> str:
    """Safe input with escape sequence prevention and cross-platform support"""
    import sys
    import platform
    
    if platform.system() == "Windows":
        return _fallback_input(prompt, default)
    
    try:
        import select
        import termios
        import tty
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            print(prompt, end="", flush=True)
            
            tty.setraw(sys.stdin.fileno())
            
            user_input = ""
            
            while True:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    
                    if char == '\r' or char == '\n':
                        print()
                        break
                    
                    elif char == '\x03':
                        print()
                        raise KeyboardInterrupt
                    
                    elif char == '\x7f' or char == '\x08':
                        if user_input:
                            user_input = user_input[:-1]
                            print('\b \b', end="", flush=True)
                    
                    elif char == '\x1b':
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            next_char = sys.stdin.read(1)
                            if next_char == '[':
                                if select.select([sys.stdin], [], [], 0.1)[0]:
                                    sys.stdin.read(1)
                        continue
                    
                    elif char.isprintable():
                        user_input += char
                        print(char, end="", flush=True)
            
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            result = user_input.strip()
            return result if result else (default or "")
            
        except Exception:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            raise
            
    except (ImportError, OSError, termios.error):
        return _fallback_input(prompt, default)
