"""Screen and terminal utilities for lu77U-MobileSec"""

import os
import subprocess
import platform
from typing import Optional
from .verbose import verbose_print

def clear_screen(verbose=False):
    """Clear the terminal screen and scrollback buffer completely across all platforms"""
    verbose_print("Starting screen clearing process", verbose)
    
    system = platform.system()
    verbose_print(f"Detected platform: {system}", verbose)
    
    try:
        if system == "Windows":
            verbose_print("Using Windows-specific screen clearing methods", verbose)
            try:
                verbose_print("Attempting PowerShell Clear-Host command", verbose)
                subprocess.run(['powershell', '-Command', 'Clear-Host'], check=True, timeout=2.0, capture_output=True)
                verbose_print("PowerShell Clear-Host successful", verbose)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                verbose_print(f"PowerShell Clear-Host failed: {e}", verbose)
                try:
                    verbose_print("Attempting Windows cmd cls command", verbose)
                    subprocess.run(['cmd', '/c', 'cls'], check=True, timeout=1.0)
                    verbose_print("Windows cmd cls successful", verbose)
                except Exception as e2:
                    verbose_print(f"Windows cmd cls failed: {e2}, falling back to os.system", verbose)
                    os.system('cls')
        
        elif system == "Darwin":
            verbose_print("Using macOS-specific screen clearing methods", verbose)
            try:
                verbose_print("Attempting macOS reset command", verbose)
                subprocess.run(['reset'], check=True, timeout=2.0)
                verbose_print("macOS reset command successful", verbose)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                verbose_print(f"macOS reset command failed: {e}", verbose)
                try:
                    verbose_print("Attempting ANSI escape sequences for macOS", verbose)
                    print("\033[2J\033[3J\033[H", end="", flush=True)
                    verbose_print("ANSI escape sequences successful", verbose)
                except Exception as e2:
                    verbose_print(f"ANSI escape sequences failed: {e2}, falling back to os.system", verbose)
                    os.system('clear')
        
        else:
            verbose_print("Using Linux/Unix-specific screen clearing methods", verbose)
            try:
                verbose_print("Attempting Linux clear with scrollback buffer clearing", verbose)
                subprocess.run(['sh', '-c', 'clear && printf "\\033[3J"'], check=True, timeout=2.0)
                verbose_print("Linux clear command successful", verbose)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                verbose_print(f"Linux clear command failed: {e}", verbose)
                try:
                    verbose_print("Attempting ANSI escape sequences for Linux", verbose)
                    print("\033[2J\033[3J\033[H", end="", flush=True)
                    verbose_print("ANSI escape sequences successful", verbose)
                except Exception as e2:
                    verbose_print(f"ANSI escape sequences failed: {e2}, falling back to os.system", verbose)
                    os.system('clear')
    
    except Exception as e:
        verbose_print(f"All screen clearing methods failed with exception: {e}", verbose)
        verbose_print("Using final fallback os.system method", verbose)
        if system == "Windows":
            os.system('cls')
        else:
            os.system('clear')
    
    verbose_print("Screen clearing process completed", verbose)

def _fallback_input(prompt: str, default: Optional[str] = None, verbose=False) -> str:
    """Fallback input method for when termios is not available"""
    verbose_print(f"Using fallback input method with prompt: '{prompt}'", verbose)
    verbose_print(f"Default value: {default}", verbose)
    
    try:
        result = input(prompt).strip()
        verbose_print(f"User input received: '{result}'", verbose)
        final_result = result if result else (default or "")
        verbose_print(f"Final result after default handling: '{final_result}'", verbose)
        return final_result
    except (KeyboardInterrupt, EOFError) as e:
        verbose_print(f"Input interrupted with {type(e).__name__}", verbose)
        fallback_result = default or "0"
        verbose_print(f"Returning fallback result: '{fallback_result}'", verbose)
        return fallback_result


def safe_input(prompt: str, default: Optional[str] = None, verbose=False) -> str:
    """Safe input with escape sequence prevention and cross-platform support"""
    verbose_print(f"Starting safe input with prompt: '{prompt}'", verbose)
    verbose_print(f"Default value: {default}", verbose)
    
    import sys
    import platform
    
    current_platform = platform.system()
    verbose_print(f"Current platform: {current_platform}", verbose)
    
    if current_platform == "Windows":
        verbose_print("Windows detected, using fallback input method", verbose)
        return _fallback_input(prompt, default, verbose)
    
    verbose_print("Non-Windows platform, attempting advanced input handling", verbose)
    
    try:
        import select
        import termios
        import tty
        verbose_print("Successfully imported termios modules", verbose)
        
        fd = sys.stdin.fileno()
        verbose_print(f"stdin file descriptor: {fd}", verbose)
        
        old_settings = termios.tcgetattr(fd)
        verbose_print("Saved original terminal settings", verbose)
        
        try:
            print(prompt, end="", flush=True)
            verbose_print("Prompt displayed, setting raw terminal mode", verbose)
            
            tty.setraw(sys.stdin.fileno())
            verbose_print("Terminal set to raw mode", verbose)
            
            user_input = ""
            verbose_print("Starting character-by-character input processing", verbose)
            
            while True:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    verbose_print(f"Character received: {repr(char)}", verbose)
                    
                    if char == '\r' or char == '\n':
                        verbose_print("Enter key detected, ending input", verbose)
                        print()
                        break
                    
                    elif char == '\x03':
                        verbose_print("Ctrl+C detected", verbose)
                        print()
                        raise KeyboardInterrupt
                    
                    elif char == '\x7f' or char == '\x08':
                        if user_input:
                            user_input = user_input[:-1]
                            print('\b \b', end="", flush=True)
                            verbose_print("Backspace processed", verbose)
                    
                    elif char == '\x1b':
                        verbose_print("Escape sequence detected, consuming following characters", verbose)
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            next_char = sys.stdin.read(1)
                            if next_char == '[':
                                if select.select([sys.stdin], [], [], 0.1)[0]:
                                    sys.stdin.read(1)
                        continue
                    
                    elif char.isprintable():
                        user_input += char
                        print(char, end="", flush=True)
                        verbose_print(f"Added printable character: '{char}'", verbose)
            
            verbose_print("Restoring original terminal settings", verbose)
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            result = user_input.strip()
            final_result = result if result else (default or "")
            verbose_print(f"Final input result: '{final_result}'", verbose)
            return final_result
            
        except Exception as e:
            verbose_print(f"Error during advanced input processing: {e}", verbose)
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            raise
            
    except (ImportError, OSError, termios.error) as e:
        verbose_print(f"Advanced input not available ({type(e).__name__}: {e}), using fallback", verbose)
        return _fallback_input(prompt, default, verbose)
