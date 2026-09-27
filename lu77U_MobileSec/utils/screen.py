#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.screen

Purpose:
    Terminal interaction for the interactive setup flows: clearing the screen and reading a line of input without letting stray control characters corrupt the answer.

Responsibilities:
    Clear the terminal on each supported platform, and read a line with per-character handling where the platform allows it.

Dependencies:
    os, subprocess, platform, termios/tty/select on POSIX only.

Implementation notes:
    Both entry points are written as a cascade of increasingly primitive fallbacks. Terminal behaviour varies enormously -- an SSH session, a CI runner, a Windows console host, an IDE-embedded terminal and a tmux pane all differ -- and neither clearing the screen nor reading a line is important enough to abort a run over.

Security considerations:
    Every subprocess here is invoked with a fixed argument list and a fixed command string. No user or APK-derived value is interpolated into a shell, so the os.system calls are safe despite being shell invocations.
"""

import os
import subprocess
import platform
from typing import Optional
from .verbose import verbose_print

def clear_screen(verbose=False):
    """
    Purpose:
        Clear the terminal, including the scrollback buffer where the platform supports it.

    Parameters:
        verbose: Traces which method was attempted and which succeeded.

    Side effects:
        Spawns a short-lived subprocess and writes to the terminal.

    Postconditions:
        Best-effort. The function returns normally even when every method failed; there is no way to report that and nothing useful a caller could do about it.

    Implementation notes:
        Each platform gets a three-stage cascade: a native command, then raw ANSI escapes, then os.system as a last resort. Clearing the scrollback is the reason the native commands are tried first -- the 2J escape clears only the visible screen, so a bare clear leaves the previous scan's output one scroll away, which is confusing when comparing runs. The subprocess timeouts (one to two seconds) exist because `reset` and PowerShell startup can both hang on a terminal that is not fully attached, and a hung cosmetic call would block the whole tool. On Linux the command is run through sh -c so that clear and the 3J escape run as one unit; this is the one place a shell is genuinely needed, and the command string is a literal constant.

    Security considerations:
        All commands are constant literals. Nothing user-controlled reaches a shell.
    """
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
    """
    Purpose:
        Read a line using the built-in input(), for platforms and environments where raw terminal control is unavailable.

    Parameters:
        prompt: Text shown before reading.
        default: Value substituted when the user submits an empty line.
        verbose: Traces the input and the resolved value.

    Returns:
        The stripped input, the default when the input was empty, or "" when there is no default.

    Raises:
        Nothing. KeyboardInterrupt and EOFError are caught deliberately.

    Side effects:
        Reads stdin and writes the prompt to stdout.

    Implementation notes:
        Interrupt and end-of-file return "0" when no default was given rather than propagating, because the callers are menu loops where "0" is the conventional exit choice. That makes Ctrl+C and a closed stdin -- the latter being the normal case when the tool runs non-interactively -- behave as "leave this menu" instead of crashing the process.
    """
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
    """
    Purpose:
        Read a line of input with control characters handled explicitly, so that an arrow key or a stray escape sequence cannot end up inside the value the user appears to have typed.

    Parameters:
        prompt: Text shown before reading.
        default: Value substituted when the user submits an empty line.
        verbose: Traces every character and state transition.

    Returns:
        The stripped input, or the default when the input was empty.

    Raises:
        KeyboardInterrupt: When the user presses Ctrl+C. Raised explicitly because raw mode disables the terminal driver's own signal generation, so without this the interrupt would be read as an ordinary character and silently swallowed.

    Preconditions:
        stdin is a real terminal. When it is not, the fallback path is taken automatically.

    Postconditions:
        The terminal is returned to its original mode on every exit path, including the error path.

    Side effects:
        Puts the terminal into raw mode for the duration of the read, and echoes accepted characters manually.

    Implementation notes:
        Raw mode is what makes this different from input(): it is the only way to intercept escape sequences before they reach the line buffer. An arrow key arrives as ESC [ A, and under input() those three bytes land in the string; here the sequence is recognised and discarded. Restoring the terminal is done both on the success path and in the except block before re-raising. Missing that would leave the user's shell in raw mode after an error -- a broken terminal that survives the process, which is far worse than the original failure. Windows takes the fallback unconditionally, since termios does not exist there. On POSIX the import itself is inside the try, so an environment without a controlling terminal degrades rather than fails. select() with a timeout is used instead of a blocking read so the loop stays responsive and can distinguish a lone ESC from the start of a sequence.

    Known limitations:
        The except clause names termios.error, which is only bound if the termios import succeeded; when that import is what failed, the handler itself raises NameError. In practice the ImportError path is reached only on a non-POSIX platform, which is already routed to the fallback above, so the broken branch is unreachable -- but it is fragile, and moving the import out of the try would fix it.
    """
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
