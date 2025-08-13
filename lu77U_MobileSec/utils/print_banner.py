#!/usr/bin/env python3
"""
Banner display utilities for lu77U-MobileSec
"""

import re
import sys
import os

try:
    from ..ui.colors import Colors as ConsoleColors
    from .screen import clear_screen
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ui.colors import Colors as ConsoleColors
    from utils.screen import clear_screen


def get_visible_length(text):
    """Calculate the visible length of text by removing ANSI color codes"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return len(ansi_escape.sub('', text))


def center_text_in_box(text, box_width=48):
    """Center text in a box line, accounting for color codes"""
    visible_length = get_visible_length(text)
    padding = (box_width - 2 - visible_length) // 2
    return f"║{' ' * padding}{text}{' ' * (box_width - 2 - visible_length - padding)}║"


def print_banner():
    """Display the main banner for lu77U-MobileSec"""
    clear_screen()
    print(f"\n{ConsoleColors.CYAN}{ConsoleColors.BOLD}╔{'═' * 46}╗")
    print(center_text_in_box(f"{ConsoleColors.BOLD}lu77U-MobileSec{ConsoleColors.RESET}{ConsoleColors.CYAN}{ConsoleColors.BOLD}"))
    print(center_text_in_box(f"{ConsoleColors.BOLD}The Only Mobile Security Tool Which You Need{ConsoleColors.RESET}{ConsoleColors.CYAN}{ConsoleColors.BOLD}"))
    print(f"╚{'═' * 46}╝{ConsoleColors.RESET}")
