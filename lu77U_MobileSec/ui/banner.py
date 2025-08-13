"""
Banner display utilities for lu77U-MobileSec
"""

import re
from .colors import Colors

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
    print(f"\n{Colors.CYAN}{Colors.BOLD}╔{'═' * 46}╗")
    print(center_text_in_box(f"{Colors.BOLD}lu77U-MobileSec{Colors.RESET}{Colors.CYAN}{Colors.BOLD}"))
    print(center_text_in_box(f"{Colors.BOLD}The Only Mobile Security Tool Which You Need{Colors.RESET}{Colors.CYAN}{Colors.BOLD}"))
    print(f"╚{'═' * 46}╝{Colors.RESET}")

def create_menu_line(number, text, box_width=40):
    """Create a properly aligned menu line with consistent formatting"""
    prefix = f"│ {Colors.BOLD}{number}.{Colors.RESET} {Colors.WHITE}"
    content = f"{text}{Colors.RESET}"
    
    visible_length = get_visible_length(f"{prefix}{content}")
    padding = box_width - visible_length + 1
    return f"{prefix}{content}{' ' * padding}│{Colors.RESET}"
