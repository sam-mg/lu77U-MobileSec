"""Banner display utilities for lu77U-MobileSec"""

import re
from .colors import Colors
from ..utils.screen import clear_screen
from ..utils.verbose import verbose_print

def get_visible_length(text, verbose=False):
    """Calculate the visible length of text by removing ANSI color codes"""
    verbose_print(f"Calculating visible length for text: '{text}'", verbose)
    
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', text)
    visible_length = len(clean_text)
    
    verbose_print(f"Original length: {len(text)}, Visible length: {visible_length}", verbose)
    return visible_length

def center_text_in_box(text, box_width=48, verbose=False):
    """Center text in a box line, accounting for color codes"""
    verbose_print(f"Centering text in box - width: {box_width}", verbose)
    verbose_print(f"Text to center: '{text[:30]}{'...' if len(text) > 30 else ''}'", verbose)
    
    visible_length = get_visible_length(text, verbose)
    padding = (box_width - 2 - visible_length) // 2
    remaining_padding = box_width - 2 - visible_length - padding
    
    verbose_print(f"Padding left: {padding}, right: {remaining_padding}", verbose)
    
    centered_line = f"║{' ' * padding}{text}{' ' * remaining_padding}║"
    verbose_print("Text centered successfully", verbose)
    
    return centered_line

def print_banner(verbose=False):
    """Display the main banner for lu77U-MobileSec"""
    verbose_print("Starting banner display", verbose)
    
    verbose_print("Clearing screen", verbose)
    clear_screen(verbose)
    
    verbose_print("Building banner components", verbose)
    
    top_border = f"\n{Colors.CYAN}{Colors.BOLD}╔{'═' * 46}╗"
    verbose_print("Top border created", verbose)
    print(top_border)
    
    title_line = center_text_in_box(f"{Colors.BOLD}lu77U-MobileSec{Colors.RESET}{Colors.CYAN}{Colors.BOLD}", verbose=verbose)
    verbose_print("Title line created", verbose)
    print(title_line)
    
    subtitle_line = center_text_in_box(f"{Colors.BOLD}The Only Mobile Security Tool Which You Need{Colors.RESET}{Colors.CYAN}{Colors.BOLD}", verbose=verbose)
    verbose_print("Subtitle line created", verbose)
    print(subtitle_line)
    
    bottom_border = f"╚{'═' * 46}╝{Colors.RESET}"
    verbose_print("Bottom border created", verbose)
    print(bottom_border)
    
    verbose_print("Banner display completed successfully", verbose)

def create_menu_line(number, text, box_width=40, verbose=False):
    """Create a properly aligned menu line with consistent formatting"""
    verbose_print(f"Creating menu line - number: {number}, text: '{text}', width: {box_width}", verbose)
    
    prefix = f"│ {Colors.BOLD}{number}.{Colors.RESET} {Colors.WHITE}"
    content = f"{text}{Colors.RESET}"
    
    verbose_print(f"Menu prefix created: '{number}.'", verbose)
    verbose_print(f"Menu content: '{text}'", verbose)
    
    visible_length = get_visible_length(f"{prefix}{content}", verbose)
    padding = box_width - visible_length + 1
    
    verbose_print(f"Menu line padding calculated: {padding}", verbose)
    
    menu_line = f"{prefix}{content}{' ' * padding}│{Colors.RESET}"
    verbose_print("Menu line created successfully", verbose)
    
    return menu_line
