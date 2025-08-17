"""
Menu system for lu77U-MobileSec
"""

import webbrowser
import time
from .colors import Colors
from .banner import create_menu_line
from ..utils.print_banner import print_banner
from ..config.settings import SOCIAL_LINKS
from ..utils import verbose_print
from ..utils.screen import safe_input

class MenuSystem:
    """Handle menu interactions and display"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("MenuSystem initialized", self.verbose)
    
    def display_main_menu(self):
        """Display the main menu options"""
        verbose_print("Displaying main menu", self.verbose)
        print_banner()
        
        print(f"\n{Colors.CYAN}Available Actions:{Colors.RESET}")
        print(f"╭{'─' * 40}╮")
        print(create_menu_line("1", "GitHub Repository"))
        print(create_menu_line("0", "Exit"))
        print(f"╰{'─' * 40}╯")
        verbose_print("Main menu displayed successfully", self.verbose)
        
    def get_user_input(self, prompt="Enter your choice"):
        """Get user input with consistent formatting"""
        verbose_print(f"Requesting user input: {prompt}", self.verbose)
        print(f"\n{Colors.WHITE}╭─ {prompt}{Colors.RESET}")
        user_input = safe_input(f"{Colors.WHITE}╰─▸{Colors.RESET} ", "0")
        verbose_print(f"User input received: '{user_input}'", self.verbose)
        return user_input
