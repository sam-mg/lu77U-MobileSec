"""Menu system for lu77U-MobileSec"""

from .colors import Colors
from .banner import create_menu_line, print_banner
from ..utils import verbose_print

class MenuSystem:
    """Handle menu interactions and display"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("MenuSystem initialized", self.verbose)
    
    def display_main_menu(self):
        """Display the main menu options"""
        verbose_print("Starting main menu display", self.verbose)
        
        verbose_print("Calling print_banner function", self.verbose)
        print_banner(self.verbose)
        
        verbose_print("Building main menu structure", self.verbose)
        
        print(f"\n{Colors.CYAN}Available Actions:{Colors.RESET}")
        verbose_print("Menu header printed", self.verbose)
        
        print(f"╭{'─' * 40}╮")
        verbose_print("Menu top border printed", self.verbose)
        
        verbose_print("Creating menu option 1: GitHub Repository", self.verbose)
        print(create_menu_line("1", "GitHub Repository", verbose=self.verbose))
        
        verbose_print("Creating menu option 2: Detect Framework", self.verbose)
        print(create_menu_line("2", "Detect Framework", verbose=self.verbose))
        
        verbose_print("Creating menu option 0: Exit", self.verbose)
        print(create_menu_line("0", "Exit", verbose=self.verbose))
        
        print(f"╰{'─' * 40}╯")
        verbose_print("Menu bottom border printed", self.verbose)
        
        verbose_print("Main menu display completed successfully", self.verbose)
        
    def get_user_input(self, prompt="Enter your choice"):
        """Get user input with consistent formatting"""
        verbose_print(f"Preparing user input prompt: '{prompt}'", self.verbose)
        
        print(f"\n{Colors.WHITE}╭─ {prompt}{Colors.RESET}")
        verbose_print("Input prompt displayed", self.verbose)
        
        try:
            verbose_print("Waiting for user input...", self.verbose)
            user_input = input(f"{Colors.WHITE}╰─▸{Colors.RESET} ").strip()
            
            if not user_input:
                verbose_print("Empty input received - defaulting to '0'", self.verbose)
                user_input = "0"
            else:
                verbose_print(f"User input received: '{user_input}'", self.verbose)
            
            verbose_print("User input processing completed", self.verbose)
            return user_input
            
        except (KeyboardInterrupt, EOFError) as e:
            print()
            verbose_print(f"Input interrupted: {type(e).__name__}", self.verbose)
            verbose_print("Raising KeyboardInterrupt", self.verbose)
            raise KeyboardInterrupt
