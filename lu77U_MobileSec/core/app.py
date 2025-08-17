"""
Main application class for lu77U-MobileSec
"""

import sys
import signal
import time
from ..ui.colors import Colors
from ..ui.menu import MenuSystem
from ..utils import verbose_print

class MobileSecApp:
    """Main application class for lu77U-MobileSec"""
    
    def __init__(self, verbose=False):
        """Initialize the Mobile Security application"""
        self.running = True
        self.verbose = verbose
        verbose_print("Initializing MobileSecApp", self.verbose)
        self.menu_system = MenuSystem(verbose=verbose)
        self._setup_signal_handlers()
        verbose_print("MobileSecApp initialization complete", self.verbose)
    
    def _setup_signal_handlers(self):
        """Set up handlers for graceful shutdown"""
        verbose_print("Setting up signal handlers", self.verbose)
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        verbose_print("Signal handlers configured", self.verbose)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully"""
        verbose_print(f"Received shutdown signal: {signum}", self.verbose)
        print(f"\n{Colors.INFO}[!] Received shutdown signal. Exiting...{Colors.RESET}")
        self.running = False
        time.sleep(1)
        sys.exit(0)
    
    def run_socials_menu(self):
        """Run the socials menu in a loop"""
        verbose_print("Starting socials menu loop", self.verbose)
        while self.running:
            try:
                self.menu_system.display_socials_menu()
                choice = self.menu_system.get_user_input("Select a social link to open")
                
                if not self.menu_system.handle_social_choice(choice):
                    verbose_print("User chose to exit socials menu", self.verbose)
                    break
                    
            except KeyboardInterrupt:
                verbose_print("Keyboard interrupt in socials menu", self.verbose)
                break
            except Exception as e:
                verbose_print(f"Error in socials menu: {str(e)}", self.verbose)
                print(f"\n{Colors.ERROR}✗ Error: {str(e)}{Colors.RESET}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                time.sleep(2)
        verbose_print("Exiting socials menu loop", self.verbose)
    
    def run(self):
        """Main application loop"""
        verbose_print("Starting main application loop", self.verbose)
        while self.running:
            try:
                self.menu_system.display_main_menu()
                choice = self.menu_system.get_user_input()
                
                verbose_print(f"User selected main menu option: {choice}", self.verbose)
                
                if choice == "1":
                    verbose_print("Opening GitHub repository", self.verbose)
                    github_url = "https://github.com/sam-mg/lu77U-MobileSec"
                    print(f"\n{Colors.SUCCESS}🌐 Opening GitHub Repository...{Colors.RESET}")
                    if self.verbose:
                        print(f"{Colors.BLUE}URL: {github_url}{Colors.RESET}")
                    
                    import webbrowser
                    webbrowser.open(github_url)
                    verbose_print("Successfully opened GitHub repository in browser", self.verbose)
                    time.sleep(1)
                elif choice == "0":
                    verbose_print("User chose to exit application", self.verbose)
                    print(f"\n{Colors.SUCCESS}✨ Thanks for using lu77U-MobileSec!")
                    print(f"🔒 Stay secure!{Colors.RESET}")
                    break
                else:
                    verbose_print(f"Invalid menu choice: {choice}", self.verbose)
                    print(f"\n{Colors.ERROR}✗ Invalid choice. Please try again.{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                verbose_print("Keyboard interrupt in main loop", self.verbose)
                print(f"\n\n{Colors.SUCCESS}✨ Thanks for using lu77U-MobileSec!")
                print(f"🔒 Stay secure!{Colors.RESET}")
                break
            except Exception as e:
                verbose_print(f"Error in main loop: {str(e)}", self.verbose)
                print(f"\n{Colors.ERROR}✗ Error: {str(e)}{Colors.RESET}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                time.sleep(2)
        verbose_print("Application loop ended", self.verbose)
