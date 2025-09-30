"""Path manager module for lu77U-MobileSec"""

from ..ui.colors import Colors
from ..utils import verbose_print
from .path_processor import PathProcessor
from .gui_path_handler import GUIPathHandler
from .manual_path_handler import ManualPathHandler

class PathManager:
    """Main class for managing all path handling operations"""
    
    def __init__(self, menu_system, verbose=False):
        """Initialize the path manager"""
        self.menu_system = menu_system
        self.verbose = verbose
        
        verbose_print("PathManager initialization started", self.verbose)
        
        # Initialize sub-components
        verbose_print("Initializing PathProcessor", self.verbose)
        self.path_processor = PathProcessor(verbose=verbose)
        
        verbose_print("Initializing GUIPathHandler", self.verbose)
        self.gui_handler = GUIPathHandler(menu_system, verbose=verbose)
        
        verbose_print("Initializing ManualPathHandler", self.verbose)
        self.manual_handler = ManualPathHandler(menu_system, self.path_processor, verbose=verbose)
        
        verbose_print("PathManager initialization complete", self.verbose)
    
    def get_target_path(self) -> str:
        """Get target path using the appropriate method"""
        verbose_print("Starting target path selection process", self.verbose)
        
        # Check GUI availability first
        gui_available = self.gui_handler.is_gui_available()
        verbose_print(f"GUI availability check result: {gui_available}", self.verbose)
        
        print(f"\n{Colors.CYAN}Framework Detection{Colors.RESET}")
        print(f"╭{'─' * 40}╮")
        print(f"│ Choose how to select your target:      │")
        print(f"│                                        │")
        
        if gui_available:
            verbose_print("Displaying menu with GUI option", self.verbose)
            print(f"│ {Colors.GREEN}1.{Colors.RESET} Use GUI File Picker (Recommended)   │")
            print(f"│ {Colors.YELLOW}2.{Colors.RESET} Enter path manually                 │")
        else:
            verbose_print("Displaying menu without GUI option (GUI unavailable)", self.verbose)
            print(f"│ {Colors.YELLOW}1.{Colors.RESET} Enter path manually (UI missing)    │")
        
        print(f"╰{'─' * 40}╯")
        
        choice = self.menu_system.get_user_input("Select input method")
        verbose_print(f"User selected input method: {choice}", self.verbose)
        
        # Handle user choice
        if choice == "0":
            verbose_print("User selected to exit (choice 0)", self.verbose)
            return None
        elif choice == "1" and gui_available:
            verbose_print("User selected GUI option - delegating to GUI handler", self.verbose)
            target_path = self.gui_handler.get_target_path_gui()
            if target_path is None:
                verbose_print("GUI path selection failed, falling back to manual input", self.verbose)
                return self.manual_handler.get_target_path_manual()
            else:
                verbose_print(f"GUI path selection successful: {target_path}", self.verbose)
                return target_path
        elif (choice == "1" and not gui_available) or choice == "2":
            verbose_print("User selected manual input option - delegating to manual handler", self.verbose)
            return self.manual_handler.get_target_path_manual()
        else:
            verbose_print(f"Invalid choice entered: {choice}", self.verbose)
            print(f"\n{Colors.ERROR}Invalid choice{Colors.RESET}")
            return None
