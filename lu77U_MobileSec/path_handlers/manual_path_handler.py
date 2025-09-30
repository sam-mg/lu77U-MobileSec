"""Manual path handler module for lu77U-MobileSec"""

import time
from ..ui.colors import Colors
from ..utils import verbose_print

class ManualPathHandler:
    """Class for handling file path selection through manual input"""
    
    def __init__(self, menu_system, path_processor, verbose=False):
        """Initialize the manual path handler"""
        self.menu_system = menu_system
        self.path_processor = path_processor
        self.verbose = verbose
        verbose_print("ManualPathHandler initialized", self.verbose)
    
    def get_target_path_manual(self) -> str:
        """Get target path via manual input"""
        verbose_print("Starting manual path input process", self.verbose)
        
        print(f"\n{Colors.CYAN}Manual Path Input{Colors.RESET}")
        print(f"╭{'─' * 40}╮")
        print(f"│ Provide path to APK or project         │")
        print(f"╰{'─' * 40}╯")

        verbose_print("Prompting user for target path input", self.verbose)
        target_path = self.menu_system.get_user_input("Enter target path")
        verbose_print(f"User entered path: '{target_path}'", self.verbose)
        
        # Check if user provided any input
        if not target_path:
            verbose_print("No path provided by user (None)", self.verbose)
            print(f"\n{Colors.ERROR}No path provided{Colors.RESET}")
            time.sleep(2)
            return None
            
        # Check if path is empty or only whitespace
        if target_path.strip() == "":
            verbose_print("Empty or whitespace-only path provided", self.verbose)
            print(f"\n{Colors.ERROR}No path provided{Colors.RESET}")
            time.sleep(2)
            return None
        
        # Process the path
        raw_path = target_path.strip()
        verbose_print(f"Processing raw path: '{raw_path}'", self.verbose)
        
        processed_path = self.path_processor.process_target_path(raw_path)
        verbose_print(f"Path processing complete: '{processed_path}'", self.verbose)
        
        # Validate the processed path
        verbose_print("Validating processed path", self.verbose)
        if not self.path_processor.validate_path_exists(processed_path):
            verbose_print(f"Path validation failed - path does not exist: {processed_path}", self.verbose)
            print(f"\n{Colors.ERROR}Path does not exist: {processed_path}{Colors.RESET}")
            time.sleep(3)
            return None
        
        verbose_print(f"Path validation successful: {processed_path}", self.verbose)
        return processed_path
