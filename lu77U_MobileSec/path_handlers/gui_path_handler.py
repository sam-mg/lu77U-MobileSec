"""GUI path handler module for lu77U-MobileSec"""

import os
from ..ui.colors import Colors
from ..utils import verbose_print

try:
    import tkinter as tk
    from tkinter import filedialog
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class GUIPathHandler:
    """Class for handling file path selection through GUI"""
    
    def __init__(self, menu_system, verbose=False):
        """Initialize the GUI path handler"""
        self.menu_system = menu_system
        self.verbose = verbose
        self.gui_available = GUI_AVAILABLE
        verbose_print("GUIPathHandler initialized", self.verbose)
        verbose_print(f"GUI availability: {self.gui_available}", self.verbose)
    
    def is_gui_available(self) -> bool:
        """Check if GUI is available"""
        verbose_print(f"Checking GUI availability: {self.gui_available}", self.verbose)
        if not self.gui_available:
            verbose_print("GUI not available - tkinter import failed", self.verbose)
        else:
            verbose_print("GUI available - tkinter imported successfully", self.verbose)
        return self.gui_available
    
    def get_target_path_gui(self) -> str:
        """Get target path using GUI file picker"""
        verbose_print("Starting GUI path selection process", self.verbose)
        
        if not self.gui_available:
            verbose_print("GUI not available - cannot open file picker", self.verbose)
            print(f"\n{Colors.ERROR}GUI not available{Colors.RESET}")
            return None
            
        verbose_print("GUI available - proceeding with file picker", self.verbose)
        
        try:
            verbose_print("Initializing tkinter root window", self.verbose)
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            root.attributes('-topmost', True)
            verbose_print("Tkinter root window initialized and hidden", self.verbose)
            
            print(f"\n{Colors.INFO}Opening file picker...{Colors.RESET}")
            verbose_print("Displaying target type selection menu", self.verbose)
            
            print(f"\n{Colors.CYAN}What do you want to analyze?{Colors.RESET}")
            print(f"╭{'─' * 40}╮")
            print(f"│ 1. APK File                            │")
            print(f"│ 2. Project Directory                   │")
            print(f"╰{'─' * 40}╯")
            
            choice = self.menu_system.get_user_input("Select type")
            verbose_print(f"User selected option: {choice}", self.verbose)
            
            target_path = None
            
            if choice == "1":
                verbose_print("Opening APK file selection dialog", self.verbose)
                initial_dir = self._get_initial_apk_directory()
                verbose_print(f"Initial directory for APK selection: {initial_dir}", self.verbose)
                
                target_path = filedialog.askopenfilename(
                    title="Select APK File",
                    filetypes=[
                        ("APK files", "*.apk"),
                        ("All files", "*.*")
                    ],
                    initialdir=initial_dir
                )
                verbose_print(f"APK file dialog result: {target_path if target_path else 'None (canceled)'}", self.verbose)
                
            elif choice == "2":
                verbose_print("Opening project directory selection dialog", self.verbose)
                initial_dir = os.getcwd()
                verbose_print(f"Initial directory for project selection: {initial_dir}", self.verbose)
                
                target_path = filedialog.askdirectory(
                    title="Select Project Directory",
                    initialdir=initial_dir
                )
                verbose_print(f"Directory dialog result: {target_path if target_path else 'None (canceled)'}", self.verbose)
                
            else:
                verbose_print(f"Invalid choice entered: {choice}", self.verbose)
                print(f"\n{Colors.ERROR}Invalid choice{Colors.RESET}")
                root.destroy()
                return None
            
            verbose_print("Destroying tkinter root window", self.verbose)
            root.destroy()
            
            if target_path:
                verbose_print(f"User selected path: {target_path}", self.verbose)
                # Validate the selected path
                if os.path.exists(target_path):
                    verbose_print("Selected path exists and is valid", self.verbose)
                    print(f"\n{Colors.SUCCESS}Selected: {target_path}{Colors.RESET}")
                    return target_path
                else:
                    verbose_print("Selected path does not exist", self.verbose)
                    print(f"\n{Colors.ERROR}Selected path does not exist: {target_path}{Colors.RESET}")
                    return None
            else:
                verbose_print("No file/folder selected by user", self.verbose)
                print(f"\n{Colors.WARNING}No file/folder selected{Colors.RESET}")
                return None
                
        except Exception as e:
            verbose_print(f"Exception occurred in GUI file picker: {type(e).__name__}: {str(e)}", self.verbose)
            print(f"\n{Colors.ERROR}Error opening file picker: {str(e)}{Colors.RESET}")
            print(f"{Colors.INFO}Falling back to manual input...{Colors.RESET}")
            return None
    
    def _get_initial_apk_directory(self) -> str:
        """Get the initial directory for APK file selection"""
        verbose_print("Determining initial directory for APK selection", self.verbose)
        
        # Check for Samples/APKs directory
        samples_apk_dir = os.path.join(os.getcwd(), "Samples", "APKs")
        verbose_print(f"Checking for samples directory: {samples_apk_dir}", self.verbose)
        
        if os.path.exists(samples_apk_dir):
            verbose_print("Samples APK directory exists - using as initial directory", self.verbose)
            return samples_apk_dir
        else:
            verbose_print("Samples APK directory not found - using current working directory", self.verbose)
            cwd = os.getcwd()
            verbose_print(f"Current working directory: {cwd}", self.verbose)
            return cwd
