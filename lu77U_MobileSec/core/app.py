"""Main application class for lu77U-MobileSec"""

import sys
import signal
import time
from ..ui.colors import Colors
from ..ui.menu import MenuSystem
from ..utils import verbose_print
from ..path_handlers.path_manager import PathManager
from ..detection.detector import MobileSecurityDetector

class MobileSecApp:
    """Main application class for lu77U-MobileSec"""
    
    def __init__(self, verbose=False):
        """Initialize the Mobile Security application"""
        verbose_print("Starting MobileSecApp initialization", verbose)
        self.running = True
        self.verbose = verbose
        verbose_print("Initializing MobileSecApp", self.verbose)
        
        verbose_print("Creating MenuSystem instance", self.verbose)
        self.menu_system = MenuSystem(verbose=verbose)
        verbose_print("MenuSystem created successfully", self.verbose)
        
        verbose_print("Creating PathManager instance", self.verbose)
        self.path_manager = PathManager(self.menu_system, verbose=verbose)
        verbose_print("PathManager created successfully", self.verbose)
        
        verbose_print("Creating MobileSecurityDetector instance", self.verbose)
        self.mobile_detector = MobileSecurityDetector(verbose=verbose)
        verbose_print("MobileSecurityDetector created successfully", self.verbose)
        
        verbose_print("Setting up signal handlers", self.verbose)
        self._setup_signal_handlers()
        verbose_print("MobileSecApp initialization complete", self.verbose)
    
    def _setup_signal_handlers(self):
        """Set up handlers for graceful shutdown"""
        verbose_print("Setting up signal handlers", self.verbose)
        verbose_print("Registering SIGINT handler", self.verbose)
        signal.signal(signal.SIGINT, self._handle_shutdown)
        verbose_print("Registering SIGTERM handler", self.verbose)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        verbose_print("Signal handlers configured successfully", self.verbose)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully"""
        verbose_print(f"Received shutdown signal: {signum}", self.verbose)
        verbose_print(f"Signal frame info: {frame}", self.verbose)
        print(f"\n{Colors.INFO}Received shutdown signal. Exiting...{Colors.RESET}")
        verbose_print("Setting running flag to False", self.verbose)
        self.running = False
        verbose_print("Waiting 1 second before exit", self.verbose)
        time.sleep(1)
        verbose_print("Exiting application", self.verbose)
        sys.exit(0)
    
    def run(self):
        """Main application loop"""
        verbose_print("Starting main application loop", self.verbose)
        loop_iteration = 0
        
        while self.running:
            loop_iteration += 1
            verbose_print(f"Main loop iteration {loop_iteration}", self.verbose)
            
            try:
                verbose_print("Displaying main menu", self.verbose)
                self.menu_system.display_main_menu()
                verbose_print("Getting user input", self.verbose)
                choice = self.menu_system.get_user_input()
                verbose_print(f"User selected main menu option: {choice}", self.verbose)
                
                if choice == "1":
                    verbose_print("Processing GitHub repository option", self.verbose)
                    self._open_github_repository()
                elif choice == "2":
                    verbose_print("User selected framework detection", self.verbose)
                    self._run_framework_detection()
                elif choice == "0":
                    verbose_print("User chose to exit application", self.verbose)
                    print(f"\n{Colors.SUCCESS}Thanks for using lu77U-MobileSec!")
                    print(f"Stay secure!{Colors.RESET}")
                    verbose_print("Breaking out of main loop", self.verbose)
                    break
                else:
                    verbose_print(f"Invalid menu choice: {choice}", self.verbose)
                    print(f"\n{Colors.ERROR}Invalid choice. Please try again.{Colors.RESET}")
                    verbose_print("Waiting 1 second before continuing", self.verbose)
                    time.sleep(1)
            except KeyboardInterrupt:
                verbose_print("Keyboard interrupt in main loop", self.verbose)
                print(f"\n\n{Colors.SUCCESS}Thanks for using lu77U-MobileSec!")
                print(f"Stay secure!{Colors.RESET}")
                verbose_print("Breaking out of main loop due to keyboard interrupt", self.verbose)
                break
            except Exception as e:
                verbose_print(f"Exception in main loop: {type(e).__name__}", self.verbose)
                verbose_print(f"Error in main loop: {str(e)}", self.verbose)
                print(f"\n{Colors.ERROR}Error: {str(e)}{Colors.RESET}")
                if self.verbose:
                    verbose_print("Printing full traceback", self.verbose)
                    import traceback
                    traceback.print_exc()
                verbose_print("Waiting 2 seconds before continuing", self.verbose)
                time.sleep(2)
                
        verbose_print(f"Application loop ended after {loop_iteration} iterations", self.verbose)

    def _open_github_repository(self):
        """Open the GitHub repository in the default browser"""
        verbose_print("Opening GitHub repository", self.verbose)
        github_url = "https://github.com/sam-mg/lu77U-MobileSec"
        verbose_print(f"GitHub URL: {github_url}", self.verbose)
        print(f"\n{Colors.SUCCESS}Opening GitHub Repository...{Colors.RESET}")
        if self.verbose:
            print(f"{Colors.BLUE}URL: {github_url}{Colors.RESET}")
            
        verbose_print("Importing webbrowser module", self.verbose)
        import webbrowser
        verbose_print("Opening URL in default browser", self.verbose)
        webbrowser.open(github_url)
        verbose_print("Successfully opened GitHub repository in browser", self.verbose)
        verbose_print("Waiting 1 second", self.verbose)
        time.sleep(1)
    
    def _run_framework_detection(self):
        """Run framework detection and generate report"""
        try:
            verbose_print("Starting framework detection process", self.verbose)
            verbose_print("Getting target path from path manager", self.verbose)
            target_path = self.path_manager.get_target_path()
            
            if not target_path:
                verbose_print("No target path provided by user", self.verbose)
                print(f"\n{Colors.ERROR}No target path provided. Operation cancelled.{Colors.RESET}")
                return
                
            verbose_print(f"Target path obtained: {target_path}", self.verbose)
            verbose_print("Starting mobile security detection", self.verbose)
            detection_result = self.mobile_detector.detect(target_path)
            
            if not detection_result:
                verbose_print("Detection failed - no results returned", self.verbose)
                print(f"\n{Colors.ERROR}Detection failed. Unable to proceed.{Colors.RESET}")
                return
                
            verbose_print("Detection completed successfully", self.verbose)
            verbose_print(f"Detection result type: {type(detection_result)}", self.verbose)
            
            verbose_print("Attempting to import ReportBuilder", self.verbose)
            try:
                from ..report_generator.report_builder import ReportBuilder
                verbose_print("ReportBuilder imported successfully", self.verbose)
                verbose_print("Creating ReportBuilder instance", self.verbose)
                report_builder = ReportBuilder(verbose=self.verbose)
                verbose_print("ReportBuilder instance created", self.verbose)
            except ImportError as e:
                verbose_print(f"ImportError while creating ReportBuilder: {e}", self.verbose)
                if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
                    verbose_print("PDF dependencies not available", self.verbose)
                    print(f"\n{Colors.WARNING}PDF dependencies not available on this system.{Colors.RESET}")
                    print(f"{Colors.INFO}Detection completed, but PDF report cannot be generated.{Colors.RESET}")
                    print(f"{Colors.INFO}The detection results are available in memory.{Colors.RESET}")
                    return
                else:
                    verbose_print("Unknown import error, re-raising", self.verbose)
                    raise
            
            verbose_print("Generating PDF report", self.verbose)
            report_path = report_builder.generate_pdf_report(detection_result)
            
            if report_path:
                verbose_print(f"PDF report generated successfully: {report_path}", self.verbose)
                print(f"\n{Colors.SUCCESS}Framework detection completed successfully!{Colors.RESET}")
                
                if self.verbose:
                    print(f"{Colors.INFO}Report saved as PDF: {report_path}{Colors.RESET}")
                else:
                    verbose_print("Formatting report path for display", self.verbose)
                    import os
                    cwd = os.getcwd()
                    verbose_print(f"Current working directory: {cwd}", self.verbose)
                    
                    try:
                        rel_path = os.path.relpath(report_path, cwd)
                        filename = os.path.basename(report_path)
                        verbose_print(f"Relative path: {rel_path}, Filename: {filename}", self.verbose)
                        
                        if len(rel_path) < len(report_path):
                            print(f"{Colors.INFO}Report saved as PDF: {rel_path}{Colors.RESET}")
                        else:
                            print(f"{Colors.INFO}Report saved as: {filename}{Colors.RESET}")
                    except (ValueError, OSError) as e:
                        verbose_print(f"Error formatting path: {e}", self.verbose)
                        filename = os.path.basename(report_path)
                        print(f"{Colors.INFO}Report saved as: {filename}{Colors.RESET}")
                
                verbose_print("Handling post-report options", self.verbose)
                report_builder.handle_post_report_options(report_path)
                verbose_print("Post-report options completed", self.verbose)
            else:
                verbose_print("PDF report generation failed", self.verbose)
                print(f"\n{Colors.ERROR}Failed to generate report.{Colors.RESET}")
                print(f"\n{Colors.CYAN}Press ENTER to continue...{Colors.RESET}")
                input()
                
        except Exception as e:
            verbose_print(f"Exception in framework detection: {type(e).__name__}", self.verbose)
            verbose_print(f"Error in framework detection: {str(e)}", self.verbose)
            print(f"\n{Colors.ERROR}Error during framework detection: {str(e)}{Colors.RESET}")
            if self.verbose:
                verbose_print("Printing full traceback for framework detection error", self.verbose)
                import traceback
                traceback.print_exc()
