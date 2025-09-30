"""Report Builder for lu77U-MobileSec"""

from lu77U_MobileSec.detection.results import DetectionResult
from ..ui.colors import Colors
from ..utils import verbose_print
from typing import Optional
import subprocess
import platform
import os

class ReportBuilder:
    """Main report builder class that orchestrates report generation"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.pdf_generator = None
        verbose_print("ReportBuilder initialized", self.verbose)
    
    def _get_pdf_generator(self):
        """Lazy initialization of PDF generator"""
        verbose_print("Getting PDF generator (lazy initialization)", self.verbose)
        
        if self.pdf_generator is None:
            verbose_print("PDF generator not initialized - creating new instance", self.verbose)
            try:
                from .pdf_generator import PDFReportGenerator
                self.pdf_generator = PDFReportGenerator(verbose=self.verbose)
                verbose_print("PDF generator initialized successfully", self.verbose)
            except Exception as e:
                verbose_print(f"Failed to initialize PDF generator: {e}", self.verbose)
                
                if self.verbose:
                    print("Failed to initialize PDF generator")
                    print(f"   Error: {str(e)}")
                    print("\n   WeasyPrint installation may be required:")
                    if platform.system() == "Windows":
                        print("   For Windows:")
                        print("   1. Install MSYS2: https://www.msys2.org/")
                        print("   2. Run: pacman -S mingw-w64-x86_64-pango")
                        print("   3. Set: set WEASYPRINT_DLL_DIRECTORIES=C:\\msys64\\mingw64\\bin")
                        print("   4. Restart your terminal and try again")
                    elif platform.system() == "Darwin":
                        print("   For macOS: brew install weasyprint")
                    elif platform.system() == "Linux":
                        print("   For Linux: Install pango library for your distribution")
                    print("\n   More info: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html")
                raise
        else:
            verbose_print("PDF generator already initialized", self.verbose)
            
        return self.pdf_generator
    
    def generate_pdf_report(self, detection_result: DetectionResult) -> Optional[str]:
        verbose_print("Starting PDF report generation", self.verbose)
        
        try:
            pdf_generator = self._get_pdf_generator()
            verbose_print("PDF generator obtained successfully", self.verbose)
            
            pdf_path = pdf_generator.generate_pdf_report(detection_result)
            
            if pdf_path:
                verbose_print(f"PDF report generated successfully: {pdf_path}", self.verbose)
                return pdf_path
            else:
                verbose_print("PDF report generation failed - no path returned", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error in report generation: {str(e)}", self.verbose)
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def handle_post_report_options(self, report_path: str) -> None:
        """Handle post-report generation options (open PDF, return to menu)"""
        verbose_print("Starting post-report options handling", self.verbose)
        verbose_print(f"Report path: {report_path}", self.verbose)
        
        while True:
            print(f"\n{Colors.CYAN}What would you like to do next?{Colors.RESET}")
            print(f"╭{'─' * 40}╮")
            print(f"│ 1. Open PDF report                     │")
            print(f"│ 0. Return to main menu                 │")
            print(f"╰{'─' * 40}╯")
            
            user_choice = input(f"\n{Colors.CYAN}╭─ Enter your choice\n╰─▸ {Colors.RESET}").strip()
            verbose_print(f"User selected option: {user_choice}", self.verbose)
            
            if user_choice == '1':
                verbose_print(f"User chose to open PDF: {report_path}", self.verbose)
                self._open_pdf_report(report_path)
            elif user_choice == '0':
                verbose_print("User chose to return to main menu", self.verbose)
                break
            else:
                verbose_print(f"Invalid choice entered: {user_choice}", self.verbose)
                print(f"\n{Colors.ERROR}Invalid choice. Please try again.{Colors.RESET}")
                
        verbose_print("Post-report options handling completed", self.verbose)
    
    def _open_pdf_report(self, pdf_path: str) -> None:
        """Open the PDF report using the system's default PDF viewer"""
        try:
            verbose_print(f"Attempting to open PDF: {pdf_path}", self.verbose)
            if not os.path.exists(pdf_path):
                print(f"\n{Colors.ERROR}PDF file not found: {pdf_path}{Colors.RESET}")
                return
            system = platform.system()
            if system == "Darwin":
                verbose_print("Opening PDF on macOS using 'open' command", self.verbose)
                subprocess.run(["open", pdf_path], check=True)
                print(f"\n{Colors.SUCCESS}PDF opened successfully!{Colors.RESET}")
            elif system == "Windows":
                verbose_print("Opening PDF on Windows using 'start' command", self.verbose)
                subprocess.run(["start", pdf_path], shell=True, check=True)
                print(f"\n{Colors.SUCCESS}PDF opened successfully!{Colors.RESET}")
            elif system == "Linux":
                verbose_print("Opening PDF on Linux using 'xdg-open' command", self.verbose)
                subprocess.run(["xdg-open", pdf_path], check=True)
                print(f"\n{Colors.SUCCESS}PDF opened successfully!{Colors.RESET}")
            else:
                print(f"\n{Colors.ERROR}Unsupported operating system: {system}{Colors.RESET}")
                print(f"{Colors.INFO}Please manually open: {pdf_path}{Colors.RESET}")
            print(f"\n{Colors.CYAN}Press ENTER to return to main menu...{Colors.RESET}")
            input()
        except subprocess.CalledProcessError as e:
            verbose_print(f"Failed to open PDF: {str(e)}", self.verbose)
            print(f"\n{Colors.ERROR}Failed to open PDF automatically.{Colors.RESET}")
            print(f"{Colors.INFO}Please manually open: {pdf_path}{Colors.RESET}")
            print(f"\n{Colors.CYAN}Press ENTER to continue...{Colors.RESET}")
            input()
        except Exception as e:
            verbose_print(f"Unexpected error opening PDF: {str(e)}", self.verbose)
            print(f"\n{Colors.ERROR}Unexpected error opening PDF: {str(e)}{Colors.RESET}")
            print(f"{Colors.INFO}Please manually open: {pdf_path}{Colors.RESET}")
            print(f"\n{Colors.CYAN}Press ENTER to continue...{Colors.RESET}")
            input()
