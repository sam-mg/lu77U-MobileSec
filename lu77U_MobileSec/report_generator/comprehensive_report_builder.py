"""Comprehensive Report Builder for lu77U-MobileSec"""

from lu77U_MobileSec.detection.results import DetectionResult
from ..ui.colors import Colors
from ..utils.verbose import verbose_print
from typing import Optional, Dict, Union
import platform
import os
import traceback

class ComprehensiveReportBuilder:
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.pdf_generator = None

    def generate_comprehensive_report(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None, output_manager=None) -> str:
        if not detection_result:
            raise ValueError("Detection result is required for report generation")
        if not output_path:
            raise ValueError("Output path is required for report generation")
            
        try:
            pdf_generator = self._get_pdf_generator()
            
            report_path = pdf_generator.generate_comprehensive_pdf(
                detection_result=detection_result,
                output_path=output_path,
                vulnerability_results=vulnerability_results,
                analyzer_results=analyzer_results,
                output_manager=output_manager
            )

            exists = bool(report_path and os.path.exists(report_path))

            if not exists:
                raise RuntimeError("Report generation failed - no valid output file created")

            try:
                file_size = os.path.getsize(report_path) / 1024  # KB
            except Exception as e:
                verbose_print(f"Report generated but failed to stat file: {e}", self.verbose)
                verbose_print(f"Report location (best effort): {report_path}", self.verbose)
            
            return report_path
            
        except Exception as e:
            error_msg = f"Comprehensive report generation failed: {str(e)}"
            verbose_print(f"{error_msg}", self.verbose)
            
            if self.verbose:
                print(f"{Colors.RED}Comprehensive report generation failed: {str(e)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Full error details:{Colors.RESET}")
                traceback.print_exc()
            else:
                print(f"{Colors.RED}Report generation failed. Use --verbose for details.{Colors.RESET}")
                
            raise RuntimeError(error_msg) from e

    def generate_framework_only_report(self, detection_result: DetectionResult, output_path: str) -> str:
        if not detection_result:
            raise ValueError("Detection result is required for report generation")
        if not output_path:
            raise ValueError("Output path is required for report generation")
            
        try:
            pdf_generator = self._get_pdf_generator()
            
            report_path = pdf_generator.generate_pdf_report(detection_result, output_path)
            
            exists = bool(report_path and os.path.exists(report_path))
            if not exists:
                raise RuntimeError("Framework report generation failed - no valid output file created")

            try:
                file_size = os.path.getsize(report_path) / 1024
            except Exception as e:
                verbose_print(f"Framework report generated but failed to stat file: {e}", self.verbose)
                verbose_print(f"Report location (best effort): {report_path}", self.verbose)
            
            return report_path
            
        except Exception as e:
            error_msg = f"Framework-only report generation failed: {str(e)}"
            verbose_print(f"{error_msg}", self.verbose)
            
            if self.verbose:
                print(f"{Colors.RED}Framework report generation failed: {str(e)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Full error details:{Colors.RESET}")
                traceback.print_exc()
            else:
                print(f"{Colors.RED}Report generation failed. Use --verbose for details.{Colors.RESET}")
                
            raise RuntimeError(error_msg) from e

    def _get_pdf_generator(self):
        if self.pdf_generator is None:
            verbose_print("Initializing PDF generator (lazy loading)", self.verbose)
            
            try:
                from .comprehensive_pdf_generator import ComprehensivePDFGenerator
                self.pdf_generator = ComprehensivePDFGenerator(verbose=self.verbose)
                verbose_print("Comprehensive PDF generator initialized successfully", self.verbose)
                
            except ImportError as e:
                verbose_print(f"Comprehensive PDF generator not available: {e}", self.verbose)
                verbose_print("Falling back to standard PDF generator", self.verbose)
                
                try:
                    from .pdf_generator import PDFReportGenerator
                    self.pdf_generator = PDFReportGenerator(verbose=self.verbose)
                    verbose_print("Standard PDF generator initialized successfully", self.verbose)
                    
                except ImportError as fallback_error:
                    verbose_print(f"Standard PDF generator also unavailable: {fallback_error}", self.verbose)
                    raise RuntimeError("No PDF generator modules available") from fallback_error
                    
            except Exception as e:
                verbose_print(f"Failed to initialize PDF generator: {e}", self.verbose)
                
                self._print_installation_help(e)
                raise RuntimeError(f"PDF generator initialization failed: {e}") from e
            else:
                verbose_print("♻Using existing PDF generator instance", self.verbose)
                verbose_print(f"Existing generator type: {type(self.pdf_generator).__name__}", self.verbose)
            
        return self.pdf_generator
    
    def _print_installation_help(self, error: Exception):
        """Print helpful installation instructions for PDF generation dependencies."""
        verbose_print(f"\n{Colors.RED}PDF Generator Initialization Failed{Colors.RESET}", self.verbose)
        verbose_print(f"{Colors.YELLOW}Error: {str(error)}{Colors.RESET}\n", self.verbose)
        
        verbose_print(f"{Colors.CYAN}WeasyPrint Installation Instructions:{Colors.RESET}", self.verbose)
        
        system = platform.system()
        if system == "Windows":
            verbose_print(f"{Colors.GREEN}Windows Setup:{Colors.RESET}", self.verbose)
            verbose_print("   PDF generation on Windows uses headless Microsoft Edge.", self.verbose)
            verbose_print("   Install Microsoft Edge or ensure msedge.exe is on PATH.", self.verbose)

        elif system == "Darwin":
            verbose_print(f"{Colors.GREEN}macOS Setup:{Colors.RESET}", self.verbose)
            verbose_print("   brew install weasyprint", self.verbose)
            
        elif system == "Linux":
            verbose_print(f"{Colors.GREEN}Linux Setup:{Colors.RESET}", self.verbose)
            verbose_print("   # Ubuntu/Debian:", self.verbose)
            verbose_print("   sudo apt-get install python3-cffi python3-brotli libpango-1.0-0", self.verbose)
            verbose_print("   # RHEL/CentOS:", self.verbose)
            verbose_print("   sudo yum install python3-cffi pango", self.verbose)
            
        verbose_print(f"\n{Colors.BLUE}More information:{Colors.RESET}", self.verbose)
        verbose_print(f"   https://doc.courtbouillon.org/weasyprint/stable/first_steps.html{Colors.RESET}", self.verbose)