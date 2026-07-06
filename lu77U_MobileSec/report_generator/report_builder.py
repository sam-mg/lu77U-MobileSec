"""Report Builder for lu77U-MobileSec"""

from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print
from typing import Optional
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
        verbose_print("_get_pdf_generator called", self.verbose)
        verbose_print(f"Current pdf_generator state: {self.pdf_generator}", self.verbose)
        
        if self.pdf_generator is None:
            verbose_print("PDF generator is None - creating new instance", self.verbose)
            try:
                verbose_print("Attempting to import PDFReportGenerator", self.verbose)
                from .pdf_generator import PDFReportGenerator
                verbose_print("PDFReportGenerator imported successfully", self.verbose)
                
                verbose_print(f"Creating PDFReportGenerator with verbose={self.verbose}", self.verbose)
                self.pdf_generator = PDFReportGenerator(verbose=self.verbose)
                verbose_print("PDF generator instance created successfully", self.verbose)
                verbose_print(f"PDF generator type: {type(self.pdf_generator)}", self.verbose)
            except ImportError as ie:
                verbose_print(f"ImportError when loading PDF generator: {ie}", self.verbose)
                verbose_print("PDF generator module may not be available", self.verbose)
            except Exception as e:
                verbose_print(f"Exception during PDF generator initialization: {e}", self.verbose)
                verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
                
                verbose_print("Failed to initialize PDF generator", self.verbose)
                verbose_print(f"   Error: {str(e)}", self.verbose)
                verbose_print("\n   WeasyPrint installation may be required:", self.verbose)
                
                system = platform.system()
                verbose_print(f"   Detected OS: {system}", self.verbose)
                
                if platform.system() == "Windows":
                    verbose_print("   For Windows:", self.verbose)
                    verbose_print("   1. Install MSYS2: https://www.msys2.org/", self.verbose)
                    verbose_print("   2. Run: pacman -S mingw-w64-x86_64-pango", self.verbose)
                    verbose_print("   3. Set: set WEASYPRINT_DLL_DIRECTORIES=C:\\msys64\\mingw64\\bin", self.verbose)
                    verbose_print("   4. Restart your terminal and try again", self.verbose)
                elif platform.system() == "Darwin":
                    verbose_print("   For macOS: brew install weasyprint", self.verbose)
                elif platform.system() == "Linux":
                    verbose_print("   For Linux: Install pango library for your distribution", self.verbose)
                else:
                    verbose_print(f"   For {system}: Check WeasyPrint documentation", self.verbose)
                    
                verbose_print("\n   More info: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html", self.verbose)
        else:
            verbose_print("PDF generator already initialized - reusing existing instance", self.verbose)
            verbose_print(f"Existing generator type: {type(self.pdf_generator)}", self.verbose)
            
        verbose_print(f"Returning pdf_generator: {self.pdf_generator}", self.verbose)
        return self.pdf_generator
    
    def generate_pdf_report(self, detection_result: DetectionResult) -> Optional[str]:
        verbose_print("generate_pdf_report called", self.verbose)
        verbose_print(f"detection_result type: {type(detection_result)}", self.verbose)
        verbose_print(f"detection_result.target_path: {getattr(detection_result, 'target_path', 'N/A')}", self.verbose)
        
        try:
            verbose_print("Attempting to get PDF generator", self.verbose)
            pdf_generator = self._get_pdf_generator()
            verbose_print(f"PDF generator obtained: {pdf_generator}", self.verbose)
            
            if pdf_generator is None:
                verbose_print("PDF generator is None - cannot generate report", self.verbose)
                return None
            
            verbose_print("Calling pdf_generator.generate_pdf_report()", self.verbose)
            pdf_path = pdf_generator.generate_pdf_report(detection_result)
            verbose_print(f"PDF generation returned path: {pdf_path}", self.verbose)
            
            if pdf_path:
                verbose_print(f"PDF report generated successfully: {pdf_path}", self.verbose)
                
                if os.path.exists(pdf_path):
                    file_size = os.path.getsize(pdf_path)
                    verbose_print(f"PDF file exists, size: {file_size} bytes", self.verbose)
                else:
                    verbose_print(f"WARNING: PDF path returned but file does not exist: {pdf_path}", self.verbose)
                    
                return pdf_path
            else:
                verbose_print("PDF report generation failed - no path returned", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Exception in generate_pdf_report: {str(e)}", self.verbose)
            verbose_print(f"Exception type: {type(e).__name__}", self.verbose)
            if self.verbose:
                import traceback
                verbose_print("Full traceback:", self.verbose)
                traceback.print_exc()
            return None