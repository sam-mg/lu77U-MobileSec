"""Core PDF Generation Engine"""

import platform
from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from .html_content_builder import HTMLContentBuilder
from .pdf_styles import PDFStyleManager, WEASYPRINT_AVAILABLE, WEASYPRINT_ERROR
from .path_utils import ReportPathManager
from ..utils import verbose_print

try:
    from weasyprint import HTML
    WEASYPRINT_HTML_AVAILABLE = True
    WEASYPRINT_HTML_ERROR = None
except ImportError as e:
    WEASYPRINT_HTML_AVAILABLE = False
    HTML = None
    WEASYPRINT_HTML_ERROR = str(e)
except Exception as e:
    WEASYPRINT_HTML_AVAILABLE = False
    HTML = None
    WEASYPRINT_HTML_ERROR = str(e)

class PDFGenerationEngine:
    """Core engine for PDF generation with separated concerns"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("PDFGenerationEngine initializing", self.verbose)
        
        self.html_builder = HTMLContentBuilder(verbose=verbose)
        verbose_print("HTMLContentBuilder initialized", self.verbose)
        
        self.path_manager = ReportPathManager(verbose=verbose)
        verbose_print("ReportPathManager initialized", self.verbose)
        
        self.style_manager = PDFStyleManager(verbose=verbose)
        verbose_print("PDFStyleManager initialized", self.verbose)
        
        verbose_print("PDFGenerationEngine initialization complete", self.verbose)
    
    def generate_pdf(self, detection_result: DetectionResult) -> Optional[str]:
        verbose_print("Starting PDF generation process", self.verbose)
        
        try:
            # Check dependencies first
            if not self._check_dependencies():
                verbose_print("Dependency check failed", self.verbose)
                return None
                
            # Generate filename and filepath
            verbose_print("Generating filename and filepath", self.verbose)
            filename = self.path_manager.generate_filename(detection_result, verbose=self.verbose)
            filepath = self.path_manager.get_output_path(detection_result, filename, verbose=self.verbose)
            verbose_print(f"Target filepath: {filepath}", self.verbose)
            
            # Ensure directory exists
            if not self.path_manager.ensure_directory_exists(filepath, verbose=self.verbose):
                verbose_print(f"Failed to create output directory for: {filepath}", self.verbose)
                return None
                
            # Build HTML content
            verbose_print("Building HTML content", self.verbose)
            html_content = self.html_builder.build_html_content(detection_result)
            verbose_print(f"HTML content built - length: {len(html_content)} characters", self.verbose)
            
            # Convert to PDF
            verbose_print("Converting HTML to PDF", self.verbose)
            if self._convert_to_pdf(html_content, filepath):
                verbose_print(f"PDF report saved to: {filepath}", self.verbose)
                return filepath
            else:
                verbose_print("PDF conversion failed", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error generating PDF report: {str(e)}", self.verbose)
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def _check_dependencies(self) -> bool:
        """Check if required dependencies are available"""
        verbose_print("Checking WeasyPrint dependencies", self.verbose)
        
        if not WEASYPRINT_AVAILABLE or not WEASYPRINT_HTML_AVAILABLE:
            verbose_print("WeasyPrint dependencies not available", self.verbose)
            
            if self.verbose:
                verbose_print("WeasyPrint is not available. Cannot generate PDF.", self.verbose)
                verbose_print("Error details:", self.verbose)
                if WEASYPRINT_ERROR:
                    verbose_print(f"- CSS import error: {WEASYPRINT_ERROR}", self.verbose)
                if WEASYPRINT_HTML_ERROR:
                    verbose_print(f"- HTML import error: {WEASYPRINT_HTML_ERROR}", self.verbose)
                
                verbose_print("Installation instructions:", self.verbose)
                if platform.system() == "Windows":
                    verbose_print("For Windows:", self.verbose)
                    verbose_print("1. Install MSYS2: https://www.msys2.org/", self.verbose)
                    verbose_print("2. Run: pacman -S mingw-w64-x86_64-pango", self.verbose)
                    verbose_print("3. Set: set WEASYPRINT_DLL_DIRECTORIES=C:\\msys64\\mingw64\\bin", self.verbose)
                    verbose_print("4. Restart your terminal and try again", self.verbose)
                    verbose_print("5. Alternative: Use WSL (Windows Subsystem for Linux)", self.verbose)
                elif platform.system() == "Darwin":
                    verbose_print("For macOS:", self.verbose)
                    verbose_print("1. Install Homebrew: https://brew.sh/", self.verbose)
                    verbose_print("2. Run: brew install weasyprint", self.verbose)
                elif platform.system() == "Linux":
                    verbose_print("For Linux:", self.verbose)
                    verbose_print("- Ubuntu/Debian: sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0", self.verbose)
                    verbose_print("- Fedora: sudo dnf install pango", self.verbose)
                    verbose_print("- Arch: sudo pacman -S pango", self.verbose)
                
                verbose_print("More info: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html", self.verbose)
            return False
        
        verbose_print("WeasyPrint dependencies available", self.verbose)
        return True
    
    def _convert_to_pdf(self, html_content: str, filepath: str) -> bool:
        verbose_print(f"Converting HTML to PDF: {filepath}", self.verbose)
        
        try:
            verbose_print("Getting PDF CSS styles", self.verbose)
            pdf_css = self.style_manager.get_pdf_css(verbose=self.verbose)
            
            verbose_print("Creating HTML document from string", self.verbose)
            html_doc = HTML(string=html_content)
            
            verbose_print("Writing PDF to file", self.verbose)
            html_doc.write_pdf(filepath, stylesheets=[pdf_css])
            
            verbose_print("PDF conversion completed successfully", self.verbose)
            return True
        except Exception as e:
            verbose_print(f"Error during PDF conversion: {str(e)}", self.verbose)
            return False
