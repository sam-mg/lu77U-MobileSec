"""Core PDF Generation Engine"""

import platform
from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from .html_content_builder import HTMLContentBuilder
from .pdf_styles import PDFStyleManager, WEASYPRINT_AVAILABLE, WEASYPRINT_ERROR
from .path_utils import ReportPathManager
from ..utils.verbose import verbose_print

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

        self.html_builder = HTMLContentBuilder(verbose=verbose)

        self.path_manager = ReportPathManager(verbose=verbose)

        self.style_manager = PDFStyleManager(verbose=verbose)

        verbose_print("PDFGenerationEngine initialization complete", self.verbose)
    
    def generate_pdf(self, detection_result: DetectionResult) -> Optional[str]:
        verbose_print("Starting PDF generation process", self.verbose)
        
        try:
            deps_ok = self._check_dependencies()
            verbose_print(f"Dependency check result: {deps_ok}", self.verbose)
            if not deps_ok:
                verbose_print("Dependency check failed - aborting PDF generation", self.verbose)
                return None

            verbose_print("Generating filename and filepath", self.verbose)
            filename = self.path_manager.generate_filename(detection_result, verbose=self.verbose)
            verbose_print(f"Generated filename: {filename}", self.verbose)
            filepath = self.path_manager.get_output_path(detection_result, filename, verbose=self.verbose)

            dir_ok = self.path_manager.ensure_directory_exists(filepath, verbose=self.verbose)
            if not dir_ok:
                verbose_print(f"Failed to create output directory for: {filepath}", self.verbose)
                return None

            html_content = self.html_builder.build_html_content(detection_result)
            if html_content is None:
                verbose_print("HTML content builder returned None", self.verbose)
                return None

            converted = self._convert_to_pdf(html_content, filepath)
            if converted:
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

        if not WEASYPRINT_AVAILABLE or not WEASYPRINT_HTML_AVAILABLE:

            if self.verbose:
                verbose_print("WeasyPrint is not available. Cannot generate PDF.", self.verbose)
                verbose_print("Error details:", self.verbose)
                if WEASYPRINT_ERROR:
                    verbose_print(f"- CSS import error: {WEASYPRINT_ERROR}", self.verbose)
                if WEASYPRINT_HTML_ERROR:
                    verbose_print(f"- HTML import error: {WEASYPRINT_HTML_ERROR}", self.verbose)

                verbose_print("Installation instructions:", self.verbose)
                system = platform.system()
                verbose_print(f"Detected platform: {system}", self.verbose)
                if system == "Windows":
                    verbose_print("For Windows:", self.verbose)
                    verbose_print("1. Install MSYS2: https://www.msys2.org/", self.verbose)
                    verbose_print("2. Run: pacman -S mingw-w64-x86_64-pango", self.verbose)
                    verbose_print("3. Set: set WEASYPRINT_DLL_DIRECTORIES=C:\\msys64\\mingw64\\bin", self.verbose)
                    verbose_print("4. Restart your terminal and try again", self.verbose)
                    verbose_print("5. Alternative: Use WSL (Windows Subsystem for Linux)", self.verbose)
                elif system == "Darwin":
                    verbose_print("For macOS:", self.verbose)
                    verbose_print("1. Install Homebrew: https://brew.sh/", self.verbose)
                    verbose_print("2. Run: brew install weasyprint", self.verbose)
                elif system == "Linux":
                    verbose_print("For Linux:", self.verbose)
                    verbose_print("- Ubuntu/Debian: sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0", self.verbose)
                    verbose_print("- Fedora: sudo dnf install pango", self.verbose)
                    verbose_print("- Arch: sudo pacman -S pango", self.verbose)

                verbose_print("More info: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html", self.verbose)
            return False
        
        return True
    
    def generate_pdf_report(self, detection_result: DetectionResult, output_path: str) -> str:
        
        try:
            if not self._check_dependencies():
                verbose_print("Dependency check failed", self.verbose)
                raise Exception("WeasyPrint dependencies not available")
                
            verbose_print("Generating filename and filepath", self.verbose)
            filename = self.path_manager.generate_filename(detection_result, verbose=self.verbose)
            verbose_print(f"Generated filename: {filename}", self.verbose)
            filepath = self.path_manager.generate_output_filepath(output_path, filename, verbose=self.verbose)
            
            if not self.path_manager.ensure_directory_exists(filepath, verbose=self.verbose):
                verbose_print(f"Failed to create output directory for: {filepath}", self.verbose)
                raise Exception(f"Failed to create output directory for: {filepath}")
                
            html_content = self.html_builder.build_html_content(detection_result)
            if html_content is None:
                verbose_print("HTML builder returned None", self.verbose)
                raise Exception("HTML content generation failed")
            
            if self._convert_to_pdf(html_content, filepath):
                return filepath
            else:
                verbose_print("PDF conversion failed", self.verbose)
                raise Exception("PDF conversion failed")
                
        except Exception as e:
            verbose_print(f"Error generating PDF report: {str(e)}", self.verbose)
            raise

    def generate_pdf_from_html(self, html_content: str, detection_result: DetectionResult, output_path: str, output_manager=None) -> str:
        """Generate PDF from custom HTML content"""
        verbose_print("Starting PDF generation from custom HTML", self.verbose)
        
        try:
            if not self._check_dependencies():
                verbose_print("Dependency check failed", self.verbose)
                raise Exception("WeasyPrint dependencies not available")
            
            if output_manager:
                package_name = detection_result.basic_info.package_name if detection_result.basic_info else "unknown"
                verbose_print(f"Using OutputManager to get PDF path for package: {package_name}", self.verbose)
                filepath = output_manager.get_pdf_path(package_name)
                verbose_print(f"OutputManager returned PDF path: {filepath}", self.verbose)
            else:
                verbose_print("Generating filename and filepath", self.verbose)
                filename = self.path_manager.generate_filename(detection_result, verbose=self.verbose)
                filepath = self.path_manager.generate_output_filepath(output_path, filename, verbose=self.verbose)
            
            if not self.path_manager.ensure_directory_exists(filepath, verbose=self.verbose):
                verbose_print(f"Failed to create output directory for: {filepath}", self.verbose)
                raise Exception(f"Failed to create output directory for: {filepath}")

            if self._convert_to_pdf(html_content, filepath, apply_default_css=False):
                return filepath
            else:
                verbose_print("PDF conversion failed", self.verbose)
                raise Exception("PDF conversion failed")

        except Exception as e:
            verbose_print(f"Error generating PDF from HTML: {str(e)}", self.verbose)
            raise

    def _convert_to_pdf(self, html_content: str, filepath: str, apply_default_css: bool = True) -> bool:
        """Render ``html_content`` to a PDF at ``filepath``.

        ``apply_default_css`` layers the legacy stylesheet on top of the
        document. The comprehensive report ships its own complete stylesheet
        (fonts, colors, layout) and must be rendered with this off, or the
        legacy Arial/blue rules would fight its design.
        """
        try:
            stylesheets = [self.style_manager.get_pdf_css(verbose=self.verbose)] if apply_default_css else []

            html_doc = HTML(string=html_content)

            html_doc.write_pdf(filepath, stylesheets=stylesheets)

            return True
        except Exception as e:
            verbose_print(f"Error during PDF conversion: {str(e)}", self.verbose)
            if self.verbose:
                import traceback
                verbose_print("PDF conversion traceback:", self.verbose)
                traceback.print_exc()
            return False