#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.pdf_generation_engine

Purpose:
    Turn report HTML into a PDF, using WeasyPrint where its native dependencies are available and headless Microsoft Edge on Windows where they typically are not.

Responsibilities:
    Check dependencies, locate a renderer, and convert HTML to PDF.

Dependencies:
    WeasyPrint on POSIX, Microsoft Edge on Windows.

Implementation notes:
    The two-renderer split is a deployment decision rather than a preference. WeasyPrint needs GTK libraries that Windows users have to install by hand and frequently cannot, whereas Edge is present on every supported Windows install and renders to PDF headlessly. Both consume the same HTML, so the output differs only in typographic detail.

Security considerations:
    The HTML being rendered contains attacker-derived strings from the APK. Rendering is performed on local content written to a temporary file; no remote resource is fetched.
"""

import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from .html_content_builder import HTMLContentBuilder
from .pdf_styles import PDFStyleManager, WEASYPRINT_AVAILABLE, WEASYPRINT_ERROR
from .path_utils import ReportPathManager
from ..utils.verbose import verbose_print

_EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

def _find_edge_executable() -> Optional[str]:
    """
    Purpose:
        Locate Microsoft Edge for headless PDF rendering on Windows.

    Returns:
        The executable path, or None when Edge cannot be found.

    Implementation notes:
        Known install locations are checked before falling back to a PATH lookup, because Edge is not normally on PATH despite being installed.
    """
    for candidate in _EDGE_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return shutil.which("msedge")

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
    """
    Purpose:
        Renders report HTML to PDF.

    Attributes:
        verbose: Whether generation is traced.
        html_builder: Builds the detection-only report when no HTML is supplied.
        path_manager: Resolves output paths.

    Thread-safety:
        Not intended for concurrent use; the Windows path writes to fixed temporary files.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the engine and its helpers.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose

        self.html_builder = HTMLContentBuilder(verbose=verbose)

        self.path_manager = ReportPathManager(verbose=verbose)

        verbose_print("PDFGenerationEngine initialization complete", self.verbose)
    
    def generate_pdf(self, detection_result: DetectionResult) -> Optional[str]:
        """
        Purpose:
            Build the detection-only report and render it to PDF.

        Parameters:
            detection_result: Detection output.

        Returns:
            The path written, or None when rendering was not possible.

        Side effects:
            Writes a PDF.

        Implementation notes:
            Dependencies are checked before any work is done, so a machine without a renderer fails immediately with a clear message rather than after building the document.
        """
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
        """
        Purpose:
            Determine whether a PDF renderer is available on this machine.

        Returns:
            True when rendering is possible.

        Implementation notes:
            The check is platform-specific because the requirement is: Edge on Windows, WeasyPrint and its native libraries elsewhere. Both failure paths trace what to install, since the underlying errors name a missing shared library or executable rather than the fix.
        """
        if platform.system() == "Windows":
            if _find_edge_executable() is None:
                verbose_print("Microsoft Edge not found. Cannot generate PDF.", self.verbose)
                verbose_print("Install Microsoft Edge or ensure msedge.exe is on PATH.", self.verbose)
                return False
            return True

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
                if system == "Darwin":
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
        """
        Purpose:
            Build and write a detection-only PDF report to a given path.

        Parameters:
            detection_result: Detection output.
            output_path: Where to write the PDF.

        Returns:
            The path written.

        Raises:
            Exception: When no renderer is available.

        Side effects:
            Writes a PDF.
        """
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
        """
        Purpose:
            Render caller-supplied HTML to PDF, which is how the full findings report is produced.

        Parameters:
            html_content: The report HTML.
            detection_result: Detection output, used for naming.
            output_path: Where to write the PDF.
            output_manager: Supplies the report path.

        Returns:
            The path written.

        Raises:
            Exception: When no renderer is available.

        Side effects:
            Writes a PDF.

        Implementation notes:
            This is the entry point that keeps the PDF and HTML reports identical: the comprehensive builder produces one document and both outputs render it.
        """
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
        """
        Purpose:
            Render HTML to a PDF file.

        Parameters:
            html_content: The report HTML.
            filepath: Where to write the PDF.
            apply_default_css: Whether to apply the print stylesheet.

        Returns:
            True when the PDF was written.
        """
        return convert_html_to_pdf(html_content, filepath, apply_default_css, verbose=self.verbose)


def convert_html_to_pdf(html_content: str, filepath: str, apply_default_css: bool = True, verbose: bool = False) -> bool:
    """
    Purpose:
        Render HTML to PDF with whichever renderer this platform provides.

    Parameters:
        html_content: The report HTML.
        filepath: Where to write the PDF.
        apply_default_css: Whether to apply the print stylesheet.
        verbose: Traces the outcome.

    Returns:
        True when the PDF was written.

    Side effects:
        Writes a PDF, and on Windows spawns a browser process.

    Implementation notes:
        Exposed as a module-level function as well as a method so that callers holding only HTML -- the web layer among them -- can render without constructing an engine.
    """
    try:
        if platform.system() == "Windows":
            return _convert_to_pdf_windows(html_content, filepath, apply_default_css, verbose)

        stylesheets = [PDFStyleManager.get_pdf_css(verbose=verbose)] if apply_default_css else []

        html_doc = HTML(string=html_content)

        html_doc.write_pdf(filepath, stylesheets=stylesheets)

        return True
    except Exception as exc:
        verbose_print(f"Error during PDF conversion: {str(exc)}", verbose)
        if verbose:
            import traceback
            verbose_print("PDF conversion traceback:", verbose)
            traceback.print_exc()
        return False


def _convert_to_pdf_windows(html_content: str, filepath: str, apply_default_css: bool, verbose: bool) -> bool:
    """
    Purpose:
        Render HTML to PDF using headless Microsoft Edge.

    Parameters:
        html_content: The report HTML.
        filepath: Where to write the PDF.
        apply_default_css: Whether to inline the print stylesheet.
        verbose: Traces the outcome.

    Returns:
        True when the PDF was written.

    Side effects:
        Writes the HTML to a temporary file and spawns Edge.

    Implementation notes:
        Edge renders from a file rather than from standard input, so the document is written out first. The print stylesheet is inlined rather than linked, because a linked local stylesheet is subject to the browser's file-access rules and would silently not apply.

    Security considerations:
        Edge is launched headless with the document as a local file. The document contains APK-derived content, and it is rendered by a full browser engine -- which is why nothing in it references a remote resource.
    """
    edge = _find_edge_executable()
    if edge is None:
        verbose_print("Microsoft Edge not found for PDF conversion", verbose)
        return False

    if apply_default_css:
        css = PDFStyleManager._get_css_content(verbose=verbose)
        style_tag = f"<style>{css}</style>"
        if "</head>" in html_content:
            html_content = html_content.replace("</head>", f"{style_tag}</head>", 1)
        else:
            html_content = f"{style_tag}{html_content}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        html_path = Path(tmp_dir) / "report.html"
        html_path.write_text(html_content, encoding="utf-8")

        try:
            result = subprocess.run(
                [
                    edge,
                    "--headless",
                    "--disable-gpu",
                    f"--print-to-pdf={filepath}",
                    "--no-pdf-header-footer",
                    html_path.as_uri(),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            verbose_print("Edge PDF conversion timed out", verbose)
            return False

        verbose_print(f"Edge exit code: {result.returncode}", verbose)
        if result.returncode != 0:
            verbose_print(f"Edge stderr: {result.stderr}", verbose)
            return False

        return Path(filepath).exists()
