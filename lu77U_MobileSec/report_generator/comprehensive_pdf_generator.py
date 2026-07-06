"""
Comprehensive PDF Generator for Full Analysis Reports"""

from lu77U_MobileSec.detection.results import DetectionResult
from .pdf_generation_engine import PDFGenerationEngine
from .comprehensive_html_builder import ComprehensiveHTMLBuilder
from ..utils.verbose import verbose_print
from typing import Optional, Dict, Union
import os
import traceback

class ComprehensivePDFGenerator:
    """
    Advanced PDF report generator for comprehensive mobile security analysis.
    
    This class orchestrates the creation of detailed PDF reports that include:
    - Framework detection results
    - Vulnerability analysis findings
    - Security recommendations
    - Application information
    - Executive summary with metrics
    
    Attributes:
        verbose (bool): Enable detailed logging output
        html_builder (ComprehensiveHTMLBuilder): HTML content generator
        pdf_engine (PDFGenerationEngine): PDF creation engine
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the comprehensive PDF generator.
        
        Args:
            verbose (bool): Enable verbose logging for debugging
        """
        self.verbose = verbose
        
        try:
            # Initialize HTML content builder
            self.html_builder = ComprehensiveHTMLBuilder(verbose=self.verbose)
            
            # Initialize PDF generation engine
            self.pdf_engine = PDFGenerationEngine(verbose=self.verbose)
            
        except Exception as e:
            verbose_print(f"Failed to initialize ComprehensivePDFGenerator: {e}", self.verbose)
            if self.verbose:
                traceback.print_exc()
            raise RuntimeError(f"PDF generator initialization failed: {e}") from e

    def generate_comprehensive_pdf(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None, output_manager=None) -> str:
        if not detection_result:
            raise ValueError("Detection result is required for PDF generation")
        if not output_path:
            raise ValueError("Output path is required for PDF generation")
            
        try:
            # Build comprehensive HTML content
            html_content = self.html_builder.build_comprehensive_report(
                detection_result=detection_result,
                vulnerability_results=vulnerability_results,
                analyzer_results=analyzer_results
            )
            
            if not html_content:
                raise RuntimeError("HTML content generation failed - empty content returned")
                
            verbose_print(f"HTML content built successfully ({len(html_content):,} characters)", self.verbose)
            
            # Generate PDF using the engine
            verbose_print("Converting HTML to PDF", self.verbose)
            report_path = self.pdf_engine.generate_pdf_from_html(
                html_content=html_content,
                detection_result=detection_result,
                output_path=output_path,
                output_manager=output_manager
            )
            
            verbose_print(f"generate_pdf_from_html returned: {report_path}", self.verbose)
            exists = bool(report_path and os.path.exists(report_path))
            verbose_print(f"PDF exists on disk: {exists}", self.verbose)
            if not exists:
                raise RuntimeError("PDF generation failed - no valid output file created")

            try:
                file_size = os.path.getsize(report_path) / 1024  # KB
                verbose_print(f"Comprehensive PDF report generated successfully!", self.verbose)
                verbose_print(f"Report location: {report_path}", self.verbose)
                verbose_print(f"File size: {file_size:.1f} KB", self.verbose)
            except Exception as e:
                verbose_print(f"PDF generated but failed to stat file: {e}", self.verbose)
                verbose_print(f"Report path (best effort): {report_path}", self.verbose)
            
            return report_path
            
        except Exception as e:
            error_msg = f"Comprehensive PDF generation failed: {str(e)}"
            verbose_print(f"{error_msg}", self.verbose)
            
            if self.verbose:
                verbose_print("Full error traceback:", self.verbose)
                traceback.print_exc()
                
            raise RuntimeError(error_msg) from e

    def generate_pdf_report(self, detection_result: DetectionResult, output_path: str) -> str:
        if not detection_result:
            raise ValueError("Detection result is required for PDF generation")
        if not output_path:
            raise ValueError("Output path is required for PDF generation")
            
        verbose_print("Generating standard PDF report (compatibility mode)", self.verbose)
        verbose_print(f"Output path: {output_path}", self.verbose)
        
        try:
            report_path = self.pdf_engine.generate_pdf_report(detection_result, output_path)
            verbose_print(f"Standard PDF report returned path: {report_path}", self.verbose)
            try:
                exists = bool(report_path and os.path.exists(report_path))
                verbose_print(f"Standard PDF exists: {exists}", self.verbose)
                if exists:
                    verbose_print(f"Standard PDF size: {os.path.getsize(report_path)} bytes", self.verbose)
            except Exception:
                verbose_print("Could not stat standard PDF file", self.verbose)
            return report_path
            
        except Exception as e:
            error_msg = f"Standard PDF generation failed: {str(e)}"
            verbose_print(f"{error_msg}", self.verbose)
            
            if self.verbose:
                traceback.print_exc()
                
            raise RuntimeError(error_msg) from e