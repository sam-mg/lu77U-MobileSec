#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.comprehensive_pdf_generator

Purpose:
    Produce the full PDF report by building the HTML and rendering it through the PDF engine.

Responsibilities:
    Hold the HTML builder and the engine, and run the two stages in order.

Dependencies:
    The comprehensive HTML builder and the PDF generation engine.

Implementation notes:
    PDF output is generated from the same HTML the browser report uses rather than from a separate template, so the two cannot diverge. Only the stylesheet differs.
"""

from lu77U_MobileSec.detection.results import DetectionResult
from .pdf_generation_engine import PDFGenerationEngine
from .comprehensive_html_builder import ComprehensiveHTMLBuilder
from ..utils.verbose import verbose_print
from typing import Optional, Dict, Union
import os
import traceback

class ComprehensivePDFGenerator:
    """
    Purpose:
        Renders the full report to PDF.

    Attributes:
        verbose: Whether generation is traced.
        html_builder: Builds the report HTML.
        pdf_engine: Renders HTML to PDF.

    Thread-safety:
        Not intended for concurrent use.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the builder and the rendering engine.

        Parameters:
            verbose: Enables tracing.

        Side effects:
            Loads the native PDF stack through the engine.

        Implementation notes:
            Construction is guarded so that a missing native dependency surfaces here, where the caller can print installation guidance, rather than partway through rendering.
        """
        self.verbose = verbose
        
        try:
            self.html_builder = ComprehensiveHTMLBuilder(verbose=self.verbose)
            
            self.pdf_engine = PDFGenerationEngine(verbose=self.verbose)
            
        except Exception as e:
            verbose_print(f"Failed to initialize ComprehensivePDFGenerator: {e}", self.verbose)
            if self.verbose:
                traceback.print_exc()
            raise RuntimeError(f"PDF generator initialization failed: {e}") from e

    def generate_comprehensive_pdf(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None, output_manager=None) -> str:
        """
        Purpose:
            Build the report HTML and render it to PDF.

        Parameters:
            detection_result: Detection output.
            output_path: Where to write the PDF.
            vulnerability_results: Findings from the analysis.
            analyzer_results: Per-analyzer detail.
            output_manager: Supplies companion paths.

        Returns:
            The path written.

        Side effects:
            Writes a PDF.

        Security considerations:
            The HTML being rendered contains attacker-derived strings from the APK, escaped by the builder. The PDF renderer is given local content only; no remote resource is fetched during rendering.
        """
        if not detection_result:
            raise ValueError("Detection result is required for PDF generation")
        if not output_path:
            raise ValueError("Output path is required for PDF generation")
            
        try:
            html_content = self.html_builder.build_comprehensive_report(
                detection_result=detection_result,
                vulnerability_results=vulnerability_results,
                analyzer_results=analyzer_results
            )
            
            if not html_content:
                raise RuntimeError("HTML content generation failed - empty content returned")
                
            verbose_print(f"HTML content built successfully ({len(html_content):,} characters)", self.verbose)
            
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
                file_size = os.path.getsize(report_path) / 1024
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
        """
        Purpose:
            Generate a detection-only PDF report, matching the method name the simpler generator exposes.

        Parameters:
            detection_result: Detection output.
            output_path: Where to write the PDF.

        Returns:
            The path written.

        Raises:
            ValueError: When the detection result or the output path is missing.

        Side effects:
            Writes a PDF.

        Implementation notes:
            Present so this generator is interchangeable with the simpler one at call sites that predate the comprehensive report. It renders through the PDF engine directly rather than through the comprehensive HTML builder, so the result covers detection rather than the full finding report.
        """
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
