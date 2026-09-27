#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.pdf_generator

Purpose:
    Thin public face over the PDF generation engine, so callers depend on a stable name rather than on the engine's internals.

Responsibilities:
    Construct the engine and delegate to it.

Dependencies:
    The PDF generation engine, which pulls in the native PDF stack.
"""

from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from .pdf_generation_engine import PDFGenerationEngine
from ..utils.verbose import verbose_print

class PDFReportGenerator:
    """
    Purpose:
        Generates PDF reports.

    Attributes:
        verbose: Whether generation is traced.
        engine: The underlying generation engine.

    Thread-safety:
        As safe as the engine it wraps; not intended for concurrent use.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the generator and its engine.

        Parameters:
            verbose: Enables tracing.

        Side effects:
            Loads the native PDF stack through the engine.
        """
        self.verbose = verbose
        verbose_print("PDFReportGenerator initializing", self.verbose)
        
        self.engine = PDFGenerationEngine(verbose=verbose)
        verbose_print("PDFGenerationEngine initialized", self.verbose)
    
    def generate_pdf_report(self, detection_result: DetectionResult) -> Optional[str]:
        """
        Purpose:
            Generate a PDF report.

        Parameters:
            detection_result: The detection result to report on.

        Returns:
            The report path, or None when generation failed.

        Side effects:
            Writes a PDF.
        """
        verbose_print("Delegating PDF report generation to engine", self.verbose)
        result = self.engine.generate_pdf(detection_result)
        
        if result:
            verbose_print(f"PDF report generation successful: {result}", self.verbose)
        else:
            verbose_print("PDF report generation failed", self.verbose)
            
        return result
