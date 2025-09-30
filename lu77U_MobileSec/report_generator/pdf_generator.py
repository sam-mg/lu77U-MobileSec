"""PDF Report Generator for lu77U-MobileSec"""

from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from .pdf_generation_engine import PDFGenerationEngine
from ..utils.verbose import verbose_print

class PDFReportGenerator:
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("PDFReportGenerator initializing", self.verbose)
        
        self.engine = PDFGenerationEngine(verbose=verbose)
        verbose_print("PDFGenerationEngine initialized", self.verbose)
        
        verbose_print("PDFReportGenerator initialization complete", self.verbose)
    
    def generate_pdf_report(self, detection_result: DetectionResult) -> Optional[str]:
        verbose_print("Delegating PDF report generation to engine", self.verbose)
        result = self.engine.generate_pdf(detection_result)
        
        if result:
            verbose_print(f"PDF report generation successful: {result}", self.verbose)
        else:
            verbose_print("PDF report generation failed", self.verbose)
            
        return result