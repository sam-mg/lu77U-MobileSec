#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.comprehensive_report_builder

Purpose:
    Entry point for the full PDF report, including the guidance shown when the native PDF stack is missing.

Responsibilities:
    Validate inputs, lazily construct the PDF generator, and print platform-specific installation help on failure.

Dependencies:
    The comprehensive PDF generator, imported on demand.

Implementation notes:
    WeasyPrint's native dependencies are the single most common setup failure in this tool, and the error it raises names a missing shared library rather than what to install. The installation help exists to close that gap.
"""

from lu77U_MobileSec.detection.results import DetectionResult
from ..ui.colors import Colors
from ..utils.verbose import verbose_print
from typing import Optional, Dict
import platform
import os
import traceback

class ComprehensiveReportBuilder:
    """
    Purpose:
        Builds the full PDF report.

    Attributes:
        verbose: Whether report building is traced.
        pdf_generator: The lazily constructed generator, or None.

    Invariants:
        The generator is constructed at most once per instance.

    Thread-safety:
        The lazy construction is unsynchronised.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the builder without loading the PDF stack.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        self.pdf_generator = None

    def generate_comprehensive_report(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None, output_manager=None) -> str:
        """
        Purpose:
            Generate the full PDF report for a completed scan.

        Parameters:
            detection_result: Detection output.
            output_path: Where to write the PDF.
            vulnerability_results: Findings from the analysis.
            analyzer_results: Per-analyzer detail.
            output_manager: Supplies companion paths.

        Returns:
            The path written.

        Raises:
            ValueError: When the detection result or the output path is missing.

        Side effects:
            Writes a PDF.

        Implementation notes:
            The two required arguments are validated up front rather than allowed to fail inside the renderer, where the error would name a template variable instead of the missing input.
        """
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
                verbose_print(f"Report size: {os.path.getsize(report_path) / 1024:.1f} KB", self.verbose)
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
        """
        Purpose:
            Generate a report covering detection alone, for an app whose framework this tool cannot analyse deeply.

        Parameters:
            detection_result: Detection output.
            output_path: Where to write the PDF.

        Returns:
            The path written.

        Raises:
            ValueError: When either argument is missing.

        Side effects:
            Writes a PDF.

        Implementation notes:
            Exists so an unsupported framework still produces a report saying what the app is and why it was not analysed further, rather than nothing at all.
        """
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
                verbose_print(f"Report size: {os.path.getsize(report_path) / 1024:.1f} KB", self.verbose)
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
        """
        Purpose:
            Construct the PDF generator on first use, printing installation help if it fails.

        Returns:
            The generator.

        Raises:
            RuntimeError: When the comprehensive generator cannot be imported or constructed, chained to the original error.

        Side effects:
            Imports the native PDF stack, and prints guidance on failure.

        Implementation notes:
            There is deliberately no fallback to the standard PDFReportGenerator. It has no generate_comprehensive_pdf and its generate_pdf_report takes only the detection result, so a fallback instance crashed on first use with an error naming a method signature instead of the missing dependency. An import failure therefore takes the same path as any other construction failure: the installation help is printed and a RuntimeError is raised.
        """
        if self.pdf_generator is None:
            verbose_print("Initializing PDF generator (lazy loading)", self.verbose)

            try:
                from .comprehensive_pdf_generator import ComprehensivePDFGenerator
                self.pdf_generator = ComprehensivePDFGenerator(verbose=self.verbose)
                verbose_print("Comprehensive PDF generator initialized successfully", self.verbose)

            except Exception as e:
                verbose_print(f"Failed to initialize PDF generator: {e}", self.verbose)

                self._print_installation_help(e)
                raise RuntimeError(f"PDF generator initialization failed: {e}") from e
        else:
            verbose_print("Using existing PDF generator instance", self.verbose)
            verbose_print(f"Existing generator type: {type(self.pdf_generator).__name__}", self.verbose)

        return self.pdf_generator
    
    def _print_installation_help(self, error: Exception):
        """
        Purpose:
            Print platform-specific instructions for installing WeasyPrint's native dependencies.

        Parameters:
            error: The import failure.

        Side effects:
            Writes guidance to the verbose stream.

        Implementation notes:
            Branching on platform matters because the fix differs completely -- a package manager command on Linux, Homebrew on macOS, a GTK runtime on Windows -- and generic advice leaves the user no further forward.
        """
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
