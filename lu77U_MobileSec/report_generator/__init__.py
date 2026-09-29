#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator

Purpose:
    Facade for report building, split deliberately into two tiers: the HTML builders are re-exported eagerly because they are pure Python, while every PDF entry point is reached through an accessor function.

Responsibilities:
    Re-export the HTML and path builders directly, and expose get_pdf_generator, get_pdf_style_manager, get_pdf_generation_engine and get_comprehensive_report_builder as deferred accessors.

Dependencies:
    .html_content_builder, .path_utils, .report_builder, .comprehensive_report_builder, .comprehensive_html_builder eagerly; the PDF modules and WeasyPrint only on accessor call.

Security considerations:
    Reports embed attacker-controlled strings recovered from the APK. The escaping that makes that safe lives in the HTML builders; this facade performs no sanitisation of its own.
"""

from ..utils.verbose import verbose_print
from .html_content_builder import HTMLContentBuilder
from .path_utils import ReportPathManager
from .report_builder import ReportBuilder
from .comprehensive_report_builder import ComprehensiveReportBuilder
from .comprehensive_html_builder import ComprehensiveHTMLBuilder

def get_pdf_generator():
    """
    Purpose:
        Import PDFReportGenerator only when the caller actually needs it, and turn a missing native dependency into a message that names the real problem.

    Returns:
        The PDFReportGenerator class itself, not an instance.

    Raises:
        ImportError: Re-raised with an actionable message when the failure is a missing WeasyPrint native library; re-raised unchanged otherwise, so a genuine coding error is never disguised as a setup problem.

    Side effects:
        Loads the PDF submodule and, transitively, WeasyPrint's native libraries on first call.

    Implementation notes:
        The deferred import is the point of this accessor. WeasyPrint depends on libgobject/libpango, which are absent on many machines; importing it at package level would make the whole report_generator package unimportable and break HTML reporting, which needs no native code at all. The failure is classified by substring because the loader's message differs per platform: POSIX reports the missing .so by name, Windows reports a DLL load failure.
    """
    try:
        from .pdf_generator import PDFReportGenerator
        return PDFReportGenerator
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_pdf_style_manager():
    """
    Purpose:
        Import PDFStyleManager only when the caller actually needs it, and turn a missing native dependency into a message that names the real problem.

    Returns:
        The PDFStyleManager class itself, not an instance.

    Raises:
        ImportError: Re-raised with an actionable message when the failure is a missing WeasyPrint native library; re-raised unchanged otherwise, so a genuine coding error is never disguised as a setup problem.

    Side effects:
        Loads the PDF submodule and, transitively, WeasyPrint's native libraries on first call.

    Implementation notes:
        The deferred import is the point of this accessor. WeasyPrint depends on libgobject/libpango, which are absent on many machines; importing it at package level would make the whole report_generator package unimportable and break HTML reporting, which needs no native code at all. The failure is classified by substring because the loader's message differs per platform: POSIX reports the missing .so by name, Windows reports a DLL load failure.
    """
    try:
        from .pdf_styles import PDFStyleManager
        return PDFStyleManager
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_pdf_generation_engine():
    """
    Purpose:
        Import PDFGenerationEngine only when the caller actually needs it, and turn a missing native dependency into a message that names the real problem.

    Returns:
        The PDFGenerationEngine class itself, not an instance.

    Raises:
        ImportError: Re-raised with an actionable message when the failure is a missing WeasyPrint native library; re-raised unchanged otherwise, so a genuine coding error is never disguised as a setup problem.

    Side effects:
        Loads the PDF submodule and, transitively, WeasyPrint's native libraries on first call.

    Implementation notes:
        The deferred import is the point of this accessor. WeasyPrint depends on libgobject/libpango, which are absent on many machines; importing it at package level would make the whole report_generator package unimportable and break HTML reporting, which needs no native code at all. The failure is classified by substring because the loader's message differs per platform: POSIX reports the missing .so by name, Windows reports a DLL load failure.
    """
    try:
        from .pdf_generation_engine import PDFGenerationEngine
        return PDFGenerationEngine
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_comprehensive_report_builder():
    """
    Purpose:
        Return ComprehensiveReportBuilder through the same guarded path as the PDF accessors, so callers that want a full report have one consistent failure mode.

    Returns:
        The ComprehensiveReportBuilder class itself, not an instance.

    Raises:
        ImportError: Re-raised with a WeasyPrint-specific message when the failure is a missing native library; re-raised unchanged otherwise.

    Side effects:
        Imports .comprehensive_report_builder on first call.

    Implementation notes:
        ComprehensiveReportBuilder is also re-exported eagerly at module level, so this accessor is redundant for the common case; it exists so that a caller written against the accessor pattern keeps working, and so that the guarded message is produced if the eager import is ever removed.
    """
    try:
        from .comprehensive_report_builder import ComprehensiveReportBuilder
        return ComprehensiveReportBuilder
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

__all__ = [
    'ReportBuilder',
    'HTMLContentBuilder',
    'ReportPathManager',
    'ComprehensiveReportBuilder',
    'ComprehensiveHTMLBuilder',
    'get_pdf_generator',
    'get_pdf_style_manager', 
    'get_pdf_generation_engine',
    'get_comprehensive_report_builder'
]
