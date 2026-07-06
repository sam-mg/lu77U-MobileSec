"""Report Generation Module for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
from .html_content_builder import HTMLContentBuilder
from .path_utils import ReportPathManager
from .report_builder import ReportBuilder
from .comprehensive_report_builder import ComprehensiveReportBuilder
from .comprehensive_html_builder import ComprehensiveHTMLBuilder

PDF_MODULES_AVAILABLE = None

def get_pdf_generator():
    """Lazy import and return PDFReportGenerator"""
    try:
        from .pdf_generator import PDFReportGenerator
        return PDFReportGenerator
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_pdf_style_manager():
    """Lazy import and return PDFStyleManager"""
    try:
        from .pdf_styles import PDFStyleManager
        return PDFStyleManager
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_pdf_generation_engine():
    """Lazy import and return PDFGenerationEngine"""
    try:
        from .pdf_generation_engine import PDFGenerationEngine
        return PDFGenerationEngine
    except ImportError as e:
        if "libgobject" in str(e) or "libpango" in str(e) or "DLL" in str(e):
            raise ImportError("WeasyPrint dependencies not available. Please install WeasyPrint dependencies.")
        raise

def get_comprehensive_report_builder():
    """Lazy import and return ComprehensiveReportBuilder"""
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