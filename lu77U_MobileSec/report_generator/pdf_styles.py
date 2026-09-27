#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.pdf_styles

Purpose:
    Supply the print stylesheet for PDF reports: page geometry, page numbering and the typographic rules that make a security report readable on paper.

Responsibilities:
    Build the CSS and wrap it in the PDF engine's stylesheet object.

Dependencies:
    WeasyPrint, which is required for this module's public entry point.

Implementation notes:
    The print stylesheet is separate from the HTML report's own styling because the two media differ in ways that cannot be reconciled in one sheet -- fixed page size, page-break control and running footers have no screen equivalent.
"""

from .._metadata import NAME as APP_NAME
from ..utils.verbose import verbose_print

try:
    from weasyprint import CSS
    WEASYPRINT_AVAILABLE = True
    WEASYPRINT_ERROR = None
except ImportError as e:
    WEASYPRINT_AVAILABLE = False
    CSS = None
    WEASYPRINT_ERROR = str(e)
except Exception as e:
    WEASYPRINT_AVAILABLE = False
    CSS = None
    WEASYPRINT_ERROR = str(e)

class PDFStyleManager:
    """
    Purpose:
        Provides the print stylesheet for PDF reports.

    Attributes:
        verbose: Whether style generation is traced.

    Thread-safety:
        Stateless; the methods are static.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the manager.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        verbose_print("PDFStyleManager initialized", self.verbose)
    
    @staticmethod
    def get_pdf_css(verbose: bool = False):
        """
        Purpose:
            Build the stylesheet object the PDF engine renders with.

        Parameters:
            verbose: Traces the construction.

        Returns:
            The stylesheet.

        Raises:
            ImportError: When WeasyPrint is unavailable, with the install command in the message.

        Implementation notes:
            Raising rather than returning None is right here: the caller has already committed to producing a PDF, and a stylesheet-less render would silently produce an unreadable document.
        """
        verbose_print("Generating PDF CSS styles", verbose)
        
        if not WEASYPRINT_AVAILABLE:
            verbose_print("WeasyPrint not available - cannot generate CSS", verbose)
            raise ImportError("WeasyPrint is not available. Please install it with: pip install weasyprint")
        
        css_content = PDFStyleManager._get_css_content(verbose)
        verbose_print(f"CSS content generated - length: {len(css_content)} characters", verbose)
        
        css_object = CSS(string=css_content)
        verbose_print("CSS object created successfully", verbose)
        
        return css_object
    
    @staticmethod
    def _get_css_content(verbose: bool = False) -> str:
        """
        Purpose:
            Return the print stylesheet text.

        Parameters:
            verbose: Traces the construction.

        Returns:
            The CSS.

        Implementation notes:
            Page geometry, margins and the footer page counter are set here because they exist only in paged media. The rest mirrors the HTML report's severity colours, so a finding looks the same on screen and on paper.
        """
        verbose_print("Building CSS content string", verbose)
        
        return """
            @page {
                margin: 1in;
                size: A4;
                @bottom-center {
                    content: "__APP_NAME__ Analysis Report - Page " counter(page);
                    font-size: 9pt;
                    color: #666;
                }
            }
            
            body {
                font-family: Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.4;
                color: #333;
            }
            
            .container {
                max-width: 100%;
            }
            
            .header {
                text-align: center;
                padding: 20px 0;
                border-bottom: 2px solid #2c3e50;
                margin-bottom: 30px;
            }
            
            .header h1 {
                color: #2c3e50;
                font-size: 24pt;
                margin: 0 0 10px 0;
                font-weight: bold;
            }
            
            .header .subtitle {
                color: #7f8c8d;
                font-size: 12pt;
                margin: 5px 0;
            }
            
            .header .timestamp {
                color: #95a5a6;
                font-size: 10pt;
                margin: 5px 0;
            }
            
            .section {
                margin-bottom: 25px;
                page-break-inside: avoid;
            }
            
            .section h2 {
                color: #2c3e50;
                font-size: 16pt;
                border-bottom: 1px solid #bdc3c7;
                padding-bottom: 5px;
                margin-top: 0;
                margin-bottom: 15px;
            }
            
            .section h3 {
                color: #34495e;
                font-size: 14pt;
                margin-top: 20px;
                margin-bottom: 10px;
            }
            
            .info-grid {
                display: table;
                width: 100%;
                margin-bottom: 15px;
            }
            
            .info-row {
                display: table-row;
            }
            
            .info-label {
                display: table-cell;
                font-weight: bold;
                padding: 5px 10px 5px 0;
                width: 30%;
                color: #2c3e50;
                vertical-align: top;
            }
            
            .info-value {
                display: table-cell;
                padding: 5px 0;
                color: #555;
                vertical-align: top;
                word-break: break-word;
            }
            
            .framework-item {
                background: #ecf0f1;
                padding: 10px;
                margin: 5px 0;
                border-left: 4px solid #3498db;
                page-break-inside: avoid;
            }
            
            .component-list {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
            }
            
            .component-list ul {
                margin: 0;
                padding-left: 20px;
            }
            
            .component-list li {
                margin: 3px 0;
                font-size: 10pt;
                word-break: break-all;
            }
            
            .status-success {
                color: #27ae60;
                font-weight: bold;
            }
            
            .status-warning {
                color: #f39c12;
                font-weight: bold;
            }
            
            .status-error {
                color: #e74c3c;
                font-weight: bold;
            }
            
            .summary-box {
                background: #3498db;
                color: white;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }
            
            .summary-box h3 {
                color: white;
                margin-top: 0;
                margin-bottom: 10px;
            }
            
            .summary-box .info-label {
                color: white;
                font-weight: bold;
            }
            
            .summary-box .info-value {
                color: white;
            }
            
            .footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #bdc3c7;
                text-align: center;
                font-size: 9pt;
                color: #7f8c8d;
            }
            
            .footer a {
                color: #3498db;
                text-decoration: none;
            }
            
            /* Print-specific styles */
            @media print {
                .section {
                    page-break-inside: avoid;
                }
                
                .framework-item {
                    page-break-inside: avoid;
                }
                
                .summary-box {
                    page-break-inside: avoid;
                }
            }
        """.replace("__APP_NAME__", APP_NAME)
