"""CSS Styles for PDF Reports"""

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
    """Manages CSS styles for PDF report generation"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("PDFStyleManager initialized", self.verbose)
    
    @staticmethod
    def get_pdf_css(verbose: bool = False):
        """Get the main CSS styling for PDF reports"""
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
        """Get the CSS content as a string"""
        verbose_print("Building CSS content string", verbose)
        
        return """
            @page {
                margin: 1in;
                size: A4;
                @bottom-center {
                    content: "lu77U-MobileSec Analysis Report - Page " counter(page);
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
        """
