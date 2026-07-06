"""Output Directory Manager for lu77U-MobileSec"""

from pathlib import Path
from datetime import datetime
from typing import Optional
from .verbose import verbose_print

class OutputManager:
    """Manages organized output directory structure for analysis results"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.output_dir = None
        self.timestamp = None
        self.apk_name = None
        # Log initialization
        verbose_print("OutputManager initialized", self.verbose)
        
    def create_output_directory(self, apk_path: str) -> Path:
        verbose_print(f"Creating output directory structure for: {apk_path}", self.verbose)

        apk_path_obj = Path(apk_path)
        self.apk_name = apk_path_obj.stem
        self.output_dir = apk_path_obj.parent

        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        verbose_print(f"Generated timestamp: {self.timestamp}", self.verbose)
        verbose_print(f"APK name: {self.apk_name}", self.verbose)
        verbose_print(f"Using scan output directory: {self.output_dir}", self.verbose)

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            verbose_print(f"Failed to create output directory {self.output_dir}: {e}", self.verbose)
            raise

        verbose_print(f"create_output_directory returning: {self.output_dir}", self.verbose)
        return self.output_dir
    
    def get_html_path(self) -> str:
        """Get the path for the HTML report file"""
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_{self.timestamp}.html")
        verbose_print(f"HTML path computed: {path}", self.verbose)
        return path
    
    def get_css_path(self) -> str:
        """Get the path for the CSS file"""
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_{self.timestamp}.css")
        verbose_print(f"CSS path computed: {path}", self.verbose)
        return path
    
    def get_json_path(self) -> str:
        """Get the path for the JSON analysis file"""
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_analysis-{self.timestamp}.json")
        verbose_print(f"JSON path computed: {path}", self.verbose)
        return path
    
    def get_pdf_filename(self, package_name: str) -> str:
        if not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        
        verbose_print(f"Generating PDF filename for package: {package_name}", self.verbose)
        clean_package = "".join(c for c in package_name if c.isalnum() or c in "._-")
        verbose_print(f"Clean package name: {clean_package}", self.verbose)
        
        date_part = self.timestamp.split('_')[0]
        time_part = self.timestamp.split('_')[1]
        filename = f"lu77U-MobileSec-{clean_package}-{date_part}-{time_part}.pdf"
        verbose_print(f"PDF filename generated: {filename}", self.verbose)
        return filename
    
    def get_pdf_path(self, package_name: str) -> str:
        """Get the full path for the PDF report"""
        if not self.output_dir:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / self.get_pdf_filename(package_name))
        verbose_print(f"PDF path computed: {path}", self.verbose)
        return path
    
    def get_jadx_output_dir(self) -> Path:
        """Get the path for JADX decompilation output"""
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_jadx_output_{self.timestamp}"
        verbose_print(f"JADX output dir computed: {path}", self.verbose)
        return path
    
    def get_ollama_log_path(self, request_timestamp: str) -> Path:
        """Get the path for Ollama request/response log"""
        if not self.output_dir:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_Ollama_Request_Response_{request_timestamp}.md"
        verbose_print(f"Ollama log path computed for request timestamp {request_timestamp}: {path}", self.verbose)
        return path

    def get_dynamic_dir(self) -> Path:
        """Get (creating if needed) the subdirectory for dynamic-analysis artifacts."""
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_dynamic_{self.timestamp}"
        path.mkdir(parents=True, exist_ok=True)
        verbose_print(f"Dynamic dir computed: {path}", self.verbose)
        return path

    def get_frida_log_path(self) -> Path:
        """Get the path for the Frida runtime trace log."""
        path = self.get_dynamic_dir() / f"{self.apk_name}_Frida_Log_{self.timestamp}.json"
        verbose_print(f"Frida log path computed: {path}", self.verbose)
        return path

    def get_traffic_log_path(self) -> Path:
        """Get the path for the captured HTTP traffic log."""
        path = self.get_dynamic_dir() / f"{self.apk_name}_Traffic_{self.timestamp}.json"
        verbose_print(f"Traffic log path computed: {path}", self.verbose)
        return path

    def get_action_log_path(self) -> Path:
        """Get the path for the AI UI-interaction action log."""
        path = self.get_dynamic_dir() / f"{self.apk_name}_Actions_{self.timestamp}.json"
        verbose_print(f"Action log path computed: {path}", self.verbose)
        return path
    
    def get_output_dir(self) -> Optional[Path]:
        """Get the current output directory"""
        verbose_print(f"get_output_dir returning: {self.output_dir}", self.verbose)
        return self.output_dir
    
    def get_timestamp(self) -> Optional[str]:
        """Get the current timestamp"""
        verbose_print(f"get_timestamp returning: {self.timestamp}", self.verbose)
        return self.timestamp
    
    def get_apk_name(self) -> Optional[str]:
        """Get the APK name"""
        verbose_print(f"get_apk_name returning: {self.apk_name}", self.verbose)
        return self.apk_name