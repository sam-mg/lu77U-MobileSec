"""File Path Utilities for PDF Report Generation"""

import os
from datetime import datetime
from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print


class ReportPathManager:
    """Manages file paths and naming for PDF reports"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("ReportPathManager initialized", self.verbose)
    
    @staticmethod
    def get_output_path(detection_result: DetectionResult, filename: str, verbose: bool = False) -> str:
        verbose_print(f"Generating output path for filename: {filename}", verbose)
        target_path = detection_result.target_path
        verbose_print(f"Target path: {target_path}", verbose)
        
        # Determine if target is a file or directory
        is_file = (os.path.isfile(target_path) or 
                  (os.path.splitext(target_path)[1] and not os.path.isdir(target_path)))
        
        if is_file:
            target_dir = os.path.dirname(target_path)
            verbose_print(f"Target is file - using parent directory: {target_dir}", verbose)
        else:
            target_dir = target_path
            verbose_print(f"Target is directory: {target_dir}", verbose)
        
        output_path = os.path.join(target_dir, filename)
        verbose_print(f"Final output path: {output_path}", verbose)
        return output_path
    
    @staticmethod
    def generate_filename(detection_result: DetectionResult, verbose: bool = False) -> str:
        verbose_print("Generating filename for report", verbose)
        
        package_name = "unknown"
        if detection_result.basic_info and detection_result.basic_info.package_name:
            package_name = detection_result.basic_info.package_name
            verbose_print(f"Using package name: {package_name}", verbose)
            # Sanitize package name for filename
            package_name = "".join(c for c in package_name if c.isalnum() or c in "._-")
            verbose_print(f"Sanitized package name: {package_name}", verbose)
        else:
            verbose_print("No package name available - using 'unknown'", verbose)
        
        now = datetime.now()
        date_str = now.strftime("%Y%m%d")
        time_str = now.strftime("%H%M%S")
        verbose_print(f"Generated timestamp: {date_str}-{time_str}", verbose)
        
        filename = f"lu77U-MobileSec-{package_name}-{date_str}-{time_str}.pdf"
        verbose_print(f"Generated filename: {filename}", verbose)
        return filename
    
    @staticmethod
    def ensure_directory_exists(filepath: str, verbose: bool = False) -> bool:
        verbose_print(f"Ensuring directory exists for: {filepath}", verbose)
        
        try:
            directory = os.path.dirname(filepath)
            verbose_print(f"Target directory: {directory}", verbose)
            
            if not os.path.exists(directory):
                verbose_print(f"Directory does not exist - creating: {directory}", verbose)
                os.makedirs(directory, exist_ok=True)
                verbose_print("Directory created successfully", verbose)
            else:
                verbose_print("Directory already exists", verbose)
            
            return True
        except Exception as e:
            verbose_print(f"Failed to create directory: {e}", verbose)
            return False
