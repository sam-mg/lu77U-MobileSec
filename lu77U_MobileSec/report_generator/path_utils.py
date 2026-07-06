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
        verbose_print(f"get_output_path called with filename: {filename}", verbose)
        target_path = getattr(detection_result, 'target_path', None)
        verbose_print(f"Target path from detection_result: {target_path}", verbose)

        verbose_print(f"Type checks - filename type: {type(filename)}, target_path type: {type(target_path)}", verbose)

        try:
            abs_target = os.path.abspath(target_path) if target_path is not None else None
            verbose_print(f"Absolute target path: {abs_target}", verbose)
        except Exception as e:
            abs_target = target_path
            verbose_print(f"Could not resolve absolute path, using raw: {abs_target} - error: {e}", verbose)

        try:
            has_ext = False
            ext = ''
            if target_path:
                _, ext = os.path.splitext(target_path)
                has_ext = bool(ext)
            is_file = (os.path.isfile(target_path) or (has_ext and not os.path.isdir(target_path)))
            verbose_print(f"Determined is_file={is_file} (ext={ext})", verbose)
        except Exception as e:
            is_file = False
            verbose_print(f"Error while determining is_file: {e}", verbose)

        if is_file:
            target_dir = os.path.dirname(target_path) if target_path else ''
            verbose_print(f"Target is file - using parent directory: {target_dir}", verbose)
        else:
            target_dir = target_path or ''
            verbose_print(f"Target is directory: {target_dir}", verbose)

        try:
            output_path = os.path.join(target_dir, filename)
            verbose_print(f"Final output path: {output_path}", verbose)
            return output_path
        except Exception as e:
            verbose_print(f"Failed to join path components: {e}", verbose)
            verbose_print(f"Falling back to filename only: {filename}", verbose)
            return filename
    
    @staticmethod
    def generate_filename(detection_result: DetectionResult, verbose: bool = False) -> str:
        verbose_print("generate_filename called for report", verbose)

        package_name = "unknown"
        basic = getattr(detection_result, 'basic_info', None)
        raw_pkg = getattr(basic, 'package_name', None) if basic else None
        verbose_print(f"Raw package name from detection_result: {raw_pkg}", verbose)
        if raw_pkg:
            package_name = raw_pkg
            verbose_print(f"Using package name: {package_name}", verbose)
            sanitized = "".join(c for c in package_name if c.isalnum() or c in "._-")
            verbose_print(f"Sanitized package name: {sanitized}", verbose)
            if sanitized:
                package_name = sanitized
            else:
                verbose_print("Sanitized package name was empty - falling back to 'unknown'", verbose)
                package_name = "unknown"
        else:
            verbose_print("No package name available - using 'unknown'", verbose)

        now = datetime.now()
        date_str = now.strftime("%Y%m%d")
        time_str = now.strftime("%H%M%S")
        verbose_print(f"Generated timestamp parts: date={date_str}, time={time_str}", verbose)

        filename = f"lu77U-MobileSec-{package_name}-{date_str}-{time_str}.pdf"
        verbose_print(f"Generated filename: {filename}", verbose)
        return filename
    
    @staticmethod
    def generate_output_filepath(output_path: str, filename: str, verbose: bool = False) -> str:
        """Generate output filepath from output path and filename"""
        verbose_print(f"generate_output_filepath called with output_path={output_path}, filename={filename}", verbose)

        try:
            abs_output = os.path.abspath(output_path) if output_path is not None else None
            verbose_print(f"Absolute output path: {abs_output}", verbose)
        except Exception as e:
            abs_output = output_path
            verbose_print(f"Could not resolve absolute output path, using raw: {abs_output} - error: {e}", verbose)

        try:
            _, out_ext = os.path.splitext(output_path or "")
            is_file = (os.path.isfile(output_path) or (bool(out_ext) and not os.path.isdir(output_path)))
            verbose_print(f"Determined is_file={is_file} (out_ext={out_ext})", verbose)
        except Exception as e:
            is_file = False
            verbose_print(f"Error while determining is_file for output_path: {e}", verbose)

        if is_file:
            target_dir = os.path.dirname(output_path) if output_path else ''
            verbose_print(f"Output path is file - using parent directory: {target_dir}", verbose)
        else:
            target_dir = output_path or ''
            verbose_print(f"Output path is directory: {target_dir}", verbose)

        try:
            filepath = os.path.join(target_dir, filename)
            verbose_print(f"Generated filepath: {filepath}", verbose)
            return filepath
        except Exception as e:
            verbose_print(f"Failed to join output components: {e}", verbose)
            verbose_print(f"Fallback to filename only: {filename}", verbose)
            return filename

    @staticmethod
    def ensure_directory_exists(filepath: str, verbose: bool = False) -> bool:
        verbose_print(f"ensure_directory_exists called for filepath: {filepath}", verbose)

        try:
            directory = os.path.dirname(filepath)
            verbose_print(f"Computed directory to ensure: {directory}", verbose)

            if not directory:
                verbose_print("No directory component in filepath; nothing to ensure", verbose)
                return True

            if not os.path.exists(directory):
                verbose_print(f"Directory does not exist - creating: {directory}", verbose)
                try:
                    os.makedirs(directory, exist_ok=True)
                    verbose_print("Directory created successfully", verbose)
                except Exception as e:
                    verbose_print(f"Failed during os.makedirs: {e}", verbose)
                    return False
            else:
                verbose_print(f"Directory already exists: {directory}", verbose)

            try:
                exists_now = os.path.exists(directory)
                can_write = os.access(directory, os.W_OK)
                verbose_print(f"Directory existence after ensure: {exists_now}, writable: {can_write}", verbose)
                return exists_now and can_write
            except Exception as e:
                verbose_print(f"Error checking directory properties: {e}", verbose)
                return False
        except Exception as e:
            verbose_print(f"Failed to create directory: {e}", verbose)
            return False