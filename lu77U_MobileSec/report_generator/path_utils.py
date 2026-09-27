#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.path_utils

Purpose:
    Decide where a report is written and what it is called, from the detection result.

Responsibilities:
    Resolve an output path beside the analysed target, build a filename from the package name, and ensure the directory exists.

Dependencies:
    os only.

Security considerations:
    The filename incorporates the package name, which is declared inside an untrusted APK. It is sanitised before use, because an unsanitised package name containing separators would place the report outside the intended directory.
"""

import os
from datetime import datetime
from lu77U_MobileSec.detection.results import DetectionResult
from .._metadata import NAME as APP_NAME
from ..utils.verbose import verbose_print

class ReportPathManager:
    """
    Purpose:
        Resolves report output locations and filenames.

    Attributes:
        verbose: Whether path resolution is traced.

    Invariants:
        Every method returns a usable value rather than raising, so a path problem degrades where the report is written rather than preventing it.

    Thread-safety:
        Stateless apart from the verbose flag; the methods are static.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the manager.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        verbose_print("ReportPathManager initialized", self.verbose)
    
    @staticmethod
    def get_output_path(detection_result: DetectionResult, filename: str, verbose: bool = False) -> str:
        """
        Purpose:
            Resolve the directory a report should be written into, beside the analysed target.

        Parameters:
            detection_result: The detection result, consulted for the target path.
            filename: The report filename.
            verbose: Traces the resolution.

        Returns:
            The full path.

        Implementation notes:
            Reports go beside the analysed file so a scan stays self-contained and shareable as one directory. The target path is read defensively and every resolution step is guarded, because this runs at the end of a long analysis and failing to place a report would discard everything the scan produced.
        """
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
        """
        Purpose:
            Build a report filename from the app's package name.

        Parameters:
            detection_result: The detection result, consulted for the package name.
            verbose: Traces the construction.

        Returns:
            The filename.

        Implementation notes:
            Named after the package rather than the APK file, so the report stays identifiable once separated from the scan directory. A missing package name falls back to a placeholder rather than producing an empty name.

        Security considerations:
            The package name is attacker-declared and is sanitised before being used as a filename component.
        """
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

        filename = f"{APP_NAME}-{package_name}-{date_str}-{time_str}.pdf"
        verbose_print(f"Generated filename: {filename}", verbose)
        return filename
    
    @staticmethod
    def generate_output_filepath(output_path: str, filename: str, verbose: bool = False) -> str:
        """
        Purpose:
            Combine an output directory and a filename into a full path.

        Parameters:
            output_path: The directory.
            filename: The report filename.
            verbose: Traces the construction.

        Returns:
            The full path.

        Implementation notes:
            Resolution is guarded and falls back to the raw values, so an unresolvable path still yields something the caller can attempt to write.
        """
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
        """
        Purpose:
            Create the directory a report is about to be written into.

        Parameters:
            filepath: The full report path.
            verbose: Traces the outcome.

        Returns:
            True when the directory exists or was created.

        Side effects:
            Creates directories.

        Implementation notes:
            A path with no directory component is treated as success, since writing into the current directory needs nothing created.
        """
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
