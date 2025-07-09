#!/usr/bin/env python3
"""
Helper utilities package for lu77U-MobileSec
"""

from .time_utils import start_analysis_timer, end_analysis_timer, format_duration
from .validation import (
    is_likely_user_defined_string,
    validate_apk_path,
    clean_string_for_analysis,
    extract_code_blocks
)
from .string_utils import (
    fix_code_snippet_quotes,
    sanitize_filename,
    truncate_text,
    extract_urls_from_text,
    normalize_whitespace,
    extract_java_class_name,
    count_lines
)

__all__ = [
    # Time utilities
    "start_analysis_timer",
    "end_analysis_timer", 
    "format_duration",
    
    # Validation utilities
    "is_likely_user_defined_string",
    "validate_apk_path",
    "clean_string_for_analysis",
    "extract_code_blocks",
    
    # String utilities
    "fix_code_snippet_quotes",
    "sanitize_filename",
    "truncate_text",
    "extract_urls_from_text",
    "normalize_whitespace",
    "extract_java_class_name",
    "count_lines",
]
