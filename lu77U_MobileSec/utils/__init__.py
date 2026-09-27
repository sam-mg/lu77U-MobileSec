#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils

Purpose:
    Flat facade over the small, dependency-free helpers used across the codebase, so that call sites read `from ..utils import verbose_print` instead of reaching into six separate modules.

Responsibilities:
    Re-export terminal helpers, duration formatting, platform probes, the Android XML filters and the vulnerability display helper.

Dependencies:
    .verbose, .screen, .time_utils, .system, .xml_utils, .display_utils -- all standard-library only, which is what makes eager re-export cheap here and inappropriate in the heavier packages.

Security considerations:
    filter_strings_xml_* exist to keep framework-supplied resource strings out of AI prompts and reports; they are exported here so that no caller has an excuse to read strings.xml raw.
"""

from .verbose import verbose_print
from .screen import clear_screen, safe_input
from .time_utils import format_duration
from .system import get_python_version, check_python_compatibility, get_platform_info, get_system_info
from .xml_utils import filter_strings_xml_content, filter_strings_xml_file, is_framework_layout_file
from .display_utils import display_vulnerabilities

__all__ = [
    'verbose_print', 
    'clear_screen', 
    'safe_input', 
    'format_duration',
    'get_python_version',
    'check_python_compatibility',
    'get_platform_info',
    'get_system_info',
    'filter_strings_xml_content',
    'filter_strings_xml_file',
    'is_framework_layout_file',
    'display_vulnerabilities'
]
