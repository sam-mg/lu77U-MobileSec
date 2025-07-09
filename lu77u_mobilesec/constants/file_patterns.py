#!/usr/bin/env python3
"""
File pattern constants for lu77U-MobileSec
"""

# Default Android framework string prefixes to filter out
DEFAULT_STRING_PREFIXES = [
    'abc_', 'androidx_', 'appbar_', 'bottom_sheet_', 'bottomsheet_',
    'character_counter_', 'clear_text_', 'error_', 'exposed_dropdown_',
    'fab_', 'hide_bottom_', 'icon_content_', 'item_view_', 'm3_',
    'material_', 'mtrl_', 'password_toggle_', 'path_password_',
    'search_menu_', 'searchbar_', 'searchview_', 'side_sheet_', 'status_bar_'
]

# Default Android framework exact string matches to filter out
DEFAULT_STRING_EXACT_MATCHES = {'search_menu_title', 'submit'}

# File size limits
MAX_JS_BEAUTIFY_SIZE = 1000000  # 1MB
MAX_COMPLEX_FORMATTING_SIZE = 500000  # 500KB
MAX_JAVA_FILES_ANALYSIS = 50
