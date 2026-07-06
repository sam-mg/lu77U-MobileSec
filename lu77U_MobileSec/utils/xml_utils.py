"""XML manipulation and filtering utilities for lu77U-MobileSec"""

from typing import Optional
from pathlib import Path

try:
    import defusedxml.ElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET  # type: ignore[no-redef]

from .verbose import verbose_print
from .validation_utils import is_likely_user_defined_string

def filter_strings_xml_content(strings_xml_content: str, verbose: bool = False) -> Optional[str]:
    """Filter strings.xml content to remove Android framework strings"""
    try:
        root = ET.fromstring(strings_xml_content)

        filtered_strings = []
        user_defined_count = 0

        for i, string_elem in enumerate(root.findall('.//string'), start=1):
            name = string_elem.get('name', '')

            if is_likely_user_defined_string(name, verbose):
                verbose_print(f"  -> Keeping user-defined string: {name}", verbose)
                filtered_strings.append(ET.tostring(string_elem, encoding='unicode'))
                user_defined_count += 1

        if user_defined_count > 0:
            result = f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
            result += '\n'.join(filtered_strings)
            result += '\n</resources>'
            verbose_print(f"Filtered strings.xml: {user_defined_count} user-defined strings retained", verbose)
            return result
        else:
            verbose_print("No user-defined strings found in strings.xml", verbose)
            return None

    except Exception as e:
        verbose_print(f"Error filtering strings.xml: {e}", verbose)
        verbose_print("Returning original strings.xml content due to error", verbose)
        return strings_xml_content

def filter_strings_xml_file(strings_xml_path: str, verbose: bool = False) -> Optional[str]:
    """Filter strings.xml file to remove default Android framework strings"""
    try:
        path = Path(strings_xml_path)
        verbose_print(f"filter_strings_xml_file called for path: {strings_xml_path}", verbose)
        if not path.exists():
            verbose_print(f"strings.xml not found at: {strings_xml_path}", verbose)
            return None

        content = path.read_text(encoding='utf-8')
        return filter_strings_xml_content(content, verbose)
    except Exception as e:
        verbose_print(f"Could not filter strings.xml: {e}", verbose)
        return None

def extract_xml_element_text(xml_content: str, xpath: str, verbose: bool = False) -> Optional[str]:
    """Extract text from XML element using XPath"""
    try:
        verbose_print(f"extract_xml_element_text called for xpath: {xpath}", verbose)
        root = ET.fromstring(xml_content)
        element = root.find(xpath)

        if element is not None and element.text:
            verbose_print(f"Found element at {xpath}: {element.text}", verbose)
            return element.text
        else:
            verbose_print(f"Element not found at {xpath}", verbose)
            return None
    except Exception as e:
        verbose_print(f"Error extracting XML element: {e}", verbose)
        return None

def is_framework_layout_file(filename: str, verbose: bool = False) -> bool:
    """Check if a layout file is from Android framework (not app-specific)"""

    framework_prefixes = [
        'mtrl_', 'abc_', 'design_', 'support_', 'notification_',
        'select_dialog_', 'browser_', 'material_', 'm3_', 'custom_dialog',
    ]
    verbose_print(f"is_framework_layout_file called for: {filename}", verbose)
    for prefix in framework_prefixes:
        if filename.startswith(prefix):
            verbose_print(f"Layout {filename} is framework layout (prefix: {prefix})", verbose)
            return True

    verbose_print(f"Layout {filename} is app-specific", verbose)
    return False