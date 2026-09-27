#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.xml_utils

Purpose:
    Read Android XML resources safely and cut them down to what a human actually wrote, so that AI prompts and reports are not swamped by framework-supplied strings.

Responsibilities:
    Parse resource XML, filter strings.xml to user-defined entries, extract single elements by XPath, and recognise framework layout filenames.

Dependencies:
    defusedxml when installed, the standard ElementTree otherwise; .validation_utils for the user-defined heuristic.

Security considerations:
    The XML here comes from an untrusted APK. defusedxml is preferred because stdlib ElementTree is vulnerable to entity-expansion attacks -- a crafted resource file can otherwise exhaust memory during parsing. The ImportError fallback means that protection is absent when defusedxml is not installed, which is a real exposure rather than a formality: defusedxml should be treated as a required dependency, not an optional hardening.

Implementation notes:
    An app's strings.xml typically contains hundreds of entries added by AndroidX and Material, and only a handful written by the developer. Filtering is not cosmetic -- it is what keeps the prompt within a useful size and stops the model spending its attention on framework boilerplate.
"""

from typing import Optional
from pathlib import Path

try:
    import defusedxml.ElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from .verbose import verbose_print
from .validation_utils import is_likely_user_defined_string

def filter_strings_xml_content(strings_xml_content: str, verbose: bool = False) -> Optional[str]:
    """
    Purpose:
        Reduce a strings.xml document to the entries that look developer-written.

    Parameters:
        strings_xml_content: Raw XML text from the APK.
        verbose: Traces each retained entry by name.

    Returns:
        A rebuilt XML document containing only the retained entries, None when nothing was retained, or -- on a parse failure -- the original input unchanged.

    Side effects:
        Writes to the verbose stream.

    Complexity:
        O(n) in the number of <string> elements.

    Implementation notes:
        The three return shapes are distinct on purpose. None means "parsed fine, nothing worth keeping", so the caller can skip the resource entirely. Returning the original on failure is a deliberate fail-open: a resource file this parser cannot read is more useful to the analysis unfiltered than dropped, and the alternative -- returning None -- would make a malformed file indistinguishable from an uninteresting one. Output is rebuilt by serialising each retained element rather than by pruning the tree in place, which keeps the original document untouched and the result free of the namespace declarations ElementTree would otherwise re-emit on every child.

    Security considerations:
        The fail-open path returns attacker-controlled XML to the caller verbatim; whatever consumes it must still escape it. The retained values themselves are APK-derived and untrusted.
    """
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
    """
    Purpose:
        Read a strings.xml from disk and filter it.

    Parameters:
        strings_xml_path: Path to the resource file, typically inside decompiled output.
        verbose: Traces the path and any failure.

    Returns:
        The filtered document, or None when the file is missing, unreadable, or contained nothing worth keeping.

    Side effects:
        Reads from the filesystem; writes to the verbose stream.

    Implementation notes:
        A missing file is an expected outcome, not an error -- plenty of APKs ship no strings.xml at the path being probed -- so it returns None quietly rather than raising. Decoding errors are swallowed for the same reason: an undecodable resource must not abort the surrounding scan.

    Security considerations:
        The caller is responsible for ensuring the path lies inside the intended output directory; no containment check is performed here.
    """
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
    """
    Purpose:
        Pull the text of a single element out of an XML document.

    Parameters:
        xml_content: Raw XML text.
        xpath: An ElementTree-supported path expression, which is a limited subset of XPath -- not the full language.
        verbose: Traces the lookup and the result.

    Returns:
        The element's text, or None when the document will not parse, the path matches nothing, or the matched element has no text.

    Side effects:
        Writes to the verbose stream.

    Implementation notes:
        An element that exists but is empty is reported the same as a missing element, because every caller treats both as "this value is not present".

    Security considerations:
        Parses untrusted XML; see the module note on defusedxml.
    """
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

_FRAMEWORK_LAYOUT_PREFIXES = (
    'mtrl_', 'abc_', 'design_', 'support_', 'notification_',
    'select_dialog_', 'browser_', 'material_', 'm3_', 'custom_dialog',
)


def is_framework_layout_file(filename: str, verbose: bool = False) -> bool:
    """
    Purpose:
        Recognise layout files shipped by AndroidX, Material and the support libraries, so they can be skipped before they reach an analyzer.

    Parameters:
        filename: Bare filename, not a path.
        verbose: Accepted for signature consistency with the other helpers in this module; deliberately unused, as a per-file trace line here would produce thousands of lines of noise.

    Returns:
        True when the name carries a known framework prefix.

    Complexity:
        O(1) against a fixed prefix tuple.

    Implementation notes:
        str.startswith accepts a tuple and short-circuits, so the whole set is one C-level call rather than a Python loop -- this runs once per layout file in an APK that may hold thousands. The match is by prefix rather than by exact name because these libraries version their resources; matching prefixes survives an AndroidX upgrade where an exact list would silently stop matching.

    Known limitations:
        A developer layout that happens to start with one of these prefixes is misclassified as framework and skipped. The prefixes are distinctive enough that this is rare, and the cost of a false negative here is one skipped layout rather than a missed finding in code.
    """
    return filename.startswith(_FRAMEWORK_LAYOUT_PREFIXES)
