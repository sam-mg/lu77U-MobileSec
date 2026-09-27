#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.display_utils

Purpose:
    Render findings to the terminal in the verbose stream, for operators who watch a run from the shell rather than the dashboard.

Responsibilities:
    Format a finding list as indented text. Presentation only -- no filtering, sorting, severity ranking or deduplication happens here.

Dependencies:
    .verbose for the gated print.

Security considerations:
    Every field printed originates in an untrusted APK and reaches the terminal unescaped. This is acceptable only because the destination is a terminal stream and not an HTML report; a finding string containing ANSI escapes could still garble the operator's terminal.
"""

from typing import List, Dict
from .verbose import verbose_print

def display_vulnerabilities(vulnerabilities: List[Dict], verbose: bool = False) -> bool:
    """
    Purpose:
        Print a human-readable summary of findings to the verbose stream.

    Parameters:
        vulnerabilities: Finding dicts. Every field is read with .get and a fallback, because findings arrive from an AI provider as well as from rule engines and no key is guaranteed.
        verbose: When False every line is suppressed, but the return value is still computed.

    Returns:
        True when the list was non-empty, False when it was empty. The return reports whether there was anything to show, not whether it was shown -- callers use it as a "did this scan find anything" signal, which is why it stays meaningful with verbose=False.

    Side effects:
        Writes to the verbose output stream.

    Complexity:
        O(n) in the number of findings.

    Implementation notes:
        line_number and code_snippet are printed only when present, because a finding derived from a manifest or a certificate has no line and an empty "Line:" row reads as a bug. The blank line before every entry but the first is emitted as a prefix rather than a trailing separator so the block does not end with a dangling empty line.
    """
    if not vulnerabilities:
        verbose_print("No vulnerabilities found!", verbose)
        return False
    
    for i, vuln in enumerate(vulnerabilities, 1):
        prefix = "" if i == 1 else "\n"
        verbose_print(f"{prefix}[{i}] {vuln.get('vulnerability_type', 'Unknown Vulnerability')}", verbose)
        verbose_print(f"    File: {vuln.get('file', 'Unknown')}", verbose)
        if vuln.get('line_number'):
            verbose_print(f"    Line: {vuln.get('line_number')}", verbose)
        verbose_print(f"    Severity: {vuln.get('severity', 'Unknown')}", verbose)
        verbose_print(f"    Description: {vuln.get('description', 'No description available')}", verbose)
        if vuln.get('code_snippet'):
            verbose_print(f"    Code: {vuln.get('code_snippet')}", verbose)
    
    return True
