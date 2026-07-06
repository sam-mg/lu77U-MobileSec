"""Display utilities for vulnerability reporting in lu77U-MobileSec"""

from typing import List, Dict
from .verbose import verbose_print

def display_vulnerabilities(vulnerabilities: List[Dict], verbose: bool = False) -> bool:
    """Display vulnerabilities in a formatted way"""
    if not vulnerabilities:
        verbose_print("No vulnerabilities found!", verbose)
        return False
    
    for i, vuln in enumerate(vulnerabilities, 1):
        # Only add newline before vulnerabilities after the first one
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