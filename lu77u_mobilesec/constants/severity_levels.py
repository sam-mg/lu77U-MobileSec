#!/usr/bin/env python3
"""
Vulnerability severity level constants for lu77U-MobileSec
"""

# Java/Kotlin vulnerability severity levels
SEVERITY_HIGH = ['XSS', 'SQL Injection', 'Code Injection', 'Debug Enabled', 'Exported Component']
SEVERITY_MEDIUM = ['Hardcoded Secrets', 'Insecure Network', 'Weak Cryptography', 'WebView Security', 'Insecure Storage']
SEVERITY_LOW = ['Information Disclosure', 'Deprecated API', 'Weak Validation', 'Minor Configuration']

# React Native specific severity levels  
RN_SEVERITY_HIGH = ['WebView XSS', 'Code Injection', 'Debug Enabled', 'Authentication Bypass']
RN_SEVERITY_MEDIUM = ['Hardcoded Secrets', 'Network Security', 'Bridge Vulnerability', 'Insecure Storage']
