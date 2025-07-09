#!/usr/bin/env python3
"""
Vulnerability detection constants for lu77U-MobileSec
"""

# Common vulnerability keywords for text extraction
VULNERABILITY_KEYWORDS = [
    'webview', 'injectjavascript', 'postmessage', 'asyncstorage',
    'bridge', 'native', 'eval', 'function constructor', 'url scheme',
    'deep link', 'hardcoded', 'api key', 'token', 'password',
    'ssl', 'http', 'certificate', 'validation', 'security',
    'vulnerable', 'exploit', 'weakness', 'sql injection', 'xss', 'cross-site scripting'
]
