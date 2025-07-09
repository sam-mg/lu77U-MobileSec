#!/usr/bin/env python3
"""
Android Tools Package

Provides utilities for Android-specific operations.
"""

# Import functions on demand to avoid import issues
__all__ = [
    'extract_android_manifest',
    'decode_binary_manifest', 
    'parse_manifest_permissions',
    'parse_manifest_activities',
    'analyze_manifest_security',
    'check_avd_exists',
    'check_sdk_installed', 
    'get_avd_info',
    'install_avd',
    'start_emulator',
    'setup_env'
]
