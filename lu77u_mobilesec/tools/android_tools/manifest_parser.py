#!/usr/bin/env python3
"""
Android Tools - Manifest Parser

Provides utilities for parsing and analyzing Android manifest files.
"""

import os
import re
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any


def extract_android_manifest(apk_path: str) -> str:
    """Extract AndroidManifest.xml from APK"""
    try:
        if not os.path.exists(apk_path):
            print(f"❌ APK file not found: {apk_path}")
            return ""
        
        manifest_content = ""
        
        # Try to extract manifest using zipfile
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                if 'AndroidManifest.xml' in zip_file.namelist():
                    manifest_data = zip_file.read('AndroidManifest.xml')
                    
                    # Try to decode as text (if it's already decoded)
                    try:
                        manifest_content = manifest_data.decode('utf-8')
                    except UnicodeDecodeError:
                        # Binary manifest - need to decode it
                        manifest_content = decode_binary_manifest(apk_path)
                else:
                    print("⚠️  AndroidManifest.xml not found in APK")
                    return ""
        except Exception as e:
            print(f"❌ Error extracting manifest: {e}")
            return ""
        
        return manifest_content
        
    except Exception as e:
        print(f"❌ Error in extract_android_manifest: {e}")
        return ""


def decode_binary_manifest(apk_path: str) -> str:
    """Decode binary AndroidManifest.xml using aapt tool"""
    try:
        # Try using aapt if available
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"⚠️  aapt failed: {result.stderr}")
        except FileNotFoundError:
            print("⚠️  aapt tool not found")
        except subprocess.TimeoutExpired:
            print("⚠️  aapt timed out")
        except Exception as e:
            print(f"⚠️  aapt error: {e}")
        
        # Try using aapt2 if available
        try:
            result = subprocess.run(
                ['aapt2', 'dump', 'xmltree', apk_path, '--file', 'AndroidManifest.xml'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"⚠️  aapt2 failed: {result.stderr}")
        except FileNotFoundError:
            print("⚠️  aapt2 tool not found")
        except subprocess.TimeoutExpired:
            print("⚠️  aapt2 timed out")
        except Exception as e:
            print(f"⚠️  aapt2 error: {e}")
        
        # Try using apktool if available
        try:
            import tempfile
            import shutil
            
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ['apktool', 'd', apk_path, '-o', temp_dir, '-f'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    manifest_path = os.path.join(temp_dir, 'AndroidManifest.xml')
                    if os.path.exists(manifest_path):
                        with open(manifest_path, 'r', encoding='utf-8') as f:
                            return f.read()
                else:
                    print(f"⚠️  apktool failed: {result.stderr}")
        except FileNotFoundError:
            print("⚠️  apktool not found")
        except subprocess.TimeoutExpired:
            print("⚠️  apktool timed out")
        except Exception as e:
            print(f"⚠️  apktool error: {e}")
        
        # Fallback: try basic binary parsing (very limited)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                if 'AndroidManifest.xml' in zip_file.namelist():
                    manifest_data = zip_file.read('AndroidManifest.xml')
                    
                    # Try to extract readable strings from binary manifest
                    readable_strings = []
                    current_string = ""
                    
                    for byte in manifest_data:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += chr(byte)
                        else:
                            if len(current_string) > 3:  # Only keep strings longer than 3 chars
                                readable_strings.append(current_string)
                            current_string = ""
                    
                    if len(current_string) > 3:
                        readable_strings.append(current_string)
                    
                    # Create a basic manifest representation
                    manifest_parts = [
                        "<!-- Binary manifest - limited parsing -->",
                        "<!-- Extracted strings: -->"
                    ]
                    
                    # Look for common manifest elements
                    manifest_strings = []
                    for s in readable_strings:
                        if any(keyword in s.lower() for keyword in [
                            'permission', 'activity', 'service', 'receiver', 
                            'provider', 'intent', 'action', 'category', 'data',
                            'android:', 'package', 'versioncode', 'versionname'
                        ]):
                            manifest_strings.append(s)
                    
                    for s in sorted(set(manifest_strings)):
                        manifest_parts.append(f"<!-- {s} -->")
                    
                    return "\n".join(manifest_parts)
        except Exception as e:
            print(f"⚠️  Binary parsing fallback failed: {e}")
        
        print("❌ Unable to decode binary AndroidManifest.xml")
        print("💡 Install aapt, aapt2, or apktool for better manifest parsing")
        return ""
        
    except Exception as e:
        print(f"❌ Error in decode_binary_manifest: {e}")
        return ""


def parse_manifest_permissions(manifest_content: str) -> List[str]:
    """Parse permissions from manifest content"""
    try:
        permissions = []
        
        # Extract permissions using regex (works for both XML and aapt output)
        permission_patterns = [
            r'<uses-permission\s+android:name="([^"]+)"',
            r'android:permission="([^"]+)"',
            r'E: uses-permission.*name="([^"]+)"',  # aapt output format
        ]
        
        for pattern in permission_patterns:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE)
            permissions.extend(matches)
        
        return sorted(set(permissions))
        
    except Exception as e:
        print(f"❌ Error parsing permissions: {e}")
        return []


def parse_manifest_activities(manifest_content: str) -> List[Dict[str, str]]:
    """Parse activities from manifest content"""
    try:
        activities = []
        
        # For XML format
        try:
            if manifest_content.strip().startswith('<?xml'):
                root = ET.fromstring(manifest_content)
                app_element = root.find('.//{http://schemas.android.com/apk/res/android}application')
                if app_element is not None:
                    for activity in app_element.findall('.//{http://schemas.android.com/apk/res/android}activity'):
                        name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                        exported = activity.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                        activities.append({
                            'name': name,
                            'exported': exported
                        })
        except ET.ParseError:
            pass  # Not valid XML, try regex parsing
        
        # Fallback regex parsing (for aapt output or malformed XML)
        activity_pattern = r'android:name="([^"]+)"'
        activity_matches = re.findall(activity_pattern, manifest_content)
        
        for match in activity_matches:
            if 'Activity' in match or 'activity' in match.lower():
                activities.append({
                    'name': match,
                    'exported': 'unknown'
                })
        
        return activities
        
    except Exception as e:
        print(f"❌ Error parsing activities: {e}")
        return []


def analyze_manifest_security(manifest_content: str) -> List[Dict[str, Any]]:
    """Analyze manifest for security issues"""
    try:
        security_issues = []
        
        permissions = parse_manifest_permissions(manifest_content)
        activities = parse_manifest_activities(manifest_content)
        
        # Check for dangerous permissions
        dangerous_permissions = [
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.WRITE_SETTINGS'
        ]
        
        for permission in permissions:
            if permission in dangerous_permissions:
                security_issues.append({
                    'type': 'dangerous_permission',
                    'severity': 'MEDIUM',
                    'title': f'Dangerous Permission: {permission}',
                    'description': f'App requests dangerous permission: {permission}',
                    'location': 'AndroidManifest.xml',
                    'recommendation': 'Ensure this permission is necessary and properly justified'
                })
        
        # Check for exported activities without proper protection
        for activity in activities:
            if activity.get('exported', '').lower() == 'true':
                security_issues.append({
                    'type': 'exported_activity',
                    'severity': 'MEDIUM',
                    'title': f'Exported Activity: {activity["name"]}',
                    'description': f'Activity {activity["name"]} is exported and may be accessible to other apps',
                    'location': 'AndroidManifest.xml',
                    'recommendation': 'Ensure exported activities have proper intent filters and permission checks'
                })
        
        # Check for debug flags
        if 'android:debuggable="true"' in manifest_content:
            security_issues.append({
                'type': 'debug_enabled',
                'severity': 'HIGH',
                'title': 'Debug Mode Enabled',
                'description': 'Application has debug mode enabled, which may expose sensitive information',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Disable debug mode in production builds'
            })
        
        # Check for backup allowance
        if 'android:allowBackup="true"' in manifest_content:
            security_issues.append({
                'type': 'backup_enabled',
                'severity': 'LOW',
                'title': 'Backup Allowed',
                'description': 'Application allows backup, which may expose sensitive data',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Consider disabling backup for sensitive applications'
            })
        
        # Check for network security config
        if 'android:networkSecurityConfig' not in manifest_content:
            security_issues.append({
                'type': 'no_network_security_config',
                'severity': 'MEDIUM',
                'title': 'No Network Security Configuration',
                'description': 'Application does not specify network security configuration',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Consider adding network security configuration to prevent cleartext traffic'
            })
        
        return security_issues
        
    except Exception as e:
        print(f"❌ Error analyzing manifest security: {e}")
        return []
