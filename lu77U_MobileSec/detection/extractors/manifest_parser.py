"""AndroidManifest.xml Parser for lu77U-MobileSec"""

import os
import re
import subprocess
import zipfile
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]
from typing import Dict, Any, Optional, List
from ...utils.verbose import verbose_print
from ...config.constants import DANGEROUS_PERMISSIONS, PERMISSION_PATTERNS

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    AnalyzeAPK = None
    APK = None

class ManifestParser:
    """Comprehensive parser for AndroidManifest.xml files from both APKs and project directories"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("ManifestParser initialized", self.verbose)
        verbose_print(f"Androguard available: {ANDROGUARD_AVAILABLE}", self.verbose)
    
    def extract_manifest_info(self, input_path: str) -> Dict[str, Any]:
        """Extract manifest information from APK file or project directory"""
        verbose_print(f"Starting manifest extraction for: {input_path}", self.verbose)
        
        if input_path.lower().endswith('.apk'):
            verbose_print("Detected APK file input", self.verbose)
            return self._extract_from_apk(input_path)
        else:
            verbose_print("Detected project directory input", self.verbose)
            return self._extract_from_project(input_path)
    
    def _extract_from_project(self, project_path: str) -> Dict[str, Any]:
        """Extract manifest info from project directory"""
        verbose_print(f"Starting project-based manifest extraction for: {project_path}", self.verbose)
        manifest_info = {}
        manifest_path = self._find_manifest_file(project_path)
        
        if not manifest_path:
            verbose_print("AndroidManifest.xml not found in project", self.verbose)
            return manifest_info
        
        verbose_print(f"Manifest file located at: {manifest_path}", self.verbose)
        
        try:
            verbose_print(f"Parsing AndroidManifest.xml from: {manifest_path}", self.verbose)
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            verbose_print("XML parsing successful", self.verbose)
            
            verbose_print("Extracting basic manifest attributes", self.verbose)
            manifest_info['package_name'] = root.get('package')
            verbose_print(f"Package name: {manifest_info.get('package_name', 'Not found')}", self.verbose)
            
            manifest_info['version_name'] = root.get('{http://schemas.android.com/apk/res/android}versionName')
            verbose_print(f"Version name: {manifest_info.get('version_name', 'Not found')}", self.verbose)
            version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode')
            if version_code:
                try:
                    manifest_info['version_code'] = int(version_code)
                    verbose_print(f"Version code: {manifest_info['version_code']}", self.verbose)
                except ValueError:
                    manifest_info['version_code'] = version_code
                    verbose_print(f"Version code (non-numeric): {version_code}", self.verbose)
            
            verbose_print("Extracting SDK information", self.verbose)
            uses_sdk = root.find('./uses-sdk')
            if uses_sdk is not None:
                verbose_print("Found uses-sdk element", self.verbose)
                min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
                target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
                
                if min_sdk:
                    try:
                        manifest_info['min_sdk'] = int(min_sdk)
                        verbose_print(f"Min SDK: {manifest_info['min_sdk']}", self.verbose)
                    except ValueError:
                        manifest_info['min_sdk'] = min_sdk
                        verbose_print(f"Min SDK (non-numeric): {min_sdk}", self.verbose)
                
                if target_sdk:
                    try:
                        manifest_info['target_sdk'] = int(target_sdk)
                        verbose_print(f"Target SDK: {manifest_info['target_sdk']}", self.verbose)
                    except ValueError:
                        manifest_info['target_sdk'] = target_sdk
                        verbose_print(f"Target SDK (non-numeric): {target_sdk}", self.verbose)
            else:
                verbose_print("No uses-sdk element found", self.verbose)
            
            verbose_print("Extracting application components", self.verbose)
            application = root.find('./application')
            if application is not None:
                verbose_print("Found application element", self.verbose)
                app_label = application.get('{http://schemas.android.com/apk/res/android}label')
                if app_label:
                    verbose_print(f"App label found: {app_label}", self.verbose)
                    if app_label.startswith('@string/'):
                        verbose_print("App label is a string resource, attempting to resolve", self.verbose)
                        app_name = self._resolve_string_resource(project_path, app_label)
                        manifest_info['app_name'] = app_name or app_label
                        if app_name:
                            verbose_print(f"Resolved app name: {app_name}", self.verbose)
                        else:
                            verbose_print(f"Could not resolve, using raw label: {app_label}", self.verbose)
                    else:
                        manifest_info['app_name'] = app_label
                        verbose_print(f"Using direct app name: {app_label}", self.verbose)
                else:
                    verbose_print("No app label found", self.verbose)
                
                verbose_print("Extracting activities", self.verbose)
                activities = []
                for activity in application.findall('./activity'):
                    activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
                    if activity_name:
                        activities.append(activity_name)
                manifest_info['activities'] = activities
                verbose_print(f"Found {len(activities)} activities", self.verbose)
                
                verbose_print("Extracting services", self.verbose)
                services = []
                for service in application.findall('./service'):
                    service_name = service.get('{http://schemas.android.com/apk/res/android}name')
                    if service_name:
                        services.append(service_name)
                manifest_info['services'] = services
                verbose_print(f"Found {len(services)} services", self.verbose)
                
                verbose_print("Extracting broadcast receivers", self.verbose)
                receivers = []
                for receiver in application.findall('./receiver'):
                    receiver_name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                    if receiver_name:
                        receivers.append(receiver_name)
                manifest_info['receivers'] = receivers
                verbose_print(f"Found {len(receivers)} receivers", self.verbose)
                
                verbose_print("Extracting content providers", self.verbose)
                providers = []
                for provider in application.findall('./provider'):
                    provider_name = provider.get('{http://schemas.android.com/apk/res/android}name')
                    if provider_name:
                        providers.append(provider_name)
                manifest_info['providers'] = providers
                verbose_print(f"Found {len(providers)} providers", self.verbose)
            else:
                verbose_print("No application element found", self.verbose)
            
            verbose_print(f"Successfully parsed manifest for package: {manifest_info.get('package_name', 'Unknown')}", self.verbose)
            
        except ET.ParseError as e:
            verbose_print(f"Error parsing AndroidManifest.xml: {e}", self.verbose)
            manifest_info['parse_error'] = str(e)
        except Exception as e:
            verbose_print(f"Unexpected error parsing manifest: {e}", self.verbose)
            manifest_info['error'] = str(e)
        
        return manifest_info
    
    def _find_manifest_file(self, project_path: str) -> Optional[str]:
        verbose_print(f"Searching for AndroidManifest.xml in: {project_path}", self.verbose)
        possible_paths = [
            os.path.join(project_path, 'src', 'main', 'AndroidManifest.xml'),
            os.path.join(project_path, 'AndroidManifest.xml'),
            os.path.join(project_path, 'app', 'src', 'main', 'AndroidManifest.xml'),
        ]
        
        verbose_print(f"Checking {len(possible_paths)} standard locations", self.verbose)
        for path in possible_paths:
            if os.path.exists(path):
                verbose_print(f"Found AndroidManifest.xml at: {path}", self.verbose)
                return path
        
        verbose_print("Standard locations failed, performing recursive search", self.verbose)
        for root, dirs, files in os.walk(project_path):
            if 'AndroidManifest.xml' in files:
                found_path = os.path.join(root, 'AndroidManifest.xml')
                possible_paths.append(found_path)
                verbose_print(f"Found AndroidManifest.xml during recursive search: {found_path}", self.verbose)
        
        for path in possible_paths:
            if os.path.exists(path):
                verbose_print(f"Using AndroidManifest.xml at: {path}", self.verbose)
                return path
        
        verbose_print("AndroidManifest.xml not found in any location", self.verbose)
        return None
    
    def _resolve_string_resource(self, project_path: str, resource_ref: str) -> Optional[str]:
        verbose_print(f"Attempting to resolve string resource: {resource_ref}", self.verbose)
        if not resource_ref.startswith('@string/'):
            verbose_print("Not a string resource reference", self.verbose)
            return None
        
        string_key = resource_ref.replace('@string/', '')
        verbose_print(f"Looking for string key: {string_key}", self.verbose)
        
        possible_strings_paths = [
            os.path.join(project_path, 'src', 'main', 'res', 'values', 'strings.xml'),
            os.path.join(project_path, 'res', 'values', 'strings.xml'),
            os.path.join(project_path, 'app', 'src', 'main', 'res', 'values', 'strings.xml'),
        ]
        
        verbose_print(f"Checking {len(possible_strings_paths)} possible strings.xml locations", self.verbose)
        for strings_path in possible_strings_paths:
            verbose_print(f"Checking: {strings_path}", self.verbose)
            if os.path.exists(strings_path):
                verbose_print(f"Found strings.xml at: {strings_path}", self.verbose)
                try:
                    tree = ET.parse(strings_path)
                    root = tree.getroot()
                    
                    string_elements = root.findall('./string')
                    verbose_print(f"Found {len(string_elements)} string elements", self.verbose)
                    
                    for string_elem in string_elements:
                        elem_name = string_elem.get('name')
                        if elem_name == string_key:
                            resolved_value = string_elem.text
                            verbose_print(f"Successfully resolved {resource_ref} to: {resolved_value}", self.verbose)
                            return resolved_value
                            
                except ET.ParseError as e:
                    verbose_print(f"Error parsing {strings_path}: {e}", self.verbose)
                    continue
            else:
                verbose_print(f"strings.xml not found at: {strings_path}", self.verbose)
        
        verbose_print(f"Could not resolve string resource: {resource_ref}", self.verbose)
        return None
    
    def _extract_from_apk(self, apk_path: str) -> Dict[str, Any]:
        """Extract manifest info from APK file using Androguard"""
        verbose_print(f"Starting APK-based manifest extraction for: {apk_path}", self.verbose)
        manifest_info = {}
        
        if not os.path.exists(apk_path):
            verbose_print(f"APK file not found: {apk_path}", self.verbose)
            manifest_info['error'] = f"APK file not found: {apk_path}"
            return manifest_info
        
        if ANDROGUARD_AVAILABLE:
            verbose_print("Using Androguard for APK analysis", self.verbose)
            try:
                from .logging_config import setup_androguard_logging
                setup_androguard_logging(self.verbose)
                apk_obj, _, _ = AnalyzeAPK(apk_path)
                manifest_info = self._extract_with_androguard(apk_obj)
                verbose_print("Androguard extraction successful", self.verbose)
                return manifest_info
            except Exception as e:
                verbose_print(f"Androguard extraction failed: {e}", self.verbose)
                manifest_info['androguard_error'] = str(e)
        else:
            verbose_print("Androguard not available, using fallback methods", self.verbose)
        
        verbose_print("Attempting fallback manifest extraction", self.verbose)
        manifest_content = self._extract_manifest_content_fallback(apk_path)
        
        if manifest_content:
            verbose_print("Fallback extraction successful, parsing content", self.verbose)
            manifest_info = self._parse_manifest_content(manifest_content)
        else:
            verbose_print("All extraction methods failed", self.verbose)
            manifest_info['error'] = "Unable to extract manifest from APK"
        
        return manifest_info
    
    def _extract_with_androguard(self, apk_obj) -> Dict[str, Any]:
        """Extract manifest info using Androguard APK object"""
        verbose_print("Extracting manifest info with Androguard", self.verbose)
        manifest_info = {}
        
        try:
            verbose_print("Extracting basic APK information", self.verbose)
            manifest_info['package_name'] = apk_obj.get_package()
            manifest_info['app_name'] = apk_obj.get_app_name()
            manifest_info['version_name'] = apk_obj.get_androidversion_name()
            manifest_info['version_code'] = apk_obj.get_androidversion_code()
            
            verbose_print(f"Package: {manifest_info.get('package_name', 'Unknown')}", self.verbose)
            verbose_print(f"App name: {manifest_info.get('app_name', 'Unknown')}", self.verbose)
            
            verbose_print("Extracting SDK information", self.verbose)
            manifest_info['min_sdk'] = apk_obj.get_min_sdk_version()
            manifest_info['target_sdk'] = apk_obj.get_target_sdk_version()
            manifest_info['effective_target_sdk'] = apk_obj.get_effective_target_sdk_version()
            
            verbose_print("Extracting permissions", self.verbose)
            permissions = apk_obj.get_permissions()
            manifest_info['permissions'] = permissions if permissions else []
            verbose_print(f"Found {len(manifest_info['permissions'])} permissions", self.verbose)
            
            verbose_print("Extracting application components", self.verbose)
            manifest_info['activities'] = apk_obj.get_activities()
            manifest_info['services'] = apk_obj.get_services()
            manifest_info['receivers'] = apk_obj.get_receivers()
            manifest_info['providers'] = apk_obj.get_providers()
            
            verbose_print(f"Found {len(manifest_info.get('activities', []))} activities", self.verbose)
            verbose_print(f"Found {len(manifest_info.get('services', []))} services", self.verbose)
            verbose_print(f"Found {len(manifest_info.get('receivers', []))} receivers", self.verbose)
            verbose_print(f"Found {len(manifest_info.get('providers', []))} providers", self.verbose)
            
            verbose_print("Extracting raw manifest XML", self.verbose)
            try:
                manifest_xml = apk_obj.get_android_manifest_axml().get_xml()
                manifest_info['raw_manifest'] = manifest_xml
                
                additional_info = self._parse_manifest_content(manifest_xml)
                manifest_info.update(additional_info)
                
            except Exception as e:
                verbose_print(f"Error extracting raw manifest XML: {e}", self.verbose)
            
            verbose_print("Androguard extraction completed successfully", self.verbose)
            
        except Exception as e:
            verbose_print(f"Error in Androguard extraction: {e}", self.verbose)
            manifest_info['extraction_error'] = str(e)
        
        return manifest_info
    
    def _extract_manifest_content_fallback(self, apk_path: str) -> str:
        """Extract manifest content using fallback methods"""
        verbose_print("Attempting fallback manifest extraction methods", self.verbose)
        
        for tool in ['aapt', 'aapt2']:
            verbose_print(f"Trying {tool} for manifest extraction", self.verbose)
            try:
                if tool == 'aapt':
                    cmd = ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml']
                else:
                    cmd = ['aapt2', 'dump', 'xmltree', apk_path, '--file', 'AndroidManifest.xml']
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout:
                    verbose_print(f"{tool} extraction successful", self.verbose)
                    return result.stdout
                else:
                    verbose_print(f"{tool} failed: {result.stderr}", self.verbose)
                    
            except FileNotFoundError:
                verbose_print(f"{tool} not found", self.verbose)
            except subprocess.TimeoutExpired:
                verbose_print(f"{tool} timed out", self.verbose)
            except Exception as e:
                verbose_print(f"{tool} error: {e}", self.verbose)
        
        verbose_print("Trying apktool for manifest extraction", self.verbose)
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ['apktool', 'd', apk_path, '-o', temp_dir, '-f'],
                    capture_output=True, text=True, timeout=60
                )
                
                if result.returncode == 0:
                    manifest_path = os.path.join(temp_dir, 'AndroidManifest.xml')
                    if os.path.exists(manifest_path):
                        with open(manifest_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            verbose_print("apktool extraction successful", self.verbose)
                            return content
                else:
                    verbose_print(f"apktool failed: {result.stderr}", self.verbose)
                    
        except FileNotFoundError:
            verbose_print("apktool not found", self.verbose)
        except Exception as e:
            verbose_print(f"apktool error: {e}", self.verbose)
        
        verbose_print("Attempting basic binary parsing fallback", self.verbose)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                if 'AndroidManifest.xml' in zip_file.namelist():
                    manifest_data = zip_file.read('AndroidManifest.xml')
                    
                    try:
                        return manifest_data.decode('utf-8')
                    except UnicodeDecodeError:
                        verbose_print("Binary manifest detected, extracting readable strings", self.verbose)
                        return self._extract_readable_strings(manifest_data)
                        
        except Exception as e:
            verbose_print(f"Binary extraction failed: {e}", self.verbose)
        
        verbose_print("All fallback methods failed", self.verbose)
        return ""
    
    def _extract_readable_strings(self, manifest_data: bytes) -> str:
        """Extract readable strings from binary manifest"""
        verbose_print("Extracting readable strings from binary manifest", self.verbose)
        
        readable_strings = []
        current_string = ""
        
        for byte in manifest_data:
            if 32 <= byte <= 126:
                current_string += chr(byte)
            else:
                if len(current_string) > 3:
                    readable_strings.append(current_string)
                current_string = ""
        
        if len(current_string) > 3:
            readable_strings.append(current_string)
        
        manifest_strings = []
        for s in readable_strings:
            if any(keyword in s.lower() for keyword in [
                'permission', 'activity', 'service', 'receiver', 
                'provider', 'intent', 'action', 'category', 'data',
                'android:', 'package', 'versioncode', 'versionname'
            ]):
                manifest_strings.append(s)
        
        manifest_parts = [
            "<!-- Binary manifest - limited parsing -->",
            "<!-- Extracted strings: -->"
        ]
        
        for s in sorted(set(manifest_strings)):
            manifest_parts.append(f"<!-- {s} -->")
        
        verbose_print(f"Extracted {len(manifest_strings)} manifest-relevant strings", self.verbose)
        return "\n".join(manifest_parts)
    
    def _parse_manifest_content(self, manifest_content: str) -> Dict[str, Any]:
        """Parse manifest content for additional information"""
        verbose_print("Parsing manifest content for additional information", self.verbose)
        manifest_info = {}
        
        try:
            permissions = self._parse_permissions(manifest_content)
            if permissions:
                manifest_info['permissions'] = permissions
                verbose_print(f"Parsed {len(permissions)} permissions from content", self.verbose)
            
            activities_detailed = self._parse_activities_detailed(manifest_content)
            manifest_info['activities_detailed'] = activities_detailed
            verbose_print(f"Parsed {len(activities_detailed)} detailed activities", self.verbose)
            
            security_flags = self._parse_security_flags(manifest_content)
            manifest_info['security_flags'] = security_flags
            verbose_print(f"Found {len(security_flags)} security flags", self.verbose)
            
            security_issues = self._analyze_security(manifest_content, manifest_info)
            manifest_info['security_issues'] = security_issues
            verbose_print(f"Identified {len(security_issues)} security issues", self.verbose)
            
        except Exception as e:
            verbose_print(f"Error parsing manifest content: {e}", self.verbose)
            manifest_info['parsing_error'] = str(e)
        
        return manifest_info
    
    def _parse_permissions(self, manifest_content: str) -> List[str]:
        """Parse permissions from manifest content"""
        verbose_print("Parsing permissions from manifest content", self.verbose)
        permissions = []
        
        for pattern in PERMISSION_PATTERNS:
            matches = re.findall(pattern, manifest_content, re.IGNORECASE)
            permissions.extend(matches)
        
        unique_permissions = sorted(set(permissions))
        verbose_print(f"Found {len(unique_permissions)} unique permissions", self.verbose)
        return unique_permissions
    
    def _parse_activities_detailed(self, manifest_content: str) -> List[Dict[str, Any]]:
        """Parse activities with detailed information"""
        verbose_print("Parsing detailed activity information", self.verbose)
        activities = []
        
        try:
            if manifest_content.strip().startswith('<?xml') or manifest_content.strip().startswith('<manifest'):
                root = ET.fromstring(manifest_content)
                application = root.find('./application')
                
                if application is not None:
                    for activity in application.findall('./activity'):
                        activity_info = {
                            'name': activity.get('{http://schemas.android.com/apk/res/android}name', ''),
                            'exported': activity.get('{http://schemas.android.com/apk/res/android}exported', 'false'),
                            'enabled': activity.get('{http://schemas.android.com/apk/res/android}enabled', 'true'),
                            'permission': activity.get('{http://schemas.android.com/apk/res/android}permission', ''),
                            'has_intent_filters': len(activity.findall('./intent-filter')) > 0
                        }
                        activities.append(activity_info)
                        
        except ET.ParseError:
            verbose_print("XML parsing failed, using regex fallback", self.verbose)
            activity_pattern = r'android:name="([^"]+)"'
            activity_matches = re.findall(activity_pattern, manifest_content)
            
            for match in activity_matches:
                if 'Activity' in match or 'activity' in match.lower():
                    activities.append({
                        'name': match,
                        'exported': 'unknown',
                        'enabled': 'unknown',
                        'permission': '',
                        'has_intent_filters': False
                    })
        
        verbose_print(f"Parsed {len(activities)} detailed activities", self.verbose)
        return activities
    
    def _parse_security_flags(self, manifest_content: str) -> Dict[str, Any]:
        """Parse security-related flags from manifest"""
        verbose_print("Parsing security flags from manifest", self.verbose)
        flags = {}
        
        flags['debuggable'] = 'android:debuggable="true"' in manifest_content
        flags['allow_backup'] = 'android:allowBackup="true"' in manifest_content
        flags['clear_text_traffic'] = 'android:usesCleartextTraffic="true"' in manifest_content
        flags['has_network_security_config'] = 'android:networkSecurityConfig' in manifest_content
        flags['request_legacy_external_storage'] = 'android:requestLegacyExternalStorage="true"' in manifest_content
        
        verbose_print(f"Security flags: {flags}", self.verbose)
        return flags
    
    def _analyze_security(self, manifest_content: str, manifest_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze manifest for security vulnerabilities"""
        verbose_print("Performing security analysis on manifest", self.verbose)
        security_issues = []
        
        permissions = manifest_info.get('permissions', [])
        activities = manifest_info.get('activities_detailed', [])
        security_flags = manifest_info.get('security_flags', {})
        
        for permission in permissions:
            if permission in DANGEROUS_PERMISSIONS:
                security_issues.append({
                    'type': 'dangerous_permission',
                    'severity': 'MEDIUM',
                    'title': f'Dangerous Permission: {permission}',
                    'description': f'App requests dangerous permission: {permission}',
                    'location': 'AndroidManifest.xml',
                    'recommendation': 'Ensure this permission is necessary and properly justified'
                })
        
        for activity in activities:
            if activity.get('exported', '').lower() == 'true' and not activity.get('permission'):
                security_issues.append({
                    'type': 'exported_activity',
                    'severity': 'MEDIUM',
                    'title': f'Unprotected Exported Activity: {activity["name"]}',
                    'description': f'Activity {activity["name"]} is exported without permission protection',
                    'location': 'AndroidManifest.xml',
                    'recommendation': 'Add permission protection or intent filters to exported activities'
                })
        
        if security_flags.get('debuggable', False):
            security_issues.append({
                'type': 'debug_enabled',
                'severity': 'HIGH',
                'title': 'Debug Mode Enabled',
                'description': 'Application has debug mode enabled in production',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Disable debug mode in production builds'
            })
        
        if security_flags.get('allow_backup', False):
            security_issues.append({
                'type': 'backup_enabled',
                'severity': 'LOW',
                'title': 'Backup Allowed',
                'description': 'Application allows backup which may expose sensitive data',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Consider disabling backup for sensitive applications'
            })
        
        if security_flags.get('clear_text_traffic', False):
            security_issues.append({
                'type': 'cleartext_traffic',
                'severity': 'HIGH',
                'title': 'Cleartext Traffic Allowed',
                'description': 'Application allows cleartext HTTP traffic',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Disable cleartext traffic and use HTTPS only'
            })
        
        if not security_flags.get('has_network_security_config', False):
            security_issues.append({
                'type': 'no_network_security_config',
                'severity': 'MEDIUM',
                'title': 'No Network Security Configuration',
                'description': 'Application does not specify network security configuration',
                'location': 'AndroidManifest.xml',
                'recommendation': 'Add network security configuration to prevent cleartext traffic'
            })
        
        verbose_print(f"Security analysis completed, found {len(security_issues)} issues", self.verbose)
        return security_issues