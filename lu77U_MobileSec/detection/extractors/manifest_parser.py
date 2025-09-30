"""AndroidManifest.xml Parser for lu77U-MobileSec"""

import os
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from ...utils.verbose import verbose_print

class ManifestParser:
    """Parser for AndroidManifest.xml files"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("ManifestParser initialized", self.verbose)
    
    def extract_manifest_info(self, project_path: str) -> Dict[str, Any]:
        verbose_print(f"Starting manifest extraction for: {project_path}", self.verbose)
        manifest_info = {}
        manifest_path = self._find_manifest_file(project_path)
        
        if not manifest_path:
            verbose_print("AndroidManifest.xml not found", self.verbose)
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