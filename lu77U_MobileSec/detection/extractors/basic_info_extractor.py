"""Basic Information Extractor for lu77U-MobileSec"""

import os
from ...utils.verbose import verbose_print
from ..results.basic_info_results import BasicInfoResult
from .manifest_parser import ManifestParser

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

class BasicInfoExtractor:
    """Extractor for basic application information"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("BasicInfoExtractor initializing", self.verbose)
        self.manifest_parser = ManifestParser(verbose=verbose)
        verbose_print("BasicInfoExtractor initialization complete", self.verbose)
    
    def extract_basic_info(self, input_path: str) -> BasicInfoResult:
        verbose_print("Extracting basic application information", self.verbose)
        basic_info = BasicInfoResult()
        file_type = 'APK' if input_path.endswith('.apk') else 'Project Directory'
        basic_info.file_type = file_type
        verbose_print(f"Input type detected: {file_type}", self.verbose)
        
        try:
            if input_path.endswith('.apk'):
                verbose_print("Starting APK extraction", self.verbose)
                self._extract_from_apk(input_path, basic_info)
            else:
                verbose_print("Starting project directory extraction", self.verbose)
                self._extract_from_project(input_path, basic_info)
            verbose_print("Basic information extraction completed successfully", self.verbose)
        except Exception as e:
            verbose_print(f"Error extracting basic info: {str(e)}", self.verbose)
        return basic_info
    
    def _extract_from_apk(self, apk_path: str, basic_info: BasicInfoResult):
        """Extract data from APK file using androguard"""
        verbose_print(f"Starting APK extraction for: {apk_path}", self.verbose)
        
        verbose_print("Calculating APK file size", self.verbose)
        basic_info.file_size = os.path.getsize(apk_path)
        verbose_print(f"APK file size: {basic_info.file_size} bytes", self.verbose)
        
        if not ANDROGUARD_AVAILABLE:
            verbose_print("Androguard not available - limited APK extraction", self.verbose)
            basic_info.package_name = "Unknown (androguard required)"
            basic_info.app_name = "Unknown (androguard required)"
            return
        try:
            verbose_print("Loading APK with androguard", self.verbose)
            apk, _, _ = AnalyzeAPK(apk_path)
            verbose_print("APK loaded successfully", self.verbose)
            
            verbose_print("Extracting package information", self.verbose)
            basic_info.package_name = apk.get_package()
            verbose_print(f"Package name: {basic_info.package_name}", self.verbose)
            
            verbose_print("Extracting app name", self.verbose)
            raw_app_name = apk.get_app_name()
            verbose_print(f"Raw app name: {raw_app_name}", self.verbose)
            basic_info.app_name = self._resolve_apk_string_resource(apk, raw_app_name)
            verbose_print(f"Resolved app name: {basic_info.app_name}", self.verbose)
            
            verbose_print("Extracting version information", self.verbose)
            basic_info.version_name = apk.get_androidversion_name()
            basic_info.version_code = apk.get_androidversion_code()
            verbose_print(f"Version: {basic_info.version_name} (code: {basic_info.version_code})", self.verbose)
            
            verbose_print("Extracting SDK versions", self.verbose)
            basic_info.min_sdk = apk.get_min_sdk_version()
            basic_info.target_sdk = apk.get_target_sdk_version()
            verbose_print(f"SDK versions - Min: {basic_info.min_sdk}, Target: {basic_info.target_sdk}", self.verbose)
            
            verbose_print("Extracting application components", self.verbose)
            basic_info.activities = apk.get_activities()
            verbose_print(f"Found {len(basic_info.activities) if basic_info.activities else 0} activities", self.verbose)
            
            basic_info.services = apk.get_services()
            verbose_print(f"Found {len(basic_info.services) if basic_info.services else 0} services", self.verbose)
            
            basic_info.receivers = apk.get_receivers()
            verbose_print(f"Found {len(basic_info.receivers) if basic_info.receivers else 0} receivers", self.verbose)
            
            basic_info.providers = apk.get_providers()
            verbose_print(f"Found {len(basic_info.providers) if basic_info.providers else 0} providers", self.verbose)
            
            verbose_print(f"Successfully extracted from APK: {basic_info.package_name}", self.verbose)
        except Exception as e:
            verbose_print(f"Error extracting from APK with androguard: {e}", self.verbose)
            basic_info.package_name = f"Error: {str(e)}"
            basic_info.app_name = "Extraction failed"
    
    def _extract_from_project(self, project_path: str, basic_info: BasicInfoResult):
        """Extract data from project directory"""
        verbose_print(f"Starting project directory extraction for: {project_path}", self.verbose)
        
        verbose_print("Calculating directory size", self.verbose)
        basic_info.file_size = self._calculate_directory_size(project_path)
        verbose_print(f"Directory size: {basic_info.file_size} bytes", self.verbose)
        
        verbose_print("Extracting manifest information", self.verbose)
        manifest_info = self.manifest_parser.extract_manifest_info(project_path)
        verbose_print(f"Manifest extraction completed, found {len(manifest_info)} attributes", self.verbose)
        
        verbose_print("Processing manifest data", self.verbose)
        basic_info.package_name = manifest_info.get('package_name')
        basic_info.app_name = manifest_info.get('app_name')
        basic_info.version_name = manifest_info.get('version_name')
        basic_info.version_code = manifest_info.get('version_code')
        basic_info.min_sdk = manifest_info.get('min_sdk')
        basic_info.target_sdk = manifest_info.get('target_sdk')
        basic_info.activities = manifest_info.get('activities', [])
        basic_info.services = manifest_info.get('services', [])
        basic_info.receivers = manifest_info.get('receivers', [])
        basic_info.providers = manifest_info.get('providers', [])
        
        verbose_print(f"Components found - Activities: {len(basic_info.activities)}, Services: {len(basic_info.services)}, Receivers: {len(basic_info.receivers)}, Providers: {len(basic_info.providers)}", self.verbose)
        
        if not basic_info.package_name:
            verbose_print("Package name not found in manifest, attempting to extract from Java directory structure", self.verbose)
            java_package_name = self._extract_package_from_java_structure(project_path)
            if java_package_name:
                basic_info.package_name = java_package_name
                verbose_print(f"Extracted package name from Java structure: {java_package_name}", self.verbose)
            else:
                verbose_print("Could not extract package name from Java structure", self.verbose)
        
        verbose_print(f"Successfully extracted from project: {basic_info.package_name or 'Unknown'}", self.verbose)
    
    def _extract_package_from_java_structure(self, project_path: str) -> str:
        """Extract package name from Java directory structure"""
        verbose_print("Starting package extraction from Java directory structure", self.verbose)
        java_source_dirs = [
            os.path.join(project_path, 'src', 'main', 'java'),
            os.path.join(project_path, 'app', 'src', 'main', 'java'),
            os.path.join(project_path, 'src', 'main', 'kotlin'),
            os.path.join(project_path, 'app', 'src', 'main', 'kotlin'),
        ]
        
        verbose_print(f"Checking {len(java_source_dirs)} standard source directories", self.verbose)
        for java_dir in java_source_dirs:
            if os.path.exists(java_dir):
                verbose_print(f"Searching for package structure in: {java_dir}", self.verbose)
                package_name = self._find_deepest_package_path(java_dir)
                if package_name:
                    verbose_print(f"Found package structure: {package_name}", self.verbose)
                    return package_name
                else:
                    verbose_print(f"No package structure found in: {java_dir}", self.verbose)
            else:
                verbose_print(f"Source directory not found: {java_dir}", self.verbose)
                
        verbose_print("Fallback: searching for package declarations in source files", self.verbose)
        for java_dir in java_source_dirs:
            if os.path.exists(java_dir):
                verbose_print(f"Scanning source files in: {java_dir}", self.verbose)
                package_name = self._extract_package_from_source_files(java_dir)
                if package_name:
                    verbose_print(f"Found package from source files: {package_name}", self.verbose)
                    return package_name
                else:
                    verbose_print(f"No package declarations found in: {java_dir}", self.verbose)
                    
        verbose_print("Package extraction from Java structure failed", self.verbose)
        return None
    
    def _find_deepest_package_path(self, java_dir: str) -> str:
        """Find the deepest package path that contains Java/Kotlin files"""
        verbose_print(f"Finding deepest package path in: {java_dir}", self.verbose)
        deepest_package = None
        max_depth = 0
        directories_checked = 0
        files_found = 0
        
        for root, dirs, files in os.walk(java_dir):
            directories_checked += 1
            source_files = [f for f in files if f.endswith(('.java', '.kt'))]
            has_source_files = len(source_files) > 0
            files_found += len(source_files)
            
            if has_source_files:
                rel_path = os.path.relpath(root, java_dir)
                if rel_path != '.':
                    depth = len(rel_path.split(os.sep))
                    verbose_print(f"Found {len(source_files)} source files at depth {depth}: {rel_path}", self.verbose)
                    if depth > max_depth:
                        max_depth = depth
                        deepest_package = rel_path.replace(os.sep, '.')
                        verbose_print(f"New deepest package candidate: {deepest_package}", self.verbose)
                        
        verbose_print(f"Scanned {directories_checked} directories, found {files_found} source files", self.verbose)
        if deepest_package:
            verbose_print(f"Deepest package path: {deepest_package} (depth: {max_depth})", self.verbose)
        else:
            verbose_print("No package path with source files found", self.verbose)
            
        return deepest_package
    
    def _extract_package_from_source_files(self, java_dir: str) -> str:
        """Extract package name from Java/Kotlin source file content"""
        verbose_print(f"Extracting package from source file content in: {java_dir}", self.verbose)
        files_scanned = 0
        
        for root, dirs, files in os.walk(java_dir):
            source_files = [f for f in files if f.endswith(('.java', '.kt'))]
            for file in source_files:
                files_scanned += 1
                file_path = os.path.join(root, file)
                verbose_print(f"Scanning file {files_scanned}: {file}", self.verbose)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        import re
                        package_match = re.search(r'package\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;', content)
                        if package_match:
                            package_name = package_match.group(1)
                            verbose_print(f"Found package declaration in {file}: {package_name}", self.verbose)
                            return package_name
                        else:
                            verbose_print(f"No package declaration found in {file}", self.verbose)
                            
                except (IOError, UnicodeDecodeError) as e:
                    verbose_print(f"Could not read file {file_path}: {e}", self.verbose)
                    continue
                    
        verbose_print(f"Scanned {files_scanned} source files, no package declarations found", self.verbose)
        return None
    
    def _resolve_apk_string_resource(self, apk, resource_ref: str) -> str:
        """Resolve @string/resource_name references in APK files"""
        verbose_print(f"Attempting to resolve APK string resource: {resource_ref}", self.verbose)
        
        if not resource_ref or not resource_ref.startswith('@string/'):
            resolved_name = resource_ref or "Unknown"
            verbose_print(f"Not a string resource, returning: {resolved_name}", self.verbose)
            return resolved_name
        
        try:
            verbose_print("Getting APK resources", self.verbose)
            resources = apk.get_android_resources()
            if not resources:
                verbose_print("No resources found in APK", self.verbose)
                return resource_ref
            
            string_key = resource_ref.replace('@string/', '')
            verbose_print(f"Looking for string key: {string_key}", self.verbose)
            
            packages_checked = 0
            total_strings_found = 0
            
            for package in resources.get_packages():
                packages_checked += 1
                verbose_print(f"Checking package {packages_checked}", self.verbose)
                
                for locale, resources_dict in package.get_configs_array():
                    if 'string' in resources_dict:
                        string_resources = resources_dict['string']
                        total_strings_found += len(string_resources)
                        verbose_print(f"Found {len(string_resources)} string resources in locale: {locale or 'default'}", self.verbose)
                        
                        for res_id, res_name, res_value in string_resources:
                            if res_name == string_key:
                                verbose_print(f"Resolved {resource_ref} to: {res_value}", self.verbose)
                                return res_value
            
            verbose_print(f"Checked {packages_checked} packages with {total_strings_found} total strings", self.verbose)            
            verbose_print(f"Could not resolve string resource: {resource_ref}", self.verbose)
            return resource_ref
            
        except Exception as e:
            verbose_print(f"Error resolving string resource {resource_ref}: {e}", self.verbose)
            return resource_ref
    
    def _calculate_directory_size(self, path: str) -> int:
        """Calculate total size of directory"""
        verbose_print(f"Calculating directory size for: {path}", self.verbose)
        total_size = 0
        file_count = 0
        error_count = 0
        
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    file_size = os.path.getsize(filepath)
                    total_size += file_size
                    file_count += 1
                except OSError as e:
                    error_count += 1
                    verbose_print(f"Could not get size of {filepath}: {e}", self.verbose)
                    
        verbose_print(f"Directory size calculation complete: {file_count} files, {total_size} bytes total, {error_count} errors", self.verbose)
        return total_size