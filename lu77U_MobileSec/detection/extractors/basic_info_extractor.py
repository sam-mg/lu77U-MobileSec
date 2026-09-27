#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.extractors.basic_info_extractor

Purpose:
    Read the facts an app declares about itself -- package, label, versions, SDK levels, permissions and components -- from either a built APK or a source project.

Responsibilities:
    Dispatch on input type, drive androguard for APKs and the manifest parser for projects, resolve string resources, and recover a package name when the manifest does not give one.

Dependencies:
    androguard when installed, .manifest_parser, ...config.constants for the permission patterns.

Implementation notes:
    Two quite different paths share one result type. An APK has a binary manifest and a resource table, so androguard does the work; a project has a text manifest and a source tree, so the manifest parser does, with the directory layout as a fallback. Failures degrade rather than propagate. Every level either returns a partial result or falls back to a weaker method, because a scan that cannot name the package is still worth running.

Security considerations:
    Every value read here is declared by an untrusted app and is used later to name output files and to populate reports. Nothing is trusted as a path or a shell fragment, and the package name in particular is filtered before it reaches a filename.
"""

import os
import re
from typing import List

from ...config.constants import PERMISSION_PATTERNS
from ...utils.verbose import verbose_print
from ..results.basic_info_results import BasicInfoResult
from .manifest_parser import ManifestParser

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

class BasicInfoExtractor:
    """
    Purpose:
        Extracts package information from an APK or a source project.

    Attributes:
        verbose: Whether extraction is traced.
        manifest_parser: Parses text manifests on the project path.

    Invariants:
        Always returns a result object, however little could be read.

    Thread-safety:
        Holds no per-extraction state, but androguard's logging setup it triggers is process-wide.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the extractor and its manifest parser.

        Parameters:
            verbose: Enables tracing and is forwarded to the parser.
        """
        self.verbose = verbose
        verbose_print("BasicInfoExtractor initializing", self.verbose)
        self.manifest_parser = ManifestParser(verbose=verbose)
        verbose_print("BasicInfoExtractor initialization complete", self.verbose)
    
    def extract_basic_info(self, input_path: str) -> BasicInfoResult:
        """
        Purpose:
            Extract package information from whatever the target is.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            A result object, populated as far as extraction got. Never None.

        Side effects:
            Reads the target from disk.

        Implementation notes:
            Dispatch is by file extension rather than by inspecting content, which is enough here because the caller has already decided what it is scanning. Failures are swallowed: the partially-populated result is returned so that the framework detection alongside it is not lost to a manifest problem.
        """
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
        """
        Purpose:
            Read package information out of a built APK using androguard.

        Parameters:
            apk_path: Path to the APK.
            basic_info: Result object, populated in place.

        Side effects:
            Parses the APK, and configures androguard logging.

        Implementation notes:
            androguard's absence is handled explicitly with placeholder values rather than by raising, so the rest of the scan proceeds and the report shows why the identity is missing. The app label frequently comes back as a resource reference rather than text, so it is resolved against the resource table before being stored. On a parse failure the package field is set to the error text. That is deliberate: it surfaces in the report where a silent Unknown would leave the reader unable to tell a failure from an app that declares nothing.

        Security considerations:
            androguard is parsing an attacker-supplied archive, which is why the whole body is guarded rather than trusting the library not to raise on malformed input.
        """
        basic_info.file_size = os.path.getsize(apk_path)
        verbose_print(f"APK file size: {basic_info.file_size} bytes", self.verbose)
        
        if not ANDROGUARD_AVAILABLE:
            verbose_print("Androguard not available - limited APK extraction", self.verbose)
            basic_info.package_name = "Unknown (androguard required)"
            basic_info.app_name = "Unknown (androguard required)"
            return
        try:
            from .logging_config import setup_androguard_logging
            setup_androguard_logging(self.verbose)
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
            
            verbose_print("Extracting permissions", self.verbose)
            basic_info.permissions = self._extract_permissions(apk)
            verbose_print(f"Found {len(basic_info.permissions)} permissions", self.verbose)

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
        """
        Purpose:
            Read package information out of a source project.

        Parameters:
            project_path: Path to the project root.
            basic_info: Result object, populated in place.

        Side effects:
            Walks the directory and reads the manifest.

        Implementation notes:
            When the manifest yields no package name, the Java or Kotlin source layout is consulted instead. A project without a usable manifest is common -- a library module, or a partial checkout -- and the directory structure encodes the same information.
        """
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
        basic_info.permissions = manifest_info.get('permissions', []) or []
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
    
    def _extract_permissions(self, apk) -> List[str]:
        """
        Purpose:
            List the permissions the app declares, falling back to the raw manifest when androguard reports none.

        Parameters:
            apk: The androguard APK object.

        Returns:
            Permission names, possibly empty.

        Implementation notes:
            androguard occasionally returns an empty permission list for an APK whose manifest plainly declares permissions, typically where the binary XML uses an encoding its parser mishandles. Rather than trust the empty answer, the raw manifest XML is pattern-matched as a second opinion. The fallback runs only when the primary returned nothing, so a correct parse is never second-guessed. When the fallback does find permissions the discrepancy is traced, because it indicates a parsing problem worth knowing about.

        Security considerations:
            Permissions widen the impact of other findings, so under-reporting them understates severity. That asymmetry is why the fallback exists.
        """
        primary: List[str] = []
        try:
            primary = list(apk.get_permissions() or [])
        except Exception as e:
            verbose_print(f"androguard get_permissions() failed: {e}", self.verbose)

        if primary:
            return primary

        try:
            xml = apk.get_android_manifest_axml().get_xml()
            if isinstance(xml, bytes):
                xml = xml.decode("utf-8", errors="ignore")
        except Exception as e:
            verbose_print(f"Could not read raw manifest XML for permissions: {e}", self.verbose)
            return []

        found: List[str] = []
        for pattern in PERMISSION_PATTERNS:
            for match in re.findall(pattern, xml, re.IGNORECASE):
                if match not in found:
                    found.append(match)

        if found:
            verbose_print(
                f"androguard reported no permissions but the raw manifest declares "
                f"{len(found)}; using the manifest", self.verbose)
        return found

    def _extract_package_from_java_structure(self, project_path: str) -> str:
        """
        Purpose:
            Recover a package name from a project's source layout when the manifest did not provide one.

        Parameters:
            project_path: Path to the project root.

        Returns:
            The package name, or None.

        Implementation notes:
            Two strategies in order: infer from the directory hierarchy, then read an actual package declaration out of a source file. The directory walk is cheaper and usually right; reading declarations is definitive but costs file reads. Both strategies are tried across the four standard source roots, covering plain and Gradle-module layouts in Java and Kotlin.
        """
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
        """
        Purpose:
            Infer a package name from the deepest directory that actually contains source files.

        Parameters:
            java_dir: A source root.

        Returns:
            The dotted package name, or None.

        Implementation notes:
            Depth is the signal: the package root contains intermediate directories with no sources, while the leaf holding the code is the full package. Taking the shallowest directory would yield a truncated name like "com". Only directories containing Java or Kotlin files are considered, so resource and generated directories alongside the sources do not win on depth.

        Known limitations:
            A project whose deepest source directory is a subpackage rather than the main one yields that subpackage. The declaration-reading fallback is more reliable, which is why it exists.
        """
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
        """
        Purpose:
            Read a package declaration out of the first source file that carries one.

        Parameters:
            java_dir: A source root.

        Returns:
            The declared package, or None.

        Implementation notes:
            Returns on the first match rather than surveying every file, since a project's sources share a package root and the first declaration is representative. The pattern requires a trailing semicolon, which is Java syntax; a Kotlin file declaring a package without one is not matched. That is a gap, mitigated by the directory-structure strategy that runs first. Unreadable and undecodable files are skipped rather than aborting the walk.
        """
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
        """
        Purpose:
            Turn a string resource reference into the text it names.

        Parameters:
            apk: The androguard APK object.
            resource_ref: A value that may be a reference such as an at-string path, or plain text.

        Returns:
            The resolved text, or the original value when it was not a reference or could not be resolved.

        Implementation notes:
            An app's label is usually a resource reference, and showing that reference in a report instead of the app's name is unhelpful. Every configuration of every package is searched, because the default locale is not always where the value lives -- an app can define its label only under a specific locale. The first name match wins rather than preferring a locale, since any human-readable label is better than the unresolved reference. Every failure returns the original reference, so the report shows something traceable rather than an empty field.

        Security considerations:
            The resolved value is attacker-controlled text from the APK and must be escaped by whatever renders it.
        """
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
        """
        Purpose:
            Total the size of a project directory, for the size field a project has in place of an APK file size.

        Parameters:
            path: Directory to measure.

        Returns:
            Total bytes across every readable file.

        Side effects:
            Walks the tree and stats every file.

        Implementation notes:
            Unreadable files are counted as errors and skipped rather than aborting the walk, so a permissions problem on one file does not lose the measurement.

        Known limitations:
            Symlinks are followed by the walk and hard links are counted once per name, so the total can exceed the space actually occupied.
        """
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
