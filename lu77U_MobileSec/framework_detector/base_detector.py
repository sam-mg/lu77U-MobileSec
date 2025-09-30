"""Base Framework Detector for lu77U-MobileSec"""

import os
from typing import List, Dict, Set
from dataclasses import dataclass
from pathlib import Path

from ..utils.verbose import verbose_print

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    APK = None
    DalvikVMFormat = None
    Analysis = None
    AnalyzeAPK = None

@dataclass
class FrameworkScore:
    """Framework detection score with confidence"""
    name: str
    score: int
    confidence: float
    indicators: List[str]
    framework_type: str

class BaseFrameworkDetector:
    def __init__(self, verbose=False):
        """Initialize base detector"""
        self.verbose = verbose
        verbose_print("BaseFrameworkDetector initialized", self.verbose)
        self.apk = None
        self.dalvik_files = []
        self.analysis = None
        self.confidence_threshold = 0.3
        verbose_print(f"Confidence threshold set to: {self.confidence_threshold}", self.verbose)
    
    def load_apk(self, apk_path: str) -> bool:
        """Load APK using androguard"""
        verbose_print(f"Attempting to load APK: {apk_path}", self.verbose)
        
        if not ANDROGUARD_AVAILABLE:
            verbose_print("Androguard not available - cannot load APK", self.verbose)
            return False
            
        try:
            verbose_print(f"Loading APK with androguard: {apk_path}", self.verbose)
            self.apk, self.dalvik_files, self.analysis = AnalyzeAPK(apk_path)
            verbose_print("APK loaded successfully", self.verbose)
            verbose_print(f"Found {len(self.dalvik_files)} dalvik files", self.verbose)
            return True
        except Exception as e:
            verbose_print(f"Error loading APK: {e}", self.verbose)
            return False
    
    def get_apk_files(self) -> list:
        """Get list of files in the APK"""
        verbose_print("Retrieving APK file list", self.verbose)
        if not self.apk:
            verbose_print("APK not loaded - cannot get file list", self.verbose)
            return []
        
        try:
            files = self.apk.get_files()
            verbose_print(f"Retrieved {len(files)} files from APK", self.verbose)
            return files
        except Exception as e:
            verbose_print(f"Error getting APK files: {e}", self.verbose)
            return []
    
    def get_classes(self) -> list:
        """Get classes from the APK"""
        verbose_print("Retrieving classes from APK", self.verbose)
        if not self.dalvik_files:
            verbose_print("No dalvik files loaded - cannot get classes", self.verbose)
            return []
        
        try:
            classes = []
            verbose_print(f"Processing {len(self.dalvik_files)} dalvik files", self.verbose)
            for dex in self.dalvik_files:
                dex_classes = [class_analysis.name for class_analysis in self.analysis.get_classes()]
                classes.extend(dex_classes)
                verbose_print(f"Found {len(dex_classes)} classes in dalvik file", self.verbose)
            verbose_print(f"Total classes found: {len(classes)}", self.verbose)
            return classes
        except Exception as e:
            verbose_print(f"Error getting classes: {e}", self.verbose)
            return []
    
    def get_strings(self) -> Set[str]:
        """Get all strings from DEX files"""
        verbose_print("Extracting strings from DEX files", self.verbose)
        strings = set()
        
        if not self.dalvik_files:
            verbose_print("No dalvik files loaded - cannot extract strings", self.verbose)
            return strings
        
        try:
            verbose_print(f"Processing strings from {len(self.dalvik_files)} dalvik files", self.verbose)
            for i, dex in enumerate(self.dalvik_files):
                dex_strings = set(dex.get_strings())
                verbose_print(f"Found {len(dex_strings)} strings in dalvik file {i+1}", self.verbose)
                strings.update(dex_strings)
            
            verbose_print(f"Total unique strings extracted: {len(strings)}", self.verbose)
            return strings
        except Exception as e:
            verbose_print(f"Error getting strings: {e}", self.verbose)
            return strings
    
    def get_manifest_content(self) -> str:
        """Get manifest content as string"""
        verbose_print("Retrieving manifest content", self.verbose)
        if not self.apk:
            verbose_print("APK not loaded - cannot get manifest", self.verbose)
            return ""
        
        try:
            manifest = self.apk.get_android_manifest_xml()
            manifest_str = str(manifest)
            verbose_print(f"Retrieved manifest content ({len(manifest_str)} characters)", self.verbose)
            return manifest_str
        except Exception as e:
            verbose_print(f"Error getting manifest: {e}", self.verbose)
            return ""
    
    def resolve_apk_string_resource(self, resource_ref: str) -> str:
        """Resolve @string/resource_name references in APK files"""
        verbose_print(f"Resolving string resource: {resource_ref}", self.verbose)
        
        if not self.apk or not resource_ref or not resource_ref.startswith('@string/'):
            verbose_print(f"Cannot resolve resource: APK={bool(self.apk)}, ref='{resource_ref}'", self.verbose)
            return resource_ref or "Unknown"
        
        try:
            verbose_print("Retrieving APK resources", self.verbose)
            resources = self.apk.get_android_resources()
            if not resources:
                verbose_print("No resources found in APK", self.verbose)
                return resource_ref
            
            string_key = resource_ref.replace('@string/', '')
            verbose_print(f"Looking for string key: {string_key}", self.verbose)
            
            packages = resources.get_packages()
            verbose_print(f"Found {len(packages)} resource packages", self.verbose)
            
            for package in packages:
                for locale, resources_dict in package.get_configs_array():
                    if 'string' in resources_dict:
                        verbose_print(f"Checking strings in locale: {locale}", self.verbose)
                        for res_id, res_name, res_value in resources_dict['string']:
                            if res_name == string_key:
                                verbose_print(f"Resolved {resource_ref} to: {res_value}", self.verbose)
                                return res_value
            
            verbose_print(f"Could not resolve string resource: {resource_ref}", self.verbose)
            return resource_ref
            
        except Exception as e:
            verbose_print(f"Error resolving string resource {resource_ref}: {e}", self.verbose)
            return resource_ref
    
    def calculate_framework_score(self, content: str, indicators: Dict[str, int], framework_name: str) -> FrameworkScore:
        """Calculate weighted score for a framework"""
        verbose_print(f"Calculating framework score for: {framework_name}", self.verbose)
        verbose_print(f"Content length: {len(content)} characters", self.verbose)
        verbose_print(f"Indicators to check: {len(indicators)} - {list(indicators.keys())}", self.verbose)
        
        total_score = 0
        found_indicators = []
        content_lower = content.lower()
        
        for indicator, weight in indicators.items():
            verbose_print(f"Checking indicator '{indicator}' (weight: {weight})", self.verbose)
            if indicator.lower() in content_lower:
                total_score += weight
                found_indicators.append(indicator)
                verbose_print(f"Found indicator '{indicator}' - score increased by {weight} (total: {total_score})", self.verbose)
            else:
                verbose_print(f"Indicator '{indicator}' not found", self.verbose)
        
        max_possible_score = sum(indicators.values())
        confidence = min(total_score / max_possible_score, 1.0) if max_possible_score > 0 else 0.0
        
        verbose_print(f"Framework score calculation complete:", self.verbose)
        verbose_print(f"  Total score: {total_score}/{max_possible_score}", self.verbose)
        verbose_print(f"  Confidence: {confidence:.3f}", self.verbose)
        verbose_print(f"  Found indicators: {found_indicators}", self.verbose)
        
        return FrameworkScore(
            name=framework_name,
            score=total_score,
            confidence=confidence,
            indicators=found_indicators,
            framework_type=framework_name.lower().replace(" ", "_")
        )
    
    def analyze_project_structure(self, project_path: str) -> Dict[str, any]:
        """Analyze project folder structure"""
        verbose_print(f"Analyzing project structure: {project_path}", self.verbose)
        
        structure = {
            'has_android_folder': False,
            'has_ios_folder': False,
            'kotlin_files': 0,
            'java_files': 0,
            'dart_files': 0,
            'js_files': 0,
            'native_libs': 0,
            'config_files': []
        }
        
        try:
            project = Path(project_path)
            verbose_print(f"Project path exists: {project.exists()}", self.verbose)
            
            # Check for platform folders
            verbose_print("Checking for platform folders", self.verbose)
            structure['has_android_folder'] = (project / 'android').exists()
            structure['has_ios_folder'] = (project / 'ios').exists()
            verbose_print(f"Android folder: {structure['has_android_folder']}", self.verbose)
            verbose_print(f"iOS folder: {structure['has_ios_folder']}", self.verbose)
            
            # Count file types
            verbose_print("Counting source files by type", self.verbose)
            structure['kotlin_files'] = len(list(project.rglob('*.kt')))
            structure['java_files'] = len(list(project.rglob('*.java')))
            structure['dart_files'] = len(list(project.rglob('*.dart')))
            structure['js_files'] = len(list(project.rglob('*.js'))) + len(list(project.rglob('*.jsx')))
            structure['native_libs'] = len(list(project.rglob('*.so')))
            
            verbose_print(f"Kotlin files: {structure['kotlin_files']}", self.verbose)
            verbose_print(f"Java files: {structure['java_files']}", self.verbose)
            verbose_print(f"Dart files: {structure['dart_files']}", self.verbose)
            verbose_print(f"JS files: {structure['js_files']}", self.verbose)
            verbose_print(f"Native libraries: {structure['native_libs']}", self.verbose)
            
            # Check for config files
            verbose_print("Checking for configuration files", self.verbose)
            config_files = ['pubspec.yaml', 'package.json', 'build.gradle', 'CMakeLists.txt']
            for config in config_files:
                config_path = project / config
                if config_path.exists():
                    structure['config_files'].append(config)
                    verbose_print(f"Found config file: {config}", self.verbose)
            
            verbose_print(f"Total config files found: {len(structure['config_files'])}", self.verbose)
            verbose_print("Project structure analysis complete", self.verbose)
            return structure
            
        except Exception as e:
            verbose_print(f"Error analyzing project structure: {e}", self.verbose)
            return structure
    
    def extract_combined_content(self, input_path: str) -> str:
        """Extract and combine all content for analysis"""
        verbose_print(f"Extracting content from: {input_path}", self.verbose)
        
        if os.path.isfile(input_path) and input_path.lower().endswith('.apk'):
            verbose_print("Input is APK file - extracting APK content", self.verbose)
            return self._extract_apk_content(input_path)
        elif os.path.isdir(input_path):
            verbose_print("Input is directory - extracting project content", self.verbose)
            return self._extract_project_content(input_path)
        else:
            verbose_print(f"Invalid input path: {input_path}", self.verbose)
            return ""
    
    def _extract_apk_content(self, apk_path: str) -> str:
        """Extract content from APK"""
        verbose_print(f"Starting APK content extraction from: {apk_path}", self.verbose)
        
        if not self.load_apk(apk_path):
            verbose_print("Failed to load APK - returning empty content", self.verbose)
            return ""
        
        verbose_print("Extracting various content types from APK", self.verbose)
        apk_files = self.get_apk_files()
        classes = self.get_classes()
        strings = self.get_strings()
        manifest = self.get_manifest_content()
        
        verbose_print("Combining APK content", self.verbose)
        combined_content = f"{' '.join(apk_files)} {' '.join(classes)} {' '.join(strings)} {manifest}"
        
        verbose_print(f"APK content extraction complete - total length: {len(combined_content)} characters", self.verbose)
        return combined_content
    
    def _extract_project_content(self, project_path: str) -> str:
        """Extract content from project folder"""
        verbose_print(f"Starting project content extraction from: {project_path}", self.verbose)
        content_parts = []
        
        try:
            project = Path(project_path)
            verbose_print(f"Project path validated: {project.exists()}", self.verbose)
            
            # Get all file paths
            verbose_print("Collecting all file paths", self.verbose)
            all_files = [str(f.relative_to(project)) for f in project.rglob('*') if f.is_file()]
            verbose_print(f"Found {len(all_files)} files in project", self.verbose)
            content_parts.extend(all_files)
            
            # Read specific config files
            verbose_print("Reading configuration files", self.verbose)
            config_files = ['pubspec.yaml', 'package.json', 'build.gradle']
            for config in config_files:
                config_path = project / config
                verbose_print(f"Checking config file: {config}", self.verbose)
                if config_path.exists():
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            config_content = f.read()
                            content_parts.append(config_content)
                            verbose_print(f"Read config file {config} ({len(config_content)} characters)", self.verbose)
                    except Exception as e:
                        verbose_print(f"Error reading config file {config}: {e}", self.verbose)
                        pass
                else:
                    verbose_print(f"Config file not found: {config}", self.verbose)
            
        except Exception as e:
            verbose_print(f"Error extracting project content: {e}", self.verbose)
        
        combined_content = ' '.join(content_parts)
        verbose_print(f"Project content extraction complete - total length: {len(combined_content)} characters", self.verbose)
        return combined_content