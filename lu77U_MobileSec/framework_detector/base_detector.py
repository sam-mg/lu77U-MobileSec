#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.base_detector

Purpose:
    The shared machinery every framework detector is built on: loading an APK, pulling its files, classes, strings and manifest into one searchable blob, and scoring that blob against a weighted indicator table.

Responsibilities:
    Define the score type, expose the APK accessors, implement weighted scoring, and extract comparable content from an APK or a project.

Dependencies:
    androguard when installed, pathlib, ..detection.extractors.logging_config.

Implementation notes:
    Detection is deliberately uniform: every detector reduces to a table of substrings with weights, matched against one combined text blob. That makes a detector a few lines of data rather than bespoke logic, and it makes the confidence scores comparable across frameworks -- which is what lets the hybrid arbitrator rank them against each other. Combining files, class names, strings and the manifest into one blob loses the distinction between where a marker was found. That is an accepted trade: a framework's fingerprint shows up in several of those places at once, and searching them separately would multiply the tables without improving the answer.

Security considerations:
    Everything here reads an untrusted APK. An app can plant any marker it likes, so a detector's output is a claim about what the app looks like, never a guarantee.
"""

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
    """
    Purpose:
        The outcome of scoring one framework against an app.

    Attributes:
        name: Framework name as displayed.
        score: Weighted total of the indicators found.
        confidence: Score as a fraction of the maximum possible, in the range zero to one.
        indicators: Which markers were actually found, for the report's evidence section.
        framework_type: Normalised lowercase identifier.

    Invariants:
        confidence is the score divided by the table's maximum, so it is comparable between detectors with differently-sized tables. Two detectors with the same confidence found equally strong evidence relative to what they were looking for.

    Thread-safety:
        A plain data holder; safe to share once built.
    """
    name: str
    score: int
    confidence: float
    indicators: List[str]
    framework_type: str

class BaseFrameworkDetector:
    """
    Purpose:
        Base class supplying APK access, content extraction and scoring to every framework detector.

    Attributes:
        verbose: Whether detection is traced.
        apk: The loaded androguard APK object, or None.
        dalvik_files: Loaded DEX files.
        analysis: androguard's cross-reference analysis.
        confidence_threshold: Floor below which a detection is not worth reporting.

    Invariants:
        Every accessor returns an empty result rather than raising when the APK is not loaded, so a subclass can call them unconditionally.

    Thread-safety:
        Not safe to share. The loaded APK is instance state overwritten by each load.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Initialise detector state.

        Parameters:
            verbose: Enables tracing.

        Postconditions:
            No APK is loaded; every accessor returns empty until load_apk succeeds.
        """
        self.verbose = verbose
        self.apk = None
        self.dalvik_files = []
        self.analysis = None
        self.confidence_threshold = 0.3
    
    def load_apk(self, apk_path: str) -> bool:
        """
        Purpose:
            Load an APK for analysis.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            True when the APK loaded.

        Side effects:
            Parses the APK and configures androguard logging process-wide.

        Implementation notes:
            Returns False rather than raising on every failure, including androguard being absent, because a detector that cannot load the APK should report no detection rather than abort the scan.

        Security considerations:
            androguard is parsing an attacker-supplied archive here, which is why the call is guarded rather than trusted.
        """
        verbose_print(f"Attempting to load APK: {apk_path}", self.verbose)
        
        if not ANDROGUARD_AVAILABLE:
            verbose_print("Androguard not available - cannot load APK", self.verbose)
            return False
            
        try:
            from ..detection.extractors.logging_config import setup_androguard_logging
            setup_androguard_logging(self.verbose)
            self.apk, self.dalvik_files, self.analysis = AnalyzeAPK(apk_path)
            verbose_print(f"Loaded APK with {len(self.dalvik_files)} dalvik files", self.verbose)
            return True
        except Exception as e:
            verbose_print(f"Error loading APK: {e}", self.verbose)
            return False
    
    def get_apk_files(self) -> list:
        """
        Purpose:
            List the entries inside the APK.

        Returns:
            Entry names, empty when the APK is not loaded or listing failed.

        Implementation notes:
            File names alone identify several frameworks outright -- a Flutter app ships libflutter.so, a Cordova app ships a www directory -- which is why the file list is part of the searched blob.
        """
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
        """
        Purpose:
            List the class names defined in the APK's DEX files.

        Returns:
            Class names, empty when nothing is loaded or extraction failed.

        Implementation notes:
            Class names are strong framework evidence because a framework's runtime classes are present under recognisable package prefixes regardless of how the app's own code is obfuscated.

        Known limitations:
            The loop iterates the DEX files but reads classes from the whole-APK analysis each time, so with multiple DEX files the same class list is appended once per file. Duplicates inflate the list length but do not change what a substring search finds, which is why this has not affected detection results.
        """
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
        """
        Purpose:
            Extract the string constants from the APK's DEX files.

        Returns:
            Unique strings, empty when nothing is loaded.

        Implementation notes:
            Collected as a set, both to bound the size -- a large app has hundreds of thousands of strings, many repeated -- and because the blob is only ever substring-searched, so duplicates add nothing.

        Security considerations:
            These are attacker-controlled constants from the app and are only ever matched against, never interpreted.
        """
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
        """
        Purpose:
            Retrieve the manifest as text for searching.

        Returns:
            The manifest as a string, empty when unavailable.

        Implementation notes:
            Stringified rather than traversed, because it is only used for substring matching here. Structured manifest access belongs to the manifest parser.
        """
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
        """
        Purpose:
            Resolve a string resource reference to its text.

        Parameters:
            resource_ref: A reference, or plain text.

        Returns:
            The resolved text, or the original value when it is not a reference or could not be resolved.

        Implementation notes:
            Every failure path returns something displayable rather than None, so callers can use the result directly in a report.
        """
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
        """
        Purpose:
            Score an app against a framework's weighted indicator table.

        Parameters:
            framework_name: Framework being scored.
            indicators: Marker substrings mapped to their weights.
            content: The combined content blob to search.

        Returns:
            The score, carrying the weighted total, the normalised confidence and the markers found.

        Complexity:
            O(n * m) for blob length n and indicator count m.

        Implementation notes:
            Weights let a detector distinguish a decisive marker from a suggestive one. A bundled framework runtime library is near-conclusive; a mention of the framework's name in a string is not, and equal weighting would let a dozen weak hints outvote one strong one. Confidence is the fraction of the achievable total rather than the raw score, which is what makes detectors with tables of different sizes directly comparable. A zero-weight table yields zero confidence rather than dividing by zero. The markers found are retained, not just counted, so the report can show why a framework was chosen rather than asserting it.
        """
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
        """
        Purpose:
            Summarise a source project's shape -- platform folders, source file counts by language, native libraries and build configuration files.

        Parameters:
            project_path: Path to the project root.

        Returns:
            The structure summary, with every key present.

        Side effects:
            Walks the project tree.

        Implementation notes:
            For a project, layout is a stronger signal than content: a Flutter project has a pubspec and Dart files, a React Native one has a package.json and JavaScript. Counting by extension answers that directly. On failure the partially-filled structure is returned rather than None, so every key is always present and callers need no guards.

        Known limitations:
            Recursive globs traverse the whole tree, including node_modules and build output, which is slow on a large project and inflates the JavaScript count considerably.
        """
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
            
            verbose_print("Checking for platform folders", self.verbose)
            structure['has_android_folder'] = (project / 'android').exists()
            structure['has_ios_folder'] = (project / 'ios').exists()
            verbose_print(f"Android folder: {structure['has_android_folder']}", self.verbose)
            verbose_print(f"iOS folder: {structure['has_ios_folder']}", self.verbose)
            
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
        """
        Purpose:
            Produce the searchable content blob for either an APK or a project.

        Parameters:
            input_path: Path to an APK file or a project directory.

        Returns:
            The combined content, empty when the path is neither.

        Implementation notes:
            Dispatch checks the filesystem rather than trusting the extension alone, so a directory named with an apk suffix does not take the wrong path.
        """
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
        """
        Purpose:
            Build the content blob from an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            File names, class names, strings and the manifest joined into one blob.

        Side effects:
            Loads and parses the APK.

        Implementation notes:
            All four sources are concatenated because a framework marker can appear in any of them, and searching one combined blob is far cheaper than searching four collections separately for every indicator of every detector.

        Known limitations:
            The blob for a large app is very large, since it contains every DEX string. It is built once per detector rather than shared, so a full detection pass rebuilds it repeatedly.
        """
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
        """
        Purpose:
            Build the content blob from a source project.

        Parameters:
            project_path: Path to the project root.

        Returns:
            Relative file paths and build configuration contents joined into one blob.

        Side effects:
            Walks the tree and reads the configuration files.

        Implementation notes:
            File paths carry most of the signal for a project, so they form the bulk of the blob. The build configuration files are read in full because they name the framework's own dependencies, which is the most direct evidence available. An unreadable configuration file is skipped rather than aborting, so one permissions problem does not lose the whole blob.
        """
        verbose_print(f"Starting project content extraction from: {project_path}", self.verbose)
        content_parts = []
        
        try:
            project = Path(project_path)
            verbose_print(f"Project path validated: {project.exists()}", self.verbose)
            
            verbose_print("Collecting all file paths", self.verbose)
            all_files = [str(f.relative_to(project)) for f in project.rglob('*') if f.is_file()]
            verbose_print(f"Found {len(all_files)} files in project", self.verbose)
            content_parts.extend(all_files)
            
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
