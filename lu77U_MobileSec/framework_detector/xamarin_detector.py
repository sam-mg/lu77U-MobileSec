#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.xamarin_detector

Purpose:
    Recognise a Xamarin or .NET MAUI app, whose logic is in managed .NET assemblies rather than in Dalvik bytecode, so that the right decompiler and analyzer are chosen for it.

Responsibilities:
    Detect the framework in an APK by its bundled artifacts, and in a project by its directory layout.

Dependencies:
    zipfile, pathlib, ..config.constants for the indicator tables.

Implementation notes:
    Xamarin bundles its assemblies inside the APK, sometimes compressed into a single blob. Recognising it routes the app to the .NET decompiler; analysing the Dalvik code instead would examine only the generated bindings and find nothing of the application. The indicator tables live in config rather than here, so adding a marker for a new version of the framework is a data change.

Security considerations:
    The bundled assemblies are attacker-controlled executable content. Detection reads only entry names and never extracts or loads an assembly.
"""

import os
import zipfile
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config.constants import (
    XAMARIN_APK_INDICATORS,
    XAMARIN_PROJECT_FILES,
    XAMARIN_PROJECT_EXTENSIONS
)

class XamarinDetector:
    """
    Purpose:
        Detects Xamarin in an APK or a project.

    Attributes:
        verbose: Whether detection is traced.
        framework_name: The framework name reported.
        apk_indicators: Markers looked for among APK entry names.
        project_indicators: Directories looked for in a project.

    Invariants:
        Returns None rather than a zero-confidence result when nothing matched.

    Thread-safety:
        Holds no per-detection state; safe to reuse.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct the detector and bind its indicator tables.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        self.framework_name = "Xamarin"
        self.apk_indicators = XAMARIN_APK_INDICATORS
        self.project_files = XAMARIN_PROJECT_FILES
        self.project_extensions = XAMARIN_PROJECT_EXTENSIONS
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Xamarin in an APK or a project.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            A detection dict with framework, indicators and confidence, or None.

        Implementation notes:
            The directory case is tested before the extension, so a directory is never misrouted to the archive path.
        """
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - Xamarin detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """
        Purpose:
            Detect a Xamarin project by the files and directories it contains.

        Parameters:
            project_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Indicators are interpreted by their spelling: one ending in a separator must be a directory, while the rest may be either. Xamarin projects are identified by a mix of both -- project directories and specific project files -- so a single rule would miss half the evidence. Confidence starts at a base and rises with each additional indicator, capped below certainty. Failures are swallowed and reported as no detection.
        """
        verbose_print(f"Scanning project directory for Xamarin indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            for indicator in self.project_files:
                
                if indicator.endswith('/'):
                    matches = list(project_root.rglob(indicator.rstrip('/')))
                    if matches:
                        found_indicators.append(indicator)
                        verbose_print(f"Found Xamarin indicator: {indicator}", self.verbose)
                else:
                    indicator_path = project_root / indicator
                    if indicator_path.exists():
                        found_indicators.append(indicator)
                        verbose_print(f"Found Xamarin indicator: {indicator}", self.verbose)
            
            verbose_print(f"Starting to check {len(self.project_extensions)} project extension types", self.verbose)
            for ext in self.project_extensions:
                verbose_print(f"Looking for files with extension: {ext}", self.verbose)
                matching_files = list(project_root.rglob(f"*{ext}"))
                verbose_print(f"Found {len(matching_files)} files with extension {ext}", self.verbose)
                if matching_files:
                    if ext == ".csproj":
                        verbose_print(f"Checking .csproj files for Xamarin references", self.verbose)
                        for file in matching_files:
                            verbose_print(f"Analyzing file: {file.name}", self.verbose)
                            try:
                                content = file.read_text(encoding='utf-8', errors='ignore')
                                verbose_print(f"Read {len(content)} characters from {file.name}", self.verbose)
                                if 'Xamarin' in content or 'Mono.Android' in content:
                                    found_indicators.append(f"Xamarin{ext}")
                                    verbose_print(f"Found Xamarin project file: {file.name}", self.verbose)
                                    break
                                else:
                                    verbose_print(f"No Xamarin references found in {file.name}", self.verbose)
                            except Exception as e:
                                verbose_print(f"Error reading {file.name}: {e}", self.verbose)
                    else:
                        found_indicators.append(f"*{ext}")
                        verbose_print(f"Found file with extension: {ext}", self.verbose)
                else:
                    verbose_print(f"No files found with extension: {ext}", self.verbose)
            
            verbose_print(f"Total indicators found: {len(found_indicators)}", self.verbose)
            if found_indicators:
                confidence = min(0.95, 0.7 + (len(found_indicators) * 0.05))
                verbose_print(f"Xamarin detected in project with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': found_indicators,
                    'confidence': confidence
                }
            else:
                verbose_print("Xamarin not detected in project", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error during Xamarin project detection: {e}", self.verbose)
            return None
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect Xamarin by the artifacts its runtime bundles into an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Only the archive's entry names are read; nothing is extracted. That keeps detection cheap enough to run every detector over every APK, and avoids writing attacker-controlled content to disk during detection. Markers are the Mono runtime libraries and the bundled assembly layout. The per-indicator increment is modest because these markers frequently appear together and would otherwise reach certainty on what is really a single piece of evidence.

        Security considerations:
            A malformed archive is caught and reported as no detection rather than propagating.
        """
        verbose_print(f"Scanning APK file for Xamarin indicators", self.verbose)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                for indicator in self.apk_indicators:
                    matching_files = [f for f in file_names if indicator in f]
                    if matching_files:
                        found_indicators.append(indicator)
                        verbose_print(f"Found Xamarin indicator: {indicator}", self.verbose)
                        verbose_print(f"Matching files count: {len(matching_files)}", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.7 + (len(found_indicators) * 0.05))
                    verbose_print(f"Xamarin detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                else:
                    verbose_print("Xamarin not detected in APK", self.verbose)
                    return None
                    
        except Exception as e:
            verbose_print(f"Error during Xamarin APK detection: {e}", self.verbose)
            return None
