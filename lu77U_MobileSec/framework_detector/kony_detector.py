#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.kony_detector

Purpose:
    Recognise a Kony Visualizer app, an enterprise cross-platform framework whose logic lives in bundled JavaScript, so that the right decompiler and analyzer are chosen for it.

Responsibilities:
    Detect the framework in an APK by its bundled artifacts, and in a project by its directory layout.

Dependencies:
    zipfile, pathlib, ..config.constants for the indicator tables.

Implementation notes:
    Kony is uncommon enough that its artifacts are highly distinctive, so a small number of markers is strong evidence. It matters to detect because a Kony app's Dalvik code is entirely framework: decompiling it and analysing the result would produce a confident report about none of the application's actual logic. The indicator tables live in config rather than here, so adding a marker for a new version of the framework is a data change.
"""

import os
import zipfile
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config.constants import (
    KONY_APK_INDICATORS,
    KONY_PROJECT_INDICATORS,
    KONY_PROJECT_FILES
)

class KonyDetector:
    """
    Purpose:
        Detects Kony Visualizer in an APK or a project.

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

        Implementation notes:
            The APK indicator table is assigned twice from the same constant, which is redundant but harmless.
        """
        self.verbose = verbose
        self.framework_name = "Kony Visualizer"
        self.apk_indicators = KONY_APK_INDICATORS
        self.apk_indicators = KONY_APK_INDICATORS
        self.project_indicators = KONY_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Kony Visualizer in an APK or a project.

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
            verbose_print("Input is neither an APK file nor a directory - Kony detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """
        Purpose:
            Detect a Kony project by the directories a project of that kind contains.

        Parameters:
            project_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Confidence starts at a base and rises with each additional indicator, capped below certainty. Finding one marker is suggestive; finding several together is what makes the identification safe, and no combination reaches absolute certainty because a project can be a template or a partial checkout. Indicators must be directories, matching the layout Kony Visualizer generates. Failures are swallowed and reported as no detection, so an unreadable project costs this framework's detection rather than the whole scan.
        """
        verbose_print(f"Scanning project directory for Kony Visualizer indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            for indicator in self.project_indicators:
                indicator_path = project_root / indicator.rstrip('/')
                
                if indicator_path.exists() and indicator_path.is_dir():
                    found_indicators.append(indicator)
                    verbose_print(f"Found Kony indicator: {indicator}", self.verbose)
            
            for file_indicator in self.project_files:
                file_path = project_root / file_indicator
                
                if file_path.exists():
                    found_indicators.append(file_indicator)
                    verbose_print(f"Found Kony indicator: {file_indicator}", self.verbose)
                else:
                    verbose_print(f"File indicator not found: {file_indicator}", self.verbose)
            
            verbose_print(f"Searching for Kony JavaScript files (kony*.js)", self.verbose)
            kony_js_files = list(project_root.rglob("kony*.js"))
            verbose_print(f"Found {len(kony_js_files)} Kony JavaScript files", self.verbose)
            if kony_js_files:
                found_indicators.append("kony*.js files")
                verbose_print(f"Found {len(kony_js_files)} Kony JavaScript files", self.verbose)
                verbose_print(f"Sample Kony JS files: {[f.name for f in kony_js_files[:3]]}", self.verbose)
            else:
                verbose_print(f"No Kony JavaScript files found", self.verbose)
            
            forms_dir = project_root / "forms"
            verbose_print(f"Looking for forms directory at: {forms_dir}", self.verbose)
            if forms_dir.exists() and forms_dir.is_dir():
                found_indicators.append("forms/")
                verbose_print("Found forms directory (Kony project structure)", self.verbose)
            else:
                verbose_print("forms directory not found", self.verbose)
            
            verbose_print(f"Total indicators found: {len(found_indicators)}", self.verbose)
            if found_indicators:
                confidence = min(0.95, 0.7 + (len(found_indicators) * 0.05))
                verbose_print(f"Kony Visualizer detected in project with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': found_indicators,
                    'confidence': confidence
                }
            else:
                verbose_print("Kony Visualizer not detected in project", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error during Kony Visualizer project detection: {e}", self.verbose)
            return None
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect Kony Visualizer by the artifacts its runtime bundles into an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Only the archive's entry names are read; nothing is extracted. That keeps detection cheap enough to run every detector over every APK, and avoids writing attacker-controlled content to disk during detection. Markers are the framework's own runtime libraries and its bundled JavaScript payload, which is where the application logic actually lives.

        Security considerations:
            A malformed archive is caught and reported as no detection rather than propagating.
        """
        verbose_print(f"Scanning APK file for Kony Visualizer indicators", self.verbose)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                for indicator in self.apk_indicators:
                    matching_files = [f for f in file_names if indicator in f]
                    if matching_files:
                        found_indicators.append(indicator)
                        verbose_print(f"Found Kony indicator: {indicator}", self.verbose)
                        verbose_print(f"Matching files count: {len(matching_files)}", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.7 + (len(found_indicators) * 0.1))
                    verbose_print(f"Kony Visualizer detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                else:
                    verbose_print("Kony Visualizer not detected in APK", self.verbose)
                    return None
                    
        except Exception as e:
            verbose_print(f"Error during Kony Visualizer APK detection: {e}", self.verbose)
            return None
