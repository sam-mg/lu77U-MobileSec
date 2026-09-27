#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.libgdx_detector

Purpose:
    Recognise a LibGDX game, which is Java but built on a game framework with its own native backends, so that the right decompiler and analyzer are chosen for it.

Responsibilities:
    Detect the framework in an APK by its bundled artifacts, and in a project by its directory layout.

Dependencies:
    zipfile, pathlib, ..config.constants for the indicator tables.

Implementation notes:
    LibGDX is the awkward case among the game frameworks: the game logic genuinely is Java and decompiles normally, so recognising it changes how the app is described and which code is treated as application rather than framework, not which decompiler runs. The indicator tables live in config rather than here, so adding a marker for a new version of the framework is a data change.
"""

import os
import zipfile
from pathlib import Path
from ..config.constants import (
    LIBGDX_APK_INDICATORS,
    LIBGDX_PROJECT_INDICATORS,
    LIBGDX_GRADLE_KEYWORDS
)
from ..utils.verbose import verbose_print

class LibGDXDetector:
    """
    Purpose:
        Detects LibGDX in an APK or a project.

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
        self.framework_name = "LibGDX"
        self.apk_indicators = LIBGDX_APK_INDICATORS
        self.project_indicators = LIBGDX_PROJECT_INDICATORS
        self.gradle_keywords = LIBGDX_GRADLE_KEYWORDS
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect LibGDX in an APK or a project.

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
            verbose_print("Input is neither an APK file nor a directory - LibGDX detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """
        Purpose:
            Detect a LibGDX project by the directories a project of that kind contains.

        Parameters:
            project_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Confidence starts at a base and rises with each additional indicator, capped below certainty. Finding one marker is suggestive; finding several together is what makes the identification safe, and no combination reaches absolute certainty because a project can be a template or a partial checkout. Indicators must be directories. The per-indicator increment is smaller than the other game detectors use, because LibGDX project layouts overlap heavily with ordinary Gradle multi-module projects and each individual marker is weaker evidence. Failures are swallowed and reported as no detection, so an unreadable project costs this framework's detection rather than the whole scan.
        """
        verbose_print(f"Scanning project directory for LibGDX indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            for indicator in self.project_indicators:
                indicator_path = project_root / indicator.rstrip('/')
                
                if indicator_path.exists() and indicator_path.is_dir():
                    found_indicators.append(indicator)
                    verbose_print(f"Found LibGDX indicator: {indicator}", self.verbose)
            
            gradle_files = list(project_root.rglob("build.gradle*"))
            for gradle_file in gradle_files:
                try:
                    content = gradle_file.read_text(encoding='utf-8', errors='ignore')
                    verbose_print(f"Read {len(content)} characters from {gradle_file.name}", self.verbose)
                    for keyword in self.gradle_keywords:
                        verbose_print(f"Checking for keyword: {keyword}", self.verbose)
                        if keyword in content:
                            found_indicators.append(f"build.gradle ({keyword})")
                            verbose_print(f"Found LibGDX keyword in gradle: {keyword}", self.verbose)
                            break
                    else:
                        verbose_print(f"No LibGDX keywords found in {gradle_file.name}", self.verbose)
                except Exception as e:
                    verbose_print(f"Error reading gradle file {gradle_file.name}: {e}", self.verbose)
            
            verbose_print(f"Checking for gradle wrapper files", self.verbose)
            gradlew_path = project_root / "gradlew"
            gradlew_bat_path = project_root / "gradlew.bat"
            if gradlew_path.exists() or gradlew_bat_path.exists():
                verbose_print("Found gradle wrapper (common in LibGDX projects)", self.verbose)
            else:
                verbose_print("No gradle wrapper found", self.verbose)
            
            verbose_print(f"Total indicators found: {len(found_indicators)}", self.verbose)
            if found_indicators:
                confidence = min(0.95, 0.7 + (len(found_indicators) * 0.06))
                verbose_print(f"LibGDX detected in project with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': found_indicators,
                    'confidence': confidence
                }
            else:
                verbose_print("LibGDX not detected in project", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error during LibGDX project detection: {e}", self.verbose)
            return None
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect LibGDX by the artifacts its runtime bundles into an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Only the archive's entry names are read; nothing is extracted. That keeps detection cheap enough to run every detector over every APK, and avoids writing attacker-controlled content to disk during detection. Markers are the framework's native backend libraries and its bundled asset conventions, both of which survive obfuscation of the game's own Java code.

        Security considerations:
            A malformed archive is caught and reported as no detection rather than propagating.
        """
        verbose_print(f"Scanning APK file for LibGDX indicators", self.verbose)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                for indicator in self.apk_indicators:
                    matching_files = [f for f in file_names if indicator in f]
                    if matching_files:
                        found_indicators.append(indicator)
                        verbose_print(f"Found LibGDX indicator: {indicator}", self.verbose)
                        verbose_print(f"Matching files count: {len(matching_files)}", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.7 + (len(found_indicators) * 0.1))
                    verbose_print(f"LibGDX detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                else:
                    verbose_print("LibGDX not detected in APK", self.verbose)
                    return None
                    
        except Exception as e:
            verbose_print(f"Error during LibGDX APK detection: {e}", self.verbose)
            return None
