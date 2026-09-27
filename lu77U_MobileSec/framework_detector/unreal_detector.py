#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.unreal_detector

Purpose:
    Recognise an Unreal Engine game, whose logic is in compiled native code and engine assets rather than in Dalvik bytecode, so that the right decompiler and analyzer are chosen for it.

Responsibilities:
    Detect the framework in an APK by its bundled artifacts, and in a project by its directory layout.

Dependencies:
    zipfile, pathlib, ..config.constants for the indicator tables.

Implementation notes:
    Unreal is recognised by the engine's own native libraries and its packaged asset files, which are present in every Unreal build regardless of what the game does. The indicator tables live in config rather than here, so adding a marker for a new version of the framework is a data change.
"""

import os
import zipfile
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config.constants import (
    UNREAL_APK_INDICATORS,
    UNREAL_PROJECT_INDICATORS
)

class UnrealDetector:
    """
    Purpose:
        Detects Unreal Engine in an APK or a project.

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
        self.framework_name = "Unreal Engine"
        self.apk_indicators = UNREAL_APK_INDICATORS
        self.project_indicators = UNREAL_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Unreal Engine in an APK or a project.

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
            verbose_print("Input is neither an APK file nor a directory - Unreal detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """
        Purpose:
            Detect an Unreal project by the directories a project of that kind contains.

        Parameters:
            project_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Confidence starts at a base and rises with each additional indicator, capped below certainty. Finding one marker is suggestive; finding several together is what makes the identification safe, and no combination reaches absolute certainty because a project can be a template or a partial checkout. Indicators must be directories, so a stray file sharing a name with an engine directory does not count. Failures are swallowed and reported as no detection, so an unreadable project costs this framework's detection rather than the whole scan.
        """
        verbose_print(f"Scanning project directory for Unreal Engine indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            uproject_files = list(project_root.glob("*.uproject"))
            if uproject_files:
                found_indicators.append("*.uproject")
                verbose_print(f"Found Unreal project file: {uproject_files[0].name}", self.verbose)
            
            for indicator in self.project_indicators:
                indicator_path = project_root / indicator.rstrip('/')
                
                if indicator_path.exists() and indicator_path.is_dir():
                    found_indicators.append(indicator)
                    verbose_print(f"Found Unreal Engine indicator: {indicator}", self.verbose)
            
            config_file = project_root / "Config" / "DefaultEngine.ini"
            if config_file.exists():
                found_indicators.append("Config/DefaultEngine.ini")
                verbose_print(f"Found Unreal Engine config file", self.verbose)
            else:
                verbose_print(f"DefaultEngine.ini not found", self.verbose)
            
            verbose_print(f"Total indicators found: {len(found_indicators)}", self.verbose)
            if found_indicators:
                confidence = min(0.98, 0.75 + (len(found_indicators) * 0.05))
                verbose_print(f"Unreal Engine detected in project with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': found_indicators,
                    'confidence': confidence
                }
            else:
                verbose_print("Unreal Engine not detected in project", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error during Unreal Engine project detection: {e}", self.verbose)
            return None
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect Unreal Engine by the artifacts its runtime bundles into an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Only the archive's entry names are read; nothing is extracted. That keeps detection cheap enough to run every detector over every APK, and avoids writing attacker-controlled content to disk during detection. Confidence starts high because the engine's artifacts are distinctively named, and rises with each additional marker found.

        Security considerations:
            A malformed archive is caught and reported as no detection rather than propagating.
        """
        verbose_print(f"Scanning APK file for Unreal Engine indicators", self.verbose)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                for indicator in self.apk_indicators:
                    matching_files = [f for f in file_names if indicator in f]
                    if matching_files:
                        found_indicators.append(indicator)
                        verbose_print(f"Found Unreal Engine indicator: {indicator}", self.verbose)
                        verbose_print(f"Matching files count: {len(matching_files)}", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.75 + (len(found_indicators) * 0.1))
                    verbose_print(f"Unreal Engine detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                else:
                    verbose_print("Unreal Engine not detected in APK", self.verbose)
                    return None
                    
        except Exception as e:
            verbose_print(f"Error during Unreal Engine APK detection: {e}", self.verbose)
            return None
