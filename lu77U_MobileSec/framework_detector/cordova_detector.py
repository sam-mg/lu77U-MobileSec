#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.cordova_detector

Purpose:
    Recognise a Cordova or PhoneGap app, whose logic lives in bundled web assets rather than in Dalvik bytecode, so that the right decompiler and analyzer are chosen for it.

Responsibilities:
    Detect the framework in an APK by its bundled artifacts, and in a project by its directory layout.

Dependencies:
    zipfile, pathlib, ..config.constants for the indicator tables.

Implementation notes:
    Cordova leaves two independent traces: the bridge classes in the DEX, and a www directory of HTML and JavaScript in the assets. Either alone is suggestive -- another framework may embed a WebView, and any app may ship HTML -- while both together are close to conclusive, which is why the confidence bands differ for the two cases. The indicator tables live in config rather than here, so adding a marker for a new version of the framework is a data change.

Security considerations:
    The bundled web assets are the application's actual source and are attacker-controlled. Detection only counts and names them; extracting them is the analyzer's job.
"""

import os
import zipfile
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config.constants import (
    CORDOVA_APK_INDICATORS,
    CORDOVA_APK_CLASS_INDICATORS,
    CORDOVA_PROJECT_INDICATORS
)

class CordovaDetector:
    """
    Purpose:
        Detects Cordova in an APK or a project.

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
        self.framework_name = "Cordova"
        self.apk_indicators = CORDOVA_APK_INDICATORS
        self.apk_class_indicators = CORDOVA_APK_CLASS_INDICATORS
        self.project_indicators = CORDOVA_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Cordova in an APK or a project.

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
            verbose_print("Input is neither an APK file nor a directory - Cordova detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """
        Purpose:
            Detect a Cordova project by the directories a project of that kind contains.

        Parameters:
            project_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Confidence starts at a base and rises with each additional indicator, capped below certainty. Finding one marker is suggestive; finding several together is what makes the identification safe, and no combination reaches absolute certainty because a project can be a template or a partial checkout. Each indicator is a path that exists or does not, so a project is identified by its shape rather than by reading any file. Failures are swallowed and reported as no detection, so an unreadable project costs this framework's detection rather than the whole scan.
        """
        verbose_print(f"Scanning project directory for Cordova indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            for indicator in self.project_indicators:
                indicator_path = project_root / indicator
                
                if indicator_path.exists():
                    found_indicators.append(indicator)
                    verbose_print(f"Found Cordova indicator: {indicator}", self.verbose)
            
            verbose_print(f"Total indicators found: {len(found_indicators)}", self.verbose)
            if found_indicators:
                confidence = min(0.95, 0.6 + (len(found_indicators) * 0.1))
                verbose_print(f"Cordova detected in project with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': found_indicators,
                    'confidence': confidence
                }
            else:
                verbose_print("Cordova not detected in project", self.verbose)
                return None
                
        except Exception as e:
            verbose_print(f"Error during Cordova project detection: {e}", self.verbose)
            return None
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect Cordova by the bridge classes and web assets bundled into an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Three kinds of evidence are gathered: entry-name markers, Cordova's own bridge class names, and the presence of a populated web asset directory. The web asset check requires at least one HTML file, not merely the directory, because an empty assets directory proves nothing. The counts of HTML and JavaScript files are recorded in the indicator text so the report shows how substantial the web layer is. Confidence is banded rather than accumulated linearly: finding both the bridge classes and the web assets starts much higher than finding either alone, because the combination is what distinguishes Cordova from an app that merely embeds a WebView. Only entry names are read; nothing is extracted.

        Security considerations:
            A malformed archive is caught and reported as no detection rather than propagating.
        """
        verbose_print(f"Scanning APK file for Cordova indicators", self.verbose)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                
                for indicator in self.apk_indicators:
                    matching_files = [f for f in file_names if indicator in f]
                    if matching_files:
                        found_indicators.append(indicator)
                        verbose_print(f"Found Cordova indicator: {indicator}", self.verbose)
                
                for class_indicator in self.apk_class_indicators:
                    class_path = class_indicator + ".class"
                    if any(class_path in f or class_indicator in f for f in file_names):
                        found_indicators.append(f"class:{class_indicator}")
                        verbose_print(f"Found Cordova class: {class_indicator}", self.verbose)
                
                www_files = [f for f in file_names if f.startswith('assets/www/')]
                if www_files:
                    html_count = len([f for f in www_files if f.endswith('.html')])
                    js_count = len([f for f in www_files if f.endswith('.js')])
                    css_count = len([f for f in www_files if f.endswith('.css')])
                    
                    if html_count > 0:
                        found_indicators.append(f"www_structure({html_count} HTML, {js_count} JS)")
                        verbose_print(f"Found www structure: {html_count} HTML, {js_count} JS, {css_count} CSS", self.verbose)
                
                if found_indicators:
                    has_www = any('www' in ind for ind in found_indicators)
                    has_classes = any('class:' in ind for ind in found_indicators)
                    
                    if has_www and has_classes:
                        confidence = min(0.98, 0.85 + (len(found_indicators) * 0.02))
                    else:
                        confidence = min(0.9, 0.6 + (len(found_indicators) * 0.1))
                    
                    verbose_print(f"Cordova detected with {len(found_indicators)} indicators, confidence: {confidence:.2f}", self.verbose)
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                else:
                    verbose_print("Cordova not detected in APK", self.verbose)
                    return None
                    
        except Exception as e:
            verbose_print(f"Error during Cordova APK detection: {e}", self.verbose)
            return None
