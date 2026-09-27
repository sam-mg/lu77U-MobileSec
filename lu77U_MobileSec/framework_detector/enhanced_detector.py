#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.enhanced_detector

Purpose:
    A single table-driven sweep for every framework at once, used as a broad second opinion alongside the specific detectors.

Responsibilities:
    Match the shared marker table against an APK's entry names, and format the result.

Dependencies:
    zipfile, ..config.constants for the shared marker table.

Implementation notes:
    Where each specific detector encodes its own knowledge, this one is purely the shared table applied uniformly. That makes it weaker per framework -- it has no notion of a framework's stronger and weaker markers -- but it covers every framework in one archive read, and it picks up a framework whose dedicated detector missed. APKs only. A project has no bundled artifacts to match, and its layout is what the specific detectors read.
"""

import zipfile
from typing import List, Dict, Optional
from ..utils.verbose import verbose_print
from ..config.constants import TECH_DETECTION_MAP, FRAMEWORK_JAVA

class EnhancedFrameworkDetector:
    """
    Purpose:
        Detects any framework in the shared marker table from an APK's entry names.

    Attributes:
        verbose: Whether detection is traced.
        supported_frameworks: Every framework the shared table covers.

    Invariants:
        Returns None for anything that is not an APK.

    Thread-safety:
        Holds no per-detection state; safe to reuse.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct the detector from the shared marker table.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        self.supported_frameworks = list(TECH_DETECTION_MAP.keys())
    
    def detect(self, input_path: str) -> Optional[Dict]:
        """
        Purpose:
            Detect frameworks in an APK using the shared table.

        Parameters:
            input_path: Path to an APK.

        Returns:
            A detection dict, or None for a non-APK input or when nothing matched.
        """
        if not input_path.endswith('.apk'):
            verbose_print("Input is not an APK file - enhanced detection skipped", self.verbose)
            return None
        
        detected_frameworks = self._detect_frameworks_in_apk(input_path)
        
        if not detected_frameworks:
            verbose_print("No additional frameworks detected", self.verbose)
            return None
        
        return self._format_detection_result(detected_frameworks)
    
    def _detect_frameworks_in_apk(self, apk_path: str) -> List[str]:
        """
        Purpose:
            Find every framework in the shared table whose markers appear in an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            Framework names, in table order; empty on any failure.

        Side effects:
            Opens the APK as a zip archive.

        Complexity:
            O(f * i * n) for f frameworks, i indicators each and n entries, with an early exit per indicator.

        Implementation notes:
            The inner loop breaks on the first entry matching an indicator, so a framework with many matching files costs no more than one with a single match. A framework qualifies on any single indicator, which is why this detector is broad rather than precise. The hybrid arbitrator is what reconciles its results against the specific detectors. Missing files and malformed archives return an empty list rather than raising, so a bad APK costs this detector's opinion rather than the detection stage.
        """
        detected_frameworks = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                for framework_name, indicators in TECH_DETECTION_MAP.items():
                    found_indicators = []
                    for indicator in indicators:
                        for file_name in file_names:
                            if indicator in file_name:
                                found_indicators.append(indicator)
                                break
                    
                    if found_indicators:
                        verbose_print(f"{framework_name} detected with {len(found_indicators)} indicators", self.verbose)
                        detected_frameworks.append(framework_name)
                
        except FileNotFoundError:
            verbose_print(f"File not found: {apk_path}", self.verbose)
            return []
        except zipfile.BadZipFile:
            verbose_print(f"Invalid APK/zip file: {apk_path}", self.verbose)
            return []
        except Exception as e:
            verbose_print(f"Error during APK inspection: {e}", self.verbose)
            return []
        
        verbose_print(f"Detection complete. Found {len(detected_frameworks)} frameworks", self.verbose)
        return detected_frameworks
    
    def _format_detection_result(self, detected_frameworks: List[str]) -> Dict:
        """
        Purpose:
            Turn a list of detected framework names into a single detection dict.

        Parameters:
            detected_frameworks: Framework names found.

        Returns:
            A detection dict, or None for an empty list.

        Implementation notes:
            Multiple detections report slightly lower confidence than a single one, since several frameworks matching at once more often means loose markers than a genuinely multi-framework app. The primary framework is simply the first in table order, not the strongest -- this detector has no per-framework weighting to rank by. The rest are carried as additional frameworks so the information is not lost, and the hybrid arbitrator does the real ranking using the specific detectors' confidences.
        """
        if len(detected_frameworks) == 1:
            framework = detected_frameworks[0]
            verbose_print(f"Single framework detected: {framework}", self.verbose)
            return {
                'framework': framework,
                'indicators': [f'APK contains {framework} artifacts'],
                'confidence': 0.9
            }
        elif len(detected_frameworks) > 1:
            verbose_print(f"Multiple frameworks detected: {detected_frameworks}", self.verbose)
            primary_framework = detected_frameworks[0]
            return {
                'framework': primary_framework,
                'indicators': [f'APK contains {fw} artifacts' for fw in detected_frameworks],
                'confidence': 0.85,
                'additional_frameworks': detected_frameworks[1:]
            }
        
        return None
    
    def detect_all_frameworks(self, apk_path: str) -> List[str]:
        """
        Purpose:
            List every framework detected in an APK, defaulting to a conventional Android app when none matched.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            Framework names; the Java framework name when nothing matched.

        Implementation notes:
            The default is the useful part: an APK matching no cross-platform marker is a conventional Android app, which is the correct conclusion rather than an absence of one. A non-APK input returns empty rather than the default, since nothing was examined and no conclusion is warranted.
        """
        verbose_print(f"Detecting all frameworks in: {apk_path}", self.verbose)
        
        if not apk_path.endswith('.apk'):
            verbose_print("Not an APK file - returning empty list", self.verbose)
            return []
        
        detected = self._detect_frameworks_in_apk(apk_path)
        
        if not detected:
            verbose_print("No specific frameworks detected - likely native", self.verbose)
            return [FRAMEWORK_JAVA]
        
        return detected
    
    def print_detection_results(self, detected_frameworks: List[str]):
        """
        Purpose:
            Print detected frameworks to the terminal.

        Parameters:
            detected_frameworks: Framework names to print.

        Side effects:
            Writes to stdout.

        Implementation notes:
            Prints unconditionally rather than through the verbose stream, so it is a debugging aid rather than part of the normal output path.
        """
        if len(detected_frameworks) == 1:
            print(f"App was written in {detected_frameworks[0]}")
        else:
            print("App uses multiple frameworks:")
            for framework in detected_frameworks:
                print(f"- {framework}")
