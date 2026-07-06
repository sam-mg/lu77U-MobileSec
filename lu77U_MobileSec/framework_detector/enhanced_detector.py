"""Enhanced Framework Detector for lu77U-MobileSec"""

import zipfile
from typing import List, Dict, Optional
from ..utils.verbose import verbose_print
from ..config.constants import TECH_DETECTION_MAP, FRAMEWORK_JAVA

class EnhancedFrameworkDetector:
    """Detector for additional frameworks using zipfile-based APK inspection"""
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.supported_frameworks = list(TECH_DETECTION_MAP.keys())
    
    def detect(self, input_path: str) -> Optional[Dict]:
        if not input_path.endswith('.apk'):
            verbose_print("Input is not an APK file - enhanced detection skipped", self.verbose)
            return None
        
        detected_frameworks = self._detect_frameworks_in_apk(input_path)
        
        if not detected_frameworks:
            verbose_print("No additional frameworks detected", self.verbose)
            return None
        
        return self._format_detection_result(detected_frameworks)
    
    def _detect_frameworks_in_apk(self, apk_path: str) -> List[str]:
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
        if len(detected_frameworks) == 1:
            print(f"App was written in {detected_frameworks[0]}")
        else:
            print("App uses multiple frameworks:")
            for framework in detected_frameworks:
                print(f"- {framework}")