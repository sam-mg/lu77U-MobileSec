"""Kony Visualizer Framework Detector for lu77U-MobileSec"""

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
    """Detector for Kony Visualizer framework"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = "Kony Visualizer"
        self.apk_indicators = KONY_APK_INDICATORS
        self.apk_indicators = KONY_APK_INDICATORS
        self.project_indicators = KONY_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """Detect Kony Visualizer framework in APK or project directory"""
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - Kony detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """Detect Kony Visualizer framework in project directory"""
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
        """Detect Kony Visualizer framework in APK file"""
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