"""Unreal Engine Framework Detector for lu77U-MobileSec"""

import os
import zipfile
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config.constants import (
    UNREAL_APK_INDICATORS,
    UNREAL_PROJECT_INDICATORS
)

class UnrealDetector:
    """Detector for Unreal Engine framework"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = "Unreal Engine"
        self.apk_indicators = UNREAL_APK_INDICATORS
        self.project_indicators = UNREAL_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """Detect Unreal Engine framework in APK or project directory"""
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - Unreal detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """Detect Unreal Engine framework in project directory"""
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
        """Detect Unreal Engine framework in APK file"""
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