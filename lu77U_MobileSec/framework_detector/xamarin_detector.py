"""Xamarin Framework Detector for lu77U-MobileSec"""

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
    """Detector for Xamarin framework"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = "Xamarin"
        self.apk_indicators = XAMARIN_APK_INDICATORS
        self.project_files = XAMARIN_PROJECT_FILES
        self.project_extensions = XAMARIN_PROJECT_EXTENSIONS
    
    def detect(self, input_path: str):
        """Detect Xamarin framework in APK or project directory"""
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - Xamarin detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """Detect Xamarin framework in project directory"""
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
        """Detect Xamarin framework in APK file"""
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