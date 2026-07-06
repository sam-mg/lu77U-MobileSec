"""LibGDX Framework Detector for lu77U-MobileSec"""

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
    """Detector for LibGDX game framework"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = "LibGDX"
        # Import LibGDX indicators from constants
        self.apk_indicators = LIBGDX_APK_INDICATORS
        self.project_indicators = LIBGDX_PROJECT_INDICATORS
        self.gradle_keywords = LIBGDX_GRADLE_KEYWORDS
    
    def detect(self, input_path: str):
        """Detect LibGDX framework in APK or project directory"""
        # Check if input is a directory (project) or file (APK)
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - LibGDX detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """Detect LibGDX framework in project directory"""
        verbose_print(f"Scanning project directory for LibGDX indicators", self.verbose)
        
        try:
            found_indicators = []
            project_root = Path(project_path)
            
            # Check for LibGDX project structure (multi-module layout)
            for indicator in self.project_indicators:
                indicator_path = project_root / indicator.rstrip('/')
                
                if indicator_path.exists() and indicator_path.is_dir():
                    found_indicators.append(indicator)
                    verbose_print(f"Found LibGDX indicator: {indicator}", self.verbose)
            
            # Check build.gradle files for LibGDX dependencies
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
            
            # Check for gdx-setup tool files
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
        """Detect LibGDX framework in APK file"""
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