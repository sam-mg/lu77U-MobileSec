"""Cordova Framework Detector for lu77U-MobileSec"""

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
    """Detector for Apache Cordova framework"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = "Cordova"
        self.apk_indicators = CORDOVA_APK_INDICATORS
        self.apk_class_indicators = CORDOVA_APK_CLASS_INDICATORS
        self.project_indicators = CORDOVA_PROJECT_INDICATORS
    
    def detect(self, input_path: str):
        """Detect Cordova framework in APK or project directory"""
        if os.path.isdir(input_path):
            return self._detect_in_project(input_path)
        elif input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            verbose_print("Input is neither an APK file nor a directory - Cordova detection skipped", self.verbose)
            return None
    
    def _detect_in_project(self, project_path: str):
        """Detect Cordova framework in project directory"""
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
        """Detect Cordova framework in APK file"""
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