"""Java Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
from ..config.constants import (
    FRAMEWORK_JAVA,
    FRAMEWORK_FLUTTER,
    FRAMEWORK_REACT_NATIVE,
    FRAMEWORK_UNITY,
    FRAMEWORK_UNREAL,
    TECH_DETECTION_MAP
)
import os
import zipfile

class JavaDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = FRAMEWORK_JAVA
    
    def detect(self, input_path: str):
        
        if input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            return self._detect_in_project(input_path)
    
    def _detect_in_apk(self, apk_path: str):
        """Detect Java/Kotlin in APK by analyzing DEX files and structure"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                dex_files = [f for f in file_names if f.startswith('classes') and f.endswith('.dex')]
                
                flutter_indicators = TECH_DETECTION_MAP[FRAMEWORK_FLUTTER]
                has_flutter = any(indicator in f for f in file_names for indicator in flutter_indicators)
                
                rn_indicators = TECH_DETECTION_MAP[FRAMEWORK_REACT_NATIVE]
                has_react_native = any(indicator in f for f in file_names for indicator in rn_indicators)
                
                unity_indicators = TECH_DETECTION_MAP[FRAMEWORK_UNITY]
                has_unity = any(indicator in f for f in file_names for indicator in unity_indicators)
                
                unreal_indicators = TECH_DETECTION_MAP[FRAMEWORK_UNREAL]
                has_unreal = any(indicator in f for f in file_names for indicator in unreal_indicators)
                
                if dex_files and not (has_flutter or has_react_native or has_unity or has_unreal):
                    indicators = [f'DEX files: {len(dex_files)} found']
                    
                    has_kotlin = any('kotlin' in f.lower() for f in file_names)
                    if has_kotlin:
                        indicators.append('Kotlin runtime detected')
                    
                    verbose_print(f"Java/Kotlin APK detected with {len(dex_files)} DEX files", self.verbose)
                    
                    return {
                        'framework': self.framework_name,
                        'indicators': indicators,
                        'confidence': 0.8
                    }
                
                return None
                
        except (FileNotFoundError, zipfile.BadZipFile) as e:
            verbose_print(f"Error reading APK: {e}", self.verbose)
            return None
    
    def _detect_in_project(self, input_path: str):
        """Detect Java in project directory"""
        indicators = []
        confidence = 0.0
        
        if os.path.isdir(input_path):
            
            android_structure = [
                'AndroidManifest.xml', 'src/main/java', 'app/src/main/java',
                'res/', 'app/src/main/res'
            ]
            build_files = [
                'build.gradle', 'app/build.gradle', 
                'build.gradle.kts', 'app/build.gradle.kts',
                'gradle.properties'
            ]
            
            for indicator in android_structure:
                full_path = os.path.join(input_path, indicator)
                if os.path.exists(full_path):
                    indicators.append(indicator)
                    confidence += 0.3
                    verbose_print(f"Found Android structure indicator: {indicator}", self.verbose)
            
            for build_file in build_files:
                full_path = os.path.join(input_path, build_file)
                if os.path.exists(full_path):
                    indicators.append(build_file)
                    confidence += 0.2
                    verbose_print(f"Found build file: {build_file}", self.verbose)
            
            java_files_found = []
            search_dirs = [
                os.path.join(input_path, 'src/main/java'),
                os.path.join(input_path, 'app/src/main/java')
            ]
            
            for search_dir in search_dirs:
                if os.path.exists(search_dir):
                    file_count = 0
                    for root, dirs, files in os.walk(search_dir):
                        for file in files:
                            if file.endswith('.java'):
                                java_files_found.append(file)
                                file_count += 1
                                if len(java_files_found) >= 3:
                                    break
                        if len(java_files_found) >= 3:
                            break
            
            if java_files_found:
                source_indicator = f'Java source files: {", ".join(java_files_found[:3])}{"..." if len(java_files_found) > 3 else ""}'
                indicators.append(source_indicator)
                confidence += 0.5
                verbose_print(f"Found {len(java_files_found)} Java source files", self.verbose)
        
        if indicators:
            confidence = min(confidence, 1.0)
            verbose_print(f"Java indicators found: {len(indicators)}, confidence: {confidence}", self.verbose)
            
            return {
                'framework': self.framework_name,
                'indicators': indicators,
                'confidence': confidence
            }
        
        return None
