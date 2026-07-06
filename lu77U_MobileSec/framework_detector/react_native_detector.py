"""React Native Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
from ..config.constants import FRAMEWORK_REACT_NATIVE, TECH_DETECTION_MAP
import os
import zipfile

class ReactNativeDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = FRAMEWORK_REACT_NATIVE
        self.apk_indicators = TECH_DETECTION_MAP[FRAMEWORK_REACT_NATIVE]
    
    def detect(self, input_path: str):
        
        if input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            return self._detect_in_project(input_path)
    
    def _detect_in_apk(self, apk_path: str):
        """Detect React Native in APK by checking for native libraries and bundles"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                
                rn_libs = [f for f in file_names if 'libreactnativejni.so' in f]
                if rn_libs:
                    found_indicators.append(f'libreactnativejni.so ({len(rn_libs)} architectures)')
                    verbose_print(f"Found React Native JNI library in {len(rn_libs)} architectures", self.verbose)
                
                js_bundles = [f for f in file_names if 'index.android.bundle' in f or 'index.bundle' in f]
                if js_bundles:
                    found_indicators.append('JavaScript bundle')
                    verbose_print("Found React Native JavaScript bundle", self.verbose)
                
                rn_assets = [f for f in file_names if f.startswith('assets/') and ('.bundle' in f or 'drawable-' in f)]
                if rn_assets:
                    found_indicators.append(f'React Native assets ({len(rn_assets)} files)')
                    verbose_print(f"Found {len(rn_assets)} React Native asset files", self.verbose)
                
                hermes_libs = [f for f in file_names if 'libhermes.so' in f or 'libjsi.so' in f]
                if hermes_libs:
                    found_indicators.append('Hermes engine')
                    verbose_print("Found Hermes JavaScript engine", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.8 + (len(found_indicators) * 0.05))
                    verbose_print(f"React Native detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    
                    return {
                        'framework': self.framework_name,
                        'indicators': found_indicators,
                        'confidence': confidence
                    }
                
                return None
                
        except (FileNotFoundError, zipfile.BadZipFile) as e:
            verbose_print(f"Error reading APK: {e}", self.verbose)
            return None
    
    def _detect_in_project(self, input_path: str):
        """Detect React Native in project directory"""
        
        if not os.path.isdir(input_path):
            verbose_print(f"Path is not a directory: {input_path}", self.verbose)
            return None
        
        primary_indicators = [
            'package.json', 'node_modules/react-native', 'metro.config.js'
        ]
        secondary_indicators = [
            'react-native.config.js', 'ios/Podfile'
        ]
        
        found_primary = []
        found_secondary = []
        
        for indicator in primary_indicators:
            full_path = os.path.join(input_path, indicator)
            if os.path.exists(full_path):
                verbose_print(f"Found primary indicator: {indicator}", self.verbose)
                found_primary.append(indicator)
        
        for indicator in secondary_indicators:
            full_path = os.path.join(input_path, indicator)
            if os.path.exists(full_path):
                verbose_print(f"Found secondary indicator: {indicator}", self.verbose)
                found_secondary.append(indicator)
        
        if 'package.json' in found_primary:
            try:
                import json
                package_path = os.path.join(input_path, 'package.json')
                
                with open(package_path, 'r') as f:
                    package_data = json.load(f)
                    
                    dependencies = package_data.get('dependencies', {})
                    dev_dependencies = package_data.get('devDependencies', {})
                    
                    has_react_native = 'react-native' in dependencies or 'react-native' in dev_dependencies
                    
                    if has_react_native:
                        rn_version = dependencies.get('react-native') or dev_dependencies.get('react-native')
                        verbose_print(f"React Native dependency found with version: {rn_version}", self.verbose)
                    else:
                        verbose_print("No React Native dependency found in package.json", self.verbose)
                        found_primary.remove('package.json')
                        
            except (json.JSONDecodeError, FileNotFoundError, Exception) as e:
                verbose_print(f"Could not parse package.json: {e}", self.verbose)
                if 'package.json' in found_primary:
                    found_primary.remove('package.json')
        
        if found_primary:
            all_found = found_primary + found_secondary
            
            confidence = min(1.0, 0.7 + (len(all_found) * 0.1))
            verbose_print(f"React Native indicators found: {len(all_found)}, confidence: {confidence}", self.verbose)
            
            return {
                'framework': self.framework_name,
                'indicators': all_found,
                'confidence': confidence
            }
        
        return None