"""Flutter Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
from ..config.constants import FRAMEWORK_FLUTTER, TECH_DETECTION_MAP
import os
import zipfile

class FlutterDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.framework_name = FRAMEWORK_FLUTTER
        self.apk_indicators = TECH_DETECTION_MAP[FRAMEWORK_FLUTTER]
    
    def detect(self, input_path: str):
        
        if input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            return self._detect_in_project(input_path)
    
    def _detect_in_apk(self, apk_path: str):
        """Detect Flutter in APK by checking for libflutter.so"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zipObject:
                file_names = zipObject.namelist()
                
                found_indicators = []
                
                flutter_libs = [f for f in file_names if 'libflutter.so' in f]
                if flutter_libs:
                    found_indicators.append(f'libflutter.so ({len(flutter_libs)} architectures)')
                    verbose_print(f"Found Flutter native library in {len(flutter_libs)} architectures", self.verbose)
                
                flutter_assets = [f for f in file_names if f.startswith('assets/flutter_assets/')]
                if flutter_assets:
                    found_indicators.append(f'Flutter assets ({len(flutter_assets)} files)')
                    verbose_print(f"Found {len(flutter_assets)} Flutter asset files", self.verbose)
                
                isolate_snapshots = [f for f in file_names if 'isolate_snapshot' in f]
                if isolate_snapshots:
                    found_indicators.append('Flutter VM snapshots')
                    verbose_print("Found Flutter VM snapshot files", self.verbose)
                
                if found_indicators:
                    confidence = min(0.95, 0.8 + (len(found_indicators) * 0.05))
                    verbose_print(f"Flutter detected in APK with {len(found_indicators)} indicators, confidence: {confidence}", self.verbose)
                    
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
        """Detect Flutter in project directory"""
        primary_indicators = [
            'pubspec.yaml', 'lib/main.dart'
        ]
        secondary_indicators = [
            'android/app/build.gradle', 'ios/Runner.xcodeproj',
            'flutter_assets', 'build/app/intermediates'
        ]
        
        found_primary = []
        found_secondary = []
        
        if os.path.isdir(input_path):
            
            for indicator in primary_indicators:
                full_path = os.path.join(input_path, indicator)
                if os.path.exists(full_path):
                    found_primary.append(indicator)
                    verbose_print(f"Found primary indicator: {indicator}", self.verbose)
            
            for indicator in secondary_indicators:
                full_path = os.path.join(input_path, indicator)
                if os.path.exists(full_path):
                    found_secondary.append(indicator)
                    verbose_print(f"Found secondary indicator: {indicator}", self.verbose)
            
            if 'pubspec.yaml' in found_primary:
                try:
                    import yaml
                    pubspec_path = os.path.join(input_path, 'pubspec.yaml')
                    with open(pubspec_path, 'r') as f:
                        pubspec_data = yaml.safe_load(f)
                        dependencies = pubspec_data.get('dependencies', {})
                        
                        if 'flutter' in dependencies:
                            verbose_print("Flutter dependency confirmed in pubspec.yaml", self.verbose)
                        else:
                            verbose_print("pubspec.yaml found but no flutter dependency", self.verbose)
                except (ImportError, FileNotFoundError, Exception) as e:
                    verbose_print(f"Could not parse pubspec.yaml: {e}", self.verbose)
        
        if found_primary:
            all_found = found_primary + found_secondary
            
            confidence = 0.8
            primary_bonus = len(found_primary) * 0.1
            secondary_bonus = len(found_secondary) * 0.05
            
            confidence += primary_bonus + secondary_bonus
            confidence = min(1.0, confidence)
            verbose_print(f"Flutter indicators found: {len(all_found)}, confidence: {confidence}", self.verbose)
            
            return {
                'framework': self.framework_name,
                'indicators': all_found,
                'confidence': confidence
            }
        
        return None