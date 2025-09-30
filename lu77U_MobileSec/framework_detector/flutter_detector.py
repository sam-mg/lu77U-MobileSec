"""Flutter Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
import os

class FlutterDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("FlutterDetector initialized", self.verbose)
        self.framework_name = "Flutter"

    def detect(self, input_path: str):
        verbose_print(f"Detecting Flutter framework in: {input_path}", self.verbose)
        verbose_print(f"Input path type: {'APK' if input_path.endswith('.apk') else 'Directory'}", self.verbose)
        
        if input_path.endswith('.apk'):
            verbose_print("Starting APK-based Flutter detection", self.verbose)
            path_lower = input_path.lower()
            verbose_print(f"Checking APK path for Flutter keywords: {path_lower}", self.verbose)
            
            if 'flutter' in path_lower or '/flutter/' in path_lower:
                verbose_print("Flutter APK detected by path pattern", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': ['APK path contains Flutter'],
                    'confidence': 0.9
                }
            else:
                verbose_print("No Flutter keywords found in APK path", self.verbose)
        else:
            verbose_print("Starting directory-based Flutter detection", self.verbose)
            primary_indicators = [
                'pubspec.yaml', 'lib/main.dart'
            ]
            secondary_indicators = [
                'android/app/build.gradle', 'ios/Runner.xcodeproj',
                'flutter_assets', 'build/app/intermediates'
            ]
            
            verbose_print(f"Primary indicators to check: {primary_indicators}", self.verbose)
            verbose_print(f"Secondary indicators to check: {secondary_indicators}", self.verbose)
            
            found_primary = []
            found_secondary = []
            
            if os.path.isdir(input_path):
                verbose_print(f"Input path is a valid directory: {input_path}", self.verbose)
                
                verbose_print("Checking for primary indicators", self.verbose)
                for indicator in primary_indicators:
                    full_path = os.path.join(input_path, indicator)
                    verbose_print(f"Checking: {full_path}", self.verbose)
                    if os.path.exists(full_path):
                        found_primary.append(indicator)
                        verbose_print(f"Found primary indicator: {indicator}", self.verbose)
                    else:
                        verbose_print(f"Primary indicator not found: {indicator}", self.verbose)
                
                verbose_print("Checking for secondary indicators", self.verbose)
                for indicator in secondary_indicators:
                    full_path = os.path.join(input_path, indicator)
                    verbose_print(f"Checking: {full_path}", self.verbose)
                    if os.path.exists(full_path):
                        found_secondary.append(indicator)
                        verbose_print(f"Found secondary indicator: {indicator}", self.verbose)
                    else:
                        verbose_print(f"Secondary indicator not found: {indicator}", self.verbose)
                
                verbose_print(f"Primary indicators found: {found_primary}", self.verbose)
                verbose_print(f"Secondary indicators found: {found_secondary}", self.verbose)
                
                if 'pubspec.yaml' in found_primary:
                    verbose_print("pubspec.yaml found, validating Flutter dependency", self.verbose)
                    try:
                        import yaml
                        pubspec_path = os.path.join(input_path, 'pubspec.yaml')
                        verbose_print(f"Reading pubspec.yaml from: {pubspec_path}", self.verbose)
                        with open(pubspec_path, 'r') as f:
                            pubspec_data = yaml.safe_load(f)
                            dependencies = pubspec_data.get('dependencies', {})
                            verbose_print(f"Found {len(dependencies)} dependencies", self.verbose)
                            
                            if 'flutter' in dependencies:
                                verbose_print("Flutter dependency confirmed in pubspec.yaml", self.verbose)
                            else:
                                verbose_print("pubspec.yaml found but no flutter dependency", self.verbose)
                                # Note: Not removing from found_primary as pubspec.yaml presence is still a strong indicator
                    except (ImportError, FileNotFoundError, Exception) as e:
                        verbose_print(f"Could not parse pubspec.yaml: {e}", self.verbose)
                        verbose_print("Continuing with pubspec.yaml as indicator despite parsing error", self.verbose)
            else:
                verbose_print(f"Input path is not a valid directory: {input_path}", self.verbose)
            
            if found_primary:
                all_found = found_primary + found_secondary
                verbose_print(f"Flutter indicators found: {all_found}", self.verbose)
                
                verbose_print("Calculating confidence score", self.verbose)
                confidence = 0.8
                primary_bonus = len(found_primary) * 0.1
                secondary_bonus = len(found_secondary) * 0.05
                verbose_print(f"Base confidence: {confidence}", self.verbose)
                verbose_print(f"Primary indicator bonus: {primary_bonus} ({len(found_primary)} * 0.1)", self.verbose)
                verbose_print(f"Secondary indicator bonus: {secondary_bonus} ({len(found_secondary)} * 0.05)", self.verbose)
                
                confidence += primary_bonus + secondary_bonus
                confidence = min(1.0, confidence)
                verbose_print(f"Final confidence: {confidence}", self.verbose)
                
                result = {
                    'framework': self.framework_name,
                    'indicators': all_found,
                    'confidence': confidence
                }
                verbose_print(f"Returning Flutter detection result: {result}", self.verbose)
                return result
            else:
                verbose_print("No primary Flutter indicators found", self.verbose)
        
        verbose_print("No Flutter indicators found.", self.verbose)
        return None