"""React Native Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
import os

class ReactNativeDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("ReactNativeDetector initialized", self.verbose)
        self.framework_name = "React Native"

    def detect(self, input_path: str):
        verbose_print(f"Detecting React Native framework in: {input_path}", self.verbose)
        verbose_print(f"Input type: {'APK' if input_path.endswith('.apk') else 'Directory'}", self.verbose)
        
        if input_path.endswith('.apk'):
            verbose_print("Starting APK-based React Native detection", self.verbose)
            path_lower = input_path.lower()
            verbose_print(f"Checking APK path for React Native indicators: {path_lower}", self.verbose)
            
            if 'react' in path_lower and 'native' in path_lower:
                verbose_print("React Native APK detected by path pattern", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': ['APK path contains React Native'],
                    'confidence': 0.9
                }
            else:
                verbose_print("No React Native indicators in APK path", self.verbose)
                return None
        else:
            verbose_print("Starting directory-based React Native detection", self.verbose)
            return self._detect_react_native_in_project(input_path)
    def _detect_react_native_in_project(self, input_path: str):
        """Detect React Native in project directory"""
        verbose_print(f"Starting React Native detection in project: {input_path}", self.verbose)
        
        # Validate directory
        if not os.path.isdir(input_path):
            verbose_print(f"Path is not a directory: {input_path}", self.verbose)
            return None
        verbose_print("Directory validated successfully", self.verbose)
        
        # Define primary and secondary indicators
        primary_indicators = [
            'package.json', 'node_modules/react-native', 'metro.config.js'
        ]
        secondary_indicators = [
            'react-native.config.js', 'ios/Podfile'
        ]
        
        verbose_print(f"Primary indicators to check: {primary_indicators}", self.verbose)
        verbose_print(f"Secondary indicators to check: {secondary_indicators}", self.verbose)
        
        found_primary = []
        found_secondary = []
        
        # Check for primary indicators
        verbose_print("Checking for primary React Native indicators", self.verbose)
        for indicator in primary_indicators:
            full_path = os.path.join(input_path, indicator)
            verbose_print(f"Checking primary indicator: {full_path}", self.verbose)
            if os.path.exists(full_path):
                verbose_print(f"Found primary indicator: {indicator}", self.verbose)
                found_primary.append(indicator)
            else:
                verbose_print(f"Primary indicator not found: {indicator}", self.verbose)
        
        # Check for secondary indicators
        verbose_print("Checking for secondary React Native indicators", self.verbose)
        for indicator in secondary_indicators:
            full_path = os.path.join(input_path, indicator)
            verbose_print(f"Checking secondary indicator: {full_path}", self.verbose)
            if os.path.exists(full_path):
                verbose_print(f"Found secondary indicator: {indicator}", self.verbose)
                found_secondary.append(indicator)
            else:
                verbose_print(f"Secondary indicator not found: {indicator}", self.verbose)
        
        # Validate package.json for React Native dependency
        if 'package.json' in found_primary:
            verbose_print("Validating package.json for React Native dependency", self.verbose)
            try:
                import json
                package_path = os.path.join(input_path, 'package.json')
                verbose_print(f"Reading package.json from: {package_path}", self.verbose)
                
                with open(package_path, 'r') as f:
                    package_data = json.load(f)
                    verbose_print("Successfully parsed package.json", self.verbose)
                    
                    dependencies = package_data.get('dependencies', {})
                    dev_dependencies = package_data.get('devDependencies', {})
                    
                    verbose_print(f"Found {len(dependencies)} dependencies", self.verbose)
                    verbose_print(f"Found {len(dev_dependencies)} dev dependencies", self.verbose)
                    
                    has_react_native = 'react-native' in dependencies or 'react-native' in dev_dependencies
                    
                    if has_react_native:
                        rn_version = dependencies.get('react-native') or dev_dependencies.get('react-native')
                        verbose_print(f"React Native dependency found with version: {rn_version}", self.verbose)
                    else:
                        verbose_print("No React Native dependency found in package.json", self.verbose)
                        found_primary.remove('package.json')
                        verbose_print("Removed package.json from primary indicators", self.verbose)
                        
            except (json.JSONDecodeError, FileNotFoundError, Exception) as e:
                verbose_print(f"Could not parse package.json: {e}", self.verbose)
                if 'package.json' in found_primary:
                    found_primary.remove('package.json')
                    verbose_print("Removed invalid package.json from primary indicators", self.verbose)
        
        # Calculate results
        if found_primary:
            all_found = found_primary + found_secondary
            verbose_print(f"React Native indicators found: primary={found_primary}, secondary={found_secondary}", self.verbose)
            verbose_print(f"Total indicators found: {len(all_found)} - {all_found}", self.verbose)
            
            confidence = min(1.0, 0.7 + (len(all_found) * 0.1))
            verbose_print(f"Calculated confidence: {confidence} (base 0.7 + {len(all_found)} * 0.1)", self.verbose)
            
            return {
                'framework': self.framework_name,
                'indicators': all_found,
                'confidence': confidence
            }
        
        verbose_print("No React Native indicators found.", self.verbose)
        return None