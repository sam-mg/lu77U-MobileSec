#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.react_native_detector

Purpose:
    Recognise a React Native app, whose logic is a JavaScript bundle -- plain or compiled to Hermes bytecode -- rather than Dalvik bytecode.

Responsibilities:
    Detect React Native in an APK by its runtime libraries and bundle, and in a project by its dependency manifest.

Dependencies:
    zipfile, json, ..config.constants.

Implementation notes:
    As with Flutter, the Java code in a React Native APK is a shell around the real application. Detecting which JavaScript engine is in use matters too, because a Hermes bundle and a plain one need different decompilers.

Security considerations:
    The bundle is attacker-controlled and is the application's source. Detection names it without extracting it.
"""

from ..utils.verbose import verbose_print
from ..config.constants import FRAMEWORK_REACT_NATIVE, TECH_DETECTION_MAP
import os
import zipfile

class ReactNativeDetector:
    """
    Purpose:
        Detects React Native in an APK or a project.

    Attributes:
        verbose: Whether detection is traced.
        framework_name: The framework name reported.
        apk_indicators: Markers from the shared detection table.

    Invariants:
        Returns None when nothing matched.

    Thread-safety:
        Holds no per-detection state; safe to reuse.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct the detector and bind its indicator table.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        self.framework_name = FRAMEWORK_REACT_NATIVE
        self.apk_indicators = TECH_DETECTION_MAP[FRAMEWORK_REACT_NATIVE]
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect React Native in an APK or a project.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            A detection dict with framework, indicators and confidence, or None.
        """
        if input_path.endswith('.apk'):
            return self._detect_in_apk(input_path)
        else:
            return self._detect_in_project(input_path)
    
    def _detect_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect React Native by the runtime libraries and JavaScript bundle in an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Four artifacts are looked for: the bridge native library, the JavaScript bundle under either of its conventional names, the asset layout, and the Hermes engine libraries. The Hermes indicator is the operationally important one, since it determines which decompiler the analysis stage needs. It is recorded as its own indicator rather than folded into the bundle marker so the choice is visible in the report. The asset check is the weakest of the four, matching on a bundle extension or a drawable directory, either of which a non-React-Native app can have. It only contributes alongside the stronger markers. Only entry names are read; nothing is extracted.
        """
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
        """
        Purpose:
            Detect a React Native project by its dependency manifest and tooling configuration.

        Parameters:
            input_path: Path to the project root.

        Returns:
            A detection dict, or None when no primary indicator survived.

        Side effects:
            Stats candidate paths and reads package.json.

        Implementation notes:
            Unlike the Flutter detector, the dependency check here is load-bearing: a package.json without a React Native dependency is removed from the primary indicators, because every JavaScript project has one and its mere presence means nothing. A package.json that cannot be parsed is likewise removed, since an unreadable manifest cannot support the claim. That removal is what makes detection meaningful: after it, a primary indicator means the declared dependency, the installed module, or the Metro bundler configuration -- all three of which are specific to React Native.
        """
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
