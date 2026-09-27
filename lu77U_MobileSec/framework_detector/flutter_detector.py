#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.flutter_detector

Purpose:
    Recognise a Flutter app, whose logic is compiled into a Dart AOT snapshot rather than into Dalvik bytecode, so that the Blutter path is taken instead of JADX.

Responsibilities:
    Detect Flutter in an APK by its runtime artifacts, and in a project by its manifest of dependencies and its layout.

Dependencies:
    zipfile, yaml when installed, ..config.constants.

Implementation notes:
    Detecting Flutter matters more than most. A Flutter APK contains a perfectly ordinary Java shell that JADX will decompile happily, producing a clean report about generated plugin bindings while the entire application sits unexamined in libapp.so. A missed Flutter detection therefore yields a confident, worthless analysis.

Security considerations:
    The Dart snapshot is attacker-controlled binary content. Detection only names the entries; recovering code from them is the decompiler's job.
"""

from ..utils.verbose import verbose_print
from ..config.constants import FRAMEWORK_FLUTTER, TECH_DETECTION_MAP
import os
import zipfile

class FlutterDetector:
    """
    Purpose:
        Detects Flutter in an APK or a project.

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
        self.framework_name = FRAMEWORK_FLUTTER
        self.apk_indicators = TECH_DETECTION_MAP[FRAMEWORK_FLUTTER]
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Flutter in an APK or a project.

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
            Detect Flutter by the runtime artifacts its build embeds in an APK.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            Three independent artifacts are looked for: the engine native library, the bundled asset directory, and the VM snapshot files. Each is distinctive on its own, which is why confidence starts high rather than accumulating from a low base. The count of architectures the engine library ships for is recorded in the indicator text, since that is useful context for the decompilation step which has to pick one. Only entry names are read; nothing is extracted.
        """
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
        """
        Purpose:
            Detect a Flutter project by its dependency manifest and layout.

        Parameters:
            input_path: Path to the project root.

        Returns:
            A detection dict, or None when no primary indicator was found.

        Side effects:
            Stats candidate paths and may read pubspec.yaml.

        Implementation notes:
            Indicators are split into primary and secondary and weighted accordingly. A pubspec or a Dart entry point is definitive; an Android or iOS host directory merely corroborates, since every cross-platform framework has those. Detection requires at least one primary indicator. Secondary indicators alone would match any React Native or Cordova project equally well. The pubspec is parsed to confirm the Flutter dependency, but the result only produces a trace line -- it does not change the confidence or the verdict. A project with a pubspec and no Flutter dependency is a plain Dart package, and this detector still reports Flutter for it. yaml is treated as optional, so its absence costs the confirmation trace rather than the detection.
        """
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
