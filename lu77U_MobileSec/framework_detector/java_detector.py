#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.java_detector

Purpose:
    Recognise a conventional Android app -- one whose logic is in Dalvik bytecode rather than in a cross-platform runtime -- so that the standard JADX decompilation path is chosen.

Responsibilities:
    Detect by exclusion in an APK, and by project layout in a source tree.

Dependencies:
    zipfile, ..config.constants for the framework marker tables.

Implementation notes:
    This detector works by exclusion, which is what makes it different from the others. Every cross-platform framework also ships DEX files -- a Flutter or React Native app has a Java shell around its runtime -- so the presence of DEX proves nothing on its own. What identifies a conventional app is DEX with none of the other frameworks' markers present. That is also why it reads the marker tables for the other frameworks rather than having its own: if a new framework is added to the shared table, this detector stops misclaiming those apps without any change here.

Security considerations:
    Reads the APK as a plain archive through zipfile rather than parsing it, so it is cheap and has a small attack surface. It never extracts an entry.
"""

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
    """
    Purpose:
        Detects a conventional Java or Kotlin Android app.

    Attributes:
        verbose: Whether detection is traced.
        framework_name: The framework name reported.

    Invariants:
        Returns None rather than a zero-confidence result when nothing matched, so a caller can test the result directly.

    Thread-safety:
        Holds no per-detection state; safe to reuse.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct the detector.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        self.framework_name = FRAMEWORK_JAVA
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect a conventional Android app in an APK or a project.

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
            Detect a conventional Android app by finding DEX files and no cross-platform framework markers.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when DEX is absent or another framework was recognised.

        Side effects:
            Opens the APK as a zip archive.

        Implementation notes:
            The exclusion check is the whole logic. Reporting Java for a Flutter app would route it to JADX, which would decompile the thin Java shell and find nothing, while the actual application logic sits untouched in the Dart snapshot. Confidence is a flat high value rather than accumulated, because the conclusion is categorical: either DEX is present without other markers or it is not. The Kotlin runtime is noted as an indicator but does not change the result, since both languages compile to the same bytecode and take the same decompilation path. Only the entry names are read -- no entry is extracted -- which keeps this cheap enough to run on every scan.
        """
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
        """
        Purpose:
            Detect an Android project by its layout and build files.

        Parameters:
            input_path: Path to the project root.

        Returns:
            A detection dict, or None when nothing matched.

        Side effects:
            Walks parts of the project tree.

        Implementation notes:
            Confidence accumulates across three kinds of evidence, weighted by how conclusive each is: directory layout, then build files, then actual source files. Finding real Java sources weighs most because layout alone can be an empty scaffold. The source walk stops after a few files. It only needs to establish that Java sources exist, and walking an entire project to count them would be wasted work. The total is capped at one, since the weights are chosen to reach certainty before every indicator is found.
        """
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
