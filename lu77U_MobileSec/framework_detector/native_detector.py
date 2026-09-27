#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.native_detector

Purpose:
    Recognise native C or C++ components, so that a report can say part of the app is outside the reach of Dalvik decompilation.

Responsibilities:
    Detect native libraries and architectures in an APK, and native build configuration in a project.

Dependencies:
    androguard when installed.

Implementation notes:
    Almost every non-trivial app contains native libraries -- every cross-platform framework ships them, and so do most common SDKs -- so this detector fires constantly. That is why the hybrid arbitrator suppresses its result whenever a specific framework was detected: on its own it would report every Flutter and React Native app as native. Its useful case is the app that has native code and is not one of those: a conventional Android app with an NDK component, where the report should say that part of the logic is not in the DEX.

Security considerations:
    Native libraries are attacker-controlled binaries. Detection names them without loading or executing anything.
"""

from ..utils.verbose import verbose_print
import os

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

class NativeDetector:
    """
    Purpose:
        Detects native code components in an APK or a project.

    Attributes:
        verbose: Whether detection is traced.
        framework_name: The framework name reported.

    Invariants:
        Returns None when nothing matched.

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
        self.framework_name = "Native (C/C++)"
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect native components in an APK or a project.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            A detection dict with framework, indicators and confidence, or None.
        """
        if input_path.endswith('.apk'):
            return self._detect_native_in_apk(input_path)
        else:
            verbose_print("Starting directory-based native detection", self.verbose)
            return self._detect_native_in_project(input_path)
    
    def _detect_native_in_apk(self, apk_path: str):
        """
        Purpose:
            Detect native libraries and the architectures they are built for.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Parses the APK with androguard.

        Implementation notes:
            The library names carry most of the weight, and the architecture list corroborates. Only entries under the library directory with a shared-object extension count, so an unrelated file elsewhere in the archive does not qualify. The architecture list is useful beyond detection: it tells the decompilation stage which build to work from for a framework that ships several. Only the first few library names go into the indicator text, since an app can bundle dozens and the report shows them verbatim. Without androguard, detection falls back to the filename heuristic alone and says so in the indicators, so a reader can see the result is weak.

        Known limitations:
            The filename check -- matching on the APK path containing a native or NDK hint -- is a corpus-shaped heuristic that contributes confidence for any file happening to be named that way. It is small enough not to reach the reporting threshold on its own.
        """
        indicators = []
        confidence = 0.0
        
        path_lower = apk_path.lower()
        if 'native' in path_lower or 'ndk' in path_lower:
            verbose_print(f"APK path contains native indicator: {path_lower}", self.verbose)
            indicators.append('APK path contains Native/NDK')
            confidence += 0.3
            verbose_print(f"Confidence increased by 0.3 due to path indicator (total: {confidence})", self.verbose)
        
        if not ANDROGUARD_AVAILABLE:
            verbose_print("Androguard not available - limited APK native detection", self.verbose)
            if indicators:
                verbose_print("Returning limited detection result", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': indicators + ['Limited detection - androguard required'],
                    'confidence': confidence
                }
            verbose_print("No indicators found and androguard unavailable", self.verbose)
            return None
        
        try:
            from ..detection.extractors.logging_config import setup_androguard_logging
            setup_androguard_logging(self.verbose)
            apk, dex, dx = AnalyzeAPK(apk_path)
            
            so_files = []
            for file_path in apk.get_files():
                if file_path.startswith('lib/') and file_path.endswith('.so'):
                    so_files.append(os.path.basename(file_path))
            
            if so_files:
                indicators.append(f'Native libraries (.so): {", ".join(so_files[:3])}{"..." if len(so_files) > 3 else ""}')
                confidence += 0.8
                verbose_print(f"Found {len(so_files)} native libraries", self.verbose)
            
            lib_dirs = set()
            for file_path in apk.get_files():
                if file_path.startswith('lib/') and '/' in file_path[4:]:
                    arch = file_path.split('/')[1]
                    lib_dirs.add(arch)
            
            if lib_dirs:
                indicators.append(f'Native architectures: {", ".join(sorted(lib_dirs))}')
                confidence += 0.4
                verbose_print(f"Found native architectures: {', '.join(sorted(lib_dirs))}", self.verbose)
                
        except Exception as e:
            verbose_print(f"Error analyzing APK: {e}", self.verbose)
        
        if indicators:
            confidence = min(confidence, 1.0)
            return {
                'framework': self.framework_name,
                'indicators': indicators,
                'confidence': confidence
            }
        else:
            verbose_print("No native indicators found in APK", self.verbose)
            return None
        
    def _detect_native_in_project(self, input_path: str):
        """
        Purpose:
            Detect native components in a project by its build configuration and source directories.

        Parameters:
            input_path: Path to the project root.

        Returns:
            A detection dict, or None when no indicator was found.

        Side effects:
            Stats the candidate paths.

        Implementation notes:
            Both the conventional native source directories and the NDK build files are checked, covering the legacy ndk-build layout and the modern CMake one, in both bare and Gradle-module projects. Confidence accumulates per indicator and is capped, since a project with several of these markers is unambiguously using the NDK.
        """
        verbose_print(f"Starting native detection in project directory: {input_path}", self.verbose)
        indicators = []
        confidence = 0.0
        
        if not os.path.isdir(input_path):
            verbose_print(f"Path is not a directory: {input_path}", self.verbose)
            return None
        verbose_print("Checking for native development directories", self.verbose)
        native_paths = [
            'jni/', 'src/main/cpp', 'src/main/jni', 'app/src/main/cpp'
        ]
        verbose_print(f"Searching for native paths: {native_paths}", self.verbose)
        
        for path in native_paths:
            full_path = os.path.join(input_path, path)
            verbose_print(f"Checking path: {full_path}", self.verbose)
            if os.path.exists(full_path):
                verbose_print(f"Found native directory: {path}", self.verbose)
                indicators.append(path)
                confidence += 0.4
                verbose_print(f"Confidence increased by 0.4 due to native directory (total: {confidence})", self.verbose)
            else:
                verbose_print(f"Native directory not found: {path}", self.verbose)
        
        verbose_print("Checking for native build files", self.verbose)
        build_files = [
            'ndk-build', 'Android.mk', 'Application.mk', 'CMakeLists.txt'
        ]
        verbose_print(f"Searching for build files: {build_files}", self.verbose)
        
        for build_file in build_files:
            full_path = os.path.join(input_path, build_file)
            verbose_print(f"Checking build file: {full_path}", self.verbose)
            if os.path.exists(full_path):
                verbose_print(f"Found native build file: {build_file}", self.verbose)
                indicators.append(build_file)
                confidence += 0.3
                verbose_print(f"Confidence increased by 0.3 due to build file (total: {confidence})", self.verbose)
            else:
                verbose_print(f"Build file not found: {build_file}", self.verbose)
        
        verbose_print("Searching for C/C++ source files", self.verbose)
        cpp_extensions = ['.cpp', '.c', '.cc', '.cxx', '.h', '.hpp']
        verbose_print(f"Looking for extensions: {cpp_extensions}", self.verbose)
        cpp_files_found = []
        
        search_dirs = [
            os.path.join(input_path, 'src/main/cpp'),
            os.path.join(input_path, 'app/src/main/cpp'),
            os.path.join(input_path, 'jni'),
            input_path
        ]
        verbose_print(f"Searching in directories: {search_dirs}", self.verbose)
        
        for search_dir in search_dirs:
            verbose_print(f"Searching directory: {search_dir}", self.verbose)
            if os.path.exists(search_dir):
                verbose_print(f"Directory exists, walking through files", self.verbose)
                for root, dirs, files in os.walk(search_dir):
                    verbose_print(f"Checking directory: {root} with {len(files)} files", self.verbose)
                    for file in files:
                        if any(file.endswith(ext) for ext in cpp_extensions):
                            verbose_print(f"Found C/C++ file: {file}", self.verbose)
                            cpp_files_found.append(file)
                            if len(cpp_files_found) >= 3:
                                verbose_print("Found enough C/C++ files, stopping search", self.verbose)
                                break
                        if len(cpp_files_found) >= 3:
                            break
            else:
                verbose_print(f"Directory does not exist: {search_dir}", self.verbose)
        
        if cpp_files_found:
            verbose_print(f"Total C/C++ files found: {len(cpp_files_found)}", self.verbose)
            indicators.append(f'C/C++ source files: {", ".join(cpp_files_found[:3])}{"..." if len(cpp_files_found) > 3 else ""}')
            confidence += 0.5
        else:
            verbose_print("No C/C++ source files found", self.verbose)
        
        if indicators:
            confidence = min(confidence, 1.0)
            return {
                'framework': self.framework_name,
                'indicators': indicators,
                'confidence': confidence
            }
        
        verbose_print("No native indicators found in project.", self.verbose)
        return None
