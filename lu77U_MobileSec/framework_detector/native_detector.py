"""Native (C/C++) Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
import os

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

class NativeDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("NativeDetector initialized", self.verbose)
        self.framework_name = "Native (C/C++)"

    def detect(self, input_path: str):
        verbose_print(f"Detecting Native framework in: {input_path}", self.verbose)
        verbose_print(f"Input type: {'APK' if input_path.endswith('.apk') else 'Directory'}", self.verbose)
        
        if input_path.endswith('.apk'):
            verbose_print("Starting APK-based native detection", self.verbose)
            return self._detect_native_in_apk(input_path)
        else:
            verbose_print("Starting directory-based native detection", self.verbose)
            return self._detect_native_in_project(input_path)
    
    def _detect_native_in_apk(self, apk_path: str):
        """Detect native libraries in APK file"""
        verbose_print(f"Starting native detection in APK: {apk_path}", self.verbose)
        indicators = []
        confidence = 0.0
        
        # Check APK path for native indicators
        verbose_print("Checking APK path for native/NDK indicators", self.verbose)
        path_lower = apk_path.lower()
        if 'native' in path_lower or 'ndk' in path_lower:
            verbose_print(f"APK path contains native indicator: {path_lower}", self.verbose)
            indicators.append('APK path contains Native/NDK')
            confidence += 0.3
            verbose_print(f"Confidence increased by 0.3 due to path indicator (total: {confidence})", self.verbose)
        else:
            verbose_print("No native indicators in APK path", self.verbose)
        
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
        
        verbose_print("Androguard available - performing detailed APK analysis", self.verbose)
        try:
            verbose_print("Loading APK with androguard", self.verbose)
            apk, dex, dx = AnalyzeAPK(apk_path)
            verbose_print("APK analyzed successfully", self.verbose)
            
            # Check for native libraries (.so files)
            verbose_print("Scanning for native libraries (.so files)", self.verbose)
            so_files = []
            lib_files = apk.get_files_types()
            verbose_print(f"Total files in APK: {len(apk.get_files())}", self.verbose)
            
            for file_path in apk.get_files():
                if file_path.startswith('lib/') and file_path.endswith('.so'):
                    so_files.append(os.path.basename(file_path))
                    verbose_print(f"Found native library: {file_path}", self.verbose)
            
            if so_files:
                verbose_print(f"Total native libraries found: {len(so_files)}", self.verbose)
                indicators.append(f'Native libraries (.so): {", ".join(so_files[:3])}{"..." if len(so_files) > 3 else ""}')
                confidence += 0.8
                verbose_print(f"Found {len(so_files)} native libraries in APK", self.verbose)
                verbose_print(f"Confidence increased by 0.8 due to native libraries (total: {confidence})", self.verbose)
            else:
                verbose_print("No native libraries (.so files) found", self.verbose)
            
            # Check for native architectures
            verbose_print("Scanning for native architectures", self.verbose)
            lib_dirs = set()
            for file_path in apk.get_files():
                if file_path.startswith('lib/') and '/' in file_path[4:]:
                    arch = file_path.split('/')[1]
                    lib_dirs.add(arch)
                    verbose_print(f"Found native architecture: {arch}", self.verbose)
            
            if lib_dirs:
                verbose_print(f"Total native architectures found: {len(lib_dirs)} - {sorted(lib_dirs)}", self.verbose)
                indicators.append(f'Native architectures: {", ".join(sorted(lib_dirs))}')
                confidence += 0.4
                verbose_print(f"Found native architectures: {lib_dirs}", self.verbose)
                verbose_print(f"Confidence increased by 0.4 due to architectures (total: {confidence})", self.verbose)
            else:
                verbose_print("No native architectures found", self.verbose)
                
        except Exception as e:
            verbose_print(f"Error analyzing APK for native libraries: {e}", self.verbose)
            if indicators:
                verbose_print("Adding APK analysis failure indicator", self.verbose)
                indicators.append('APK analysis failed - using path pattern')
            else:
                verbose_print("No indicators and APK analysis failed", self.verbose)
                return None
        
        if indicators:
            confidence = min(confidence, 1.0)
            verbose_print(f"Native detection completed - indicators: {len(indicators)}, confidence: {confidence}", self.verbose)
            verbose_print(f"Final indicators: {indicators}", self.verbose)
            return {
                'framework': self.framework_name,
                'indicators': indicators,
                'confidence': confidence
            }
        else:
            verbose_print("No native indicators found in APK", self.verbose)
            return None
        
    def _detect_native_in_project(self, input_path: str):
        """Detect native code in project directory"""
        verbose_print(f"Starting native detection in project directory: {input_path}", self.verbose)
        indicators = []
        confidence = 0.0
        
        # Validate directory
        if not os.path.isdir(input_path):
            verbose_print(f"Path is not a directory: {input_path}", self.verbose)
            return None
            
        verbose_print("Directory validated successfully", self.verbose)
        
        # Check for native development directories
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
        
        # Check for native build files
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
        
        # Search for C/C++ source files
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
            verbose_print(f"Confidence increased by 0.5 due to C/C++ files (total: {confidence})", self.verbose)
        else:
            verbose_print("No C/C++ source files found", self.verbose)
        
        if indicators:
            confidence = min(confidence, 1.0)
            verbose_print(f"Native detection completed - indicators: {len(indicators)}, confidence: {confidence}", self.verbose)
            verbose_print(f"Final indicators: {indicators}", self.verbose)
            return {
                'framework': self.framework_name,
                'indicators': indicators,
                'confidence': confidence
            }
        
        verbose_print("No native indicators found in project.", self.verbose)
        return None
