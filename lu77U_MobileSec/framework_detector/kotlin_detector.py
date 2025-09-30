"""Kotlin Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
import os

class KotlinDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("KotlinDetector initialized", self.verbose)
        self.framework_name = "Kotlin"

    def detect(self, input_path: str):
        verbose_print(f"Detecting Kotlin framework in: {input_path}", self.verbose)
        verbose_print(f"Input type: {'APK' if input_path.endswith('.apk') else 'Directory'}", self.verbose)
        
        if input_path.endswith('.apk'):
            verbose_print("Starting APK-based Kotlin detection", self.verbose)
            path_lower = input_path.lower()
            verbose_print(f"Checking APK path for Kotlin keywords: {path_lower}", self.verbose)
            
            if 'kotlin' in path_lower:
                verbose_print("Kotlin APK detected by path pattern", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': ['APK path contains Kotlin'],
                    'confidence': 0.9
                }
            else:
                verbose_print("No Kotlin keywords found in APK path", self.verbose)
        else:
            verbose_print("Starting directory-based Kotlin detection", self.verbose)
            kotlin_indicators = []
            confidence = 0.0
            
            if os.path.isdir(input_path):
                verbose_print(f"Input path is a valid directory: {input_path}", self.verbose)
                
                # Check for dedicated Kotlin source directory
                kotlin_src_path = os.path.join(input_path, 'src/main/kotlin')
                verbose_print(f"Checking for Kotlin source directory: {kotlin_src_path}", self.verbose)
                if os.path.exists(kotlin_src_path):
                    kotlin_indicators.append('src/main/kotlin directory')
                    confidence += 0.8
                    verbose_print("Found src/main/kotlin directory (confidence +0.8)", self.verbose)
                else:
                    verbose_print("src/main/kotlin directory not found", self.verbose)
                
                # Search for .kt files in Java directories
                verbose_print("Searching for .kt files in Java source directories", self.verbose)
                kt_files_found = False
                src_main_java = os.path.join(input_path, 'src/main/java')
                
                if os.path.exists(src_main_java):
                    verbose_print(f"Searching for .kt files in: {src_main_java}", self.verbose)
                    kt_file_count = 0
                    
                    for root, dirs, files in os.walk(src_main_java):
                        for file in files:
                            if file.endswith('.kt'):
                                kt_files_found = True
                                kt_file_count += 1
                                verbose_print(f"Found Kotlin file: {file}", self.verbose)
                                break
                        if kt_files_found:
                            break
                    
                    verbose_print(f"Found {kt_file_count} Kotlin files in Java directory", self.verbose)
                else:
                    verbose_print(f"Java source directory does not exist: {src_main_java}", self.verbose)
                
                if kt_files_found:
                    kotlin_indicators.append('.kt source files found')
                    confidence += 0.6
                    verbose_print("Found .kt source files (confidence +0.6)", self.verbose)
                else:
                    verbose_print("No .kt source files found", self.verbose)
                
                # Check app-level build.gradle.kts
                verbose_print("Checking app-level build.gradle.kts", self.verbose)
                build_gradle_kts = os.path.join(input_path, 'app/build.gradle.kts')
                if os.path.exists(build_gradle_kts):
                    verbose_print(f"Found build.gradle.kts, reading: {build_gradle_kts}", self.verbose)
                    try:
                        with open(build_gradle_kts, 'r', encoding='utf-8') as f:
                            content = f.read()
                            verbose_print(f"Read {len(content)} characters from build.gradle.kts", self.verbose)
                            
                            if 'kotlin-android' in content or 'org.jetbrains.kotlin.android' in content:
                                kotlin_indicators.append('Kotlin Android plugin in build.gradle.kts')
                                confidence += 0.4
                                verbose_print("Found Kotlin Android plugin in app build.gradle.kts (confidence +0.4)", self.verbose)
                            else:
                                verbose_print("No Kotlin Android plugin found in app build.gradle.kts", self.verbose)
                    except Exception as e:
                        verbose_print(f"Error reading build.gradle.kts: {e}", self.verbose)
                else:
                    verbose_print("App-level build.gradle.kts not found", self.verbose)
                
                # Check root-level build.gradle.kts
                verbose_print("Checking root-level build.gradle.kts", self.verbose)
                root_build_gradle_kts = os.path.join(input_path, 'build.gradle.kts')
                if os.path.exists(root_build_gradle_kts):
                    verbose_print(f"Found root build.gradle.kts, reading: {root_build_gradle_kts}", self.verbose)
                    try:
                        with open(root_build_gradle_kts, 'r', encoding='utf-8') as f:
                            content = f.read()
                            verbose_print(f"Read {len(content)} characters from root build.gradle.kts", self.verbose)
                            
                            if 'kotlin-android' in content or 'org.jetbrains.kotlin.android' in content:
                                kotlin_indicators.append('Kotlin Android plugin in root build.gradle.kts')
                                confidence += 0.2
                                verbose_print("Found Kotlin Android plugin in root build.gradle.kts (confidence +0.2)", self.verbose)
                            else:
                                verbose_print("No Kotlin Android plugin found in root build.gradle.kts", self.verbose)
                    except Exception as e:
                        verbose_print(f"Error reading root build.gradle.kts: {e}", self.verbose)
                else:
                    verbose_print("Root-level build.gradle.kts not found", self.verbose)
                    
            else:
                verbose_print(f"Input path is not a valid directory: {input_path}", self.verbose)
            
            verbose_print(f"Kotlin detection summary - Indicators found: {len(kotlin_indicators)}", self.verbose)
            verbose_print(f"Raw confidence score: {confidence}", self.verbose)
            
            if kotlin_indicators:
                confidence = min(confidence, 1.0)
                verbose_print(f"Final confidence (capped): {confidence}", self.verbose)
                verbose_print(f"Kotlin indicators found: {kotlin_indicators}, confidence: {confidence}", self.verbose)
                
                result = {
                    'framework': self.framework_name,
                    'indicators': kotlin_indicators,
                    'confidence': confidence
                }
                verbose_print(f"Returning Kotlin detection result: {result}", self.verbose)
                return result
            else:
                verbose_print("No Kotlin indicators found, returning None", self.verbose)
        
        verbose_print("No Kotlin indicators found.", self.verbose)
        return None
