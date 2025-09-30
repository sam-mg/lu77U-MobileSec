"""Java Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
import os

class JavaDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("JavaDetector initialized", self.verbose)
        self.framework_name = "Java"

    def detect(self, input_path: str):
        verbose_print(f"Detecting Java framework in: {input_path}", self.verbose)
        verbose_print(f"Input type: {'APK' if input_path.endswith('.apk') else 'Directory'}", self.verbose)
        
        if input_path.endswith('.apk'):
            verbose_print("Starting APK-based Java detection", self.verbose)
            path_lower = input_path.lower()
            verbose_print(f"Checking APK path: {path_lower}", self.verbose)
            
            if 'java' in path_lower or input_path.endswith('.apk'):
                verbose_print("Java APK detected by path pattern", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': ['APK file format (Java/Kotlin base)'],
                    'confidence': 0.8
                }
        else:
            verbose_print("Starting directory-based Java detection", self.verbose)
            indicators = []
            confidence = 0.0
            
            if os.path.isdir(input_path):
                verbose_print(f"Input path is a valid directory: {input_path}", self.verbose)
                
                android_structure = [
                    'AndroidManifest.xml', 'src/main/java', 'app/src/main/java',
                    'res/', 'app/src/main/res'
                ]
                build_files = [
                    'build.gradle', 'app/build.gradle', 
                    'build.gradle.kts', 'app/build.gradle.kts',
                    'gradle.properties'
                ]
                
                verbose_print(f"Checking {len(android_structure)} Android structure indicators", self.verbose)
                for indicator in android_structure:
                    full_path = os.path.join(input_path, indicator)
                    verbose_print(f"Checking Android structure: {full_path}", self.verbose)
                    if os.path.exists(full_path):
                        indicators.append(indicator)
                        confidence += 0.3
                        verbose_print(f"Found Android structure indicator: {indicator} (confidence +0.3)", self.verbose)
                    else:
                        verbose_print(f"Android structure not found: {indicator}", self.verbose)
                
                verbose_print(f"Checking {len(build_files)} build file indicators", self.verbose)
                for build_file in build_files:
                    full_path = os.path.join(input_path, build_file)
                    verbose_print(f"Checking build file: {full_path}", self.verbose)
                    if os.path.exists(full_path):
                        indicators.append(build_file)
                        confidence += 0.2
                        verbose_print(f"Found build file: {build_file} (confidence +0.2)", self.verbose)
                    else:
                        verbose_print(f"Build file not found: {build_file}", self.verbose)
                
                verbose_print("Searching for Java source files", self.verbose)
                java_files_found = []
                search_dirs = [
                    os.path.join(input_path, 'src/main/java'),
                    os.path.join(input_path, 'app/src/main/java')
                ]
                
                for search_dir in search_dirs:
                    verbose_print(f"Searching for .java files in: {search_dir}", self.verbose)
                    if os.path.exists(search_dir):
                        verbose_print(f"Directory exists, walking: {search_dir}", self.verbose)
                        file_count = 0
                        for root, dirs, files in os.walk(search_dir):
                            for file in files:
                                if file.endswith('.java'):
                                    java_files_found.append(file)
                                    file_count += 1
                                    verbose_print(f"Found Java file: {file}", self.verbose)
                                    if len(java_files_found) >= 3:
                                        verbose_print("Reached Java file limit (3), stopping search", self.verbose)
                                        break
                            if len(java_files_found) >= 3:
                                break
                        verbose_print(f"Found {file_count} Java files in {search_dir}", self.verbose)
                    else:
                        verbose_print(f"Search directory does not exist: {search_dir}", self.verbose)
                
                if java_files_found:
                    source_indicator = f'Java source files: {", ".join(java_files_found[:3])}{"..." if len(java_files_found) > 3 else ""}'
                    indicators.append(source_indicator)
                    confidence += 0.5
                    verbose_print(f"Added Java source files indicator (confidence +0.5): {source_indicator}", self.verbose)
                else:
                    verbose_print("No Java source files found", self.verbose)
                    
            else:
                verbose_print(f"Input path is not a valid directory: {input_path}", self.verbose)
            
            verbose_print(f"Java detection summary - Indicators found: {len(indicators)}", self.verbose)
            verbose_print(f"Raw confidence score: {confidence}", self.verbose)
            
            if indicators:
                confidence = min(confidence, 1.0)
                verbose_print(f"Final confidence (capped): {confidence}", self.verbose)
                verbose_print(f"Java indicators found: {indicators}, confidence: {confidence}", self.verbose)
                
                result = {
                    'framework': self.framework_name,
                    'indicators': indicators,
                    'confidence': confidence
                }
                verbose_print(f"Returning Java detection result: {result}", self.verbose)
                return result
            else:
                verbose_print("No Java indicators found, returning None", self.verbose)
        
        verbose_print("No Java indicators found.", self.verbose)
        return None
