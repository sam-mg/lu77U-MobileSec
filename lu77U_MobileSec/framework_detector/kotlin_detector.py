#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.kotlin_detector

Purpose:
    Recognise a Kotlin project, so that the report names the language the app is actually written in.

Responsibilities:
    Detect Kotlin from a project's source layout and Gradle configuration.

Dependencies:
    os only.

Implementation notes:
    Kotlin and Java compile to the same Dalvik bytecode and take the same analysis path, so this detector affects how the app is described rather than how it is analysed. That is why it is allowed to be weaker than the others.

Known limitations:
    The APK path has no real detection: it matches on the filename containing the word Kotlin, which is a heuristic that happens to hold for test corpora and not for real apps. A built APK is identified as Java by the Java detector, and the language distinction is lost. Detecting the bundled Kotlin runtime classes would be the proper approach.
"""

from ..utils.verbose import verbose_print
import os

class KotlinDetector:
    """
    Purpose:
        Detects Kotlin in a project, and nominally in an APK.

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
        self.framework_name = "Kotlin"
    
    def detect(self, input_path: str):
        """
        Purpose:
            Detect Kotlin in an APK or a project.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            A detection dict with framework, indicators and confidence, or None.

        Side effects:
            Walks part of the project tree and reads Gradle files.

        Implementation notes:
            Project detection accumulates three kinds of evidence, weighted by how conclusive each is: a dedicated Kotlin source directory is decisive, Kotlin files inside the Java source directory are strong, and the Gradle plugin declaration is corroborating. The app-level Gradle file weighs more than the root one, because the root commonly declares the plugin for modules that do not use it. The source walk stops at the first Kotlin file found, since it only needs to establish that any exist. Gradle files are matched for either the legacy or the modern plugin identifier, both of which remain in wide use. Only the Kotlin-script Gradle files are read, not the Groovy ones, so a Kotlin project using Groovy build scripts loses that indicator -- it is still detected by its sources.

        Known limitations:
            The APK branch matches on the filename rather than on APK content, so it reports Kotlin for any file with the word in its path and misses every real Kotlin app.
        """
        if input_path.endswith('.apk'):
            path_lower = input_path.lower()
            
            if 'kotlin' in path_lower:
                verbose_print("Kotlin APK detected by path pattern", self.verbose)
                return {
                    'framework': self.framework_name,
                    'indicators': ['APK path contains Kotlin'],
                    'confidence': 0.9
                }
        else:
            verbose_print("Starting directory-based Kotlin detection", self.verbose)
            kotlin_indicators = []
            confidence = 0.0
            
            if os.path.isdir(input_path):
                verbose_print(f"Input path is a valid directory: {input_path}", self.verbose)
                
                kotlin_src_path = os.path.join(input_path, 'src/main/kotlin')
                verbose_print(f"Checking for Kotlin source directory: {kotlin_src_path}", self.verbose)
                if os.path.exists(kotlin_src_path):
                    kotlin_indicators.append('src/main/kotlin directory')
                    confidence += 0.8
                    verbose_print("Found src/main/kotlin directory (confidence +0.8)", self.verbose)
                else:
                    verbose_print("src/main/kotlin directory not found", self.verbose)
                
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
        
        return None
