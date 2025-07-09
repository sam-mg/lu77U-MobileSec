#!/usr/bin/env python3
"""
Framework detector for lu77U-MobileSec

Detects APK framework type (Java/Kotlin, React Native, Flutter) based on content analysis.
"""

import os
import zipfile
import subprocess
import shutil
from typing import Optional, List

from ...constants.frameworks import REACT_NATIVE_INDICATORS, FLUTTER_INDICATORS


class FrameworkDetector:
    """
    Framework detection and common functionality
    
    Handles:
    - APK file type detection
    - Framework-specific content analysis
    """
    
    def __init__(self, debug=False):
        """Initialize framework detector"""
        self.debug = debug
        
        # AI Analysis setup (inherited from old structure)
        self.groq_api_key = os.environ.get('GROQ_API_KEY')
        self.use_local_llm = True  # Default to Ollama
        self.llm_choice_made = False
        
        # Framework detection indicators
        self.react_native_indicators = REACT_NATIVE_INDICATORS
        self.flutter_indicators = FLUTTER_INDICATORS
    
    def debug_print(self, message):
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"🐛 DETECTOR DEBUG: {message}")
    
    def find_tool_path(self, tool_name: str) -> Optional[str]:
        """Find the path to a tool executable"""
        return shutil.which(tool_name)
    
    def extract_apk_contents(self, apk_path: str) -> Optional[List[str]]:
        """Extract APK contents list for initial analysis"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                return zip_ref.namelist()
        except Exception as e:
            self.debug_print(f"Error extracting APK contents: {e}")
            return None
    
    def check_manifest_content(self, apk_path: str) -> str:
        """Check AndroidManifest.xml for framework packages using aapt"""
        try:
            aapt_path = self.find_tool_path('aapt')
            if not aapt_path:
                return ""
            result = subprocess.run(
                [aapt_path, 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'],
                capture_output=True, text=True
            )
            return result.stdout.lower() if result.returncode == 0 else ""
        except Exception:
            return ""
    
    def check_dex_content(self, apk_path: str) -> str:
        """Check DEX files for framework classes using dexdump"""
        try:
            dexdump_path = self.find_tool_path('dexdump')
            if not dexdump_path:
                return ""
            result = subprocess.run(
                [dexdump_path, '-l', 'plain', apk_path],
                capture_output=True, text=True
            )
            return result.stdout.lower() if result.returncode == 0 else ""
        except Exception:
            return ""
    
    def detect_apk_type(self, apk_path: str) -> Optional[str]:
        """
        ⭐ MAIN FUNCTION: Detect APK type: Java/Kotlin, React Native, or Flutter
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            str: Detected framework type ('java', 'kotlin', 'java_kotlin', 'react-native', 'flutter', or None)
        """
        print("🔍 Detecting APK type...")
        self.debug_print(f"Analyzing APK: {apk_path}")
        
        # Extract APK contents
        file_list = self.extract_apk_contents(apk_path)
        if file_list is None:
            self.debug_print("Failed to extract APK contents")
            return None
        
        self.debug_print(f"Extracted {len(file_list)} files from APK")
        
        # Convert file list to string for easier searching
        all_files = ' '.join(file_list).lower()
        
        # Get manifest and dex content
        manifest_content = self.check_manifest_content(apk_path)
        dex_content = self.check_dex_content(apk_path)
        
        self.debug_print(f"Manifest content length: {len(manifest_content)}")
        self.debug_print(f"DEX content length: {len(dex_content)}")
        
        # Combine all content for analysis
        all_content = f"{all_files} {manifest_content} {dex_content}"
        
        # Count indicators for each framework
        flutter_score = sum(1 for indicator in self.flutter_indicators if indicator.lower() in all_content)
        react_native_score = sum(1 for indicator in self.react_native_indicators if indicator.lower() in all_content)
        
        self.debug_print(f"Flutter indicators found: {flutter_score}")
        self.debug_print(f"React Native indicators found: {react_native_score}")
        
        # Determine APK type based on scores
        if flutter_score > 0:
            self.debug_print("Detected as Flutter based on indicators")
            print("📱 Detected: Flutter APK")
            return "flutter"
        elif react_native_score > 0:
            self.debug_print("Detected as React Native based on indicators")
            print("📱 Detected: React Native APK")
            return "react-native"
        else:
            # Check for Kotlin-specific patterns
            kotlin_patterns = ['kotlin', '.kt', 'kotlinx']
            kotlin_score = sum(1 for pattern in kotlin_patterns if pattern in all_content)
            
            self.debug_print(f"Kotlin indicators found: {kotlin_score}")
            
            if kotlin_score > 0:
                self.debug_print("Detected as Java/Kotlin based on Kotlin indicators")
                print("📱 Detected: Java/Kotlin APK (with Kotlin)")
                return "java_kotlin"
            else:
                self.debug_print("Defaulting to Java based on lack of other indicators")
                print("📱 Detected: Java/Kotlin APK")
                return "java"
    
    def is_flutter_app(self, apk_path: str) -> bool:
        """Check if APK is a Flutter application"""
        return self.detect_apk_type(apk_path) == "flutter"
    
    def is_react_native_app(self, apk_path: str) -> bool:
        """Check if APK is a React Native application"""
        return self.detect_apk_type(apk_path) == "react-native"
    
    def is_java_kotlin_app(self, apk_path: str) -> bool:
        """Check if APK is a Java/Kotlin application"""
        detected_type = self.detect_apk_type(apk_path)
        return detected_type in ["java", "kotlin", "java_kotlin"]
