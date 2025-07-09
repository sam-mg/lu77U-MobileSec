#!/usr/bin/env python3
"""
React Native Decompiler Wrapper Module

This module provides a wrapper around the react-native-decompiler tool
for extracting and decompiling JavaScript bundles from React Native APKs.
"""

import os
import subprocess
from typing import Dict, List, Optional
from pathlib import Path


class ReactNativeDecompiler:
    """
    Wrapper class for react-native-decompiler tool
    
    Handles:
    - Checking decompiler availability
    - Installing decompiler if needed
    - Decompiling JavaScript bundles
    - Managing decompiler output
    """
    
    def __init__(self, debug: bool = False):
        """Initialize React Native decompiler wrapper"""
        self.debug = debug
        
    def check_decompiler_availability(self) -> bool:
        """Check if react-native-decompiler is available"""
        if self.debug:
            print("🐛 DEBUG: Checking react-native-decompiler availability")
        
        try:
            result = subprocess.run(['npx', 'react-native-decompiler', '--help'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ react-native-decompiler is available")
                return True
            else:
                print("⚠️  react-native-decompiler not found, will install...")
                return False
        except Exception as e:
            if self.debug:
                print(f"🐛 DEBUG: Error checking react-native-decompiler: {e}")
            print(f"⚠️  Error checking react-native-decompiler: {e}")
            return False

    def install_decompiler(self) -> bool:
        """Install react-native-decompiler if not available"""
        if self.debug:
            print("🐛 DEBUG: Installing react-native-decompiler")
        
        try:
            print("📦 Installing react-native-decompiler...")
            result = subprocess.run(['npm', 'install', '-g', 'react-native-decompiler'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ react-native-decompiler installed successfully")
                return True
            else:
                print(f"❌ Failed to install react-native-decompiler: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Error installing react-native-decompiler: {e}")
            return False

    def is_hermes_bundle(self, bundle_path: str) -> bool:
        """Check if a bundle file is Hermes bytecode (binary format)"""
        try:
            with open(bundle_path, 'rb') as f:
                header = f.read(16)
                # Hermes bytecode files typically start with specific magic bytes
                # Common patterns: HBC (Hermes ByteCode), or specific version headers
                hermes_signatures = [
                    b'\\x83HBC',  # Common Hermes signature
                    b'\\x89HBC',  # Alternative Hermes signature
                    b'\\x84HBC',  # Another variant
                ]
                
                for signature in hermes_signatures:
                    if header.startswith(signature):
                        if self.debug:
                            print(f"🐛 DEBUG: Detected Hermes bundle with signature: {signature}")
                        return True
                
                # Additional check: Hermes files are typically binary and contain non-printable chars
                if len(header) > 8 and any(b < 32 and b not in [9, 10, 13] for b in header[:8]):
                    try:
                        # Try to decode as text - if it fails, likely binary (Hermes)
                        header.decode('utf-8')
                        return False
                    except UnicodeDecodeError:
                        if self.debug:
                            print("🐛 DEBUG: Bundle appears to be binary (likely Hermes)")
                        return True
                        
        except Exception as e:
            if self.debug:
                print(f"🐛 DEBUG: Error checking bundle format: {e}")
        return False

    def decompile_bundle(self, bundle_path: str, output_dir: str) -> bool:
        """Decompile JavaScript bundle using react-native-decompiler"""
        print(f"🔧 Decompiling bundle: {os.path.basename(bundle_path)}")
        
        if self.debug:
            print(f"🐛 DEBUG: Decompiling {bundle_path} to {output_dir}")
        
        # Pre-check: Analyze bundle type
        if self.is_hermes_bundle(bundle_path):
            print("⚡ Detected Hermes bytecode bundle - decompilation may not be possible")
            print("ℹ️  Hermes bundles are compiled bytecode and typically cannot be decompiled to readable JavaScript")
        
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Run react-native-decompiler
            cmd = ['npx', 'react-native-decompiler', '-i', bundle_path, '-o', output_dir]
            
            print(f"🚀 Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Bundle decompiled successfully")
                print(f"📁 Decompiled files saved to: {output_dir}")
                return True
            else:
                error_msg = result.stderr.strip()
                print(f"❌ Decompilation failed: {error_msg}")
                
                # Provide specific guidance based on error type
                if "No modules were found" in error_msg:
                    print("ℹ️  This usually indicates:")
                    print("   • Hermes bytecode bundle (common in production apps)")
                    print("   • Webpack bundle v5 (not supported)")
                    print("   • Unbundled React Native app")
                    print("   • Custom bundler configuration")
                
                # Try with additional flags for problematic bundles
                cmd_with_flags = cmd + ['--noEslint', '--unpackOnly']
                print(f"🔄 Retrying with flags: {' '.join(cmd_with_flags)}")
                
                result = subprocess.run(cmd_with_flags, capture_output=True, text=True)
                if result.returncode == 0:
                    print("✅ Bundle decompiled successfully (with fallback flags)")
                    return True
                else:
                    error_msg = result.stderr.strip()
                    print(f"❌ Decompilation failed even with fallback flags: {error_msg}")
                    print("🔄 Falling back to raw bundle analysis...")
                    return False
                
        except Exception as e:
            print(f"❌ Error during decompilation: {e}")
            return False

    def setup_decompiler_environment(self) -> bool:
        """Setup the React Native decompiler environment"""
        print("🔧 Setting up React Native decompiler environment...")
        
        # Check if decompiler is available
        if not self.check_decompiler_availability():
            # Try to install it
            if not self.install_decompiler():
                print("❌ Failed to setup React Native decompiler environment")
                return False
        
        print("✅ React Native decompiler environment ready")
        return True

    def get_decompiler_info(self) -> Dict[str, str]:
        """Get information about the installed decompiler"""
        info = {
            "available": False,
            "version": "unknown",
            "path": "unknown"
        }
        
        try:
            result = subprocess.run(['npx', 'react-native-decompiler', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info["available"] = True
                info["version"] = result.stdout.strip()
                
            # Try to get the actual path
            which_result = subprocess.run(['which', 'npx'], capture_output=True, text=True)
            if which_result.returncode == 0:
                info["path"] = which_result.stdout.strip()
                
        except Exception as e:
            if self.debug:
                print(f"🐛 DEBUG: Error getting decompiler info: {e}")
        
        return info

    def validate_output(self, output_dir: str) -> Dict[str, any]:
        """Validate decompiler output and return summary"""
        summary = {
            "success": False,
            "files_count": 0,
            "js_files": [],
            "errors": []
        }
        
        try:
            if not os.path.exists(output_dir):
                summary["errors"].append("Output directory does not exist")
                return summary
            
            # Count files in output directory
            all_files = []
            js_files = []
            
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    all_files.append(file_path)
                    
                    if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                        js_files.append(file_path)
            
            summary["files_count"] = len(all_files)
            summary["js_files"] = js_files
            summary["success"] = len(js_files) > 0
            
            if self.debug:
                print(f"🐛 DEBUG: Found {len(all_files)} total files, {len(js_files)} JavaScript files")
            
        except Exception as e:
            summary["errors"].append(f"Error validating output: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Error validating decompiler output: {e}")
        
        return summary


# Standalone functions for backward compatibility
def check_decompiler_availability(debug: bool = False) -> bool:
    """Check if react-native-decompiler is available"""
    decompiler = ReactNativeDecompiler(debug=debug)
    return decompiler.check_decompiler_availability()


def install_decompiler(debug: bool = False) -> bool:
    """Install react-native-decompiler if not available"""
    decompiler = ReactNativeDecompiler(debug=debug)
    return decompiler.install_decompiler()


def decompile_bundle(bundle_path: str, output_dir: str, debug: bool = False) -> bool:
    """Decompile JavaScript bundle using react-native-decompiler"""
    decompiler = ReactNativeDecompiler(debug=debug)
    return decompiler.decompile_bundle(bundle_path, output_dir)


def is_hermes_bundle(bundle_path: str, debug: bool = False) -> bool:
    """Check if a bundle file is Hermes bytecode (binary format)"""
    decompiler = ReactNativeDecompiler(debug=debug)
    return decompiler.is_hermes_bundle(bundle_path)
