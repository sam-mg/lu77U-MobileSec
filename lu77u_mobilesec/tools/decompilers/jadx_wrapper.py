#!/usr/bin/env python3
"""
JADX Wrapper Module

This module provides a wrapper around the JADX decompiler tool for
decompiling Android APK files.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Tuple, Optional


class JadxWrapper:
    """Wrapper class for JADX decompiler operations"""
    
    def __init__(self, debug: bool = False):
        """Initialize JADX wrapper"""
        self.debug = debug
    
    def jadx_decompile(self, apk_path: str, output_dir: Path) -> bool:
        """Decompile APK using JADX decompiler tool"""
        print("🔧 Decompiling APK with JADX...")
        
        if self.debug:
            print(f"🐛 JADX DEBUG: Starting JADX decompilation for {apk_path}")
        
        if not Path(apk_path).exists():
            print(f"❌ APK file not found: {apk_path}")
            return False
        
        if self.debug:
            print(f"🐛 JADX DEBUG: Output directory will be: {output_dir}")
            print(f"🐛 JADX DEBUG: Output directory exists: {output_dir.exists()}")
            print(f"🐛 JADX DEBUG: APK file size: {Path(apk_path).stat().st_size} bytes")
        
        try:
            # Check if JADX is available
            jadx_check = subprocess.run(['which', 'jadx'], capture_output=True, text=True)
            if jadx_check.returncode != 0:
                print("❌ JADX not found in PATH. Please install JADX.")
                return False
            else:
                if self.debug:
                    print(f"🐛 JADX DEBUG: JADX found at: {jadx_check.stdout.strip()}")
        
            # Use JADX with optimized settings for security analysis
            jadx_cmd = [
                'jadx',
                '--output-dir', str(output_dir),
                '--no-imports',  # Skip imports for cleaner analysis
                '--show-bad-code',  # Show problematic code for security analysis
                apk_path
            ]
            
            print(f"Running: {' '.join(jadx_cmd)}")
            if self.debug:
                print(f"🐛 JADX DEBUG: Command: {' '.join(jadx_cmd)}")
            
            result = subprocess.run(jadx_cmd, capture_output=True, text=True)
            
            if self.debug:
                print(f"🐛 JADX DEBUG: Return code: {result.returncode}")
                print(f"🐛 JADX DEBUG: STDOUT length: {len(result.stdout)}")
                print(f"🐛 JADX DEBUG: STDERR length: {len(result.stderr)}")
            
            # JADX often returns code 1 even with successful decompilation but with errors
            # Check if output directory was created and has content
            if output_dir.exists() and any(output_dir.iterdir()):
                error_count = self.parse_jadx_errors(result.stdout, result.stderr)
                if result.returncode == 0:
                    print(f"✅ JADX decompilation completed successfully with {error_count} errors")
                else:
                    print(f"✅ JADX decompilation completed with return code {result.returncode} and {error_count} errors")
                return True
            else:
                print(f"❌ JADX decompilation failed with return code: {result.returncode}")
                if result.stderr:
                    print(f"Error details: {result.stderr[:500]}")
                if result.stdout:
                    print(f"Output details: {result.stdout[:500]}")
                return False
                
        except FileNotFoundError as e:
            print("❌ JADX not found. Please install JADX and ensure it's in your PATH.")
            if self.debug:
                print(f"🐛 JADX DEBUG: FileNotFoundError: {e}")
            return False
        except Exception as e:
            print(f"❌ JADX decompilation error: {e}")
            return False

    def parse_jadx_errors(self, stdout: str, stderr: str) -> int:
        """Parse JADX output to extract error count and status"""
        error_count = 0
        
        # Look for error count in stdout
        if stdout:
            error_match = re.search(r'ERROR - (\d+)', stdout)
            if error_match:
                error_count = int(error_match.group(1))
        
        # If no error count found in stdout, count ERROR lines in stderr
        if error_count == 0 and stderr:
            error_count = stderr.count('ERROR')
        
        return error_count
