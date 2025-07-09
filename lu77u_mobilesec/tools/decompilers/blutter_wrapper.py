#!/usr/bin/env python3
"""
Blutter Wrapper for Flutter decompilation

Handles Blutter setup, configuration, and decompilation operations.
"""

import os
import re
import subprocess
import shutil
import platform
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from ...system.validators.path_checker import PathChecker


class BlutterWrapper:
    """Wrapper for Blutter Flutter decompiler integration"""
    
    def __init__(self, debug: bool = False):
        """Initialize Blutter wrapper"""
        self.debug = debug
        self.blutter_output_dir = None
        self.blutter_script_path = PathChecker.get_blutter_path()
        self.blutter_enabled = bool(self.blutter_script_path)
        if self.debug:
            if self.blutter_enabled:
                print(f"🐛 BLUTTER DEBUG: Blutter enabled at {self.blutter_script_path}")
            else:
                print("🐛 BLUTTER DEBUG: Blutter not found in any supported location.")
        
    def debug_print(self, message: str) -> None:
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"🐛 BLUTTER DEBUG: {message}")
    
    def setup_blutter_environment(self) -> bool:
        """Setup Blutter environment (no install, just check)"""
        self.debug_print("Setting up Blutter environment...")
        if self.blutter_enabled:
            self.debug_print("Blutter already configured and ready")
            return True
        else:
            self.debug_print("Blutter not found. Please run 'lu77u-mobilesec doctor' to install Blutter.")
            return False

    def get_blutter_status(self) -> str:
        """Get current Blutter status"""
        try:
            if not self.blutter_script_path:
                return "not_configured"
            
            if self.blutter_enabled:
                return "ready"
            else:
                return "not_enabled"

        except Exception:
            return "error"
    
    def decompile_with_blutter(self, apk_path: str) -> Dict[str, str]:
        """Decompile APK using Blutter (correct command: python3 blutter.py <lib/arm64-v8a> <output_dir>)"""
        import tempfile
        try:
            if not self.blutter_enabled or not self.blutter_script_path:
                self.debug_print("Blutter not enabled or script path missing")
                return {}
            if not os.path.exists(apk_path):
                self.debug_print(f"APK not found: {apk_path}")
                return {}

            apk_name = os.path.splitext(os.path.basename(apk_path))[0]
            self.blutter_output_dir = f"{apk_name}_blutter_output"
            if os.path.exists(self.blutter_output_dir):
                shutil.rmtree(self.blutter_output_dir)
            os.makedirs(self.blutter_output_dir, exist_ok=True)

            # Extract APK to temp dir
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                    apk_zip.extractall(tmpdir)
                # Find lib/arm64-v8a directory
                lib_dir = os.path.join(tmpdir, 'lib', 'arm64-v8a')
                if not os.path.exists(lib_dir):
                    self.debug_print(f"lib/arm64-v8a not found in extracted APK: {lib_dir}")
                    return {}
                # Run Blutter: python3 blutter.py <lib/arm64-v8a> <output_dir>
                cmd = ['python3', str(self.blutter_script_path), lib_dir, self.blutter_output_dir]
                self.debug_print(f"Running command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode != 0:
                    self.debug_print(f"Blutter failed: {result.stderr}")
                    return {}

            self.debug_print("Blutter decompilation completed")
            
            # Collect decompiled files
            blutter_files = {}
            
            # Look for main.dart or dart files
            dart_files = []
            if os.path.exists(self.blutter_output_dir):
                for root, dirs, files in os.walk(self.blutter_output_dir):
                    for file in files:
                        if file.endswith('.dart'):
                            dart_files.append(os.path.join(root, file))
            
            # Read main dart file
            main_dart_file = None
            for dart_file in dart_files:
                if 'main.dart' in dart_file.lower():
                    main_dart_file = dart_file
                    break
            
            if not main_dart_file and dart_files:
                main_dart_file = dart_files[0]  # Use first dart file
            
            if main_dart_file and os.path.exists(main_dart_file):
                try:
                    with open(main_dart_file, 'r', encoding='utf-8') as f:
                        blutter_files['main_dart'] = f.read()
                    self.debug_print(f"Read main dart file: {main_dart_file}")
                except Exception as e:
                    self.debug_print(f"Error reading dart file: {e}")
            
            # Look for objs.txt
            objs_file = os.path.join(self.blutter_output_dir, "objs.txt")
            if os.path.exists(objs_file):
                try:
                    with open(objs_file, 'r', encoding='utf-8') as f:
                        blutter_files['objs_content'] = f.read()
                    self.debug_print("Read objs.txt")
                except Exception as e:
                    self.debug_print(f"Error reading objs.txt: {e}")
            
            # Look for pp.txt
            pp_file = os.path.join(self.blutter_output_dir, "pp.txt")
            if os.path.exists(pp_file):
                try:
                    with open(pp_file, 'r', encoding='utf-8') as f:
                        blutter_files['pp_content'] = f.read()
                    self.debug_print("Read pp.txt")
                except Exception as e:
                    self.debug_print(f"Error reading pp.txt: {e}")
            
            # Look for ASM files
            asm_dir = os.path.join(self.blutter_output_dir, "asm")
            if os.path.exists(asm_dir):
                asm_files = []
                for file in os.listdir(asm_dir):
                    if file.endswith('.txt'):
                        asm_file_path = os.path.join(asm_dir, file)
                        try:
                            with open(asm_file_path, 'r', encoding='utf-8') as f:
                                asm_content = f.read()
                                asm_files.append(f"=== {file} ===\n{asm_content[:2000]}")  # Limit size
                        except Exception as e:
                            self.debug_print(f"Error reading ASM file {file}: {e}")
                
                if asm_files:
                    blutter_files['asm_content'] = "\n\n".join(asm_files)
                    self.debug_print(f"Read {len(asm_files)} ASM files")
            
            # Look for Frida script
            frida_script = os.path.join(self.blutter_output_dir, "blutter_frida.js")
            if os.path.exists(frida_script):
                try:
                    with open(frida_script, 'r', encoding='utf-8') as f:
                        blutter_files['frida_script'] = f.read()
                    self.debug_print("Read Frida script")
                except Exception as e:
                    self.debug_print(f"Error reading Frida script: {e}")
            
            self.debug_print(f"Collected {len(blutter_files)} file types from Blutter output")
            return blutter_files
            
        except subprocess.TimeoutExpired:
            self.debug_print("Blutter decompilation timed out")
            return {}
        except Exception as e:
            self.debug_print(f"Error in Blutter decompilation: {e}")
            return {}
    
    def debug_blutter_integration(self, blutter_files: Dict[str, str]):
        """Debug Blutter integration and file contents"""
        try:
            if not self.debug:
                return
            
            print("\n" + "="*50)
            print("🐛 BLUTTER INTEGRATION DEBUG")
            print("="*50)
            
            if not blutter_files:
                print("❌ No Blutter files available")
                return
            
            print(f"📁 Blutter files found: {len(blutter_files)}")
            
            for file_type, content in blutter_files.items():
                print(f"\n--- {file_type.upper()} ---")
                print(f"Size: {len(content)} characters")
                
                if content:
                    # Show first few lines
                    lines = content.split('\n')
                    preview_lines = min(5, len(lines))
                    print("Preview:")
                    for i in range(preview_lines):
                        print(f"  {i+1}: {lines[i][:100]}{'...' if len(lines[i]) > 100 else ''}")
                    
                    if len(lines) > preview_lines:
                        print(f"  ... ({len(lines) - preview_lines} more lines)")
                else:
                    print("❌ Empty content")
            
            # Check for key indicators
            print(f"\n🔍 ANALYSIS INDICATORS:")
            
            if 'main_dart' in blutter_files:
                dart_content = blutter_files['main_dart']
                if 'http' in dart_content.lower():
                    print("✅ HTTP usage detected in Dart code")
                if 'password' in dart_content.lower() or 'secret' in dart_content.lower():
                    print("⚠️  Potential credentials in Dart code")
                if 'SharedPreferences' in dart_content:
                    print("📱 SharedPreferences usage detected")
            
            if 'objs_content' in blutter_files:
                objs = blutter_files['objs_content']
                obj_count = len(re.findall(r'^[A-Za-z_][A-Za-z0-9_]*:', objs, re.MULTILINE))
                print(f"🏗️  Objects found: {obj_count}")
            
            if 'pp_content' in blutter_files:
                pp = blutter_files['pp_content']
                if pp.strip():
                    print("📝 PP content available for analysis")
            
            print("="*50)
            
        except Exception as e:
            print(f"❌ Debug error: {e}")
