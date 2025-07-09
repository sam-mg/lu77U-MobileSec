#!/usr/bin/env python3
"""
Flutter analyzer for lu77U-MobileSec

Handles analysis of Flutter-based Android applications.
Restructured to follow separation of concerns principle.
"""

import os
import re
import json
import asyncio
import subprocess
import time
import shutil
import platform
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable

from ...ai.providers.ollama_provider import OllamaProvider
from ...ai.providers.groq_provider import GroqProvider
from ...ai.processors.vulnerability_analyzer import VulnerabilityAnalyzer
from ...ai.processors.fix_generator import FixGenerator
from ...ai.processors.response_parser import ResponseParser
from ...tools.decompilers.blutter_wrapper import BlutterWrapper
from ...tools.android_tools.manifest_parser import extract_android_manifest, decode_binary_manifest
from ...core.vulnerability.patterns import scan_flutter_vulnerabilities, detect_base64text, detect_hex
from ...core.vulnerability.severity import get_severity
from ...core.vulnerability.reporting import VulnerabilityReporter
from ...cli.interactive import ask_for_fix_option
from ...utils.file_system.manager import FileSystemManager
from ...utils.helpers.validation import analyze_input_consistency
from ...utils.file_system.output_organizer import OutputDirectoryOrganizer, save_processed_file, save_ai_prompt, save_ai_response, save_vulnerability_fix, save_dynamic_analysis, create_analysis_summary


class FlutterAnalyzer:
    """Flutter APK analyzer with dependency injection architecture"""
    
    def __init__(self, detector):
        """Initialize Flutter analyzer with dependency injection"""
        self.detector = detector
        self.debug = detector.debug if detector else False
        
        self.flutter_output_dir = None
        self.dart_files = {}
        self.main_dart_content = None
        self.decompiled_flutter_dir = None
        
        if detector:
            self.use_local_llm = getattr(detector, 'use_local_llm', True)
            self.llm_preference = getattr(detector, 'llm_preference', 'ollama')
            self.apk_base = getattr(detector, 'apk_base', None)
            self.timestamp = getattr(detector, 'timestamp', None)
            self.apk_dir = getattr(detector, 'apk_dir', None)
            self.prompts_dir = getattr(detector, 'prompts_dir', None)
            self.results_dir = getattr(detector, 'results_dir', None)
            self.resources_dir = getattr(detector, 'resources_dir', None)
            self.analysis_directories = getattr(detector, 'analysis_directories', None)
        else:
            self.use_local_llm = True
            self.llm_preference = 'ollama'
            self.apk_base = None
            self.timestamp = None
            self.apk_dir = None
            self.prompts_dir = None
            self.results_dir = None
            self.resources_dir = None
            self.analysis_directories = None
        
        self.ollama_provider = OllamaProvider()
        self.groq_provider = GroqProvider()
        self.vulnerability_analyzer = VulnerabilityAnalyzer(debug=self.debug)
        self.fix_generator = FixGenerator(debug=self.debug)
        self.response_parser = ResponseParser(debug=self.debug)
        self.blutter_wrapper = BlutterWrapper(debug=self.debug)
        self.vulnerability_reporter = VulnerabilityReporter(debug=self.debug)
        self.file_manager = FileSystemManager(self.results_dir)
        
        if self.debug:
            print(f"🐛 DEBUG: FlutterAnalyzer initialized with LLM preference: {self.llm_preference}")
            print(f"🐛 DEBUG: Dependencies injected successfully")
    
    def debug_print(self, message: str) -> None:
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"🐛 FLUTTER DEBUG: {message}")

    def is_flutter_app(self, apk_path: str) -> bool:
        """Detect if APK is a Flutter application"""
        self.debug_print("Starting Flutter app detection")
        print("🔍 Detecting Flutter application...")
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                self.debug_print(f"APK contains {len(file_list)} files")
                flutter_indicators = [
                    'lib/arm64-v8a/libflutter.so',
                    'lib/armeabi-v7a/libflutter.so',
                    'assets/flutter_assets/',
                    'assets/flutter_assets/kernel_blob.bin',
                    'assets/flutter_assets/isolate_snapshot_data',
                    'assets/flutter_assets/vm_snapshot_data'
                ]
                flutter_files_found = []
                for indicator in flutter_indicators:
                    matching_files = [f for f in file_list if indicator in f]
                    if matching_files:
                        flutter_files_found.append(indicator)
                        self.debug_print(f"Found Flutter indicator: {indicator}")
                if flutter_files_found:
                    print(f"✅ Flutter app detected! Found {len(flutter_files_found)} Flutter indicators:")
                    for indicator in flutter_files_found:
                        print(f"   • {indicator}")
                    self.debug_print(f"All Flutter indicators found: {flutter_files_found}")
                    return True
                else:
                    print("❌ Not a Flutter app - no Flutter indicators found")
                    self.debug_print("No Flutter indicators found in APK")
                    return False
        except Exception as e:
            print(f"❌ Error detecting Flutter app: {e}")
            self.debug_print(f"Exception during Flutter detection: {e}")
            return False

    def extract_flutter_assets(self, apk_path: str) -> Dict[str, Any]:
        """Extract Flutter assets and analyze app structure"""
        self.debug_print("Starting Flutter asset extraction")
        print("📁 Extracting Flutter assets...")
        flutter_assets = {
            "kernel_blob": None,
            "isolate_snapshot": None,
            "vm_snapshot": None,
            "asset_manifest": {},
            "pubspec_lock": None,
            "font_manifest": None,
            "notices": None,
            "asset_files": [],
            "configuration_files": []
        }
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                self.debug_print(f"Processing {len(file_list)} files from APK")
                flutter_asset_files = [f for f in file_list 
                                     if f.startswith('assets/flutter_assets/')]
                self.debug_print(f"Found {len(flutter_asset_files)} Flutter asset files")
                suspicious_extensions = ['.key', '.pem', '.p12', '.keystore', '.jks', '.config', '.env', '.properties']
                suspicious_files = [f for f in file_list 
                                  if any(f.lower().endswith(ext) for ext in suspicious_extensions)]
                if suspicious_files:
                    flutter_assets["configuration_files"] = suspicious_files
                    print(f"⚠️  Found {len(suspicious_files)} potential configuration files")
                    self.debug_print(f"Suspicious files: {suspicious_files}")
                for asset_file in flutter_asset_files:
                    self.debug_print(f"Processing asset file: {asset_file}")
                    try:
                        asset_data = apk_zip.read(asset_file)
                        flutter_assets["asset_files"].append({
                            "path": asset_file,
                            "size": len(asset_data)
                        })
                        if asset_file.endswith('AssetManifest.json'):
                            try:
                                flutter_assets["asset_manifest"] = json.loads(asset_data.decode('utf-8'))
                                print("✅ AssetManifest.json extracted")
                                self.debug_print(f"AssetManifest contains {len(flutter_assets['asset_manifest'])} entries")
                            except Exception as e:
                                self.debug_print(f"Failed to parse AssetManifest.json: {e}")
                        elif asset_file.endswith('FontManifest.json'):
                            try:
                                flutter_assets["font_manifest"] = json.loads(asset_data.decode('utf-8'))
                                print("✅ FontManifest.json extracted")
                                self.debug_print(f"FontManifest contains {len(flutter_assets['font_manifest'])} fonts")
                            except Exception as e:
                                self.debug_print(f"Failed to parse FontManifest.json: {e}")
                        elif asset_file.endswith('NOTICES.Z') or asset_file.endswith('NOTICES'):
                            try:
                                if asset_file.endswith('.Z'):
                                    import zlib
                                    notices_content = zlib.decompress(asset_data).decode('utf-8')
                                else:
                                    notices_content = asset_data.decode('utf-8')
                                flutter_assets["notices"] = notices_content
                                print("✅ NOTICES file extracted")
                                self.debug_print(f"NOTICES file size: {len(notices_content)} characters")
                            except Exception as e:
                                self.debug_print(f"Failed to extract NOTICES: {e}")
                        elif 'pubspec.lock' in asset_file:
                            try:
                                flutter_assets["pubspec_lock"] = asset_data.decode('utf-8')
                                print("✅ pubspec.lock extracted")
                                self.debug_print("pubspec.lock successfully extracted for dependency analysis")
                            except Exception as e:
                                self.debug_print(f"Failed to extract pubspec.lock: {e}")
                        elif 'kernel_blob.bin' in asset_file:
                            flutter_assets["kernel_blob"] = len(asset_data)
                            print(f"✅ kernel_blob.bin found ({len(asset_data)} bytes)")
                            self.debug_print(f"kernel_blob.bin size: {len(asset_data)} bytes")
                        elif 'isolate_snapshot_data' in asset_file:
                            flutter_assets["isolate_snapshot"] = len(asset_data)
                            print(f"✅ isolate_snapshot_data found ({len(asset_data)} bytes)")
                            self.debug_print(f"isolate_snapshot_data size: {len(asset_data)} bytes")
                        elif 'vm_snapshot_data' in asset_file:
                            flutter_assets["vm_snapshot"] = len(asset_data)
                            print(f"✅ vm_snapshot_data found ({len(asset_data)} bytes)")
                            self.debug_print(f"vm_snapshot_data size: {len(asset_data)} bytes")
                    except Exception as e:
                        print(f"⚠️  Error extracting {asset_file}: {e}")
                        self.debug_print(f"Asset extraction error for {asset_file}: {e}")
        except Exception as e:
            print(f"❌ Error extracting Flutter assets: {e}")
            self.debug_print(f"Major error in asset extraction: {e}")
        
        # Save extracted Flutter assets to structured output directory
        if self.analysis_directories and flutter_assets:
            try:
                print("📁 Saving Flutter assets to structured output directory...")
                
                # Save AssetManifest.json
                if flutter_assets.get("asset_manifest"):
                    manifest_content = json.dumps(flutter_assets["asset_manifest"], indent=2)
                    save_processed_file(manifest_content, "AssetManifest.json", self.analysis_directories)
                
                # Save FontManifest.json
                if flutter_assets.get("font_manifest"):
                    font_content = json.dumps(flutter_assets["font_manifest"], indent=2)
                    save_processed_file(font_content, "FontManifest.json", self.analysis_directories)
                
                # Save NOTICES
                if flutter_assets.get("notices"):
                    save_processed_file(flutter_assets["notices"], "NOTICES.txt", self.analysis_directories)
                
                # Save pubspec.lock
                if flutter_assets.get("pubspec_lock"):
                    save_processed_file(flutter_assets["pubspec_lock"], "pubspec.lock", self.analysis_directories)
                
                # Save information about binary files
                binary_info = []
                if flutter_assets.get("kernel_blob"):
                    binary_info.append(f"kernel_blob.bin: {flutter_assets['kernel_blob']} bytes")
                if flutter_assets.get("isolate_snapshot"):
                    binary_info.append(f"isolate_snapshot_data: {flutter_assets['isolate_snapshot']} bytes")
                if flutter_assets.get("vm_snapshot"):
                    binary_info.append(f"vm_snapshot_data: {flutter_assets['vm_snapshot']} bytes")
                
                if binary_info:
                    binary_content = "# Flutter Binary Files Information\n\n" + "\n".join(binary_info)
                    save_processed_file(binary_content, "flutter_binary_files_info.md", self.analysis_directories)
                
                # Save asset files list
                if flutter_assets.get("asset_files"):
                    assets_content = "# Flutter Asset Files\n\n"
                    for asset in flutter_assets["asset_files"]:
                        assets_content += f"- {asset['path']} ({asset['size']} bytes)\n"
                    save_processed_file(assets_content, "flutter_asset_files_list.md", self.analysis_directories)
                
                # Save configuration files if found
                if flutter_assets.get("configuration_files"):
                    config_content = "# Potential Configuration Files Found\n\n"
                    for config_file in flutter_assets["configuration_files"]:
                        config_content += f"- {config_file}\n"
                    save_processed_file(config_content, "configuration_files_found.md", self.analysis_directories)
                
                print("📁 Saved Flutter assets to structured directory")
                
            except Exception as e:
                print(f"⚠️  Warning: Could not save Flutter assets to structured directory: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
        
        self.debug_print(f"Asset extraction complete. Extracted {len(flutter_assets['asset_files'])} asset files")
        return flutter_assets
    
    def extract_pubspec_lock(self, flutter_assets: Dict[str, Any]) -> str:
        """Extract pubspec.lock content for dependency security analysis"""
        self.debug_print("Extracting pubspec.lock for dependency analysis")
        pubspec_content = flutter_assets.get('pubspec_lock')
        if pubspec_content:
            self.debug_print(f"pubspec.lock extracted: {len(pubspec_content)} characters")
            return pubspec_content
        else:
            self.debug_print("pubspec.lock not found in Flutter assets")
            return "pubspec.lock not found"
    
    def analyze_dart_code_patterns(self, dart_code: str) -> List[Dict]:
        """Analyze Dart code for security vulnerabilities (if available)"""
        self.debug_print("Starting Dart code pattern analysis")
        vulnerabilities = []
        dart_patterns = [
            (r'http://[^"\']*["\']', 'HTTP URL without encryption'),
            (r'MethodChannel\s*\([^)]*\)\.invokeMethod\s*\([^,]*,\s*[^)]*\)', 'Platform channel without input validation'),
            (r'File\s*\([^)]*\)\.writeAsString', 'File write operation'),
            (r'Directory\s*\([^)]*\)', 'Directory access'),
            (r'SharedPreferences\.getInstance\(\)', 'SharedPreferences usage (check for sensitive data)'),
            (r'WebView\s*\(', 'WebView usage detected'),
            (r'launch\s*\([^)]*\)', 'URL launch without validation'),
            (r'Platform\.isAndroid', 'Platform-specific code path'),
            (r'jsonDecode\s*\([^)]*\)', 'JSON parsing without validation'),
            (r'Random\s*\(\)', 'Random number generation (check if cryptographically secure)'),
        ]
        self.debug_print(f"Analyzing Dart code with {len(dart_patterns)} patterns")
        for pattern, description in dart_patterns:
            matches = re.finditer(pattern, dart_code, re.IGNORECASE)
            for match in matches:
                line_num = dart_code[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                vulnerabilities.append({
                    'type': 'Code Pattern',
                    'description': f"{description}: {matched_text}",
                    'file': 'Dart code',
                    'line': line_num,
                    'severity': get_severity(description, "flutter"),
                    'confidence': 0.6
                })
                self.debug_print(f"Found pattern: {description} at line {line_num}")
        self.debug_print(f"Dart pattern analysis complete. Found {len(vulnerabilities)} potential issues")
        return vulnerabilities
    
    def analyze_blutter_dart_code(self, dart_content: str) -> List[Dict]:
        """Analyze Blutter-decompiled Dart code for security vulnerabilities"""
        self.debug_print("Starting Blutter Dart analysis")
        return self.analyze_dart_code_patterns(dart_content)

    def analyze_blutter_objects(self, objs_content: str, pp_content: str) -> List[Dict]:
        """Analyze Blutter objects and preprocessor output for security vulnerabilities"""
        self.debug_print("Starting Blutter objects analysis")
        vulnerabilities = []
        if objs_content:
            self.debug_print("Analyzing objs.txt content")
            security_patterns = [
                (r'class.*[Cc]rypto', 'Cryptographic class found'),
                (r'class.*[Aa]uth', 'Authentication class found'),
                (r'class.*[Tt]oken', 'Token handling class found'),
                (r'function.*[Pp]assword', 'Password handling function found'),
                (r'function.*[Kk]ey', 'Key handling function found'),
                (r'class.*[Nn]etwork', 'Network class found'),
                (r'function.*[Dd]ecrypt', 'Decryption function found'),
                (r'function.*[Ee]ncrypt', 'Encryption function found'),
                (r'class.*[Ss]ql', 'SQL class found (potential injection)'),
                (r'function.*[Qq]uery', 'Query function found (potential injection)'),
            ]
            for pattern, description in security_patterns:
                matches = re.finditer(pattern, objs_content, re.IGNORECASE)
                for match in matches:
                    line_num = objs_content[:match.start()].count('\n') + 1
                    matched_text = match.group(0)
                    vulnerabilities.append({
                        'type': 'Blutter Analysis',
                        'description': f"{description}: {matched_text}",
                        'file': 'objs.txt',
                        'line': line_num,
                        'severity': get_severity(description, "flutter"),
                        'confidence': 0.5
                    })
                    self.debug_print(f"Found in objs: {description} at line {line_num}")
        if pp_content:
            self.debug_print("Analyzing pp.txt content")
            secret_patterns = [
                (r'["\'][A-Za-z0-9+/]{32,}={0,2}["\']', 'Potential Base64 encoded secret'),
                (r'["\'][0-9a-f]{32,}["\']', 'Potential hexadecimal secret'),
                (r'["\']sk_[a-zA-Z0-9]{32,}["\']', 'Potential Stripe secret key'),
                (r'["\']pk_[a-zA-Z0-9]{32,}["\']', 'Potential Stripe public key'),
                (r'["\']AKIA[0-9A-Z]{16}["\']', 'Potential AWS access key'),
                (r'["\'][a-zA-Z0-9/+]{40}["\']', 'Potential AWS secret key'),
                (r'["\']gh[ps]_[A-Za-z0-9_]{36}["\']', 'Potential GitHub token'),
                (r'http://[^"\']*["\']', 'HTTP URL (insecure)'),
                (r'password["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Hardcoded password'),
                (r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Hardcoded API key'),
            ]
            for pattern, description in secret_patterns:
                matches = re.finditer(pattern, pp_content, re.IGNORECASE)
                for match in matches:
                    line_num = pp_content[:match.start()].count('\n') + 1
                    matched_text = match.group(0)
                    severity = "HIGH" if any(keyword in description.lower() for keyword in ['secret', 'key', 'password', 'token']) else "MEDIUM"
                    vulnerabilities.append({
                        'type': 'Blutter Analysis',
                        'description': f"{description}: {matched_text[:100]}..." if len(matched_text) > 100 else f"{description}: {matched_text}",
                        'file': 'pp.txt',
                        'line': line_num,
                        'severity': severity,
                        'confidence': 0.7
                    })
                    self.debug_print(f"Found in pp: {description} at line {line_num}")
        self.debug_print(f"Blutter objects analysis complete. Found {len(vulnerabilities)} potential issues")
        return vulnerabilities

    def analyze_manifest_for_flutter(self, apk_path: str) -> List[Dict]:
        """Analyze AndroidManifest.xml for Flutter-specific security configurations"""
        self.debug_print("Starting Flutter manifest analysis")
        vulnerabilities = []
        manifest_content = extract_android_manifest(apk_path)
        if "error" in manifest_content.lower() or "not found" in manifest_content.lower():
            self.debug_print("AndroidManifest.xml not available for analysis")
            return vulnerabilities
        flutter_manifest_patterns = [
            (r'android:allowBackup="true"', 'App data backup enabled (potential data exposure)', 'MEDIUM'),
            (r'android:debuggable="true"', 'App is debuggable in production', 'HIGH'),
            (r'android:exported="true".*android:permission=""', 'Exported component without permission', 'HIGH'),
            (r'<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"', 'Write external storage permission', 'MEDIUM'),
            (r'<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"', 'Read external storage permission', 'LOW'),
            (r'android:usesCleartextTraffic="true"', 'Cleartext traffic allowed', 'HIGH'),
            (r'<activity.*android:exported="true".*intent-filter', 'Exported activity with intent filter', 'MEDIUM'),
            (r'<service.*android:exported="true"', 'Exported service', 'MEDIUM'),
            (r'<receiver.*android:exported="true"', 'Exported broadcast receiver', 'MEDIUM'),
        ]
        for pattern, description, severity in flutter_manifest_patterns:
            matches = re.finditer(pattern, manifest_content, re.IGNORECASE)
            for match in matches:
                line_num = manifest_content[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                vulnerabilities.append({
                    'type': 'Manifest Security',
                    'description': f"{description}: {matched_text}",
                    'file': 'AndroidManifest.xml',
                    'line': line_num,
                    'severity': severity,
                    'confidence': 0.8
                })
                self.debug_print(f"Found manifest issue: {description} at line {line_num}")
        self.debug_print(f"Flutter manifest analysis complete. Found {len(vulnerabilities)} issues")
        return vulnerabilities

    def scan_blutter_decompiled_vulnerabilities(self, blutter_files: Dict[str, Any]) -> List[Dict]:
        self.debug_print(f"Entered scan_blutter_decompiled_vulnerabilities with blutter_files keys: {list(blutter_files.keys())}")
        """Scan Blutter decompiled files (main.dart, objs.txt, pp.txt) for explicit vulnerabilities"""
        vulnerabilities = []
        manifest_content = blutter_files.get('manifest_content') or blutter_files.get('AndroidManifest.xml')
        if manifest_content:
            if 'android:debuggable="true"' in manifest_content:
                vulnerabilities.append({
                    'title': 'App is Debuggable',
                    'severity': 'HIGH',
                    'description': 'android:debuggable="true" found in AndroidManifest.xml',
                    'location': 'AndroidManifest.xml',
                    'file_type': 'Manifest',
                    'pattern': 'debuggable',
                    'matched_text': 'android:debuggable="true"',
                    'impact': 'App can be debugged in production, increasing risk of reverse engineering.',
                    'recommendation': 'Remove android:debuggable="true" for production builds.',
                    'code': 'android:debuggable="true"'
                })
            if 'android:allowBackup="true"' in manifest_content:
                vulnerabilities.append({
                    'title': 'App Data Backup Enabled',
                    'severity': 'MEDIUM',
                    'description': 'android:allowBackup="true" found in AndroidManifest.xml',
                    'location': 'AndroidManifest.xml',
                    'file_type': 'Manifest',
                    'pattern': 'allowBackup',
                    'matched_text': 'android:allowBackup="true"',
                    'impact': 'App data can be backed up and restored, which may leak sensitive data.',
                    'recommendation': 'Set android:allowBackup="false" unless backup is required.',
                    'code': 'android:allowBackup="true"'
                })
            if 'android:usesCleartextTraffic="true"' in manifest_content:
                vulnerabilities.append({
                    'title': 'Cleartext Traffic Allowed',
                    'severity': 'HIGH',
                    'description': 'android:usesCleartextTraffic="true" found in AndroidManifest.xml',
                    'location': 'AndroidManifest.xml',
                    'file_type': 'Manifest',
                    'pattern': 'usesCleartextTraffic',
                    'matched_text': 'android:usesCleartextTraffic="true"',
                    'impact': 'App allows unencrypted network traffic.',
                    'recommendation': 'Set android:usesCleartextTraffic="false" for production.',
                    'code': 'android:usesCleartextTraffic="true"'
                })
        for fname in ['main_dart', 'objs_content', 'pp_content']:
            content = blutter_files.get(fname)
            if not content:
                continue
            vulnerabilities.extend(detect_base64text(content, fname))
            vulnerabilities.extend(detect_hex(content, fname))
            for match in re.finditer(r'_getNativeField|native peer', content, re.IGNORECASE):
                vulnerabilities.append({
                    'title': 'Suspicious Native Access',
                    'severity': 'LOW',
                    'description': 'Suspicious native access string found.',
                    'location': fname,
                    'file_type': 'Blutter',
                    'pattern': match.group(0),
                    'matched_text': match.group(0),
                    'impact': 'May indicate native code or unsafe operations.',
                    'recommendation': 'Review native access for security risks.',
                    'code': match.group(0)
                })
        self.debug_print(f"scan_blutter_decompiled_vulnerabilities returning {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _normalize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Normalize vulnerability dicts to match VulnerabilityReporter expectations"""
        normalized = []
        for vuln in vulnerabilities:
            v = vuln.copy()
            if 'type' in v and 'vulnerability_type' not in v:
                v['vulnerability_type'] = v['type']
            if 'title' in v and 'vulnerability_type' not in v:
                v['vulnerability_type'] = v['title']
            if 'location' in v and 'file' not in v:
                v['file'] = v['location']
            if 'file_type' in v and 'file' not in v:
                v['file'] = v['file_type']
            if 'line' in v and 'line_number' not in v:
                v['line_number'] = v['line']
            if 'lineNumber' in v and 'line_number' not in v:
                v['line_number'] = v['lineNumber']
            if 'code' in v and 'code_snippet' not in v:
                v['code_snippet'] = v['code']
            if 'matched_text' in v and 'code_snippet' not in v:
                v['code_snippet'] = v['matched_text']
            if 'vulnerability_type' not in v:
                v['vulnerability_type'] = 'Unknown'
            if 'file' not in v:
                v['file'] = 'Unknown'
            if 'description' not in v:
                v['description'] = 'No description'
            normalized.append(v)
        return normalized

    async def analyze_flutter_apk(self, apk_path: str, output_dir: str = None, use_ai: bool = True, fix_vulnerabilities: bool = False, selected_fix_indices: list = None, end_timer_callback: callable = None, format_duration_callback: callable = None) -> list:
        """
        Main Flutter APK analysis method
        
        This method orchestrates the complete Flutter analysis workflow:
        1. Flutter app detection
        2. Asset extraction
        3. Vulnerability pattern scanning  
        4. Blutter decompilation (if available)
        5. AI-powered analysis (if enabled)
        6. Vulnerability reporting
        7. Fix generation (if requested)
        """
        self.debug_print(f"Starting Flutter APK analysis for: {apk_path}")
        print(f"\n{'='*80}")
        print("🔍 FLUTTER APK SECURITY ANALYSIS")
        print(f"{'='*80}")
        print(f"📱 APK: {os.path.basename(apk_path)}")
        print(f"🎯 Analysis Mode: {'AI + Pattern' if use_ai else 'Pattern Only'}")
        print(f"{'='*80}\n")
        
        all_vulnerabilities = []
        if not self.is_flutter_app(apk_path):
            print("❌ Not a Flutter app - analysis terminated")
            return []
        flutter_assets = self.extract_flutter_assets(apk_path)
        pubspec_content = self.extract_pubspec_lock(flutter_assets)
        print("\n🔍 Starting pattern-based vulnerability scanning...")
        pattern_vulnerabilities = scan_flutter_vulnerabilities(flutter_assets)
        if pattern_vulnerabilities:
            all_vulnerabilities.extend(pattern_vulnerabilities)
            print(f"✅ Pattern scanning found {len(pattern_vulnerabilities)} potential issues")
        else:
            print("✅ Pattern scanning complete - no issues found")
        print("\n📄 Analyzing AndroidManifest.xml for Flutter security...")
        manifest_vulnerabilities = self.analyze_manifest_for_flutter(apk_path)
        if manifest_vulnerabilities:
            all_vulnerabilities.extend(manifest_vulnerabilities)
            print(f"✅ Manifest analysis found {len(manifest_vulnerabilities)} issues")
        else:
            print("✅ Manifest analysis complete - no issues found")
        blutter_files = {}
        try:
            print("\n🔧 Attempting Blutter decompilation...")
            blutter_files = self.blutter_wrapper.decompile_with_blutter(apk_path)
            if blutter_files and any(blutter_files.values()):
                print(f"✅ Blutter decompilation successful - analyzing {len(blutter_files)} files")
                dart_vulnerabilities = []
                object_vulnerabilities = []
                if 'main_dart' in blutter_files and blutter_files['main_dart']:
                    dart_vulnerabilities = self.analyze_blutter_dart_code(blutter_files['main_dart'])
                    all_vulnerabilities.extend(dart_vulnerabilities)
                if 'objs' in blutter_files and 'pp' in blutter_files:
                    object_vulnerabilities = self.analyze_blutter_objects(
                        blutter_files.get('objs', ''), 
                        blutter_files.get('pp', '')
                    )
                    all_vulnerabilities.extend(object_vulnerabilities)
                self.debug_print("About to call scan_blutter_decompiled_vulnerabilities with blutter_files keys: " + str(list(blutter_files.keys())))
                explicit_blutter_vulns = self.scan_blutter_decompiled_vulnerabilities(blutter_files)
                self.debug_print("scan_blutter_decompiled_vulnerabilities returned: " + str(len(explicit_blutter_vulns)) + " items")
                if explicit_blutter_vulns:
                    all_vulnerabilities.extend(explicit_blutter_vulns)
                    print(f"✅ Explicit Blutter pattern scan found {len(explicit_blutter_vulns)} issues")
                print(f"✅ Blutter analysis complete - found {len(dart_vulnerabilities + object_vulnerabilities + explicit_blutter_vulns)} additional issues")
            else:
                print("⚠️  Blutter decompilation failed or produced no results")
        except Exception as e:
            self.debug_print(f"Blutter analysis failed: {e}")
            print(f"⚠️  Blutter analysis error: {e}")
        if use_ai:
            try:
                print("\n🤖 Starting AI-powered vulnerability analysis...")
                ai_context = {
                    'manifest_content': extract_android_manifest(apk_path),
                    'main_dart': blutter_files.get('main_dart'),
                    'objs_content': blutter_files.get('objs') or blutter_files.get('objs_content'),
                    'pp_content': blutter_files.get('pp') or blutter_files.get('pp_content'),
                    'pubspec_content': pubspec_content if pubspec_content != 'pubspec.lock not found' else None
                }
                ai_context = {k: v for k, v in ai_context.items() if v}
                key_to_filename = {
                    'manifest_content': 'AndroidManifest.xml',
                    'main_dart': 'main.dart',
                    'objs_content': 'objs.txt',
                    'pp_content': 'pp.txt',
                    'pubspec_content': 'pubspec.lock',
                }
                if self.debug:
                    print("📝 AI Vulnerability Search Prompt Details:")
                    for fname, content in ai_context.items():
                        print(f"  - {fname}: {len(content)} characters")
                ai_vulns = []
                if ai_context:
                    print(f"📝 Analyzing {len(ai_context)} Flutter files with specialized AI prompts...")
                    for key, content in ai_context.items():
                        mapped_fname = key_to_filename.get(key, key)
                        print(f"\n🔍 [AI] Analyzing file: {mapped_fname} ({len(content)} chars)")
                        ai_file_context = {'filename': mapped_fname}
                        try:
                            file_vulns = await self.vulnerability_analyzer.analyze_code_with_ai(
                                "flutter",
                                code_content=content,
                                context=ai_file_context,
                                use_local_llm=self.use_local_llm,
                                llm_preference=self.llm_preference
                            )
                            if self.debug:
                                print(f"[AI DEBUG] Raw response for {mapped_fname}: {file_vulns}")
                            if file_vulns:
                                for v in file_vulns:
                                    v['file'] = mapped_fname
                                ai_vulns.extend(file_vulns)
                                print(f"✅ AI found {len(file_vulns)} vulnerabilities in {mapped_fname}")
                            else:
                                print(f"✅ AI found no issues in {mapped_fname}")
                        except Exception as e:
                            print(f"⚠️  AI analysis error for {mapped_fname}: {e}")
                            self.debug_print(f"AI analysis failed for {mapped_fname}: {e}")
                    if ai_vulns:
                        all_vulnerabilities.extend(ai_vulns)
                        print(f"✅ AI analysis complete - found {len(ai_vulns)} potential vulnerabilities")
                        by_file = {}
                        for v in ai_vulns:
                            file = v.get('file', 'Unknown')
                            by_file.setdefault(file, []).append(v)
                        for file, vulns in by_file.items():
                            print(f"\n📄 {file}: {len(vulns)} findings")
                            for v in vulns:
                                print(f"  • {v['title']} ({v['severity']})")
                    else:
                        print("✅ AI analysis complete - no issues found")
                else:
                    print("⚠️  No Flutter files available for AI analysis")
            except Exception as e:
                self.debug_print(f"AI analysis failed: {e}")
                print(f"⚠️  AI analysis error: {e}")
        if all_vulnerabilities:
            all_vulnerabilities = self.vulnerability_reporter.deduplicate_vulnerabilities(
                self._normalize_vulnerabilities(all_vulnerabilities)
            )
            print(f"\n📊 Analysis Summary:")
            print(f"   Total vulnerabilities found: {len(all_vulnerabilities)}")
            self.vulnerability_reporter.display_vulnerabilities(all_vulnerabilities)
            if fix_vulnerabilities:
                try:
                    print("\nWould you like to generate fixes for any of the above vulnerabilities?")
                    selected_fix_indices = ask_for_fix_option(all_vulnerabilities)
                    if selected_fix_indices:
                        print(f"\n🔧 Generating fixes for selected vulnerabilities: {selected_fix_indices}")
                        for vuln in all_vulnerabilities:
                            if vuln.get("file") == "pp_content":
                                vuln["original_file"] = vuln["file"]
                        files_content = {
                            'main_dart': blutter_files.get('main_dart', ''),
                            'objs_content': blutter_files.get('objs_content', ''),
                            'pp_content': blutter_files.get('pp_content', ''),
                            'pp_content.dart': blutter_files.get('pp_content', ''),
                            'frida_script': blutter_files.get('frida_script', ''),
                            'AndroidManifest.xml': extract_android_manifest(apk_path) or '',
                            'manifest_content': extract_android_manifest(apk_path) or '',
                        }
                        for orig_name, content in blutter_files.items():
                            if isinstance(content, str):
                                files_content[orig_name] = content
                                if not orig_name.endswith('.dart') and orig_name != 'frida_script':
                                    files_content[f"{orig_name}.dart"] = content
                        alias_map = {
                            "main_dart": "main.dart",
                            "objs_content": "objs.txt", 
                            "pp_content": "pp.txt",
                            "frida_script": "blutter_frida.js",
                            "manifest_content": "AndroidManifest.xml"
                        }
                        for key, alias in alias_map.items():
                            if files_content.get(key):
                                files_content[alias] = files_content[key]
                        await self.fix_generator.process_vulnerability_fixes(
                            all_vulnerabilities,
                            selected_fix_indices,
                            files_content,
                            self.llm_preference,
                            "flutter",
                            self.results_dir,
                            self.apk_base or 'unknown'
                        )
                        print("✅ Fix generation complete!")
                    else:
                        print("✅ No fixes requested - analysis complete!")
                except Exception as e:
                    self.debug_print(f"Fix generation failed: {e}")
                    print(f"⚠️  Fix generation error: {e}")
        else:
            print("\n✅ No vulnerabilities found - Flutter app appears secure!")
        print(f"\n{'='*80}")
        print("🎉 FLUTTER ANALYSIS COMPLETE")
        print(f"{'='*80}")
        if end_timer_callback:
            try:
                end_timer_callback()
            except Exception as e:
                self.debug_print(f"Timer callback error: {e}")
        return all_vulnerabilities