#!/usr/bin/env python3
"""
Enhanced React Native APK Analysis Module with Decompiler Integration

This module handles comprehensive analysis of React Native Android APKs including:
- JavaScript bundle extraction and decompilation using react-native-decompiler
- React Native specific vulnerability scanning on decompiled code
- Metro bundler and JSI bridge security analysis
- Module-level vulnerability detection
"""

import os
import re
import json
import time
import asyncio
import subprocess
import tempfile
import shutil
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any

from ...constants.vulnerabilities import VULNERABILITY_KEYWORDS
from ...constants.severity_levels import SEVERITY_HIGH, SEVERITY_MEDIUM
from ...constants.frameworks import REACT_NATIVE_INDICATORS
from ...ai.providers.ollama_provider import OllamaProvider
from ...ai.providers.groq_provider import GroqProvider
from ...ai.processors.fix_generator import FixGenerator
from ...ai.processors.vulnerability_analyzer import VulnerabilityAnalyzer
from ...tools.decompilers.react_native_decompiler import ReactNativeDecompiler
from ...core.vulnerability.severity import get_enhanced_severity
from ...core.vulnerability.reporting import VulnerabilityReporter
from ...cli.interactive import ask_for_fix_option
from ...utils.file_system.output_organizer import OutputDirectoryOrganizer, save_processed_file, save_ai_prompt, save_ai_response, save_vulnerability_fix, save_dynamic_analysis, create_analysis_summary


class ReactNativeAnalyzer:
    """
    Enhanced React Native APK Analysis Class with Decompiler Integration
    
    Handles:
    - JavaScript bundle extraction and decompilation
    - React Native vulnerability scanning on decompiled modules
    - Bridge security analysis
    - Metro bundler artifact analysis
    - Module-level code analysis
    """
    
    def __init__(self, orchestrator=None, debug=False):
        """Initialize Enhanced React Native analyzer"""
        self.orchestrator = orchestrator
        self.debug = debug
        self.js_bundle_content = ""
        self.decompiled_modules = {}
        self.react_native_version = ""
        self.metro_config = {}
        self.decompiler_output_dir = ""
        self.analysis_start_time = None
        self.analysis_end_time = None
        
        # Copy directory attributes from orchestrator if available
        if self.orchestrator:
            self.apk_base = getattr(self.orchestrator, 'apk_base', None)
            self.timestamp = getattr(self.orchestrator, 'timestamp', None)
            self.apk_dir = getattr(self.orchestrator, 'apk_dir', None)
            self.prompts_dir = getattr(self.orchestrator, 'prompts_dir', None)
            self.results_dir = getattr(self.orchestrator, 'results_dir', None)
            self.resources_dir = getattr(self.orchestrator, 'resources_dir', None)
            self.use_local_llm = getattr(self.orchestrator, 'use_local_llm', False)
            self.llm_preference = getattr(self.orchestrator, 'llm_preference', 'ollama')
            self.analysis_directories = getattr(self.orchestrator, 'analysis_directories', None)
        else:
            # Initialize default values
            self.apk_base = None
            self.timestamp = None
            self.apk_dir = None
            self.prompts_dir = None
            self.results_dir = None
            self.resources_dir = None
            self.use_local_llm = False
            self.llm_preference = 'ollama'
            self.analysis_directories = None
        
        # Initialize consolidated components
        self.decompiler = ReactNativeDecompiler(debug=self.debug)
        self.vulnerability_analyzer = VulnerabilityAnalyzer(debug=self.debug)
        self.reporter = VulnerabilityReporter(debug=self.debug)
        
        # Initialize AI providers (legacy support)
        self.ollama_provider = OllamaProvider()
        self.groq_provider = GroqProvider()
        self.fix_generator = FixGenerator(debug=self.debug)
        
        if self.debug:
            print("🐛 DEBUG: ReactNativeAnalyzer initialized with consolidated components")
            print(f"🐛 DEBUG: LLM preference: {self.llm_preference}")

    # =================== CONSOLIDATED FUNCTION ACCESS ===================
    
    def start_ollama_if_needed(self) -> bool:
        """Start Ollama if needed (delegates to Ollama provider)"""
        return self.ollama_provider.start_ollama_if_needed()
    
    def check_deepseek_model(self) -> bool:
        """Check DeepSeek model availability (delegates to Ollama provider)"""
        return self.ollama_provider.check_deepseek_model()
    
    def ensure_ollama_ready(self) -> bool:
        """Ensure Ollama is ready (delegates to Ollama provider)"""
        return self.ollama_provider.ensure_ollama_ready()
    
    def display_enhanced_vulnerabilities(self, vulnerabilities: List[Dict]) -> bool:
        """Display enhanced vulnerabilities (delegates to reporter)"""
        return self.reporter.display_enhanced_vulnerabilities(vulnerabilities)
    
    async def process_enhanced_vulnerability_fixes(
        self, 
        vulnerabilities: List[Dict], 
        selected_indices: List[int],
        files_content: Dict[str, str] = None
    ) -> bool:
        """Process vulnerability fixes (delegates to fix generator)"""
        if files_content is None:
            files_content = {}
        
        return await self.fix_generator.process_vulnerability_fixes(
            vulnerabilities=vulnerabilities,
            selected_indices=selected_indices,
            files_content=files_content,
            llm_preference=self.llm_preference,
            framework_type='react-native',
            results_dir=getattr(self, 'results_dir', None),
            apk_base=getattr(self, 'apk_base', 'unknown')
        )

    # =================== REACT NATIVE DETECTION ===================
    
    def detect_react_native_specific(self, extracted_files: List[str]) -> Dict[str, Any]:
        """Enhanced React Native detection with version and configuration analysis"""
        print("🔍 Performing detailed React Native analysis...")
        
        if self.debug:
            print(f"🐛 DEBUG: Checking {len(extracted_files)} files for React Native indicators")
        
        rn_info = {
            "is_react_native": False,
            "version": "",
            "js_bundle_found": False,
            "hermes_enabled": False,
            "metro_config": {},
            "indicators_found": [],
            "bundle_files": []
        }
        
        # Check for JavaScript bundle files
        js_files = [f for f in extracted_files if f.endswith('.js') or 'bundle' in f.lower()]
        bundle_files = [f for f in extracted_files if any(bundle_name in f.lower() for bundle_name in 
                       ['index.android.bundle', 'index.bundle', 'main.jsbundle', 'app.bundle'])]
        
        if js_files or bundle_files:
            rn_info["js_bundle_found"] = True
            rn_info["bundle_files"] = bundle_files
            rn_info["indicators_found"].append("JavaScript bundle files")
            if self.debug:
                print(f"📄 Found {len(js_files)} JavaScript files and {len(bundle_files)} bundle files")
        
        # Check for Hermes bytecode
        hbc_files = [f for f in extracted_files if f.endswith('.hbc')]
        if hbc_files:
            rn_info["hermes_enabled"] = True
            rn_info["indicators_found"].append("Hermes bytecode files")
            if self.debug:
                print("⚡ Hermes engine detected - bytecode bundles may not be decompilable")
        
        # Check if bundle looks like Hermes bytecode (binary format)
        if bundle_files:
            for bundle_file in bundle_files:
                if self.is_hermes_bundle(bundle_file):
                    rn_info["hermes_enabled"] = True
                    rn_info["indicators_found"].append("Hermes bytecode bundle detected")
                    if self.debug:
                        print("⚡ Hermes bytecode bundle detected in JavaScript files")
        
        # Look for React Native specific indicators in file paths
        for file_path in extracted_files:
            file_lower = file_path.lower()
            for indicator in REACT_NATIVE_INDICATORS:
                if indicator in file_lower:
                    rn_info["is_react_native"] = True
                    if indicator not in rn_info["indicators_found"]:
                        rn_info["indicators_found"].append(indicator)
        
        # Try to extract React Native version from assets
        for file_path in extracted_files:
            if 'package.json' in file_path or 'react-native' in file_path:
                try:
                    # This would require actual file reading - placeholder for now
                    rn_info["version"] = "Unknown"
                except:
                    pass
        
        if rn_info["is_react_native"]:
            print(f"✅ React Native app confirmed - found {len(rn_info['indicators_found'])} indicators")
        
        return rn_info

    def is_hermes_bundle(self, bundle_path: str) -> bool:
        """Check if a bundle file is Hermes bytecode (delegated to decompiler class)"""
        return self.decompiler.is_hermes_bundle(bundle_path)

    # =================== JAVASCRIPT EXTRACTION ===================
    
    def extract_javascript_bundles(self, apk_path: str) -> List[Dict[str, str]]:
        """Extract all JavaScript bundle files from React Native APK"""
        print("📦 Extracting JavaScript bundles from APK...")
        
        if self.debug:
            print(f"🐛 DEBUG: Extracting JavaScript bundles from {apk_path}")
        
        extracted_bundles = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                bundle_files = []
                
                # Look for common React Native bundle locations
                bundle_patterns = [
                    r'assets/.*\.bundle$',
                    r'assets/.*\.jsbundle$',
                    r'assets/index\.android\.bundle$',
                    r'assets/index\.bundle$',
                    r'assets/main\.jsbundle$',
                    r'assets/app\.bundle$',
                    r'assets/.*bundle.*\.js$'
                ]
                
                # Find JavaScript bundles in assets
                for file_info in apk_zip.filelist:
                    file_path = file_info.filename
                    if any(re.match(pattern, file_path, re.IGNORECASE) for pattern in bundle_patterns):
                        bundle_files.append(file_info.filename)
                
                print(f"📄 Found {len(bundle_files)} bundle files in APK")
                
                # Extract all bundle files
                for bundle_file in bundle_files:
                    try:
                        with apk_zip.open(bundle_file) as bundle_handle:
                            bundle_content = bundle_handle.read().decode('utf-8', errors='ignore')
                            
                            # Save bundle to temporary file for decompilation
                            temp_bundle_path = os.path.join(tempfile.gettempdir(), os.path.basename(bundle_file))
                            with open(temp_bundle_path, 'w', encoding='utf-8') as temp_file:
                                temp_file.write(bundle_content)
                            
                            extracted_bundles.append({
                                'name': bundle_file,
                                'path': temp_bundle_path,
                                'content': bundle_content,
                                'size': len(bundle_content)
                            })
                            
                            print(f"📦 Extracted bundle: {bundle_file} ({len(bundle_content)} characters)")
                            if self.debug:
                                print(f"🐛 DEBUG: Bundle saved to: {temp_bundle_path}")
                    
                    except Exception as e:
                        print(f"⚠️  Error extracting {bundle_file}: {e}")
                        continue
                    
        except Exception as e:
            print(f"❌ Error extracting JavaScript bundles: {e}")
        
        # Save extracted bundles to structured output directory
        if self.analysis_directories and extracted_bundles:
            try:
                print("📁 Saving extracted bundles to structured output directory...")
                for bundle in extracted_bundles:
                    # Save bundle content as processed file
                    safe_filename = bundle['name'].replace('/', '_').replace('\\', '_')
                    if not safe_filename.endswith('.js'):
                        safe_filename += '.js'
                    save_processed_file(bundle['content'], safe_filename, self.analysis_directories)
                
                print(f"📁 Saved {len(extracted_bundles)} bundle files to structured directory")
                
            except Exception as e:
                print(f"⚠️  Warning: Could not save bundles to structured directory: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
        
        return extracted_bundles

    # =================== DECOMPILER INTEGRATION ===================
    
    def check_decompiler_availability(self) -> bool:
        """Check if react-native-decompiler is available (delegated to decompiler class)"""
        return self.decompiler.check_decompiler_availability()

    def install_decompiler(self) -> bool:
        """Install react-native-decompiler if not available (delegated to decompiler class)"""
        return self.decompiler.install_decompiler()

    def decompile_bundle(self, bundle_path: str, output_dir: str) -> bool:
        """Decompile JavaScript bundle (delegated to decompiler class)"""
        return self.decompiler.decompile_bundle(bundle_path, output_dir)

    def load_decompiled_modules(self, output_dir: str) -> Dict[str, str]:
        """Load all decompiled JavaScript modules"""
        print(f"📂 Loading decompiled modules from: {output_dir}")
        
        if self.debug:
            print(f"🐛 DEBUG: Loading modules from {output_dir}")
        
        decompiled_modules = {}
        
        try:
            if not os.path.exists(output_dir):
                print(f"❌ Output directory does not exist: {output_dir}")
                return decompiled_modules
            
            # Find all JavaScript files in the output directory
            js_files = []
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file.endswith('.js') or file.endswith('.jsx'):
                        js_files.append(os.path.join(root, file))
            
            print(f"📄 Found {len(js_files)} decompiled JavaScript files")
            
            # Load content of each file
            for js_file in js_files:
                try:
                    with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Use relative path as module name
                        module_name = os.path.relpath(js_file, output_dir)
                        decompiled_modules[module_name] = content
                        if self.debug:
                            print(f"📝 Loaded module: {module_name} ({len(content)} characters)")
                
                except Exception as e:
                    print(f"⚠️  Error loading {js_file}: {e}")
                    continue
            
            self.decompiled_modules = decompiled_modules
            print(f"✅ Successfully loaded {len(decompiled_modules)} decompiled modules")
            
        except Exception as e:
            print(f"❌ Error loading decompiled modules: {e}")
        
        return decompiled_modules

    # =================== ENHANCED VULNERABILITY SCANNING ===================
    
    def scan_decompiled_vulnerabilities(self, decompiled_modules: Dict[str, str]) -> List[Dict]:
        """Comprehensive vulnerability scanner for decompiled React Native modules"""
        print("🔍 Scanning decompiled modules for vulnerabilities...")
        
        if self.debug:
            print(f"🐛 DEBUG: Scanning {len(decompiled_modules)} decompiled modules")
        
        vulnerabilities = []
        
        # Enhanced vulnerability patterns for decompiled code
        vulnerability_patterns = {
            'React Native Bridge Security': [
                (r'NativeModules\.[^.]+\.[^(]+\([^)]*(?:props|userInput|params|data)', 'User input passed to native module'),
                (r'ReactMethod.*public.*\([^)]*String[^)]*\)', 'Native method accepting string input'),
                (r'bridge\.callNative\([^)]*["\'][^"\']*["\'].*\+', 'Dynamic native bridge calls with concatenation'),
                (r'RCTDeviceEventEmitter\.emit\([^)]*(?:props|userInput|params)', 'User input in device event'),
                (r'NativeEventEmitter.*addListener\([^)]*userInput', 'User input in native event listener'),
            ],
            
            'JavaScript Injection': [
                (r'eval\s*\([^)]*(?:\+|props|userInput|params)', 'Dynamic eval() with user input'),
                (r'Function\s*\([^)]*(?:\+|props|userInput)', 'Dynamic Function constructor'),
                (r'evaluateJavaScript\s*\([^)]*(?:\+|props|userInput)', 'Dynamic JavaScript evaluation in WebView'),
                (r'postMessage\s*\([^)]*(?:props|userInput|params)', 'User input in postMessage'),
                (r'webView\.injectJavaScript\([^)]*(?:\+|props|userInput)', 'Dynamic JavaScript injection'),
                (r'setTimeout\s*\([^)]*(?:\+|props|userInput)', 'Dynamic setTimeout with user input'),
                (r'setInterval\s*\([^)]*(?:\+|props|userInput)', 'Dynamic setInterval with user input'),
            ],
            
            'Insecure Data Storage': [
                (r'AsyncStorage\.setItem\s*\([^,]*,\s*[^)]*(?:password|pwd|pass)', 'Password stored in AsyncStorage'),
                (r'AsyncStorage\.setItem\s*\([^,]*,\s*[^)]*(?:token|jwt|auth)', 'Authentication token stored in AsyncStorage'),
                (r'AsyncStorage\.setItem\s*\([^,]*,\s*[^)]*(?:secret|key|private)', 'Secret/key stored in AsyncStorage'),
                (r'AsyncStorage\.setItem\s*\([^,]*,\s*[^)]*(?:credit|card|payment)', 'Payment info stored in AsyncStorage'),
                (r'SecureStore\.setItemAsync\s*\([^,]*,\s*[^)]*(?:plain|unencrypted)', 'Unencrypted data in SecureStore'),
                (r'localStorage\.setItem\s*\([^,]*,\s*[^)]*(?:password|token|secret)', 'Sensitive data in localStorage'),
            ],
            
            'Insecure Network Communication': [
                (r'fetch\s*\(\s*["\']http://[^"\']*["\']', 'HTTP request (insecure)'),
                (r'XMLHttpRequest.*open\s*\([^,]*,\s*["\']http://', 'HTTP XMLHttpRequest'),
                (r'axios\.(?:get|post|put|delete)\s*\(\s*["\']http://', 'HTTP Axios request'),
                (r'trustAllCerts\s*:\s*true', 'Trust all certificates enabled'),
                (r'rejectUnauthorized\s*:\s*false', 'SSL verification disabled'),
                (r'allowsArbitraryLoads\s*:\s*true', 'Arbitrary loads allowed'),
                (r'agent\s*:\s*new\s+https\.Agent\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*false', 'HTTPS agent with disabled verification'),
            ],
            
            'Hardcoded Secrets and API Keys': [
                (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9+/]{16,}["\']', 'Hardcoded API key'),
                (r'(?i)(?:access[_-]?token|accesstoken)\s*[=:]\s*["\'][A-Za-z0-9+/._-]{20,}["\']', 'Hardcoded access token'),
                (r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\'][A-Za-z0-9+/._-]{16,}["\']', 'Hardcoded secret key'),
                (r'(?i)(?:private[_-]?key|privatekey)\s*[=:]\s*["\'][A-Za-z0-9+/._-]{32,}["\']', 'Hardcoded private key'),
                (r'(?i)(?:aws[_-]?secret|aws[_-]?key)\s*[=:]\s*["\'][A-Za-z0-9+/]{20,}["\']', 'Hardcoded AWS credentials'),
                (r'(?i)(?:firebase[_-]?key|firebase[_-]?secret)\s*[=:]\s*["\'][A-Za-z0-9+/._-]{20,}["\']', 'Hardcoded Firebase key'),
                (r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', 'Potential base64 encoded secret'),
                (r'(?i)bearer\s+[A-Za-z0-9+/._-]{20,}', 'Hardcoded bearer token'),
            ],
            
            'React Native Security Issues': [
                (r'__DEV__\s*(?:===?\s*true|&&)', 'Development mode check in production'),
                (r'console\.(?:log|warn|error)\s*\([^)]*(?:password|token|secret|key)', 'Sensitive data logged to console'),
                (r'debugger\s*;', 'Debugger statements in production'),
                (r'ReactNative\.NativeModules\.DevSettings', 'Dev settings exposed in production'),
                (r'require\s*\(\s*["\']react-devtools', 'React DevTools required in production'),
                (r'window\.__REACT_DEVTOOLS_GLOBAL_HOOK__', 'React DevTools hook exposed'),
                (r'allowFileAccess\s*:\s*true', 'File access allowed in WebView'),
                (r'allowUniversalAccessFromFileURLs\s*:\s*true', 'Universal file access allowed'),
            ],
            
            'Deep Link and URL Handling Vulnerabilities': [
                (r'Linking\.openURL\s*\([^)]*(?:props|userInput|params)', 'User input in deep link opening'),
                (r'Linking\.getInitialURL\s*\(\)', 'Initial URL handling without validation'),
                (r'onReceiveNotification.*(?:props|userInput|params)', 'User input in notification handler'),
                (r'router\.push\s*\([^)]*(?:props|userInput|params)', 'User input in navigation'),
                (r'navigation\.navigate\s*\([^)]*(?:props|userInput|params)', 'User input in navigation'),
                (r'WebView.*source=\{\{uri:\s*(?:props|userInput)', 'User input in WebView URI'),
            ],
            
            'Input Validation Issues': [
                (r'JSON\.parse\s*\([^)]*(?:props|userInput|params)[^)]*\)', 'Unsafe JSON parsing of user input'),
                (r'parseInt\s*\([^)]*(?:props|userInput|params)[^)]*\)', 'Unsafe integer parsing'),
                (r'parseFloat\s*\([^)]*(?:props|userInput|params)[^)]*\)', 'Unsafe float parsing'),
                (r'new\s+RegExp\s*\([^)]*(?:props|userInput|params)', 'User input in RegExp constructor'),
                (r'\.innerHTML\s*=\s*(?:props|userInput|params)', 'User input in innerHTML (XSS risk)'),
                (r'\.outerHTML\s*=\s*(?:props|userInput|params)', 'User input in outerHTML (XSS risk)'),
            ],
            
            'Cryptographic Vulnerabilities': [
                (r'Math\.random\s*\(\)', 'Weak random number generation'),
                (r'md5\s*\([^)]*(?:password|secret)', 'MD5 used for sensitive data'),
                (r'sha1\s*\([^)]*(?:password|secret)', 'SHA1 used for sensitive data'),
                (r'DES|3DES', 'Weak encryption algorithm'),
                (r'ECB', 'ECB encryption mode (insecure)'),
                (r'crypto\.createCipher\s*\(\s*["\']des', 'DES encryption used'),
                (r'AES.*128.*ECB', 'AES with ECB mode'),
            ]
        }
        
        # Scan each decompiled module
        for module_name, module_content in decompiled_modules.items():
            if self.debug:
                print(f"🔍 Scanning module: {module_name}")
            
            # Scan for all vulnerability patterns
            for vuln_category, patterns in vulnerability_patterns.items():
                for pattern, description in patterns:
                    matches = re.finditer(pattern, module_content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = module_content[:match.start()].count('\n') + 1
                        
                        # Get context around the match
                        lines = module_content.split('\n')
                        context_start = max(0, line_num - 3)
                        context_end = min(len(lines), line_num + 2)
                        context = '\n'.join(lines[context_start:context_end])
                        
                        vulnerabilities.append({
                            "vulnerability_type": vuln_category,
                            "file": module_name,
                            "line_number": line_num,
                            "code_snippet": match.group(0)[:150],
                            "context": context,
                            "description": description,
                            "severity": self._get_enhanced_severity(vuln_category, description)
                        })
        
        # Deduplicate vulnerabilities
        seen_vulns = set()
        unique_vulnerabilities = []
        for vuln in vulnerabilities:
            vuln_key = (vuln['vulnerability_type'], vuln['file'], vuln['line_number'], vuln['description'])
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                unique_vulnerabilities.append(vuln)
        
        if self.debug:
            print(f"🔍 Found {len(unique_vulnerabilities)} vulnerabilities in decompiled modules")
        return unique_vulnerabilities

    def _get_enhanced_severity(self, vuln_type: str, description: str) -> str:
        """Enhanced severity assessment (delegated to consolidated severity module)"""
        return get_enhanced_severity(vuln_type, description, framework="react_native")

    # =================== AI ANALYSIS ===================
    
    async def analyze_decompiled_with_ai(self, decompiled_modules: Dict[str, str]) -> List[Dict]:
        """AI-powered analysis of decompiled React Native modules (delegated to vulnerability analyzer)"""
        if self.debug:
            print("🐛 DEBUG: Delegating AI analysis to VulnerabilityAnalyzer")
        
        context = {
            'decompiled_modules': decompiled_modules
        }
        
        return await self.vulnerability_analyzer.analyze_code_with_ai(
            framework_type='react-native',
            context=context,
            use_local_llm=self.use_local_llm,
            llm_preference=self.llm_preference
        )

    # =================== DISPLAY AND UTILITY ===================
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict]):
        """Display found vulnerabilities (delegated to consolidated reporter)"""
        return self.reporter.display_vulnerabilities(vulnerabilities)

    def ask_for_fix_option(self, vulnerabilities: List[Dict]) -> List[int]:
        """Ask user which vulnerabilities they want to fix (delegated to CLI interactive)"""
        return ask_for_fix_option(vulnerabilities)

    # =================== MAIN ANALYSIS FUNCTION ===================
    
    async def analyze_react_native_apk_enhanced(self, apk_path: str, fix_vulnerabilities: bool = False) -> bool:
        """Enhanced main function to analyze React Native APK with decompiler integration"""
        print("\n⚛️  Starting Enhanced React Native APK Analysis...")
        
        if self.debug:
            print(f"🐛 DEBUG: analyze_react_native_apk_enhanced called with: {apk_path}")
            print(f"🐛 DEBUG: Current settings - LLM: {self.llm_preference}, Debug: {self.debug}")
            print(f"🐛 DEBUG: Fix vulnerabilities mode: {fix_vulnerabilities}")
        
        # Initialize APK paths if not already set
        if not hasattr(self, 'apk_base') or not self.apk_base:
            apk_path_obj = Path(apk_path)
            self.apk_base = apk_path_obj.stem  # filename without extension
            self.apk_dir = apk_path_obj.parent / "mobilesec_analysis" / self.apk_base
            
            if self.debug:
                print(f"🐛 DEBUG: Initialized apk_base: {self.apk_base}")
                print(f"🐛 DEBUG: Initialized apk_dir: {self.apk_dir}")
        
        self.analysis_start_time = time.time()
        
        try:
            # Step 1: Extract JavaScript bundles
            bundles = self.extract_javascript_bundles(apk_path)
            if not bundles:
                print("⚠️  No JavaScript bundles found for analysis")
                return False
            
            # Step 2: Check and install decompiler if needed
            if not self.check_decompiler_availability():
                if not self.install_decompiler():
                    print("❌ Failed to install react-native-decompiler")
                    print("🔄 Falling back to basic bundle analysis...")
                    return await self.analyze_raw_bundles(bundles, fix_vulnerabilities)
            
            # Step 3: Decompile bundles
            all_decompiled_modules = {}
            for bundle in bundles:
                # Create output directory for this bundle
                bundle_name = os.path.splitext(os.path.basename(bundle['name']))[0]
                output_dir = os.path.join(tempfile.gettempdir(), f"rn_decompiled_{bundle_name}")
                
                if self.decompile_bundle(bundle['path'], output_dir):
                    # Load decompiled modules
                    modules = self.load_decompiled_modules(output_dir)
                    all_decompiled_modules.update(modules)
                    
                    # Clean up bundle output directory
                    try:
                        shutil.rmtree(output_dir)
                    except:
                        pass
            
            if not all_decompiled_modules:
                print("⚠️  No modules could be decompiled")
                print("🔄 Falling back to basic bundle analysis...")
                return await self.analyze_raw_bundles(bundles, fix_vulnerabilities)
            
            # Step 4: Comprehensive vulnerability scanning
            print(f"\n🔍 Analyzing {len(all_decompiled_modules)} decompiled modules...")
            
            # Pattern-based scanning
            pattern_vulnerabilities = self.scan_decompiled_vulnerabilities(all_decompiled_modules)
            
            # AI-powered analysis
            ai_vulnerabilities = await self.analyze_decompiled_with_ai(all_decompiled_modules)
            
            # Combine and deduplicate vulnerabilities
            all_vulnerabilities = pattern_vulnerabilities + ai_vulnerabilities
            
            # Deduplicate
            seen_vulns = set()
            unique_vulnerabilities = []
            for vuln in all_vulnerabilities:
                vuln_key = (vuln.get('vulnerability_type', ''), vuln.get('file', ''), 
                           vuln.get('line_number', 0), vuln.get('description', ''))
                if vuln_key not in seen_vulns:
                    seen_vulns.add(vuln_key)
                    unique_vulnerabilities.append(vuln)
            
            # Step 5: Display results
            if self.display_vulnerabilities(unique_vulnerabilities):
                if fix_vulnerabilities:
                    # Step 6: Ask for fixes (only if --fix flag is enabled)
                    fix_indices = self.ask_for_fix_option(unique_vulnerabilities)
                    if fix_indices:
                        try:
                            print(f"\n🔧 Generating fixes for {len(fix_indices)} selected vulnerabilities...")
                            
                            # Build files_content for fix generator - use decompiled modules as context
                            files_content = {
                                'decompiled_modules': all_decompiled_modules,
                                'react_native_assets': {
                                    'bundles': bundles,
                                    'framework_type': 'react-native'
                                }
                            }
                            
                            # Use the proper fix generator
                            await self.fix_generator.process_vulnerability_fixes(
                                unique_vulnerabilities,
                                fix_indices,
                                files_content,
                                self.llm_preference,
                                "react-native",
                                getattr(self, 'results_dir', None),
                                getattr(self, 'apk_base', 'unknown')
                            )
                            print("✅ Fix generation complete!")
                        except Exception as e:
                            print(f"⚠️  Fix generation error: {e}")
                            if self.debug:
                                print(f"🐛 DEBUG: Fix generation exception: {e}")
                    else:
                        print("✅ No fixes requested - analysis complete!")
                else:
                    print("\n💡 Use --fix flag to enable vulnerability fix generation after analysis")
            else:
                print("\n✅ No vulnerabilities found - no fixes needed!")
            
            self.analysis_end_time = time.time()
            analysis_duration = self.analysis_end_time - self.analysis_start_time
            print(f"\n✅ Enhanced React Native analysis completed in {analysis_duration:.2f} seconds")
            
            return True
            
        except Exception as e:
            print(f"❌ Enhanced React Native analysis error: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Exception in analyze_react_native_apk_enhanced: {e}")
            return False

    async def analyze_raw_bundles(self, bundles: List[Dict[str, str]], fix_vulnerabilities: bool = False) -> bool:
        """Fallback analysis for raw JavaScript bundles when decompilation fails"""
        print("🔍 Analyzing raw JavaScript bundles...")
        
        if self.debug:
            print(f"🐛 DEBUG: Analyzing {len(bundles)} raw bundles")
            print(f"🐛 DEBUG: Fix vulnerabilities mode: {fix_vulnerabilities}")
        
        vulnerabilities = []
        
        for bundle in bundles:
            print(f"📄 Scanning bundle: {bundle['name']}")
            
            # Basic pattern matching on raw bundle content
            content = bundle['content']
            
            # Simplified vulnerability patterns for minified/bundled code
            patterns = [
                (r'eval\s*\([^)]*\+', 'Dynamic eval() with concatenation'),
                (r'AsyncStorage\.setItem\s*\([^,]*,\s*[^)]*(?:password|token|secret)', 'Sensitive data in AsyncStorage'),
                (r'http://[^"\']*', 'HTTP URL (insecure)'),
                (r'(?i)(?:api[_-]?key|token|secret)\s*[=:]\s*["\'][A-Za-z0-9+/]{16,}["\']', 'Hardcoded credentials'),
                (r'console\.log\([^)]*(?:password|token|secret)', 'Sensitive data logged'),
            ]
            
            for pattern, description in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        "vulnerability_type": "React Native Security Issue",
                        "file": bundle['name'],
                        "line_number": line_num,
                        "code_snippet": match.group(0)[:100],
                        "description": description,
                        "severity": "Medium"
                    })
        
        # Display results
        if self.display_vulnerabilities(vulnerabilities):
            if fix_vulnerabilities:
                fix_indices = self.ask_for_fix_option(vulnerabilities)
                if fix_indices:
                    try:
                        print(f"\n🔧 Generating fixes for {len(fix_indices)} selected vulnerabilities...")
                        
                        # Build files_content for fix generator - use raw bundles as context
                        files_content = {
                            'raw_bundles': bundles,
                            'react_native_assets': {
                                'framework_type': 'react-native',
                                'analysis_method': 'raw_bundle'
                            }
                        }
                        
                        # Use the proper fix generator with all required parameters
                        await self.fix_generator.process_vulnerability_fixes(
                            vulnerabilities,
                            fix_indices,
                            files_content,
                            getattr(self.orchestrator, 'llm_preference', 'ollama') if self.orchestrator else self.llm_preference,
                            "react-native",
                            getattr(self.orchestrator, 'results_dir', None) if self.orchestrator else None,
                            getattr(self.orchestrator, 'apk_base', 'unknown') if self.orchestrator else self.apk_base or 'unknown'
                        )
                        print("✅ Fix generation complete!")
                    except Exception as e:
                        print(f"⚠️  Fix generation error: {e}")
                        if self.debug:
                            print(f"🐛 DEBUG: Fix generation exception: {e}")
                else:
                    print("✅ No fixes requested - analysis complete!")
            else:
                print("\n💡 Use --fix flag to enable vulnerability fix generation after analysis")
        else:
            print("\n✅ No vulnerabilities found - no fixes needed!")
        
        return True

    async def generate_fixes_with_batching(
        self,
        vulnerabilities: List[Dict],
        selected_indices: List[int],
        bundles: List[str]
    ) -> bool:
        """
        Generate fixes with intelligent batching for React Native decompiled modules.
        
        This is now a wrapper around the official FixGenerator.generate_fixes_with_batching()
        method that provides intelligent batching to handle cases where there are many
        decompiled modules that could exceed AI token/context limits.
        
        Args:
            vulnerabilities: List of all detected vulnerabilities
            selected_indices: 1-based indices of vulnerabilities to fix
            bundles: List of JavaScript bundles for context
            
        Returns:
            True if at least one fix was successfully generated
        """
        try:
            # Get decompiled modules if available
            decompiled_modules = getattr(self, 'decompiled_modules', {})
            
            return await self.fix_generator.generate_fixes_with_batching(
                vulnerabilities,
                selected_indices,
                decompiled_modules,
                bundles,
                self.llm_preference,
                getattr(self.orchestrator, 'results_dir', None),
                getattr(self.orchestrator, 'apk_base', 'unknown')
            )
            
        except Exception as e:
            print(f"❌ Error in batched fix generation: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Batching error: {e}")
                import traceback
                traceback.print_exc()
            return False
    
    def find_relevant_modules(self, file_name: str, decompiled_modules: Dict[str, str]) -> Dict[str, str]:
        """
        Find decompiled modules that are relevant to a specific vulnerability file.
        
        This is now a wrapper around the official BatchProcessor.find_relevant_modules()
        method that provides intelligent module relevance detection for targeted analysis.
        
        Args:
            file_name: The file name where vulnerability was detected
            decompiled_modules: Dictionary of module_name -> module_content
            
        Returns:
            Dictionary of relevant module_name -> module_content
        """
        from ...ai.processors.batch_processor import find_relevant_modules
        return find_relevant_modules(file_name, decompiled_modules)

    # Main entry point for compatibility
    async def analyze_react_native_apk(self, apk_path: str, fix_vulnerabilities: bool = False) -> bool:
        """Main entry point for React Native APK analysis"""
        print("\n⚛️  Starting Enhanced React Native APK Analysis...")
        
        if self.debug:
            print(f"🐛 DEBUG: analyze_react_native_apk called with: {apk_path}")
            print(f"🐛 DEBUG: Current settings - LLM: {self.llm_preference}, Debug: {self.debug}")
            print(f"🐛 DEBUG: Fix vulnerabilities mode: {fix_vulnerabilities}")
        
        # Initialize APK paths if not already set
        if not hasattr(self, 'apk_base') or not self.apk_base:
            apk_path_obj = Path(apk_path)
            self.apk_base = apk_path_obj.stem  # filename without extension
            self.apk_dir = apk_path_obj.parent / "mobilesec_analysis" / self.apk_base
            
            if self.debug:
                print(f"🐛 DEBUG: Initialized apk_base: {self.apk_base}")
                print(f"🐛 DEBUG: Initialized apk_dir: {self.apk_dir}")
        
        self.analysis_start_time = time.time()
        
        try:
            # Step 1: Extract JavaScript bundles
            bundles = self.extract_javascript_bundles(apk_path)
            if not bundles:
                print("⚠️  No JavaScript bundles found for analysis")
                return False
            
            # Step 2: Check and install decompiler if needed
            if not self.check_decompiler_availability():
                if not self.install_decompiler():
                    print("❌ Failed to install react-native-decompiler")
                    print("🔄 Falling back to basic bundle analysis...")
                    return await self.analyze_raw_bundles(bundles, fix_vulnerabilities)
            
            # Step 3: Decompile bundles
            all_decompiled_modules = {}
            for bundle in bundles:
                # Create output directory for this bundle
                bundle_name = os.path.splitext(os.path.basename(bundle['name']))[0]
                output_dir = os.path.join(tempfile.gettempdir(), f"rn_decompiled_{bundle_name}")
                
                if self.decompile_bundle(bundle['path'], output_dir):
                    # Load decompiled modules
                    modules = self.load_decompiled_modules(output_dir)
                    all_decompiled_modules.update(modules)
                    
                    # Clean up bundle output directory
                    try:
                        shutil.rmtree(output_dir)
                    except:
                        pass
            
            if not all_decompiled_modules:
                print("⚠️  No modules could be decompiled")
                print("🔄 Falling back to basic bundle analysis...")
                return await self.analyze_raw_bundles(bundles, fix_vulnerabilities)
            
            # Store decompiled modules for batching in fix generation
            self.decompiled_modules = all_decompiled_modules
            
            # Step 4: Comprehensive vulnerability scanning
            print(f"\n🔍 Analyzing {len(all_decompiled_modules)} decompiled modules...")
            
            # Pattern-based scanning
            pattern_vulnerabilities = self.scan_decompiled_vulnerabilities(all_decompiled_modules)
            
            # AI-powered analysis
            ai_vulnerabilities = await self.analyze_decompiled_with_ai(all_decompiled_modules)
            
            # Combine and deduplicate vulnerabilities
            all_vulnerabilities = pattern_vulnerabilities + ai_vulnerabilities
            
            # Deduplicate
            seen_vulns = set()
            unique_vulnerabilities = []
            for vuln in all_vulnerabilities:
                vuln_key = (vuln.get('vulnerability_type', ''), vuln.get('file', ''), 
                           vuln.get('line_number', 0), vuln.get('description', ''))
                if vuln_key not in seen_vulns:
                    seen_vulns.add(vuln_key)
                    unique_vulnerabilities.append(vuln)
            
            # Step 5: Display results
            if self.display_vulnerabilities(unique_vulnerabilities):
                if fix_vulnerabilities:
                    try:
                        print("\nWould you like to generate fixes for any of the above vulnerabilities?")
                        selected_fix_indices = self.ask_for_fix_option(unique_vulnerabilities)
                        if selected_fix_indices:
                            print(f"\n🔧 Generating fixes for selected vulnerabilities: {selected_fix_indices}")
                            
                            # Implement batching for large numbers of decompiled modules
                            await self.generate_fixes_with_batching(
                                unique_vulnerabilities,
                                selected_fix_indices,
                                bundles
                            )
                            print("✅ Fix generation complete!")
                        else:
                            print("✅ No fixes requested - analysis complete!")
                    except Exception as e:
                        print(f"⚠️  Fix generation error: {e}")
            else:
                print("\n✅ No vulnerabilities found - no fixes needed!")
            
            self.analysis_end_time = time.time()
            analysis_duration = self.analysis_end_time - self.analysis_start_time
            print(f"\n✅ Enhanced React Native analysis completed in {analysis_duration:.2f} seconds")
            
            return True
            
        except Exception as e:
            print(f"❌ Enhanced React Native analysis error: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Exception in analyze_react_native_apk: {e}")
            return False