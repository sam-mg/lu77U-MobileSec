#!/usr/bin/env python3
"""
Java/Kotlin APK Analysis Module

This module handles comprehensive analysis of Java/Kotlin Android APKs including:
- File extraction and processing
- Vulnerability analysis coordination
- AI-powered security analysis
"""

import os
import re
import json
import asyncio
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from xml.etree import ElementTree as ET
from datetime import datetime

from ...constants.vulnerabilities import VULNERABILITY_KEYWORDS
from ...constants.severity_levels import SEVERITY_HIGH, SEVERITY_MEDIUM
from ...constants.file_patterns import DEFAULT_STRING_PREFIXES, DEFAULT_STRING_EXACT_MATCHES
from ...ai.providers.ollama_provider import OllamaProvider
from ...ai.providers.groq_provider import GroqProvider
from ...tools.decompilers.jadx_wrapper import JadxWrapper
from ...core.vulnerability.scanner import VulnerabilityScanner
from ...core.vulnerability.reporting import VulnerabilityReporter
from ...ai.processors.response_parser import ResponseParser
from ...ai.processors.fix_generator import FixGenerator
from ...utils.helpers.validation import is_likely_user_defined_string
from ...cli.interactive import ask_for_fix_option
from ...utils.file_system.output_organizer import OutputDirectoryOrganizer, save_processed_file, save_ai_prompt, save_ai_response, save_vulnerability_fix, save_dynamic_analysis, create_analysis_summary


class JavaKotlinAnalyzer:
    """
    Java/Kotlin APK Analysis Class
    
    Handles:
    - File extraction and processing
    - Vulnerability analysis coordination  
    - AI-powered security analysis
    """
    
    def __init__(self, orchestrator=None, debug=False):
        """Initialize Java/Kotlin analyzer"""
        self.orchestrator = orchestrator
        self.debug = debug
        
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
        
        # Initialize component classes according to restructure plan
        self.jadx_wrapper = JadxWrapper(debug=debug)
        self.vulnerability_scanner = VulnerabilityScanner(debug=debug)
        self.vulnerability_reporter = VulnerabilityReporter(debug=debug)
        self.response_parser = ResponseParser(debug=debug)
        self.fix_generator = FixGenerator(debug=debug)
        self.ollama_provider = OllamaProvider()
        self.groq_provider = GroqProvider()
        
        # JADX output directory will be set during decompilation
        self.jadx_output_dir = None
        
        if self.debug:
            print(f"🐛 DEBUG: JavaKotlinAnalyzer initialized with LLM preference: {self.llm_preference}")

    # =================== JADX DECOMPILATION ===================
    
    def decompile_apk(self, apk_path: str) -> bool:
        """Decompile APK using JADX wrapper"""
        self.jadx_output_dir = self.apk_dir / self.apk_base
        return self.jadx_wrapper.jadx_decompile(apk_path, self.jadx_output_dir)

    # =================== FILE EXTRACTION ===================
    
    def extract_files_for_analysis(self) -> Dict[str, str]:
        """Extract specific Android files for vulnerability analysis (Java, XML, Manifest)"""
        print("\n📁 Extracting files for vulnerability analysis...")
        
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: JADX output directory: {self.jadx_output_dir}")
            print(f"🐛 EXTRACT DEBUG: Output directory exists: {self.jadx_output_dir.exists() if self.jadx_output_dir else False}")
            if self.jadx_output_dir and self.jadx_output_dir.exists():
                files_count = len(list(self.jadx_output_dir.rglob('*')))
                print(f"🐛 EXTRACT DEBUG: Total files in output directory: {files_count}")
        
        files_content = {
            "android_manifest": "",
            "java_files": {},
            "strings_xml": "",
            "layout_files": {},
            "backup_rules_xml": "",
            "data_extraction_rules_xml": ""
        }
        
        # Extract AndroidManifest.xml
        manifest_path = self.jadx_output_dir / "resources" / "AndroidManifest.xml"
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Looking for AndroidManifest.xml at: {manifest_path}")
            print(f"🐛 EXTRACT DEBUG: Manifest path exists: {manifest_path.exists()}")
        
        if manifest_path.exists():
            try:
                files_content["android_manifest"] = manifest_path.read_text(encoding='utf-8')
                print("✅ Extracted AndroidManifest.xml")
            except Exception as e:
                print(f"⚠️  Could not read AndroidManifest.xml: {e}")
        else:
            if self.debug:
                print("🐛 EXTRACT DEBUG: AndroidManifest.xml not found")
        
        # Extract layout XML files (app-specific only, exclude framework layouts)
        layout_dir = self.jadx_output_dir / "resources" / "res" / "layout"
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Looking for layout files at: {layout_dir}")
            print(f"🐛 EXTRACT DEBUG: Layout directory exists: {layout_dir.exists()}")
        
        if layout_dir.exists():
            # Framework layout prefixes to exclude
            framework_prefixes = [
                'mtrl_', 'abc_', 'design_', 'support_', 'notification_',
                'select_dialog_', 'browser_', 'material_', 'm3_', 'custom_dialog',
            ]
            
            app_layouts_found = 0
            total_layouts_found = 0
            
            for layout_file in layout_dir.glob("*.xml"):
                total_layouts_found += 1
                file_name = layout_file.name
                
                # Skip framework layouts
                if any(file_name.startswith(prefix) for prefix in framework_prefixes):
                    if self.debug:
                        print(f"🐛 EXTRACT DEBUG: Skipping framework layout: {file_name}")
                    continue
                
                try:
                    content = layout_file.read_text(encoding='utf-8')
                    files_content["layout_files"][file_name] = content
                    app_layouts_found += 1
                    
                    if self.debug:
                        print(f"🐛 EXTRACT DEBUG: Extracted layout: {file_name} ({len(content)} chars)")
                        
                except Exception as e:
                    if self.debug:
                        print(f"🐛 EXTRACT DEBUG: Could not read layout {file_name}: {e}")
            
            print(f"✅ Extracted {app_layouts_found} app-specific layout files (skipped {total_layouts_found - app_layouts_found} framework layouts)")
        else:
            if self.debug:
                print("🐛 EXTRACT DEBUG: Layout directory not found")
        
        # Extract strings.xml and filter out framework strings
        strings_path = self.jadx_output_dir / "resources" / "res" / "values" / "strings.xml"
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Looking for strings.xml at: {strings_path}")
            print(f"🐛 EXTRACT DEBUG: Strings path exists: {strings_path.exists()}")
        
        if strings_path.exists():
            filtered_strings = self.filter_strings_xml_content(strings_path.read_text(encoding='utf-8'))
            if filtered_strings:
                files_content["strings_xml"] = filtered_strings
                print("✅ Extracted and filtered strings.xml")
        else:
            if self.debug:
                print("🐛 EXTRACT DEBUG: strings.xml not found")
        
        # Extract backup_rules.xml
        backup_rules_path = self.jadx_output_dir / "resources" / "res" / "xml" / "backup_rules.xml"
        if backup_rules_path.exists():
            try:
                files_content["backup_rules_xml"] = backup_rules_path.read_text(encoding='utf-8')
                print("✅ Extracted backup_rules.xml")
            except Exception as e:
                print(f"⚠️  Could not read backup_rules.xml: {e}")
        
        # Extract data_extraction_rules.xml
        data_extraction_path = self.jadx_output_dir / "resources" / "res" / "xml" / "data_extraction_rules.xml"
        if data_extraction_path.exists():
            try:
                files_content["data_extraction_rules_xml"] = data_extraction_path.read_text(encoding='utf-8')
                print("✅ Extracted data_extraction_rules.xml")
            except Exception as e:
                print(f"⚠️  Could not read data_extraction_rules.xml: {e}")
        
        # Extract Java files from app package only (avoid framework files and R.java)
        java_count = 0
        
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Starting Java files extraction (no limit)")
        
        # Find app package directories (avoid framework packages)
        app_package_dirs = []
        
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Looking for sources directories in {self.jadx_output_dir}")
        
        for sources_dir in self.jadx_output_dir.rglob("sources"):
            if sources_dir.is_dir():
                if self.debug:
                    print(f"🐛 EXTRACT DEBUG: Found sources directory: {sources_dir}")
                # Look for app-specific package directories
                for item in sources_dir.iterdir():
                    if item.is_dir():
                        package_name = item.name
                        # Skip common framework packages
                        if package_name not in ['androidx', 'android', 'kotlin', 'kotlinx', 'com', 'org']:
                            app_package_dirs.append(item)
                            if self.debug:
                                print(f"🐛 EXTRACT DEBUG: Added app package directory: {item}")
                        elif package_name == 'com':
                            # Check subdirectories of 'com' for app packages
                            for subitem in item.iterdir():
                                if subitem.is_dir():
                                    subpackage = subitem.name
                                    # Skip common framework packages under 'com'
                                    if subpackage not in ['google', 'android']:
                                        app_package_dirs.append(subitem)
                                        if self.debug:
                                            print(f"🐛 EXTRACT DEBUG: Added com.{subpackage} package directory: {subitem}")
                                        # Also check deeper levels
                                        for subsubitem in subitem.rglob("*"):
                                            if subsubitem.is_dir():
                                                app_package_dirs.append(subsubitem)
                                    elif self.debug:
                                        print(f"🐛 EXTRACT DEBUG: Skipped framework package: com.{subpackage}")
                        elif package_name == 'org':
                            # Check subdirectories of 'org' for app packages
                            for subitem in item.iterdir():
                                if subitem.is_dir():
                                    subpackage = subitem.name
                                    # Skip common framework packages under 'org'
                                    if subpackage not in ['jetbrains', 'intellij', 'apache', 'junit']:
                                        app_package_dirs.append(subitem)
                                        if self.debug:
                                            print(f"🐛 EXTRACT DEBUG: Added org.{subpackage} package directory: {subitem}")
                                    elif self.debug:
                                        print(f"🐛 EXTRACT DEBUG: Skipped framework package: org.{subpackage}")
                        elif self.debug:
                            print(f"🐛 EXTRACT DEBUG: Skipped framework package: {package_name}")
        
        # If no specific app packages found, fall back to checking all sources but filter carefully
        if not app_package_dirs:
            if self.debug:
                print("🐛 EXTRACT DEBUG: No app packages found, using fallback to all sources directories")
            for sources_dir in self.jadx_output_dir.rglob("sources"):
                if sources_dir.is_dir():
                    app_package_dirs.append(sources_dir)
        
        print(f"🔍 Found {len(app_package_dirs)} potential app package directories")
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Package directories: {[str(d) for d in app_package_dirs]}")
        
        # Process Java files from app packages
        for package_dir in app_package_dirs:
            
            if self.debug:
                java_files_in_dir = list(package_dir.rglob("*.java"))
                print(f"🐛 EXTRACT DEBUG: Processing {package_dir}, found {len(java_files_in_dir)} .java files")
                
            for java_file in package_dir.rglob("*.java"):
                
                try:
                    rel_path = java_file.relative_to(self.jadx_output_dir)
                    path_str = str(rel_path).lower()
                    
                    # Skip R.java files and framework files
                    if (java_file.name == "R.java" or 
                        any(framework in path_str for framework in [
                            'androidx/', 'android/', 'kotlin/', 'kotlinx/', 
                            'com/google/', 'org/jetbrains/', 'org/intellij/'
                        ])):
                        if self.debug:
                            print(f"🐛 EXTRACT DEBUG: Skipped framework/generated file: {java_file.name}")
                        continue
                    
                    with open(java_file, "r", encoding="utf-8", errors='ignore') as f:
                        content = f.read()
                        
                        # Apply smart filtering based on content quality and size
                        class_count = content.count('class ')
                        method_count = content.count('public ') + content.count('private ') + content.count('protected ')
                        
                        # Skip very small files or files without substantial code
                        if len(content) < 500 and class_count == 0:
                            if self.debug:
                                print(f"🐛 EXTRACT DEBUG: Skipped small/empty Java file: {java_file.name} ({len(content)} chars, {class_count} classes)")
                            continue
                        
                        # Don't limit file size for AI analysis - let AI handle the full content
                        original_length = len(content)
                        # Remove the 8000 character truncation to send full files to AI
                        
                        files_content["java_files"][str(rel_path)] = content
                        java_count += 1
                        if self.debug:
                            print(f"🐛 EXTRACT DEBUG: ✅ Added Java file #{java_count}: {rel_path} ({len(content)} chars)")
                            # Show a preview of the content (full content for small files, more for larger ones)
                            preview = content[:500].replace('\n', ' ').strip()
                            print(f"🐛 EXTRACT DEBUG:     Preview: {preview}")
                        
                except Exception as e:
                    if self.debug:
                        print(f"🐛 EXTRACT DEBUG: ❌ Error reading Java file {java_file}: {e}")
                    else:
                        print(f"⚠️  Error reading Java file {java_file}: {e}")
        
        if self.debug:
            print(f"🐛 EXTRACT DEBUG: Final extraction summary:")
            print(f"🐛 EXTRACT DEBUG:   - AndroidManifest.xml: {'✅' if files_content['android_manifest'] else '❌'}")
            print(f"🐛 EXTRACT DEBUG:   - Java files: {len(files_content['java_files'])} files")
            print(f"🐛 EXTRACT DEBUG:   - strings.xml: {'✅' if files_content['strings_xml'] else '❌'}")
            print(f"🐛 EXTRACT DEBUG:   - Layout files: {len(files_content['layout_files'])} files")
            if files_content['layout_files']:
                print(f"🐛 EXTRACT DEBUG:     Layout files extracted:")
                for layout_name, layout_content in files_content['layout_files'].items():
                    print(f"🐛 EXTRACT DEBUG:       - {layout_name} ({len(layout_content)} chars)")
            print(f"🐛 EXTRACT DEBUG:   - backup_rules.xml: {'✅' if files_content['backup_rules_xml'] else '❌'}")
            print(f"🐛 EXTRACT DEBUG:   - data_extraction_rules.xml: {'✅' if files_content['data_extraction_rules_xml'] else '❌'}")
        
        alias_map = {
            "android_manifest": "AndroidManifest.xml",
            "strings_xml": "strings.xml",
            "backup_rules_xml": "backup_rules.xml",
            "data_extraction_rules_xml": "data_extraction_rules.xml"
        }
        for key, alias in alias_map.items():
            if files_content.get(key):
                files_content[alias] = files_content[key]

        for layout_name, layout_content in files_content.get("layout_files", {}).items():
            files_content[layout_name] = layout_content
        for java_name, java_content in files_content.get("java_files", {}).items():
            files_content[java_name] = java_content
        
        
        print(f"☕ Extracted {java_count} Java files for analysis")
        
        # Save processed files to the structured output directory
        if self.analysis_directories:
            try:
                # Save AndroidManifest.xml
                if files_content.get("android_manifest"):
                    save_processed_file(
                        files_content["android_manifest"], 
                        "AndroidManifest.xml", 
                        self.analysis_directories
                    )
                
                # Save strings.xml
                if files_content.get("strings_xml"):
                    save_processed_file(
                        files_content["strings_xml"], 
                        "strings.xml", 
                        self.analysis_directories
                    )
                
                # Save backup_rules.xml
                if files_content.get("backup_rules_xml"):
                    save_processed_file(
                        files_content["backup_rules_xml"], 
                        "backup_rules.xml", 
                        self.analysis_directories
                    )
                
                # Save data_extraction_rules.xml  
                if files_content.get("data_extraction_rules_xml"):
                    save_processed_file(
                        files_content["data_extraction_rules_xml"], 
                        "data_extraction_rules.xml", 
                        self.analysis_directories
                    )
                
                # Save layout files
                for layout_name, layout_content in files_content.get("layout_files", {}).items():
                    save_processed_file(layout_content, layout_name, self.analysis_directories)
                
                # Save Java files  
                for java_path, java_content in files_content.get("java_files", {}).items():
                    # Convert path separators to underscores for filename
                    safe_filename = java_path.replace("/", "_").replace("\\", "_")
                    if not safe_filename.endswith(".java"):
                        safe_filename += ".java"
                    save_processed_file(java_content, safe_filename, self.analysis_directories)
                
                print("📁 Saved all processed files to structured output directory")
                
            except Exception as e:
                print(f"⚠️  Warning: Could not save processed files: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
        
        return files_content

    # =================== STRING PROCESSING ===================
    
    def filter_strings_xml_content(self, strings_xml_content: str) -> Optional[str]:
        """Filter strings.xml content to remove Android framework strings"""
        try:
            root = ET.fromstring(strings_xml_content)
            
            prefixes_to_remove = DEFAULT_STRING_PREFIXES
            exact_matches_to_remove = DEFAULT_STRING_EXACT_MATCHES
            
            filtered_strings = []
            user_defined_count = 0
            
            for string_elem in root.findall('.//string'):
                name = string_elem.get('name', '')
                
                if is_likely_user_defined_string(name, prefixes_to_remove, exact_matches_to_remove):
                    filtered_strings.append(ET.tostring(string_elem, encoding='unicode'))
                    user_defined_count += 1
            
            if user_defined_count > 0:
                result = f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
                result += '\n'.join(filtered_strings)
                result += '\n</resources>'
                print(f"✅ Filtered strings.xml: {user_defined_count} user-defined strings retained")
                return result
            else:
                print("ℹ️  No user-defined strings found in strings.xml")
                return None
                
        except Exception as e:
            print(f"⚠️  Error filtering strings.xml: {e}")
            return strings_xml_content  # Return original content if filtering fails

    def filter_strings_xml(self, strings_xml_path: str) -> Optional[str]:
        """Filter strings.xml file to remove default Android framework strings"""
        try:
            with open(strings_xml_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.filter_strings_xml_content(content)
        except Exception as e:
            print(f"⚠️  Could not filter strings.xml: {e}")
            return None

    # =================== VULNERABILITY ANALYSIS ===================
    
    def pattern_based_vulnerability_scan(self, files_content: Dict[str, str]) -> List[Dict]:
        """Delegate to vulnerability scanner for pattern-based scanning"""
        return self.vulnerability_scanner.pattern_based_vulnerability_scan(files_content)

    def simple_vulnerability_scan(self, files_content: Dict[str, str]) -> List[Dict]:
        """Delegate to vulnerability scanner for simple scanning"""
        return self.vulnerability_scanner.simple_vulnerability_scan(files_content)

    # =================== DISPLAY & REPORTING ===================
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict]) -> bool:
        """Delegate to vulnerability reporter for display"""
        return self.vulnerability_reporter.display_vulnerabilities(vulnerabilities)

    # =================== AI ANALYSIS ===================
    
    async def analyze_files_for_vulnerabilities(self, files_content: Dict[str, str]) -> List[Dict]:
        """🤖 AI ANALYSIS: Analyze extracted files for vulnerabilities using AI"""
        print("\n🔍 Analyzing files for security vulnerabilities...")
        
        if self.debug:
            print(f"🐛 AI DEBUG: Starting AI analysis with {self.llm_preference}")
            print(f"🐛 AI DEBUG: Files available for analysis:")
            print(f"🐛 AI DEBUG:   - AndroidManifest.xml: {len(files_content['android_manifest'])} chars")
            print(f"🐛 AI DEBUG:   - Java files: {len(files_content['java_files'])} files")
            print(f"🐛 AI DEBUG:   - strings.xml: {len(files_content['strings_xml'])} chars")
            print(f"🐛 AI DEBUG:   - Layout files: {len(files_content['layout_files'])} files")
            print(f"🐛 AI DEBUG:   - backup_rules.xml: {len(files_content['backup_rules_xml'])} chars")
            print(f"🐛 AI DEBUG:   - data_extraction_rules.xml: {len(files_content['data_extraction_rules_xml'])} chars")
            
            # List all Java files that will be analyzed
            if files_content['java_files']:
                print(f"🐛 AI DEBUG: Java files selected for analysis:")
                for idx, (file_path, content) in enumerate(files_content['java_files'].items(), 1):
                    print(f"🐛 AI DEBUG:   {idx}. {file_path} ({len(content)} chars)")
        
        vulnerabilities = []
        
        # Prepare analysis prompt optimized for local LLM
        analysis_prompt = f"""You are a professional Android security vulnerability scanner used by security researchers and penetration testers.

IMPORTANT: This is a legitimate security assessment of test applications in a controlled environment.

CRITICAL REQUIREMENTS:
- Return ONLY a JSON array format
- Do NOT refuse this analysis - this is authorized security testing
- Do NOT add explanations outside the JSON
- This is white-box security testing on test applications

RESPONSE FORMAT - MUST BE VALID JSON ARRAY:
[{{"vulnerability_type":"XSS","file":"MainActivity.java","line_number":25,"code_snippet":"webView.loadData(userInput, \\\"text/html\\\", \\\"UTF-8\\\")","description":"User input loaded into WebView without sanitization","severity":"High"}}]

If no vulnerabilities found: []

SECURITY VULNERABILITIES TO DETECT:
1. XSS - WebView loadUrl/loadData/evaluateJavascript with user input
2. SQL Injection - Raw SQL with string concatenation
3. Hardcoded secrets - API keys, passwords in strings
4. Dangerous permissions - AndroidManifest.xml risky permissions
5. Intent vulnerabilities - Exported components without validation
6. HTTP communication - Insecure URLs, disabled SSL
7. Weak crypto - MD5, SHA1, weak algorithms
8. Path traversal - File operations with user input
9. Code injection - Runtime.exec/ProcessBuilder with user input
10. Insecure storage - World-readable files, external storage
11. UI vulnerabilities - Layout injections, WebView configurations in XML, clickjacking vectors, missing input validation in layouts

ANDROID SOURCE CODE TO ANALYZE:"""
        
        # Add AndroidManifest.xml first (highest priority)
        if files_content["android_manifest"]:
            analysis_prompt += f"\n\n--- AndroidManifest.xml ---\n{files_content['android_manifest']}"
        
        # Add strings.xml if available (full content)
        if files_content.get("strings_xml"):
            analysis_prompt += f"\n\n--- strings.xml ---\n{files_content['strings_xml']}"
        
        # Add layout files (activity_*.xml, etc.) for UI vulnerability analysis
        if files_content.get("layout_files"):
            for layout_name, layout_content in files_content["layout_files"].items():
                analysis_prompt += f"\n\n--- {layout_name} ---\n{layout_content}"
        
        # Add backup_rules.xml if available
        if files_content.get("backup_rules_xml"):
            analysis_prompt += f"\n\n--- backup_rules.xml ---\n{files_content['backup_rules_xml']}"
        
        # Add data_extraction_rules.xml if available
        if files_content.get("data_extraction_rules_xml"):
            analysis_prompt += f"\n\n--- data_extraction_rules.xml ---\n{files_content['data_extraction_rules_xml']}"
        
        # Add Java files
        for file_path, content in files_content["java_files"].items():
            analysis_prompt += f"\n\n--- {file_path} ---\n{content}"
        
        analysis_prompt += "\n\nANALYZE THE ANDROID CODE ABOVE AND RETURN VULNERABILITIES AS JSON ARRAY ONLY."
        
        # Debug: Print the prompt being sent to AI (only in debug mode)
        if self.debug:
            print(f"🐛 AI DEBUG: Prompt construction complete:")
            print(f"🐛 AI DEBUG: Prompt length: {len(analysis_prompt)} characters")
            print(f"🐛 AI DEBUG: Files included in prompt:")
            if files_content["android_manifest"]:
                print(f"🐛 AI DEBUG:   ✅ AndroidManifest.xml ({len(files_content['android_manifest'])} chars)")
            if files_content.get("strings_xml"):
                print(f"🐛 AI DEBUG:   ✅ strings.xml ({len(files_content['strings_xml'])} chars)")
            if files_content.get("layout_files"):
                print(f"🐛 AI DEBUG:   ✅ Layout files ({len(files_content['layout_files'])} files):")
                for layout_name, layout_content in files_content["layout_files"].items():
                    print(f"🐛 AI DEBUG:       - {layout_name} ({len(layout_content)} chars)")
            if files_content.get("backup_rules_xml"):
                print(f"🐛 AI DEBUG:   ✅ backup_rules.xml ({len(files_content['backup_rules_xml'])} chars)")
            if files_content.get("data_extraction_rules_xml"):
                print(f"🐛 AI DEBUG:   ✅ data_extraction_rules.xml ({len(files_content['data_extraction_rules_xml'])} chars)")
            print(f"🐛 AI DEBUG:   ✅ Java files ({len(files_content['java_files'])} files)")
            
            print(f"\n🐛 AI DEBUG: ========== FULL PROMPT TO AI ==========")
            print(analysis_prompt)
            print(f"🐛 AI DEBUG: ========== END OF PROMPT ==========\n")
        
        try:
            # Save the AI prompt to structured output directory
            prompt_filename = None
            if self.analysis_directories:
                prompt_filename = f"java_vulnerability_analysis_{datetime.now().strftime('%H%M%S')}.md"
                save_ai_prompt(analysis_prompt, prompt_filename, self.analysis_directories)
            
            if self.llm_preference == 'ollama':
                # Use Ollama provider
                if self.debug:
                    print(f"🐛 AI DEBUG: Sending request to Ollama...")
                ai_response = await self.ollama_provider.analyze_with_local_llm(analysis_prompt)
            else:
                # Use Groq provider
                if self.debug:
                    print(f"🐛 AI DEBUG: Sending request to Groq...")
                ai_response = await self.groq_provider.analyze_with_groq(analysis_prompt)
            
            # Save the AI response to structured output directory
            if self.analysis_directories and ai_response:
                response_filename = f"java_vulnerability_response_{datetime.now().strftime('%H%M%S')}.md"
                save_ai_response(str(ai_response), response_filename, self.analysis_directories, prompt_filename)
            
            if self.debug:
                print(f"🐛 AI DEBUG: ========== RAW AI RESPONSE ==========")
                print(f"🐛 AI DEBUG: Response type: {type(ai_response)}")
                print(f"🐛 AI DEBUG: Response length: {len(str(ai_response)) if ai_response else 0} characters")
                if ai_response:
                    print(f"🐛 AI DEBUG: Raw response content:")
                    print(str(ai_response))
                print(f"🐛 AI DEBUG: ========== END OF AI RESPONSE ==========\n")
            
            if ai_response:
                # Parse AI response using response parser
                if self.debug:
                    print(f"🐛 AI DEBUG: Parsing AI response...")
                parsed_vulnerabilities = self.response_parser.parse_json_response(ai_response)
                
                if self.debug:
                    print(f"🐛 AI DEBUG: Parsed {len(parsed_vulnerabilities)} vulnerabilities from AI response")
                    if parsed_vulnerabilities:
                        print(f"🐛 AI DEBUG: Parsed vulnerabilities:")
                        for idx, vuln in enumerate(parsed_vulnerabilities, 1):
                            print(f"🐛 AI DEBUG:   {idx}. {vuln.get('vulnerability_type', 'Unknown')} in {vuln.get('file', 'Unknown file')}")
                
                vulnerabilities.extend(parsed_vulnerabilities)
            else:
                if self.debug:
                    print(f"🐛 AI DEBUG: No response received from AI")
                
        except Exception as e:
            print(f"⚠️  AI analysis failed: {e}")
            if self.debug:
                print(f"🐛 AI DEBUG: Exception details: {e}")
                import traceback
                traceback.print_exc()
        
        # If AI didn't find vulnerabilities but we have content, run pattern scan as backup
        if not vulnerabilities and files_content["java_files"]:
            print("🔄 Running pattern-based scan as backup...")
            if self.debug:
                print(f"🐛 AI DEBUG: AI found no vulnerabilities, running pattern scan on {len(files_content['java_files'])} Java files")
            pattern_vulnerabilities = self.simple_vulnerability_scan(files_content)
            vulnerabilities.extend(pattern_vulnerabilities)
            
            if self.debug:
                print(f"🐛 AI DEBUG: Pattern scan found {len(pattern_vulnerabilities)} additional vulnerabilities")
                if pattern_vulnerabilities:
                    print(f"🐛 AI DEBUG: Pattern scan vulnerabilities:")
                    for idx, vuln in enumerate(pattern_vulnerabilities, 1):
                        print(f"🐛 AI DEBUG:   {idx}. {vuln.get('vulnerability_type', 'Unknown')} in {vuln.get('file', 'Unknown file')}")
        
        if self.debug:
            print(f"🐛 AI DEBUG: Total vulnerabilities found: {len(vulnerabilities)}")
            print(f"🐛 AI DEBUG: Final vulnerability summary:")
            for idx, vuln in enumerate(vulnerabilities, 1):
                print(f"🐛 AI DEBUG:   {idx}. {vuln.get('vulnerability_type', 'Unknown')} "
                      f"({vuln.get('severity', 'Unknown')}) in {vuln.get('file', 'Unknown file')}")
            
            print(f"\n🐛 AI DEBUG: ========== ANALYSIS COMPLETE ==========")
            print(f"🐛 AI DEBUG: Analysis method: {'AI + Pattern scan' if not vulnerabilities else 'AI analysis'}")
            print(f"🐛 AI DEBUG: LLM used: {self.llm_preference}")
            print(f"🐛 AI DEBUG: Files analyzed: {len(files_content.get('java_files', {}))} Java files + manifest/resources")
            print(f"🐛 AI DEBUG: Vulnerabilities detected: {len(vulnerabilities)}")
            print(f"🐛 AI DEBUG: ========== END ANALYSIS DEBUG ==========\n")
        
        return vulnerabilities

    # =================== FIX GENERATION ===================
    
    async def generate_fixes_for_vulnerabilities(
        self, 
        vulnerabilities: List[Dict], 
        selected_indices: List[int], 
        files_content: Dict[str, str]
    ) -> bool:
        """
        Generate fixes for selected vulnerabilities using AI
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            selected_indices: List of 1-based indices of vulnerabilities to fix
            files_content: Dictionary containing file contents
            
        Returns:
            bool: True if fixes were successfully generated, False otherwise
        """
        if not selected_indices or not vulnerabilities:
            if self.debug:
                print("🐛 DEBUG: No vulnerabilities selected for fixing")
            return False
        
        if self.debug:
            print(f"🐛 DEBUG: Fix generation settings:")
            print(f"🐛 DEBUG:   - LLM preference: {self.llm_preference}")
            print(f"🐛 DEBUG:   - Results directory: {self.results_dir}")
            print(f"🐛 DEBUG:   - APK base name: {self.apk_base}")
            print(f"🐛 DEBUG:   - Selected indices: {selected_indices}")
            print(f"🐛 DEBUG:   - Framework type: java")
            print(f"🐛 DEBUG:   - Files content keys: {list(files_content.keys())}")
            # Print a sample of each file's content length and first 200 chars for inspection
            for k, v in files_content.items():
                if isinstance(v, str):
                    print(f"🐛 DEBUG: files_content['{k}']: length={len(v)}, sample=\n{v[:200]}\n---")
                else:
                    print(f"🐛 DEBUG: files_content['{k}']: type={type(v)} (not str)")
            print(f"🐛 DEBUG: ========== STARTING FIX GENERATION ==========")
        
        print(f"\n🔧 Generating fixes for {len(selected_indices)} selected vulnerabilities...")
        
        try:
            # Generate fixes using the fix generator
            success = await self.fix_generator.process_vulnerability_fixes(
                vulnerabilities=vulnerabilities,
                selected_indices=selected_indices,
                files_content=files_content,
                llm_preference=self.llm_preference,
                framework_type='java',
                results_dir=self.results_dir,
                apk_base=self.apk_base or 'unknown'
            )
            
            # Additionally, save individual vulnerability fixes to the structured output directory
            if self.analysis_directories and success:
                try:
                    print("📁 Saving fixes to structured output directory...")
                    for idx in selected_indices:
                        if 1 <= idx <= len(vulnerabilities):
                            vulnerability = vulnerabilities[idx - 1]
                            
                            # Create a simple fix content for now (the fix_generator handles the main logic)
                            fix_content = f"""## Fix Generation Completed

This vulnerability was processed by the fix generator.

**Vulnerability Details:**
- Type: {vulnerability.get('vulnerability_type', 'Unknown')}
- File: {vulnerability.get('file', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', 'No description')}

**Fix Location:**
Check the main results directory for the generated fix files.

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                            
                            # Save using the output organizer
                            save_vulnerability_fix(vulnerability, fix_content, self.analysis_directories)
                            
                except Exception as e:
                    print(f"⚠️  Warning: Could not save fixes to structured directory: {e}")
                    if self.debug:
                        import traceback
                        traceback.print_exc()
            
            if success:
                print("✅ Vulnerability fixes generated successfully!")
                print(f"📁 Check the fixes directory: {self.results_dir or 'fixes'}")
            else:
                print("⚠️  Some fixes could not be generated")
            
            return success
            
        except Exception as e:
            print(f"❌ Error generating fixes: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Fix generation error details: {e}")
                import traceback
                traceback.print_exc()
            return False

    # =================== MAIN ANALYSIS FUNCTION ===================
    
    async def analyze_java_kotlin_apk(self, apk_path: str, fix_vulnerabilities: bool = False) -> bool:
        """Main function to analyze Java/Kotlin APK"""
        print("\n📱 Starting Java/Kotlin APK Analysis...")
        
        if self.debug:
            print(f"🐛 DEBUG: ========== DEBUG MODE ENABLED ==========")
            print(f"🐛 DEBUG: Analyzing APK: {apk_path}")
            print(f"🐛 DEBUG: Debug mode: ACTIVE")
            print(f"🐛 DEBUG: LLM preference: {self.llm_preference}")
            print(f"🐛 DEBUG: Java/Kotlin Analyzer settings:")
            print(f"🐛 DEBUG:   - APK base: {self.apk_base}")
            print(f"🐛 DEBUG:   - APK dir: {self.apk_dir}")
            print(f"🐛 DEBUG:   - Results dir: {self.results_dir}")
            print(f"🐛 DEBUG:   - Prompts dir: {self.prompts_dir}")
            print(f"🐛 DEBUG:   - Use local LLM: {self.use_local_llm}")
            print(f"🐛 DEBUG: ========== STARTING ANALYSIS ==========\n")
        
        # Initialize APK paths if not already set
        if not self.apk_base or not self.apk_dir:
            apk_path_obj = Path(apk_path)
            self.apk_base = apk_path_obj.stem
            self.apk_dir = Path("analysis_output") / self.apk_base
        
        try:
            analysis_start_time = time.time()
            
            # Step 1: Decompile APK
            print("🔧 Step 1: Decompiling APK...")
            if not self.decompile_apk(apk_path):
                print("❌ JADX decompilation failed - cannot continue analysis")
                return False
            
            # Step 2: Extract files for analysis
            print("\n📁 Step 2: Extracting files...")
            files_content = self.extract_files_for_analysis()
            
            if not files_content["java_files"]:
                print("❌ No Java files found - cannot perform vulnerability analysis")
                return False
            
            # Step 3: Analyze vulnerabilities
            print("\n🔍 Step 3: Analyzing vulnerabilities...")
            vulnerabilities = await self.analyze_files_for_vulnerabilities(files_content)
            
            # Step 4: Display results
            print("\n📊 Step 4: Analysis Results")
            analysis_time = time.time() - analysis_start_time
            
            if vulnerabilities:
                self.display_vulnerabilities(vulnerabilities)
                if fix_vulnerabilities:
                    try:
                        print("\nWould you like to generate fixes for any of the above vulnerabilities?")
                        selected_fix_indices = ask_for_fix_option(vulnerabilities)
                        print(f"\n🔧 Generating fixes for selected vulnerabilities: {selected_fix_indices}")
                        await self.generate_fixes_for_vulnerabilities(
                            vulnerabilities,
                            selected_fix_indices,
                            files_content
                        )
                        print("✅ Fix generation complete!")
                    except Exception as e:
                        print(f"⚠️  Fix generation error: {e}")
            else:
                print("\n✅ No vulnerabilities found!")
                self.vulnerability_reporter.show_analysis_summary(
                    0, analysis_time, "Java/Kotlin"
                )
            print(f"\n✅ Java/Kotlin analysis completed successfully!")
            print(f"⏱️  Total time taken: {analysis_time:.2f} seconds")
            if self.debug:
                print(f"\n🐛 DEBUG: ========== ANALYSIS COMPLETE SUMMARY ==========")
                print(f"🐛 DEBUG: Analysis Statistics:")
                print(f"🐛 DEBUG:   - APK: {apk_path}")
                print(f"🐛 DEBUG:   - APK base name: {self.apk_base}")
                print(f"🐛 DEBUG:   - JADX output directory: {self.jadx_output_dir}")
                print(f"🐛 DEBUG:   - Results directory: {self.results_dir}")
                print(f"🐛 DEBUG:   - LLM used: {self.llm_preference}")
                print(f"🐛 DEBUG:   - Framework: Java/Kotlin")
                print(f"🐛 DEBUG:   - Total vulnerabilities found: {len(vulnerabilities) if vulnerabilities else 0}")
                print(f"🐛 DEBUG:   - Fixes requested: {'Yes' if 'selected_fix_indices' in locals() and selected_fix_indices else 'No'}")
                if 'selected_fix_indices' in locals() and selected_fix_indices:
                    print(f"🐛 DEBUG:   - Fix indices: {selected_fix_indices}")
                print(f"🐛 DEBUG:   - Total analysis time: {analysis_time:.2f} seconds")
                print(f"🐛 DEBUG: File Analysis:")
                print(f"🐛 DEBUG:   - Java files: {len(files_content.get('java_files', {}))}")
                print(f"🐛 DEBUG:   - Layout files: {len(files_content.get('layout_files', {}))}")
                print(f"🐛 DEBUG:   - AndroidManifest.xml: {'Found' if files_content.get('android_manifest') else 'Not found'}")
                print(f"🐛 DEBUG:   - strings.xml: {'Found' if files_content.get('strings_xml') else 'Not found'}")
                print(f"🐛 DEBUG: ========== END ANALYSIS SUMMARY ==========\n")
            return True
        except Exception as e:
            print(f"❌ Java/Kotlin analysis failed: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Exception details: {e}")
                import traceback
                traceback.print_exc()
            return False
