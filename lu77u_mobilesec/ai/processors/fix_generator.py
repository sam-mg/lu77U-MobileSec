#!/usr/bin/env python3
"""
AI-powered vulnerability fix generator

This module handles generating fixes for security vulnerabilities using AI models.
Consolidates fix generation logic from different analyzers with intelligent batching support.
"""

import asyncio
import json
import re
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..providers.ollama_provider import OllamaProvider
from ..providers.groq_provider import GroqProvider
from .batch_processor import BatchProcessor


class FixGenerator:
    """
    AI-powered fix generator for security vulnerabilities
    
    Consolidates fix generation logic from Java/Kotlin, React Native, and Flutter analyzers.
    Includes intelligent batching for handling large codebases that exceed AI token limits.
    """
    
    def __init__(self, debug=False):
        """Initialize fix generator with batching support"""
        self.debug = debug
        self.ollama_provider = OllamaProvider()
        self.groq_provider = GroqProvider()
        self.batch_processor = BatchProcessor(debug=debug)
    
    async def process_vulnerability_fixes(
        self, 
        vulnerabilities: List[Dict], 
        selected_indices: List[int],
        files_content: Dict[str, str],
        llm_preference: str = 'ollama',
        framework_type: str = 'java',
        results_dir: Optional[Path] = None,
        apk_base: str = 'unknown'
    ) -> bool:
        """
        Process and generate fixes for selected vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            selected_indices: List of 1-based indices of vulnerabilities to fix
            files_content: Dictionary containing file contents
            llm_preference: 'ollama' or 'groq'
            framework_type: 'java', 'react-native', or 'flutter'
            results_dir: Directory to save fix reports
            apk_base: Base name of the APK being analyzed
        """
        if self.debug:
            print(f"🐛 FIX DEBUG: Received files_content keys: {list(files_content.keys())}")

        if not selected_indices:
            return True
            
        print(f"\n🔧 Generating fixes for {len(selected_indices)} selected vulnerabilities...")
        
        # Ensure results directory exists
        if not results_dir:
            results_dir = Path("fixes")
        results_dir.mkdir(exist_ok=True)
        
        # Limit concurrent fix requests to avoid overwhelming AI model
        max_concurrent_fixes = 3
        semaphore = asyncio.Semaphore(max_concurrent_fixes)
        
        async def fix_vulnerability_with_semaphore(index: int):
            async with semaphore:
                return await self.fix_single_vulnerability(
                    vulnerabilities[index - 1],  # Convert to 0-based index
                    files_content,
                    llm_preference,
                    framework_type,
                    results_dir,
                    apk_base
                )
        
        try:
            # Create fix tasks for selected vulnerabilities
            fix_tasks = []
            for index in selected_indices:
                if 1 <= index <= len(vulnerabilities):
                    task = fix_vulnerability_with_semaphore(index)
                    fix_tasks.append(task)
            
            # Run fix tasks concurrently with limited concurrency
            results = await asyncio.gather(*fix_tasks, return_exceptions=True)
            
            # Count successful fixes
            successful_fixes = sum(1 for result in results if result is True)
            print(f"\n✅ Successfully generated {successful_fixes}/{len(fix_tasks)} fixes!")
            
            return successful_fixes > 0
            
        except Exception as e:
            print(f"❌ Error during fix generation: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Fix generation error: {e}")
                import traceback
                traceback.print_exc()
            return False
    
    async def fix_single_vulnerability(
        self,
        vulnerability: Dict,
        files_content: Dict[str, str],
        llm_preference: str,
        framework_type: str,
        results_dir: Path,
        apk_base: str
    ) -> bool:
        """Fix a single vulnerability with AI assistance"""
        try:
            vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
            file_name = vulnerability.get('file', 'Unknown')
            description = vulnerability.get('description', 'No description')
            severity = vulnerability.get('severity', 'Unknown')
            
            print(f"\n🔍 Fixing {vuln_type} in {file_name}...")
            
            if self.debug:
                print(f"🐛 FIX DEBUG: ========== FIXING VULNERABILITY ==========")
                print(f"🐛 FIX DEBUG: Vulnerability details:")
                print(f"🐛 FIX DEBUG:   - Type: {vuln_type}")
                print(f"🐛 FIX DEBUG:   - File: {file_name}")
                print(f"🐛 FIX DEBUG:   - Description: {description}")
                print(f"🐛 FIX DEBUG:   - Severity: {severity}")
                print(f"🐛 FIX DEBUG:   - Framework: {framework_type}")
                print(f"🐛 FIX DEBUG:   - LLM: {llm_preference}")
                print(f"🐛 FIX DEBUG:   - Results dir: {results_dir}")
                print(f"🐛 FIX DEBUG:   - APK base: {apk_base}")
                print(f"🐛 FIX DEBUG: ========== START FIX PROCESS ==========\n")
            
            # Find the original code snippet for context
            original_code, matched_file_path = self.find_original_code(
                file_name, files_content, framework_type
            )
            
            if not original_code:
                print(f"⚠️  Could not find original code for {file_name}")
                if self.debug:
                    file_keys = []
                    for category, files in files_content.items():
                        if isinstance(files, dict):
                            file_keys.extend(files.keys())
                    print(f"🐛 DEBUG: Available files: {file_keys}")
                return False
            
            # Get fixed code from AI
            if self.debug:
                print(f"🐛 FIX DEBUG: Requesting AI fix for original code ({len(original_code)} chars)...")
            
            fixed_code = await self.get_fixed_code(
                vulnerability, original_code, llm_preference, framework_type
            )
            
            if self.debug:
                print(f"🐛 FIX DEBUG: AI fix generation completed")
                print(f"🐛 FIX DEBUG: Fixed code received: {len(fixed_code) if fixed_code else 0} characters")
            
            if not fixed_code or "ERROR" in fixed_code or "Error getting fixed code" in fixed_code:
                print(f"⚠️  AI fix generation failed for {vuln_type} in {file_name}")
                if self.debug:
                    print(f"🐛 FIX DEBUG: AI response failed or contained error:")
                    print(f"🐛 FIX DEBUG: Response: {fixed_code[:500]}..." if fixed_code and len(fixed_code) > 500 else f"🐛 FIX DEBUG: Response: {fixed_code}")
                return False
            
            # Save fix report and code
            if self.debug:
                print(f"🐛 FIX DEBUG: Saving fix report to {results_dir}")
            
            success = self.save_fix_report(
                vulnerability, original_code, fixed_code, matched_file_path,
                results_dir, apk_base
            )
            
            if success:
                print(f"✅ Fix generated and saved for {file_name}")
                if self.debug:
                    print(f"🐛 FIX DEBUG: Fix report saved successfully")
            else:
                if self.debug:
                    print(f"🐛 FIX DEBUG: Failed to save fix report")
            
            return success
            
        except Exception as e:
            print(f"❌ Error fixing vulnerability: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def find_original_code(
        self, 
        file_name: str, 
        files_content: Dict[str, str], 
        framework_type: str
    ) -> tuple[str, Optional[str]]:
        """Find the original code for a file across different content categories"""
        
        if self.debug:
            print(f"🐛 DEBUG: Finding original code for file: {file_name}")
            print(f"🐛 DEBUG: Available files: {list(files_content.keys())}")
        
        # Handle special Flutter file mappings
        file_mapping = {
            'pp.txt': ['pp_content', 'pp_content.dart', 'pp'],
            'objs.txt': ['objs_content', 'objs_content.dart', 'objs'],
            'main.dart': ['main_dart', 'main_dart.dart', 'main_dart_content'],
            'AndroidManifest.xml': ['manifest_content', 'AndroidManifest.xml', 'android_manifest']
        }
        
        # Get possible names for this file
        possible_names = file_mapping.get(file_name, [file_name])
        
        # Add generic variations
        base_name = file_name.replace('.dart', '').replace('.txt', '').replace('.xml', '')
        possible_names.extend([
            file_name,
            base_name,
            f"{base_name}.dart",
            f"{base_name}_content",
            f"{base_name}_content.dart"
        ])
        
        # Try direct lookup first
        for name in possible_names:
            if name in files_content and isinstance(files_content[name], str):
                if self.debug:
                    print(f"🐛 DEBUG: Found exact match for {name}")
                return files_content[name], name
        
        # Define search order based on framework type
        if framework_type == 'java':
            search_categories = ['java_files', 'layout_files']
        elif framework_type == 'react-native':
            search_categories = ['js_files', 'jsx_files', 'ts_files', 'tsx_files', 'java_files']
        elif framework_type == 'flutter':
            search_categories = ['dart_files', 'java_files', 'layout_files']
        else:
            search_categories = ['java_files', 'js_files', 'dart_files', 'layout_files']
        
        # Try category-based search
        for category in search_categories:
            files_dict = files_content.get(category, {})
            if isinstance(files_dict, dict):
                for full_path, content in files_dict.items():
                    # Try matching any of the possible names
                    for name in possible_names:
                        if full_path.endswith(name) or full_path.split('/')[-1] == name:
                            if self.debug:
                                print(f"🐛 DEBUG: Matched {name} to {full_path}")
                            return content, full_path
        
        # Special handling for content stored directly in files_content
        for key, content in files_content.items():
            if isinstance(content, str):
                for name in possible_names:
                    if key.endswith(name) or key == name or name in key:
                        if self.debug:
                            print(f"🐛 DEBUG: Found content match for {key}")
                        return content, key
        
        if self.debug:
            print(f"🐛 DEBUG: No content found for {file_name}")
            print(f"🐛 DEBUG: Tried these names: {possible_names}")
        return "", None
    
    async def get_fixed_code(
        self, 
        vulnerability: Dict, 
        original_code: str, 
        llm_preference: str,
        framework_type: str
    ) -> str:
        """Get fixed code for a specific vulnerability using AI"""
        
        vuln_type = vulnerability.get('vulnerability_type', vulnerability.get('title', 'Unknown'))
        file_name = vulnerability.get('file', 'Unknown')
        description = vulnerability.get('description', 'No description')
        severity = vulnerability.get('severity', 'Unknown')
        
        # Create framework-specific and vulnerability-specific prompts
        if framework_type == 'java':
            language = "Java/Kotlin"
            code_type = "Android Java/Kotlin"
            prompt_intro = f"You are a security expert analyzing {code_type} Framework code."
        elif framework_type == 'react-native':
            language = "JavaScript/TypeScript"
            code_type = "React Native JavaScript/TypeScript"
            prompt_intro = f"You are a security expert analyzing {code_type} Framework code."
        elif framework_type == 'flutter':
            if 'AndroidManifest.xml' in file_name:
                language = "XML"
                code_type = "Android Manifest"
                prompt_intro = "You are an Android security expert specializing in AndroidManifest.xml configuration."
            elif any(keyword in file_name.lower() for keyword in ['main.dart', 'dart']):
                language = "Dart"
                code_type = "Flutter Dart"
                prompt_intro = "You are a Flutter security expert analyzing Dart code and ARM assembly from decompiled Flutter applications."
            else:
                language = "Configuration"
                code_type = "Flutter Configuration"
                prompt_intro = "You are a Flutter security expert analyzing application configuration and data files."
        else:
            language = "Code"
            code_type = "Application code"
            prompt_intro = f"You are a security expert analyzing {code_type} Framework code."

        # Create vulnerability-specific guidance
        vuln_guidance = self._get_vulnerability_specific_guidance(vuln_type, file_name)
        
        fix_prompt = f"""
{prompt_intro}

VULNERABILITY ANALYSIS:
    Type: {vuln_type}
    Description: {description}
    File: {file_name}
    Severity: {severity}
    Language: {language}

{vuln_guidance}

ORIGINAL CODE TO FIX:
```{language.lower()}
{original_code}
```

TASK: Provide a secure, fixed version of this code that addresses the {vuln_type} vulnerability.

REQUIREMENTS:
1. Maintain functionality while fixing security issues
2. Follow {language} best practices and security guidelines
3. Add comments explaining security improvements
4. Ensure the fix is production-ready

FORMAT YOUR RESPONSE AS:
=== FIXED CODE ===
[Your complete, secure fixed code here]

=== EXPLANATION ===
[Detailed explanation of what was changed and why it improves security]

=== SECURITY IMPROVEMENTS ===
[List of specific security improvements made]

=== RECOMMENDATIONS ===
[Additional security recommendations for this type of vulnerability]
"""

        # Debug: Print the fix prompt being sent to AI (only in debug mode)
        if self.debug:
            print(f"🐛 FIX DEBUG: ========== FIX PROMPT TO AI ==========")
            print(f"🐛 FIX DEBUG: Generating fix for: {vuln_type} in {file_name}")
            print(f"🐛 FIX DEBUG: LLM preference: {llm_preference}")
            print(f"🐛 FIX DEBUG: Prompt length: {len(fix_prompt)} characters")
            
            # For Flutter mode, only show first 500 characters to avoid cluttering output
            if framework_type == 'flutter':
                if len(fix_prompt) > 500:
                    print(f"🐛 FIX DEBUG: Prompt preview (first 500 chars):")
                    print(fix_prompt[:500] + "...")
                else:
                    print(f"🐛 FIX DEBUG: Full prompt:")
                    print(fix_prompt)
            else:
                print(f"🐛 FIX DEBUG: Full prompt:")
                print(fix_prompt)
            print(f"🐛 FIX DEBUG: ========== END OF FIX PROMPT ==========\n")

        try:
            if llm_preference == 'groq':
                if self.debug:
                    print(f"🐛 FIX DEBUG: Sending fix request to Groq...")
                
                # Validate Groq provider is available
                if not hasattr(self, 'groq_provider') or not self.groq_provider:
                    error_msg = "Groq provider not initialized"
                    if self.debug:
                        print(f"🐛 FIX DEBUG: {error_msg}")
                    return f"Error: {error_msg}"
                
                response = await self.groq_provider.get_completion(fix_prompt)
            else:
                if self.debug:
                    print(f"🐛 FIX DEBUG: Sending fix request to Ollama...")
                
                # Validate Ollama provider is available
                if not hasattr(self, 'ollama_provider') or not self.ollama_provider:
                    error_msg = "Ollama provider not initialized"
                    if self.debug:
                        print(f"🐛 FIX DEBUG: {error_msg}")
                    return f"Error: {error_msg}"
                
                # Check if Ollama is running
                if not self.ollama_provider.is_ollama_running():
                    error_msg = "Ollama is not running or not accessible"
                    if self.debug:
                        print(f"🐛 FIX DEBUG: {error_msg}")
                    return f"Error: {error_msg}"
                
                response = await self.ollama_provider.get_completion(fix_prompt)
            
            # Debug: Print the AI response (only in debug mode)
            if self.debug:
                print(f"🐛 FIX DEBUG: ========== AI FIX RESPONSE ==========")
                print(f"🐛 FIX DEBUG: Response type: {type(response)}")
                print(f"🐛 FIX DEBUG: Response length: {len(str(response)) if response else 0} characters")
                
                if response:
                    if framework_type == 'flutter':
                        # For Flutter, show limited response to avoid clutter
                        response_str = str(response)
                        if len(response_str) > 1000:
                            print(f"🐛 FIX DEBUG: AI response preview (first 1000 chars):")
                            print(response_str[:1000] + "...")
                        else:
                            print(f"🐛 FIX DEBUG: Full AI response:")
                            print(response_str)
                    else:
                        print(f"🐛 FIX DEBUG: Raw fix response content:")
                        print(str(response))
                else:
                    print(f"🐛 FIX DEBUG: No response received from AI")
                print(f"🐛 FIX DEBUG: ========== END OF FIX RESPONSE ==========\n")
            
            # Validate response
            if not response:
                error_msg = "No response received from AI"
                if self.debug:
                    print(f"🐛 FIX DEBUG: {error_msg}")
                return f"Error: {error_msg}"
            
            # Convert response to string if needed
            response_str = str(response) if response else ""
            
            # Check for common error patterns
            error_patterns = [
                "Error:", "Failed to", "Unable to", "Cannot", 
                "Server disconnected", "Connection error",
                "Invalid", "Timeout"
            ]
            
            for pattern in error_patterns:
                if pattern in response_str:
                    if self.debug:
                        print(f"🐛 FIX DEBUG: Detected error pattern '{pattern}' in response")
                    return f"Error getting fixed code: {response_str}"
            
            return response_str
            
        except Exception as e:
            error_msg = f"Exception during AI request: {e}"
            if self.debug:
                print(f"🐛 FIX DEBUG: {error_msg}")
                import traceback
                traceback.print_exc()
            return f"Error getting fixed code: {error_msg}"
    
    def save_fix_report(
        self,
        vulnerability: Dict,
        original_code: str,
        fixed_code: str,
        matched_file_path: Optional[str],
        results_dir: Path,
        apk_base: str
    ) -> bool:
        """Save fix report and fixed code to files"""
        try:
            vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
            file_name = vulnerability.get('file', 'Unknown')
            description = vulnerability.get('description', 'No description')
            severity = vulnerability.get('severity', 'Unknown')
            
            if self.debug:
                print(f"🐛 SAVE DEBUG: ========== SAVING FIX REPORT ==========")
                print(f"🐛 SAVE DEBUG: Vulnerability: {vuln_type}")
                print(f"🐛 SAVE DEBUG: File: {file_name}")
                print(f"🐛 SAVE DEBUG: Results dir: {results_dir}")
                print(f"🐛 SAVE DEBUG: APK base: {apk_base}")
                print(f"🐛 SAVE DEBUG: Original code length: {len(original_code)} chars")
                print(f"🐛 SAVE DEBUG: Fixed code length: {len(fixed_code)} chars")
            
            # Create safe filenames
            vuln_type_safe = vuln_type.replace(' ', '_').replace('/', '_')
            file_name_safe = file_name.replace('/', '_').replace('\\', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.debug:
                print(f"🐛 SAVE DEBUG: Safe filenames - vuln: {vuln_type_safe}, file: {file_name_safe}")
                print(f"🐛 SAVE DEBUG: Timestamp: {timestamp}")
            
            # Create detailed fix report
            fix_report = f"""# Security Fix Report

## Vulnerability Details
- **Type**: {vuln_type}
- **File**: {file_name}
- **Matched File Path**: {matched_file_path or 'N/A'}
- **Severity**: {severity}
- **Description**: {description}

## Original Code
```java
{original_code}
```

## AI-Generated Fix
{fixed_code}

---
Generated by lu77U-MobileSec on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            # Save fix report
            fix_filename = f"{apk_base}_fix_{vuln_type_safe}_{file_name_safe}_{timestamp}.md"
            fix_file_path = results_dir / fix_filename
            
            if self.debug:
                print(f"🐛 SAVE DEBUG: Writing fix report to: {fix_file_path}")
            
            with open(fix_file_path, 'w', encoding='utf-8') as f:
                f.write(fix_report)
            
            if self.debug:
                print(f"🐛 SAVE DEBUG: Fix report written successfully")
            
            # Extract and save just the fixed code if available
            if "=== FIXED CODE ===" in fixed_code:
                if self.debug:
                    print(f"🐛 SAVE DEBUG: Extracting fixed code section from AI response")
                
                code_parts = fixed_code.split("=== FIXED CODE ===")
                if len(code_parts) > 1:
                    just_code = code_parts[1].split("=== EXPLANATION ===")[0].strip()
                    
                    if self.debug:
                        print(f"🐛 SAVE DEBUG: Extracted code length: {len(just_code)} chars")
                    
                    # Determine file extension
                    if file_name.endswith('.java') or file_name.endswith('.kt'):
                        ext = '.java' if file_name.endswith('.java') else '.kt'
                    elif file_name.endswith('.dart'):
                        ext = '.dart'
                    elif file_name.endswith(('.js', '.jsx', '.ts', '.tsx')):
                        ext = file_name[file_name.rfind('.'):]
                    else:
                        ext = '.txt'
                    
                    if self.debug:
                        print(f"🐛 SAVE DEBUG: File extension determined: {ext}")
                    
                    fixed_code_filename = f"{apk_base}_fixed_{file_name_safe}_{timestamp}{ext}"
                    fixed_code_path = results_dir / fixed_code_filename
                    
                    if self.debug:
                        print(f"🐛 SAVE DEBUG: Writing fixed code to: {fixed_code_path}")
                    
                    with open(fixed_code_path, 'w', encoding='utf-8') as f:
                        f.write(just_code)
                    
                    if self.debug:
                        print(f"� SAVE DEBUG: Fixed code file written successfully")
                    
                    print(f"�📄 Fix report: {fix_filename}")
                    print(f"📄 Fixed code: {fixed_code_filename}")
                else:
                    if self.debug:
                        print(f"🐛 SAVE DEBUG: Could not extract fixed code - malformed response")
                    print(f"📄 Fix report: {fix_filename}")
            else:
                if self.debug:
                    print(f"🐛 SAVE DEBUG: No '=== FIXED CODE ===' section found in AI response")
                print(f"📄 Fix report: {fix_filename}")
            
            if self.debug:
                print(f"🐛 SAVE DEBUG: ========== FIX REPORT SAVED SUCCESSFULLY ==========\n")
            
            return True
            
        except Exception as e:
            print(f"❌ Error saving fix report: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Save error: {e}")
            return False

    async def save_vulnerability_fix_report(
        self,
        vulnerabilities: List[Dict],
        fix_results: List[Dict],
        output_dir: Path,
        apk_base: str = 'unknown'
    ) -> str:
        """
        Save a comprehensive vulnerability fix report
        
        Args:
            vulnerabilities: List of vulnerabilities
            fix_results: List of fix results with generated fixes
            output_dir: Directory to save the report
            apk_base: Base name for the report file
            
        Returns:
            Path to the saved report file
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"{apk_base}_vulnerability_fixes_report_{timestamp}.md"
            report_path = output_dir / report_filename
            
            # Create comprehensive report
            report_content = f"""# Vulnerability Fix Report

## APK Analysis Summary
- **APK**: {apk_base}
- **Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Vulnerabilities**: {len(vulnerabilities)}
- **Fixes Generated**: {len(fix_results)}

## Vulnerability Fixes

"""
            
            for i, (vuln, fix_result) in enumerate(zip(vulnerabilities, fix_results), 1):
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                file_name = vuln.get('file', 'Unknown')
                severity = vuln.get('severity', 'Unknown')
                description = vuln.get('description', 'No description')
                
                report_content += f"""
### {i}. {vuln_type}

- **File**: {file_name}
- **Severity**: {severity}
- **Description**: {description}
- **Fix Status**: {'✅ Generated' if fix_result.get('success') else '❌ Failed'}

"""
                
                if fix_result.get('success') and fix_result.get('fix_content'):
                    report_content += f"""
#### Generated Fix:
{fix_result['fix_content']}

---

"""
                elif fix_result.get('error'):
                    report_content += f"""
#### Fix Error:
```
{fix_result['error']}
```

---

"""
            
            report_content += f"""
## Summary

- **Successful Fixes**: {len([r for r in fix_results if r.get('success')])}
- **Failed Fixes**: {len([r for r in fix_results if not r.get('success')])}

Generated by lu77U-MobileSec on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            # Save report
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return str(report_path)
            
        except Exception as e:
            print(f"❌ Error saving vulnerability fix report: {e}")
            if self.debug:
                traceback.print_exc()
            return ""

    def _get_vulnerability_specific_guidance(self, vuln_type: str, file_name: str) -> str:
        """Get specific guidance for different vulnerability types"""
        
        vuln_type_lower = vuln_type.lower()
        file_name_lower = file_name.lower()
        
        # AndroidManifest.xml vulnerabilities
        if 'androidmanifest.xml' in file_name_lower:
            if 'dangerous permissions' in vuln_type_lower or 'permission' in vuln_type_lower:
                return """
SPECIFIC GUIDANCE FOR DANGEROUS PERMISSIONS:
- Remove unnecessary dangerous permissions (SMS, CALL_PHONE, CAMERA, LOCATION, etc.)
- Add appropriate permission checks and request prompts
- Use android:maxSdkVersion for permissions that are only needed on older versions
- Consider alternatives like ACTION_CALL intent instead of CALL_PHONE permission
- Document why each permission is needed
"""
            elif 'debug' in vuln_type_lower or 'test' in vuln_type_lower:
                return """
SPECIFIC GUIDANCE FOR DEBUG/TEST FLAGS:
- Set android:debuggable="false" for production builds
- Remove android:testOnly="true" from production manifests
- Use build variants to manage debug vs release configurations
- Ensure no debug/development artifacts remain in production
"""
            elif 'exported' in vuln_type_lower:
                return """
SPECIFIC GUIDANCE FOR EXPORTED COMPONENTS:
- Add android:exported="false" for components not meant to be public
- Protect exported components with custom permissions
- Validate all input from external intents
- Use signature-level permissions for sensitive internal components
"""
            else:
                return """
GENERAL ANDROID MANIFEST SECURITY:
- Follow the principle of least privilege
- Explicitly declare android:exported for all components
- Use custom permissions for internal communication
- Validate all external inputs and intents
"""
        
        # Base64/Hex encoded secrets
        elif 'base64' in vuln_type_lower or 'hex' in vuln_type_lower or 'secret' in vuln_type_lower:
            return """
SPECIFIC GUIDANCE FOR HARDCODED SECRETS:
- Move all secrets to secure key management systems (Android Keystore, etc.)
- Use environment variables or secure configuration files
- Implement proper key rotation mechanisms
- Use certificate pinning for API communications
- Consider using Android Security Provider for cryptographic operations
"""
        
        # Native access vulnerabilities
        elif 'native' in vuln_type_lower:
            return """
SPECIFIC GUIDANCE FOR NATIVE ACCESS VULNERABILITIES:
- Validate all data passed between Dart and native code
- Use type-safe channel communication
- Implement proper error handling for native calls
- Avoid exposing internal native methods directly
- Use platform channels with proper data validation
"""
        
        # ARM assembly / decompiled code
        elif 'main.dart' in file_name_lower or 'assembly' in vuln_type_lower:
            return """
SPECIFIC GUIDANCE FOR DECOMPILED CODE SECURITY:
- Focus on logical security improvements rather than assembly fixes
- Implement input validation at the application layer
- Add runtime security checks and guards
- Use obfuscation and anti-tampering measures
- Implement proper error handling and bounds checking
"""
        
        # General object/configuration vulnerabilities  
        else:
            return """
GENERAL SECURITY GUIDANCE:
- Apply input validation and sanitization
- Use secure coding practices for the specific language/framework
- Implement proper error handling without information leakage
- Follow the principle of least privilege
- Add logging for security-relevant events
"""

    async def generate_fix_content(
        self,
        vuln: Dict[str, Any],
        framework_assets: Dict[str, Any],
        framework_type: str = 'flutter',
        llm_preference: str = 'ollama'
    ) -> str:
        """
        Generate fix content for a specific vulnerability
        
        Args:
            vuln: Vulnerability dictionary
            framework_assets: Framework-specific assets (flutter_assets, blutter_files, etc.)
            framework_type: Framework type ('flutter', 'react-native', 'java', etc.)
            llm_preference: LLM preference ('ollama' or 'groq')
            
        Returns:
            Generated fix content as string
        """
        try:
            if framework_type == 'flutter':
                return await self._generate_flutter_fix_content(vuln, framework_assets, llm_preference)
            elif framework_type == 'react-native':
                return await self._generate_react_native_fix_content(vuln, framework_assets, llm_preference)
            elif framework_type in ['java', 'kotlin']:
                return await self._generate_java_kotlin_fix_content(vuln, framework_assets, llm_preference)
            else:
                return await self._generate_generic_fix_content(vuln, framework_assets, llm_preference)
                
        except Exception as e:
            return f"Error generating fix content: {e}"
    
    async def _generate_flutter_fix_content(
        self,
        vuln: Dict[str, Any],
        flutter_assets: Dict[str, Any],
        llm_preference: str = 'ollama'
    ) -> str:
        """Generate Flutter-specific fix content"""
        try:
            # Build comprehensive prompt for Flutter fix generation
            prompt_parts = []
            
            # Base prompt
            prompt_parts.append(f"""
You are a Flutter security expert. Generate a detailed security fix for the following vulnerability.

## Vulnerability Details:
- **Title**: {vuln.get('title', 'Unknown')}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **Description**: {vuln.get('description', 'No description')}
- **Location**: {vuln.get('location', 'Unknown')}
- **Impact**: {vuln.get('impact', 'Unknown impact')}

## Current Recommendation:
{vuln.get('recommendation', 'No recommendation provided')}

Please provide:
1. **Detailed Analysis**: Explain why this is a security vulnerability
2. **Fix Implementation**: Provide specific Flutter/Dart code fixes
3. **Best Practices**: Include security best practices for Flutter
4. **Testing**: How to verify the fix works
5. **Additional Considerations**: Any other security improvements

Format your response in clear sections.
""")
            
            # Add code context if available
            if vuln.get('code'):
                prompt_parts.append(f"""

## Vulnerable Code:
```dart
{vuln['code']}
```
""")
            
            # Add Flutter assets context
            blutter_files = flutter_assets.get('blutter_files', {})
            if blutter_files.get('main_dart'):
                prompt_parts.append(f"""

## Flutter Main Code Context:
```dart
{blutter_files['main_dart'][:3000]}  # Truncated for context
```
""")
            
            if flutter_assets.get('pubspec_content'):
                prompt_parts.append(f"""

## Pubspec Dependencies:
```yaml
{flutter_assets['pubspec_content'][:1000]}  # Truncated for context
```
""")
            
            if flutter_assets.get('manifest_content'):
                prompt_parts.append(f"""

## Android Manifest Context:
```xml
{flutter_assets['manifest_content'][:1000]}  # Truncated for context
```
""")
            
            # Join all prompt parts
            full_prompt = "\n".join(prompt_parts)
            
            # Get AI fix
            if llm_preference == 'ollama' and self.ollama_provider.is_ollama_running():
                response = await self.ollama_provider.get_completion(full_prompt)
            else:
                response = await self.groq_provider.get_completion(full_prompt)
            
            return response
            
        except Exception as e:
            return f"Error generating Flutter fix: {e}"
    
    async def _generate_react_native_fix_content(
        self,
        vuln: Dict[str, Any],
        assets: Dict[str, Any],
        llm_preference: str = 'ollama'
    ) -> str:
        """Generate React Native-specific fix content"""
        try:
            # Build comprehensive prompt for React Native fix generation
            prompt_parts = []
            
            # Base prompt
            prompt_parts.append(f"""
You are a React Native security expert. Generate a detailed security fix for the following vulnerability.

## Vulnerability Details:
- **Title**: {vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **Description**: {vuln.get('description', 'No description')}
- **File**: {vuln.get('file', 'Unknown')}
- **Line**: {vuln.get('line_number', 'Unknown')}
- **Impact**: {vuln.get('impact', 'Unknown impact')}

## Current Recommendation:
{vuln.get('recommendation', 'No recommendation provided')}

Please provide:
1. **Detailed Analysis**: Explain why this is a security vulnerability in React Native context
2. **Fix Implementation**: Provide specific JavaScript/TypeScript code fixes for React Native
3. **Best Practices**: Include React Native security best practices
4. **Bridge Security**: Address React Native bridge communication security if relevant
5. **Testing**: How to verify the fix works in React Native environment
6. **Additional Considerations**: Any other React Native-specific security improvements

Format your response in clear sections.
""")
            
            # Add code context if available
            if vuln.get('code') or vuln.get('code_snippet'):
                code = vuln.get('code') or vuln.get('code_snippet')
                prompt_parts.append(f"""

## Vulnerable Code:
```javascript
{code}
```
""")
            
            # Add React Native assets context
            decompiled_modules = assets.get('decompiled_modules', {})
            if decompiled_modules:
                # Show sample of decompiled modules for context
                sample_modules = list(decompiled_modules.items())[:3]  # First 3 modules
                prompt_parts.append(f"""

## React Native Decompiled Code Context:
""")
                for module_name, module_content in sample_modules:
                    content_preview = module_content[:1000] if len(module_content) > 1000 else module_content
                    prompt_parts.append(f"""
### Module: {module_name}
```javascript
{content_preview}
{' # Truncated for context...' if len(module_content) > 1000 else ''}
```
""")
            
            # Add package.json context if available
            if assets.get('package_json'):
                prompt_parts.append(f"""

## Package.json Dependencies:
```json
{assets['package_json'][:1000]}  # Truncated for context
```
""")
            
            # Add AndroidManifest.xml context if available
            if assets.get('manifest_content'):
                prompt_parts.append(f"""

## Android Manifest Context:
```xml
{assets['manifest_content'][:1000]}  # Truncated for context
```
""")
            
            # Join all prompt parts
            full_prompt = "\n".join(prompt_parts)
            
            # Get AI fix
            if llm_preference == 'ollama' and self.ollama_provider.is_ollama_running():
                response = await self.ollama_provider.get_completion(full_prompt)
            else:
                response = await self.groq_provider.get_completion(full_prompt)
            
            return response
            
        except Exception as e:
            return f"Error generating React Native fix: {e}"
    
    async def _generate_java_kotlin_fix_content(
        self,
        vuln: Dict[str, Any],
        assets: Dict[str, Any],
        llm_preference: str = 'ollama'
    ) -> str:
        """Generate Java/Kotlin-specific fix content"""
        try:
            # Build comprehensive prompt for Java/Kotlin fix generation
            prompt_parts = []
            
            # Base prompt
            prompt_parts.append(f"""
You are an Android security expert specializing in Java/Kotlin code. Generate a detailed security fix for the following vulnerability.

## Vulnerability Details:
- **Title**: {vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **Description**: {vuln.get('description', 'No description')}
- **File**: {vuln.get('file', 'Unknown')}
- **Line**: {vuln.get('line_number', 'Unknown')}
- **Impact**: {vuln.get('impact', 'Unknown impact')}

## Current Recommendation:
{vuln.get('recommendation', 'No recommendation provided')}

Please provide:
1. **Detailed Analysis**: Explain why this is a security vulnerability in Android Java/Kotlin context
2. **Fix Implementation**: Provide specific Java/Kotlin code fixes following Android best practices
3. **Best Practices**: Include Android security best practices and OWASP Mobile guidelines
4. **Permissions**: Address Android permissions and security model implications
5. **Testing**: How to verify the fix works in Android environment
6. **ProGuard/R8**: Consider obfuscation and code protection implications
7. **Additional Considerations**: Any other Android-specific security improvements

Format your response in clear sections.
""")
            
            # Add code context if available
            if vuln.get('code') or vuln.get('code_snippet'):
                code = vuln.get('code') or vuln.get('code_snippet')
                prompt_parts.append(f"""

## Vulnerable Code:
```java
{code}
```
""")
            
            # Add Java files context
            java_files = assets.get('java_files', {})
            if java_files:
                # Show sample of java files for context
                sample_files = list(java_files.items())[:3]  # First 3 files
                prompt_parts.append(f"""

## Java/Kotlin Code Context:
""")
                for file_name, file_content in sample_files:
                    content_preview = file_content[:1000] if len(file_content) > 1000 else file_content
                    prompt_parts.append(f"""
### File: {file_name}
```java
{content_preview}
{' # Truncated for context...' if len(file_content) > 1000 else ''}
```
""")
            
            # Add layout files context if available
            layout_files = assets.get('layout_files', {})
            if layout_files:
                sample_layouts = list(layout_files.items())[:2]  # First 2 layout files
                prompt_parts.append(f"""

## Android Layout Context:
""")
                for layout_name, layout_content in sample_layouts:
                    content_preview = layout_content[:500] if len(layout_content) > 500 else layout_content
                    prompt_parts.append(f"""
### Layout: {layout_name}
```xml
{content_preview}
{' # Truncated for context...' if len(layout_content) > 500 else ''}
```
""")
            
            # Add AndroidManifest.xml context if available
            if assets.get('manifest_content'):
                prompt_parts.append(f"""

## Android Manifest Context:
```xml
{assets['manifest_content'][:1000]}  # Truncated for context
```
""")
            
            # Add strings.xml context if available
            if assets.get('strings_xml'):
                prompt_parts.append(f"""

## Strings Resources Context:
```xml
{assets['strings_xml'][:500]}  # Truncated for context
```
""")
            
            # Join all prompt parts
            full_prompt = "\n".join(prompt_parts)
            
            # Get AI fix
            if llm_preference == 'ollama' and self.ollama_provider.is_ollama_running():
                response = await self.ollama_provider.get_completion(full_prompt)
            else:
                response = await self.groq_provider.get_completion(full_prompt)
            
            return response
            
        except Exception as e:
            return f"Error generating Java/Kotlin fix: {e}"
    
    async def _generate_generic_fix_content(
        self,
        vuln: Dict[str, Any],
        assets: Dict[str, Any],
        llm_preference: str = 'ollama'
    ) -> str:
        """Generate generic fix content"""
        try:
            prompt = f"""
Generate a security fix for the following vulnerability:

**Title**: {vuln.get('title', 'Unknown')}
**Severity**: {vuln.get('severity', 'Unknown')}
**Description**: {vuln.get('description', 'No description')}
**Location**: {vuln.get('location', 'Unknown')}
**Current Recommendation**: {vuln.get('recommendation', 'No recommendation')}

Provide a detailed fix with explanations.
"""
            
            if llm_preference == 'ollama' and self.ollama_provider.is_ollama_running():
                response = await self.ollama_provider.get_completion(prompt)
            else:
                response = await self.groq_provider.get_completion(prompt)
            
            return response
            
        except Exception as e:
            return f"Error generating generic fix: {e}"
    
    async def get_fixed_code_for_vulnerability(
        self,
        vulnerability: Dict,
        files_content: Dict[str, str],
        llm_preference: str = 'ollama',
        framework_type: str = 'java'
    ) -> str:
        """
        Legacy compatibility method for getting fixed code for a vulnerability
        
        This method provides compatibility with the old analyzer interfaces
        while redirecting to the unified fix generation system.
        """
        try:
            # Find original code for the vulnerability
            file_name = vulnerability.get('file', 'Unknown')
            original_code, matched_file_path = self.find_original_code(
                file_name, files_content, framework_type
            )
            
            if not original_code:
                return f"Error: Could not find original code for {file_name}"
            
            # Generate fixed code using the main method
            fixed_code = await self.get_fixed_code(
                vulnerability, original_code, llm_preference, framework_type
            )
            
            return fixed_code
            
        except Exception as e:
            return f"Error getting fixed code: {e}"
    
    async def generate_fixes_with_batching(
        self,
        vulnerabilities: List[Dict],
        selected_indices: List[int],
        decompiled_modules: Dict[str, str],
        bundles: List[str],
        llm_preference: str = 'ollama',
        results_dir: Optional[Path] = None,
        apk_base: str = 'unknown'
    ) -> bool:
        """
        Generate fixes with intelligent batching for large codebases.
        
        This method implements smart batching to handle cases where there are many
        decompiled modules that could exceed AI token/context limits. It groups
        vulnerabilities by file and processes related modules in optimized batches.
        
        Args:
            vulnerabilities: List of all detected vulnerabilities
            selected_indices: 1-based indices of vulnerabilities to fix
            decompiled_modules: Dictionary of module_name -> module_content
            bundles: List of JavaScript bundles for context
            llm_preference: AI provider preference ('ollama', 'groq', etc.)
            results_dir: Directory to save results
            apk_base: Base name of the APK being analyzed
            
        Returns:
            True if at least one fix was successfully generated
            
        Example:
            >>> generator = FixGenerator(debug=True)
            >>> success = await generator.generate_fixes_with_batching(
            ...     vulnerabilities, [1, 2, 3], modules, bundles
            ... )
        """
        try:
            if not decompiled_modules:
                # No decompiled modules - use simple approach
                files_content = {
                    'react_native_assets': {
                        'bundles': bundles,
                        'framework_type': 'react-native'
                    }
                }
                
                return await self.process_vulnerability_fixes(
                    vulnerabilities,
                    selected_indices,
                    files_content,
                    llm_preference,
                    "react-native",
                    results_dir,
                    apk_base
                )
            
            # Determine optimal batch size
            total_modules = len(decompiled_modules)
            batch_size = self.batch_processor.calculate_optimal_batch_size(
                total_modules, llm_preference
            )
            
            if total_modules <= batch_size:
                print(f"📦 Processing {total_modules} modules (no batching needed)")
                # Small number of modules - process all at once
                files_content = {
                    'decompiled_modules': decompiled_modules,
                    'react_native_assets': {
                        'bundles': bundles,
                        'framework_type': 'react-native'
                    }
                }
                
                return await self.process_vulnerability_fixes(
                    vulnerabilities,
                    selected_indices,
                    files_content,
                    llm_preference,
                    "react-native",
                    results_dir,
                    apk_base
                )
            
            # Large number of modules - use intelligent batching
            print(f"📦 Processing {total_modules} modules in batches of {batch_size}")
            
            # Group vulnerabilities by their source files
            vuln_file_groups = self.batch_processor.group_vulnerabilities_by_file(
                vulnerabilities, selected_indices
            )
            
            # Process each file group with relevant modules
            successful_fixes = 0
            total_attempts = 0
            
            for file_name, file_vulns in vuln_file_groups.items():
                print(f"\n🔍 Processing fixes for {file_name} ({len(file_vulns)} vulnerabilities)")
                
                # Find relevant modules for this file
                relevant_modules = self.batch_processor.find_relevant_modules(
                    file_name, decompiled_modules, max_modules=batch_size * 3
                )
                
                # Create processing batches
                batches = self.batch_processor.create_processing_batches(
                    relevant_modules, batch_size
                )
                
                for batch_num, total_batches, batch_modules in batches:
                    if total_batches > 1:
                        print(f"  📦 Processing batch {batch_num}/{total_batches} ({len(batch_modules)} modules)")
                    
                    # Build files_content for this batch
                    files_content = {
                        'decompiled_modules': batch_modules,
                        'react_native_assets': {
                            'bundles': bundles,
                            'framework_type': 'react-native',
                            'context': f'Processing {file_name} - batch {batch_num}'
                        }
                    }
                    
                    # Get indices for vulnerabilities in this file
                    file_vuln_indices = []
                    for i, vuln in enumerate(vulnerabilities, 1):
                        if vuln.get('file') == file_name and i in selected_indices:
                            file_vuln_indices.append(i)
                    
                    if file_vuln_indices:
                        try:
                            result = await self.process_vulnerability_fixes(
                                vulnerabilities,
                                file_vuln_indices,
                                files_content,
                                llm_preference,
                                "react-native",
                                results_dir,
                                apk_base
                            )
                            
                            if result:
                                successful_fixes += len(file_vuln_indices)
                            total_attempts += len(file_vuln_indices)
                            
                        except Exception as e:
                            print(f"    ⚠️  Batch {batch_num} failed: {e}")
                            if self.debug:
                                print(f"🐛 DEBUG: Batch error details: {e}")
                                traceback.print_exc()
                            total_attempts += len(file_vuln_indices)
            
            print(f"\n✅ Batched fix generation complete: {successful_fixes}/{total_attempts} fixes successful")
            return successful_fixes > 0
            
        except Exception as e:
            print(f"❌ Error in batched fix generation: {e}")
            if self.debug:
                print(f"🐛 DEBUG: Batching error: {e}")
                traceback.print_exc()
            return False
