#!/usr/bin/env python3
"""
AI Response Parser Module

This module handles parsing and processing of AI responses
for vulnerability analysis and fix generation.
"""

import json
import re
from typing import List, Dict, Optional


class ResponseParser:
    """Parser for AI responses in vulnerability analysis"""
    
    def __init__(self, debug: bool = False):
        """Initialize response parser"""
        self.debug = debug
    
    def fix_json_quotes_in_code(self, json_str: str) -> str:
        """Fix common quote patterns in code snippets that break JSON parsing"""
        fixed = json_str
        
        # Common problematic patterns in Android code
        fixed = fixed.replace(', "text/html",', ', \\"text/html\\",')
        fixed = fixed.replace('"text/html"', '\\"text/html\\"')
        fixed = fixed.replace('"UTF-8"', '\\"UTF-8\\"')
        fixed = fixed.replace('"application/json"', '\\"application/json\\"')
        fixed = fixed.replace('"javascript:"', '\\"javascript:\\"')
        fixed = fixed.replace('"http:"', '\\"http:\\"')
        fixed = fixed.replace('"https:"', '\\"https:\\"')
        
        # More generic patterns for common MIME types and protocols
        fixed = re.sub(r'(?<!")(\btype\s*=\s*)"([^"]+)"', r'\1\\"\2\\"', fixed)
        fixed = re.sub(r'(?<!")(Content-Type\s*:\s*)"([^"]+)"', r'\1\\"\2\\"', fixed)
        
        return fixed
    
    def extract_vulnerabilities_from_text(self, text: str) -> List[Dict]:
        """Extract vulnerability info from plain text when JSON parsing fails"""
        vulnerabilities = []
        
        # Look for vulnerability patterns in text
        patterns = [
            (r'vulnerability_type["\s:]+([^",\n}]+)', 'vulnerability_type'),
            (r'file["\s:]+([^",\n}]+)', 'file'),
            (r'line_number["\s:]+(\d+)', 'line_number'),
            (r'code_snippet["\s:]+(.+?)(?=",|\})', 'code_snippet'),
            (r'description["\s:]+([^",\n}]+)', 'description'),
            (r'severity["\s:]+([^",\n}]+)', 'severity')
        ]
        
        # Split text into potential vulnerability blocks
        blocks = re.split(r'(?:\{|\}|\[|\])', text)
        
        for block in blocks:
            vuln = {}
            for pattern, key in patterns:
                match = re.search(pattern, block)
                if match:
                    value = match.group(1).strip().strip('"')
                    vuln[key] = value
            
            if vuln and 'vulnerability_type' in vuln:
                vulnerabilities.append(self.normalize_vulnerability(vuln))
        
        return vulnerabilities
    
    def fix_code_snippet_quotes(self, text: str) -> str:
        """Fix malformed quotes in code snippets from AI responses"""
        # Replace smart quotes with regular quotes
        text = text.replace('"', '"').replace('"', '"')
        text = text.replace(''', "'").replace(''', "'")
        
        # Fix escaped quotes in JSON - be more careful about this
        # Only fix obvious problems, don't break valid JSON
        text = re.sub(r'\\\\"', r'"', text)  # Replace \\\" with \"
        text = re.sub(r'\\"+', r'"', text)   # Replace multiple backslashes before quotes
        
        return text
    
    def escape_quotes_in_xml_attributes(self, text: str) -> str:
        """Escape double quotes inside XML/HTML attribute values for JSON parsing"""
        # This regex finds attribute values inside <...> tags and escapes inner quotes
        def replacer(match):
            tag = match.group(0)
            # Only escape quotes inside attribute values, not the tag itself
            # e.g. <tag attr="value with \"quote\" inside">
            return re.sub(r'(=)"([^"]*?)"', lambda m: f'{m.group(1)}"{m.group(2).replace('"', '\\"')}"', tag)
        return re.sub(r'<[^>]+>', replacer, text)

    def parse_json_response(self, response_text) -> List[Dict]:
        """Parse JSON response from AI, with fallback to text extraction"""
        try:
            # Handle case where response_text might be a dict already
            if isinstance(response_text, dict):
                if self.debug:
                    print("🐛 DEBUG: Response is already a dict, extracting 'response' field")
                response_text = response_text.get('response', str(response_text))
            elif response_text is None:
                if self.debug:
                    print("🐛 DEBUG: Response is None")
                return []
            
            # Ensure response_text is a string
            response_text = str(response_text)
            
            if self.debug:
                print(f"🐛 DEBUG: Processing response text (full content):")
                print(response_text)
            
            # Extract JSON block
            json_block_match = re.search(r'```json\s*(\[.*?\])\s*```', response_text, re.DOTALL)
            if not json_block_match:
                json_block_match = re.search(r'\[\s*{.*?}\s*\]', response_text, re.DOTALL)
            
            if json_block_match:
                json_str = json_block_match.group(1)
                
                # Pre-process the JSON string to handle problematic patterns
                def fix_code_snippet(match):
                    code = match.group(1)
                    # Fix WebView loadData pattern
                    code = re.sub(r'loadData\((.*?),\s*"([^"]+)",\s*"([^"]+)"\)', 
                                r'loadData(\1, \\\"\2\\\", \\\"\3\\\")', code)
                    # Fix XML attributes
                    code = re.sub(r'(android:\w+)="([^"]*)"', r'\1=\\"\2\\"', code)
                    return f'"code_snippet": "{code}"'
                
                # Fix code snippets
                json_str = re.sub(r'"code_snippet":\s*"(.*?)"', fix_code_snippet, json_str)
                
                try:
                    # Try parsing with the fixed JSON
                    vulnerabilities = json.loads(json_str)
                    
                    # Validate and normalize
                    validated_vulns = []
                    for vuln in vulnerabilities:
                        if self.validate_vulnerability(vuln):
                            normalized = self.normalize_vulnerability(vuln)
                            validated_vulns.append(normalized)
                            if self.debug:
                                print(f"🐛 DEBUG: Validated vulnerability: {normalized['vulnerability_type']} in {normalized['file']}")
                    
                    return validated_vulns
                    
                except json.JSONDecodeError as e:
                    if self.debug:
                        print(f"🐛 DEBUG: JSON parsing failed: {e}")
                        print("🐛 DEBUG: Problematic JSON:")
                        print(json_str)
                    
                    # Try alternative parsing approach
                    try:
                        # Remove all newlines and extra whitespace
                        json_str = re.sub(r'\s+', ' ', json_str).strip()
                        # Escape special characters in code snippets
                        json_str = re.sub(r'(?<=:)\s*"([^"\\]*(?:\\.[^"\\]*)*)"', 
                                        lambda m: f' "{m.group(1).replace("`", "\\`").replace("\"", "\\\"")}"', 
                                        json_str)
                        vulnerabilities = json.loads(json_str)
                        return [self.normalize_vulnerability(v) for v in vulnerabilities if self.validate_vulnerability(v)]
                    except json.JSONDecodeError:
                        if self.debug:
                            print("🐛 DEBUG: Alternative JSON parsing also failed")
            
            # If all JSON parsing attempts fail, extract from text
            if self.debug:
                print("🐛 DEBUG: Falling back to text extraction")
            return self.extract_vulnerabilities_from_text(response_text)
            
        except Exception as e:
            if self.debug:
                print(f"🐛 DEBUG: Error in parse_json_response: {e}")
            return []
    
    def validate_vulnerability(self, vulnerability: Dict) -> bool:
        """Validate that a vulnerability dict has required fields"""
        required_fields = ['vulnerability_type', 'file', 'description']
        
        for field in required_fields:
            if not vulnerability.get(field):
                if self.debug:
                    print(f"🐛 DEBUG: Vulnerability missing required field: {field}")
                return False
        
        return True
    
    def normalize_vulnerability(self, vulnerability: Dict) -> Dict:
        """Normalize vulnerability dict to ensure consistent format"""
        normalized = {
            'vulnerability_type': vulnerability.get('vulnerability_type', 'Unknown'),
            'file': vulnerability.get('file', 'Unknown'),
            'line_number': vulnerability.get('line_number', 0),
            'code_snippet': vulnerability.get('code_snippet', ''),
            'description': vulnerability.get('description', 'No description'),
            'severity': vulnerability.get('severity', 'Medium')
        }
        
        # Clean up code snippets
        if normalized['code_snippet']:
            # Unescape quotes in code snippets for better readability
            normalized['code_snippet'] = normalized['code_snippet'].replace('\\"', '"')
            # Clean up XML formatting
            if '<' in normalized['code_snippet']:
                normalized['code_snippet'] = re.sub(r'\s+', ' ', normalized['code_snippet'])
        
        # Clean up file paths
        if normalized['file'] == 'Unknown' and 'location' in vulnerability:
            normalized['file'] = vulnerability['location']
        
        # Ensure valid severity
        if normalized['severity'] not in ['High', 'Medium', 'Low']:
            normalized['severity'] = 'Medium'
        
        return normalized
    
    def debug_ai_response_patterns(self, vulnerabilities: list, consistency_report: dict) -> None:
        """Debug AI response patterns and consistency"""
        try:
            if not self.debug:
                return
            
            print("\n" + "="*60)
            print("🐛 AI RESPONSE PATTERN DEBUG")
            print("="*60)
            
            # Analyze vulnerability patterns
            if vulnerabilities:
                print(f"\n📊 VULNERABILITY ANALYSIS:")
                print(f"   Total vulnerabilities found: {len(vulnerabilities)}")
                
                # Analyze severity distribution
                severity_counts = {}
                types_counts = {}
                locations = []
                
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Unknown')
                    vuln_type = vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))
                    location = vuln.get('location', 'Unknown')
                    
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    types_counts[vuln_type] = types_counts.get(vuln_type, 0) + 1
                    locations.append(location)
                
                print(f"\n   📈 Severity Distribution:")
                for severity, count in sorted(severity_counts.items()):
                    print(f"      {severity}: {count}")
                
                print(f"\n   🔍 Vulnerability Types:")
                for vuln_type, count in sorted(types_counts.items()):
                    print(f"      {vuln_type}: {count}")
                
                print(f"\n   📍 Location Patterns:")
                unique_locations = set(locations)
                for location in sorted(unique_locations):
                    count = locations.count(location)
                    print(f"      {location}: {count} occurrence(s)")
                
                # Check for potential AI artifacts
                print(f"\n   🤖 AI Artifact Detection:")
                artifacts_found = 0
                
                for vuln in vulnerabilities:
                    description = str(vuln.get('description', ''))
                    title = str(vuln.get('title', ''))
                    
                    # Check for common AI artifacts
                    if any(artifact in description.lower() for artifact in [
                        'as an ai', 'i cannot', 'i apologize', 'please note',
                        'it appears', 'it seems', 'based on the code'
                    ]):
                        artifacts_found += 1
                        print(f"      Potential AI artifact in: {title}")
                    
                    # Check for JSON formatting issues
                    if any(char in description for char in ['{', '}', '[', ']']):
                        print(f"      JSON artifacts in description: {title}")
                    
                    # Check for extremely long descriptions (might be malformed)
                    if len(description) > 1000:
                        print(f"      Unusually long description: {title} ({len(description)} chars)")
                
                if artifacts_found == 0:
                    print(f"      No obvious AI artifacts detected ✅")
                else:
                    print(f"      Found {artifacts_found} potential AI artifacts ⚠️")
            
            else:
                print(f"\n❌ No vulnerabilities found in AI response")
            
            # Analyze input consistency
            if consistency_report:
                print(f"\n📋 INPUT CONSISTENCY ANALYSIS:")
                
                framework_type = consistency_report.get('framework_type', 'Unknown')
                print(f"   Framework: {framework_type}")
                
                input_summary = consistency_report.get('input_summary', {})
                if input_summary:
                    print(f"\n   📁 Input Data Summary:")
                    for input_type, data in input_summary.items():
                        if isinstance(data, dict):
                            available = data.get('available', False)
                            status = "✅" if available else "❌"
                            print(f"      {input_type}: {status}")
                            if available and 'size' in data:
                                print(f"         Size: {data['size']} characters")
                
                consistency_checks = consistency_report.get('consistency_checks', {})
                if consistency_checks:
                    print(f"\n   🔍 Consistency Checks:")
                    for check_name, check_data in consistency_checks.items():
                        if isinstance(check_data, dict):
                            print(f"      {check_name}:")
                            for key, value in check_data.items():
                                print(f"         {key}: {value}")
                
                recommendations = consistency_report.get('recommendations', [])
                if recommendations:
                    print(f"\n   💡 Recommendations:")
                    for i, rec in enumerate(recommendations, 1):
                        print(f"      {i}. {rec}")
            
            # Correlation analysis
            print(f"\n🔗 CORRELATION ANALYSIS:")
            
            if vulnerabilities and consistency_report:
                input_quality = consistency_report.get('consistency_checks', {}).get('data_completeness', {})
                completeness = input_quality.get('percentage', 0)
                vuln_count = len(vulnerabilities)
                
                print(f"   Data completeness: {completeness}%")
                print(f"   Vulnerabilities found: {vuln_count}")
                
                if completeness > 80 and vuln_count > 0:
                    print(f"   ✅ Good correlation: High data quality, vulnerabilities found")
                elif completeness < 50 and vuln_count == 0:
                    print(f"   ⚠️  Low data quality may have limited vulnerability detection")
                elif completeness > 80 and vuln_count == 0:
                    print(f"   ✅ Good data quality, no vulnerabilities (app may be secure)")
                else:
                    print(f"   ℹ️  Standard analysis result")
            
            print(f"\n" + "="*60)
            print("🐛 END AI RESPONSE DEBUG")
            print("="*60 + "\n")
            
        except Exception as e:
            print(f"❌ Error in AI response pattern debug: {e}")
