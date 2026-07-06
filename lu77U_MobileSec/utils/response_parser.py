"""AI Response Parser Module for lu77U-MobileSec"""

import json
import re
from typing import List, Dict
from .verbose import verbose_print
from .cvss import severity_from_vector
from ..config.constants import RESPONSE_PARSER_PATTERNS
from ..ai.schema import parse_line_span

def _derive_title_from_description(description: str) -> str:
    """Best-effort short title from a description when the model omitted one.

    Uses the first sentence, trimmed and capped, so a real finding is never
    dropped or shown as "Unknown" just because the model skipped ``title``.
    """
    text = (description or "").strip()
    if not text:
        return "Security Issue"
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0].strip()
    if len(first) > 80:
        first = first[:77].rstrip() + "..."
    return first or "Security Issue"

class ResponseParser:
    """Parser for AI responses in vulnerability analysis"""
    
    def __init__(self, verbose: bool = False):
        """Initialize response parser"""
        self.verbose = verbose
        verbose_print("ResponseParser initialized", self.verbose)
    
    def extract_vulnerabilities_from_text(self, text: str) -> List[Dict]:
        """Extract vulnerability info from plain text when JSON parsing fails"""
        vulnerabilities = []
        verbose_print(f"extract_vulnerabilities_from_text called (text length: {len(text) if text is not None else 0})", self.verbose)

        blocks = re.split(r'(?:\{|\}|\[|\])', text)
        verbose_print(f"Split text into {len(blocks)} blocks for pattern matching", self.verbose)
        
        for block in blocks:
            vuln = {}
            for pattern, key in RESPONSE_PARSER_PATTERNS:
                match = re.search(pattern, block)
                if match:
                    value = match.group(1).strip().strip('"')
                    vuln[key] = value
                    verbose_print(f"Pattern matched for key '{key}': {value}", self.verbose)
            
            if vuln and 'vulnerability_type' in vuln:
                verbose_print(f"Found vulnerability block, raw data: {vuln}", self.verbose)
                vulnerabilities.append(self.normalize_vulnerability(vuln))
        
        return vulnerabilities
    
    def parse_json_response(self, response_text) -> List[Dict]:
        """Parse JSON response from AI, with fallback to text extraction"""
        try:
            if response_text is None:
                verbose_print("Response is None", self.verbose)
                return []
            
            verbose_print("parse_json_response start", self.verbose)
            if isinstance(response_text, dict):
                verbose_print("Response is already a dict, extracting 'response' field", self.verbose)
                response_text = response_text.get('response', response_text)
            
            if isinstance(response_text, list):
                verbose_print(f"Response is already a parsed list with {len(response_text)} items", self.verbose)
                validated_vulns = []
                for vuln in response_text:
                    if isinstance(vuln, dict):
                        if self.validate_vulnerability(vuln):
                            normalized = self.normalize_vulnerability(vuln)
                            validated_vulns.append(normalized)
                            verbose_print(f"Validated vulnerability: {normalized['vulnerability_type']} in {normalized['file']}", self.verbose)
                        else:
                            verbose_print(f"Vulnerability failed validation: {vuln}", self.verbose)
                verbose_print(f"Successfully validated {len(validated_vulns)} vulnerabilities from list", self.verbose)
                return validated_vulns
            
            response_text = str(response_text)
            verbose_print(f"Processing response text (length: {len(response_text)} characters)", self.verbose)
            
            try:
                parsed = json.loads(response_text)
                verbose_print("Successfully parsed as direct JSON", self.verbose)
                
                if isinstance(parsed, list):
                    verbose_print(f"Parsed JSON is a list with {len(parsed)} items", self.verbose)
                    validated_vulns = []
                    for vuln in parsed:
                        if isinstance(vuln, dict) and self.validate_vulnerability(vuln):
                            normalized = self.normalize_vulnerability(vuln)
                            validated_vulns.append(normalized)
                    return validated_vulns
                elif isinstance(parsed, dict):
                    for key in ['vulnerabilities', 'results', 'findings', 'response']:
                        if key in parsed and isinstance(parsed[key], list):
                            verbose_print(f"Found vulnerabilities in '{key}' field", self.verbose)
                            validated_vulns = []
                            for vuln in parsed[key]:
                                if isinstance(vuln, dict) and self.validate_vulnerability(vuln):
                                    normalized = self.normalize_vulnerability(vuln)
                                    validated_vulns.append(normalized)
                            return validated_vulns
                    if self.validate_vulnerability(parsed):
                        return [self.normalize_vulnerability(parsed)]
            except json.JSONDecodeError:
                verbose_print("Direct JSON parsing failed, trying to extract JSON block", self.verbose)
            
            json_block_match = re.search(r'```json\s*(\[.*?\])\s*```', response_text, re.DOTALL)
            if not json_block_match:
                json_block_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if not json_block_match:
                json_block_match = re.search(r'\[\s*\{.*?\}\s*\]', response_text, re.DOTALL)
            if not json_block_match:
                json_block_match = re.search(r'\{\s*"vulnerabilities"\s*:\s*\[.*?\]\s*\}', response_text, re.DOTALL)
            
            if json_block_match:
                json_str = json_block_match.group(1) if json_block_match.lastindex else json_block_match.group(0)
                verbose_print(f"Extracted JSON block (length: {len(json_str)})", self.verbose)
                
                try:
                    parsed_data = json.loads(json_str)
                    verbose_print(f"Parsed extracted JSON block type: {type(parsed_data)}", self.verbose)
                    validated_vulns = []
                    
                    if isinstance(parsed_data, list):
                        vulnerabilities = parsed_data
                    elif isinstance(parsed_data, dict):
                        vulnerabilities = parsed_data.get('vulnerabilities', parsed_data.get('results', parsed_data.get('findings', [])))
                    else:
                        vulnerabilities = []
                    
                    for vuln in vulnerabilities:
                        if isinstance(vuln, dict) and self.validate_vulnerability(vuln):
                            normalized = self.normalize_vulnerability(vuln)
                            validated_vulns.append(normalized)
                            verbose_print(f"Validated vulnerability: {normalized['vulnerability_type']} in {normalized['file']}", self.verbose)
                    
                    verbose_print(f"Successfully extracted {len(validated_vulns)} vulnerabilities from JSON block", self.verbose)
                    return validated_vulns
                except json.JSONDecodeError as e:
                    verbose_print(f"JSON parsing failed: {e}", self.verbose)
                    verbose_print("Attempting sanitize and retry on extracted JSON block", self.verbose)
                    try:
                        sanitized = re.sub(r'\\\\"', '"', json_str)
                        _ = json.loads(sanitized)
                        verbose_print("Sanitized JSON parsed successfully after fallback", self.verbose)
                    except Exception:
                        verbose_print("Sanitization retry failed", self.verbose)
                        repaired = self._repair_and_extract(response_text)
            if repaired:
                return repaired

            verbose_print("All JSON parsing attempts failed, falling back to text extraction", self.verbose)
            return self.extract_vulnerabilities_from_text(response_text)
            
        except Exception as e:
            verbose_print(f"Error in parse_json_response: {e}", self.verbose)
            import traceback
            verbose_print(f"Traceback: {traceback.format_exc()}", self.verbose)
            return []

    def _repair_and_extract(self, text) -> List[Dict]:
        """Recover findings from malformed-but-repairable JSON via ``json_repair``.

        Unlike :meth:`extract_vulnerabilities_from_text`, this preserves each
        object's structured fields, so ``cvss_vector`` survives and
        :meth:`normalize_vulnerability` can still derive the real severity (the
        text fallback drops CVSS and labels everything "info"). Returns ``[]`` if
        ``json_repair`` is unavailable or nothing usable is recovered.
        """
        if not text:
            return []
        try:
            import json_repair
        except ImportError:
            verbose_print("json_repair not installed; skipping JSON repair", self.verbose)
            return []
        try:
            data = json_repair.loads(str(text))
        except Exception as e:
            verbose_print(f"json_repair failed: {e}", self.verbose)
            return []
        if isinstance(data, dict):
            for key in ("vulnerabilities", "results", "findings", "response"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            return []
        recovered = []
        for vuln in data:
            if isinstance(vuln, dict) and self.validate_vulnerability(vuln):
                recovered.append(self.normalize_vulnerability(vuln))
        if recovered:
            verbose_print(f"json_repair recovered {len(recovered)} finding(s)", self.verbose)
        return recovered

    def validate_vulnerability(self, vulnerability: Dict) -> bool:
        """Validate that a vulnerability dict has the minimum usable fields.

        A finding is accepted when it has a description and points at a place
        (``file``/``location``/``line``). A missing ``title`` is NOT a reason to
        reject — models sometimes omit it, and a sensible title is derived from
        the description in :meth:`normalize_vulnerability`. (Previously a missing
        title silently discarded real findings.)
        """
        verbose_print(f"Validating vulnerability keys: {list(vulnerability.keys())}", self.verbose)

        has_file = (vulnerability.get('file') or
                    vulnerability.get('location') or
                    vulnerability.get('line'))

        has_description = vulnerability.get('description')

        if not has_file:
            verbose_print(f"Vulnerability missing file/location/line field -- keys present: {list(vulnerability.keys())}", self.verbose)
            return False
        if not has_description:
            verbose_print(f"Vulnerability missing description field -- keys present: {list(vulnerability.keys())}", self.verbose)
            return False

        return True
    
    def normalize_vulnerability(self, vulnerability: Dict) -> Dict:
        """Normalize vulnerability dict to ensure consistent format"""
        verbose_print(f"Normalizing vulnerability, incoming keys: {list(vulnerability.keys())}", self.verbose)

        vuln_type = (vulnerability.get('vulnerability_type') or
                    vulnerability.get('title') or
                    vulnerability.get('vulnerability') or
                    vulnerability.get('issue'))
        if not vuln_type:
            vuln_type = _derive_title_from_description(vulnerability.get('description', ''))
            verbose_print(f"Derived title from description: {vuln_type}", self.verbose)

        file_location = vulnerability.get('file') or vulnerability.get('location') or 'Unknown'

        # Resolve the vulnerable line span from 'line' first (the new schema
        # field: "8" or "6-7"), else fall back to whatever is in 'location'.
        span = parse_line_span(vulnerability.get('line'))
        if span is None:
            span = parse_line_span(vulnerability.get('location'))
        if span is None:
            span = parse_line_span(vulnerability.get('line_number'))
        line_start, line_end = span if span else (0, 0)

        # Human-readable location string for display (report/UI).
        if line_start:
            location_display = f"line {line_start}" if line_start == line_end else f"lines {line_start}-{line_end}"
        else:
            location_display = vulnerability.get('location', '')

        normalized = {
            'vulnerability_type': vuln_type,
            'file': file_location,
            'line_number': line_start,
            'line_end': line_end,
            'location': location_display,
            'code_snippet': vulnerability.get('code_snippet', ''),
            'description': vulnerability.get('description', 'No description'),
            'severity': vulnerability.get('severity', 'Medium')
        }

        if 'category' in vulnerability:
            normalized['category'] = vulnerability['category']
        if 'cvss_vector' in vulnerability:
            normalized['cvss_vector'] = vulnerability['cvss_vector']
        if 'impact' in vulnerability:
            normalized['impact'] = vulnerability['impact']
        if 'cwe' in vulnerability:
            normalized['cwe'] = vulnerability['cwe']
        if 'owasp_mobile' in vulnerability:
            normalized['owasp_mobile'] = vulnerability['owasp_mobile']
        if 'exploitation' in vulnerability:
            normalized['exploitation'] = vulnerability['exploitation']
        if 'recommendation' in vulnerability:
            normalized['recommendation'] = vulnerability['recommendation']

        if normalized['code_snippet']:
            normalized['code_snippet'] = normalized['code_snippet'].replace('\\"', '"')
            if '<' in normalized['code_snippet']:
                normalized['code_snippet'] = re.sub(r'\s+', ' ', normalized['code_snippet'])

        severity_upper = normalized['severity'].upper() if normalized['severity'] else 'MEDIUM'
        if 'CRITICAL' in severity_upper:
            normalized['severity'] = 'Critical'
        elif 'HIGH' in severity_upper:
            normalized['severity'] = 'High'
        elif 'MEDIUM' in severity_upper:
            normalized['severity'] = 'Medium'
        elif 'LOW' in severity_upper:
            normalized['severity'] = 'Low'
        elif 'INFO' in severity_upper:  # matches "Info" and "Informational"
            normalized['severity'] = 'Informational'
        else:
            normalized['severity'] = 'Medium'

        cvss_vector = normalized.get('cvss_vector')
        if cvss_vector:
            computed_severity, computed_score = severity_from_vector(cvss_vector)
            if computed_severity is not None:
                normalized['severity'] = computed_severity
                normalized['cvss_score'] = computed_score
                verbose_print(
                    f"Severity derived from CVSS vector {cvss_vector!r}: "
                    f"score={computed_score}, severity={computed_severity}", self.verbose)
            else:
                verbose_print(
                    f"Invalid CVSS vector {cvss_vector!r}; keeping word-based "
                    f"severity fallback {normalized['severity']!r}", self.verbose)
                normalized.pop('cvss_vector', None)

        verbose_print(f"Normalized vulnerability result: {{'vulnerability_type': normalized['vulnerability_type'], 'file': normalized['file'], 'severity': normalized['severity']}}", self.verbose)
        return normalized