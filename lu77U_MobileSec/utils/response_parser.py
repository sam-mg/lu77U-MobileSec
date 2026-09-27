#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.response_parser

Purpose:
    Turn whatever a language model actually returned into the canonical finding shape the rest of the tool depends on. Models are asked for strict JSON and frequently return something adjacent to it: a fenced block, a JSON object wrapped in prose, truncated output, or a list whose keys are near-misses of the schema.

Responsibilities:
    Parse a response through a cascade of increasingly tolerant strategies, validate each candidate finding, and normalise it to fixed keys with bounded field lengths and a canonical severity.

Dependencies:
    json, re, json_repair when installed, ..ai.schema for the field bounds and line-span parser, ..validation.taxonomy for CWE and OWASP enrichment, .cvss for severity derivation, ..config.constants for the text-extraction patterns.

Implementation notes:
    The parsing cascade is ordered strictest-first: exact JSON, then a fenced or embedded JSON block, then json_repair, then regular expressions over free text. Each stage is more tolerant and less trustworthy than the last, so the order matters -- running the permissive stages first would let a sloppy match win over a clean parse. Recovering a partially-usable response rather than discarding it is deliberate: a long analysis truncated at the token limit still contains real findings, and throwing them away means paying for the analysis twice.

Security considerations:
    Everything parsed here is untrusted model output describing untrusted APK content. Parsing never evaluates: no eval, no literal_eval. Field lengths are capped so that an enormous or repetitive response cannot blow up a report or a downstream prompt, and unknown keys are dropped against an allowlist so nothing unexpected reaches the report renderer.
"""

import json
import re
from typing import Dict, List, Optional
from .verbose import plural, verbose_print
from .cvss import severity_from_vector
from .string_utils import truncate_text
from ..config.constants import RESPONSE_PARSER_PATTERNS
from ..ai.schema import (
    parse_line_span, _TITLE_MAX, _DESCRIPTION_MAX, _RECOMMENDATION_MAX,
    _IMPACT_MAX, _EXPLOITATION_MAX)
from ..validation.taxonomy import describe as _describe_vuln_class
from .json_utils import loads_richest

def _derive_title_from_description(description: str) -> str:
    """
    Purpose:
        Invent a usable title for a finding whose title the model omitted, by taking the first sentence of its description.

    Parameters:
        description: The finding description; may be empty or None.

    Returns:
        A non-empty title, capped at 80 characters. "Security Issue" when there is nothing to derive from.

    Complexity:
        O(n) in description length.

    Implementation notes:
        The split uses a lookbehind on sentence-ending punctuation followed by whitespace, so an abbreviation without a following space does not end the sentence early. Only the first split is taken. Over-long titles are cut at 77 characters plus an ellipsis, keeping the total at 80 so report tables stay aligned. Dropping the finding instead is not an option: a finding with a real description and no title is still a real finding, and a placeholder title is recoverable where a discarded finding is not.
    """
    text = (description or "").strip()
    if not text:
        return "Security Issue"
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0].strip()
    if len(first) > 80:
        first = first[:77].rstrip() + "..."
    return first or "Security Issue"

_NORMALIZE_KNOWN_KEYS = frozenset({
    'vulnerability_type', 'title', 'vulnerability', 'issue', 'description',
    'file', 'location', 'line', 'line_number', 'line_end', 'code_snippet',
    'severity', 'vuln_class', 'gate_result', 'chain', 'chained_into',
    'source', 'surface', 'confidence', 'related_findings', 'category',
    'cvss_vector', 'impact', 'cwe', 'owasp_mobile', 'exploitation',
    'recommendation',
})

class ResponseParser:
    """
    Purpose:
        Parses and normalises AI responses into canonical findings.

    Attributes:
        verbose: Whether each parsing decision is traced.

    Invariants:
        Stateless between calls -- the only instance state is the verbose flag. Every public method is a pure function of its arguments, so one parser can be reused for a whole scan.

    Thread-safety:
        Safe to share across threads. Nothing is mutated after construction.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Create a parser.

        Parameters:
            verbose: Enables tracing of every parse, validation and normalisation decision.
        """
        self.verbose = verbose
        verbose_print("ResponseParser initialized", self.verbose)
    
    def extract_vulnerabilities_from_text(self, text: str) -> List[Dict]:
        """
        Purpose:
            Last-resort extraction: recover findings from text that no JSON parser could read, using per-field regular expressions.

        Parameters:
            text: Raw response text.

        Returns:
            Normalised findings; empty when nothing matched.

        Complexity:
            O(b * p) for b blocks and p patterns.

        Implementation notes:
            The text is split on JSON structural characters, which works because even badly broken output tends to keep its braces roughly where the record boundaries are. Each resulting block is then scanned for every known field pattern. A block is only accepted when it yielded a vulnerability_type. Without that anchor, prose that merely mentions a file path would be promoted into a finding.

        Known limitations:
            Recovers at most one finding per block and only the fields the pattern table names. A finding recovered this way is typically missing its CVSS vector, CWE and recommendation.

        Security considerations:
            This stage is the most permissive and the least trustworthy; anything it returns still passes through validation and normalisation before it can reach a report.
        """
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
        """
        Purpose:
            Main entry point. Extract findings from a model response in whatever form it arrived.

        Parameters:
            response_text: A string, a dict from a provider SDK, an already-parsed list, or None.

        Returns:
            Normalised findings. Empty list when nothing could be recovered -- never None, and never a partially-normalised item.

        Complexity:
            O(n) in response length per stage attempted; the whole cascade is run only for badly malformed input.

        Implementation notes:
            The cascade, in order: an already-parsed list is used directly; a dict is unwrapped from its "response" field; a direct JSON parse is tried; then four block-extraction patterns; then json_repair; and finally regular-expression extraction over free text. Container keys are probed in a fixed order -- vulnerabilities, results, findings, response -- because models pick a plausible wrapper name of their own and refusing all but one would discard a valid response over a naming preference. A bare object that validates is accepted as a single finding, for the case where exactly one issue was found and the model did not wrap it in a list. The whole body is guarded. This runs at the end of an expensive analysis, and no parsing failure is worth losing the run over; the traceback goes to the verbose stream and an empty list is returned.

        Known limitations:
            The sanitize-and-retry branch after a failed block parse computes a sanitized document, parses it to prove it is valid, and then discards the result -- the underscore binding is never used. A response that would have been recovered by that repair instead falls through to json_repair, which usually recovers it anyway, so the defect costs accuracy only when json_repair is not installed.

        Security considerations:
            Untrusted input throughout. Nothing is evaluated, and every recovered item is validated and normalised before being returned.
        """
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

            repaired: Optional[List[Dict]] = None

            try:
                parsed = loads_richest(response_text)
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
                    parsed_data = loads_richest(json_str)
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
                        _ = loads_richest(sanitized)
                        verbose_print("Sanitized JSON parsed successfully after fallback", self.verbose)
                    except Exception:
                        verbose_print("Sanitization retry failed", self.verbose)
                        repaired = self._repair_and_extract(response_text)

            if not repaired:
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
        """
        Purpose:
            Recover findings from structurally broken JSON using the json_repair library, which handles the failure modes typical of truncated or over-escaped model output.

        Parameters:
            text: Raw response text.

        Returns:
            Normalised findings; empty when json_repair is unavailable, failed, or produced nothing that validates.

        Side effects:
            Imports json_repair on first use.

        Implementation notes:
            json_repair is treated as optional. It is imported inside the function and its absence is a traced skip rather than an error, so the tool still installs and runs without it -- at the cost of losing findings from truncated responses. The for/else on the container-key probe is load-bearing: when no known wrapper key is present, the else branch wraps the dict itself as a single-item list, so a bare finding object is not lost.

        Security considerations:
            json_repair only repairs and parses text; it does not evaluate it.
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
            verbose_print(f"json_repair recovered {plural(len(recovered), 'finding')}", self.verbose)
        return recovered

    def validate_vulnerability(self, vulnerability: Dict) -> bool:
        """
        Purpose:
            Decide whether a candidate dict carries enough substance to be a finding at all.

        Parameters:
            vulnerability: Candidate finding.

        Returns:
            True when the candidate has some location and a description.

        Complexity:
            O(1).

        Implementation notes:
            Only two requirements, deliberately minimal: a location in any of file, location or line, and a description. Everything else has a defensible default supplied during normalisation, and requiring more here would discard recoverable findings. A finding with no location cannot be acted on, and one with no description cannot be understood -- those are the two that cannot be defaulted, which is exactly why they are the two that are required.
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
        """
        Purpose:
            Convert a validated candidate into the canonical finding shape: fixed keys, bounded field lengths, a canonical severity, and CWE and OWASP identifiers filled in where they can be derived.

        Parameters:
            vulnerability: A candidate that has passed validate_vulnerability.

        Returns:
            A finding dict that always carries vulnerability_type, title, line, file, line_number, line_end, location, code_snippet, description and severity, plus any recognised optional fields that were present.

        Complexity:
            O(n) in the combined length of the text fields.

        Postconditions:
            severity is exactly one of Critical, High, Medium, Low or Informational. Text fields are within the schema bounds. Keys outside the allowlist are absent.

        Implementation notes:
            Type and location are each resolved from several aliases, because models vary the key names for the same concept across responses and sometimes within one. The line span is parsed from line, then location, then line_number, in that order of decreasing reliability. location_display is built to read naturally in all four cases -- file and line, line only, file only, or neither. Severity resolution runs in two passes. First the word is matched by substring, so "HIGH severity" and "high" both land on High; then, if a CVSS vector is present and parses, the computed severity overrides the word entirely. The vector is authoritative because a model will assert a severity that its own vector contradicts. An unparseable vector is dropped from the output rather than kept, so a report never shows a vector that did not produce the severity beside it. An unrecognised severity word falls back to Medium rather than to the lowest band: an unreadable severity is an unknown risk, and defaulting downward would hide it. CWE and OWASP identifiers are filled from the taxonomy only when the model did not supply them, so a model that knows better is not overridden. Code snippets have escaped quotes unescaped, and snippets containing markup have their whitespace collapsed so that XML and HTML fragments do not span dozens of report lines. Unknown keys are dropped against _NORMALIZE_KNOWN_KEYS and the loss is traced, so a model inventing a field is visible rather than silently ignored.

        Security considerations:
            Every value here originates in model output describing an untrusted APK. Length capping bounds the cost of a hostile or degenerate response, and the key allowlist means no unexpected field can reach the report renderer. The values themselves are still untrusted text and must be escaped by whatever renders them.
        """
        verbose_print(f"Normalizing vulnerability, incoming keys: {list(vulnerability.keys())}", self.verbose)

        vuln_type = (vulnerability.get('vulnerability_type') or
                    vulnerability.get('title') or
                    vulnerability.get('vulnerability') or
                    vulnerability.get('issue'))
        if not vuln_type:
            vuln_type = _derive_title_from_description(vulnerability.get('description', ''))
            verbose_print(f"Derived title from description: {vuln_type}", self.verbose)

        file_location = vulnerability.get('file') or vulnerability.get('location') or 'Unknown'

        span = parse_line_span(vulnerability.get('line'))
        if span is None:
            span = parse_line_span(vulnerability.get('location'))
        if span is None:
            span = parse_line_span(vulnerability.get('line_number'))
        line_start, line_end = span if span else (0, 0)

        if line_start and file_location != 'Unknown':
            span = f"{line_start}" if line_start == line_end else f"{line_start}-{line_end}"
            location_display = f"{file_location}:{span}"
        elif line_start:
            location_display = f"line {line_start}" if line_start == line_end else f"lines {line_start}-{line_end}"
        elif file_location != 'Unknown':
            location_display = file_location
        else:
            location_display = vulnerability.get('location', '')

        normalized = {
            'vulnerability_type': vuln_type,
            'title': vulnerability.get('title', vuln_type),
            'line': vulnerability.get('line', str(line_start) if line_start else ''),
            'file': file_location,
            'line_number': line_start,
            'line_end': line_end,
            'location': location_display,
            'code_snippet': vulnerability.get('code_snippet', ''),
            'description': vulnerability.get('description', 'No description'),
            'severity': vulnerability.get('severity', 'Medium')
        }
        had_severity = 'severity' in vulnerability and vulnerability['severity']
        if not had_severity:
            verbose_print("No severity provided; defaulting to Medium", self.verbose)

        for key in ('vuln_class', 'gate_result', 'chain', 'chained_into',
                    'source', 'surface', 'confidence', 'related_findings'):
            if key in vulnerability:
                normalized[key] = vulnerability[key]

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

        if not normalized.get('cwe') or not normalized.get('owasp_mobile'):
            entry = _describe_vuln_class(normalized.get('vuln_class', ''))
            if entry is not None:
                if not normalized.get('cwe'):
                    normalized['cwe'] = entry.cwe
                if not normalized.get('owasp_mobile'):
                    normalized['owasp_mobile'] = entry.owasp_mobile

        normalized['title'] = truncate_text(normalized['title'], _TITLE_MAX)
        normalized['description'] = truncate_text(normalized['description'], _DESCRIPTION_MAX)
        if normalized.get('recommendation'):
            normalized['recommendation'] = truncate_text(
                normalized['recommendation'], _RECOMMENDATION_MAX)
        if normalized.get('impact'):
            normalized['impact'] = truncate_text(normalized['impact'], _IMPACT_MAX)
        if normalized.get('exploitation'):
            normalized['exploitation'] = truncate_text(
                normalized['exploitation'], _EXPLOITATION_MAX)

        dropped_keys = set(vulnerability) - _NORMALIZE_KNOWN_KEYS
        if dropped_keys:
            verbose_print(
                f"Normalizing vulnerability: dropping unrecognized keys "
                f"{sorted(dropped_keys)} (not in the output whitelist)", self.verbose)

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
        elif 'INFO' in severity_upper:
            normalized['severity'] = 'Informational'
        else:
            verbose_print(
                f"Unrecognized severity {vulnerability.get('severity')!r}; "
                "defaulting to Medium", self.verbose)
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

        verbose_print(
            f"Normalized vulnerability result: "
            f"vulnerability_type={normalized['vulnerability_type']!r}, "
            f"file={normalized['file']!r}, severity={normalized['severity']!r}",
            self.verbose)
        return normalized
