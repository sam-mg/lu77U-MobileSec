#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.validation_utils

Purpose:
    Decide what is worth analysing. The dominant problem in APK analysis is volume: a decompiled app is mostly framework and library code, and feeding that to a model wastes both budget and the model's attention. These helpers separate developer-authored content from vendor noise.

Responsibilities:
    Apply the shared exclusion cascade to strings and identifiers, clean text for prompt inclusion, extract fenced code blocks from model output, and report how complete a Flutter input set is.

Dependencies:
    re, ..config.constants for the exclusion tables, .verbose.

Implementation notes:
    The exclusion tables live in config rather than here so that adding a newly-noisy library is a data change, not a code change.

Security considerations:
    Exclusion is a heuristic, and a false positive means real application code is never examined. The tables are therefore built from library prefixes that an application would not plausibly use, and are deliberately conservative: it is better to spend tokens on framework noise than to silently skip a vulnerable class.
"""

import re
from typing import List, Set, Optional
from ..config.constants import DEFAULT_STRING_PREFIXES, DEFAULT_STRING_EXACT_MATCHES, FRAMEWORK_VALIDATION_PATTERNS
from .verbose import verbose_print

def _check_against_exclusions(value: str, exact_matches: Set[str], prefixes: List[str], patterns: Optional[List[str]] = None, verbose: bool = False) -> bool:
    """
    Purpose:
        Shared three-stage exclusion test: reject exact matches, then known prefixes, then regular-expression patterns.

    Parameters:
        value: Candidate string or identifier. Surrounding whitespace is ignored.
        exact_matches: Values excluded outright.
        prefixes: Prefixes whose presence excludes the value.
        patterns: Optional regular expressions, matched case-insensitively and anchored at the start.
        verbose: Traces which rule fired.

    Returns:
        True when the value survived every stage and should be treated as user-defined.

    Complexity:
        O(p + k) where p is the prefix count and k the pattern count, times the cost of each match.

    Implementation notes:
        The stages run cheapest-first: a set lookup, then prefix comparisons, then regular expressions. Most values are rejected by the first two, so the expensive stage runs rarely. re.match rather than re.search anchors each pattern at the start, so a pattern describes how an identifier begins rather than matching anywhere inside it. A pattern intended to match mid-string must say so explicitly. Empty and whitespace-only values return False -- treated as excluded -- because they carry nothing to analyse.
    """
    if not value or len(value.strip()) == 0:
        verbose_print("Empty or whitespace-only string, returning False", verbose)
        return False
    
    value = value.strip()
    
    if value in exact_matches:
        verbose_print(f"Value '{value}' found in exact matches, returning False", verbose)
        return False
    
    for prefix in prefixes:
        if value.startswith(prefix):
            verbose_print(f"Value '{value}' starts with prefix '{prefix}', returning False", verbose)
            return False
    
    if patterns:
        for pattern in patterns:
            if re.match(pattern, value, re.IGNORECASE):
                verbose_print(f"Value '{value}' matches pattern '{pattern}', returning False", verbose)
                return False
    
    return True

def is_likely_user_defined_string(string_value: str, verbose: bool = False) -> bool:
    """
    Purpose:
        Judge whether a resource string was written by the app developer rather than supplied by a framework, so that strings.xml can be filtered down to the handful that matter.

    Parameters:
        string_value: The resource name, not its text.
        verbose: Traces the decision.

    Returns:
        True when the name looks developer-authored.

    Complexity:
        O(1) against the fixed exclusion tables.

    Implementation notes:
        Judged by resource name, not by content, because AndroidX and Material names follow recognisable conventions while their translated values do not.

    Security considerations:
        A false positive here drops a string from analysis. Since hardcoded secrets are frequently found in strings.xml, the exclusion tables must stay narrow enough that a developer-chosen name is never mistaken for a framework one.
    """
    result = _check_against_exclusions(
        string_value, 
        DEFAULT_STRING_EXACT_MATCHES, 
        DEFAULT_STRING_PREFIXES,
        FRAMEWORK_VALIDATION_PATTERNS,
        verbose
    )
    verbose_print(f"String appears to be user-defined: {result}", verbose)
    return result

def is_likely_user_defined_name(name: str, prefixes_to_remove: List[str], exact_matches_to_remove: set, verbose: bool = False) -> bool:
    """
    Purpose:
        Same judgement as is_likely_user_defined_string, but with the exclusion tables supplied by the caller, for identifiers whose noise differs per context -- class names, layout names, method names.

    Parameters:
        name: Identifier to judge.
        prefixes_to_remove: Prefixes that mark a vendor identifier.
        exact_matches_to_remove: Identifiers excluded outright.
        verbose: Traces the decision.

    Returns:
        True when the identifier looks developer-authored.

    Complexity:
        O(p) in the number of prefixes supplied.

    Implementation notes:
        No pattern stage is used here. Callers pass literal prefixes and exact names, which keeps per-context tables cheap to write and impossible to get wrong with a stray regular-expression metacharacter.
    """
    verbose_print(f"is_likely_user_defined_name called for: '{name}'", verbose)
    result = _check_against_exclusions(name, exact_matches_to_remove, prefixes_to_remove, None, verbose)
    verbose_print(f"Name appears to be user-defined: {result}", verbose)
    return result

def clean_string_for_analysis(text: str, verbose: bool = False) -> str:
    """
    Purpose:
        Normalise text before it is embedded in a prompt or a report field.

    Parameters:
        text: Text to clean.
        verbose: Traces each stage and the resulting length.

    Returns:
        The cleaned text; an empty string for empty input.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Two passes, in this order: collapse whitespace, then strip control characters. Whitespace first means newlines and tabs become spaces before the control-character pass runs, so the pass does not delete them and run words together.

    Security considerations:
        Removing control characters keeps ANSI escape sequences and NUL bytes recovered from an APK out of terminal output and report fields. It is not an HTML escape -- markup is untouched, and the consumer must still escape for its own destination.
    """
    verbose_print(f"clean_string_for_analysis called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning empty string", verbose)
        return ""
    
    verbose_print("Removing excessive whitespace and trimming", verbose)
    original_len = len(text)
    text = re.sub(r'\s+', ' ', text.strip())
    verbose_print(f"Whitespace removed: {original_len} -> {len(text)}", verbose)
    
    verbose_print("Removing control characters", verbose)
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    verbose_print(f"After control char removal length: {len(text)}", verbose)
    
    verbose_print(f"String cleaning completed, result length: {len(text)}", verbose)
    return text

def extract_code_blocks(text: str, verbose: bool = False) -> List[str]:
    """
    Purpose:
        Pull fenced code blocks out of model output, for responses that wrap a payload in Markdown despite being asked for raw content.

    Parameters:
        text: Model response text.
        verbose: Reports how many blocks were found and kept.

    Returns:
        The content of each non-empty block, in document order, without the fences or the language tag.

    Raises:
        TypeError: When text is None. Unlike its neighbours this function does not guard the empty case, so None reaches re.findall.

    Complexity:
        O(n) in text length.

    Implementation notes:
        The language tag after the opening fence is matched but not captured, so a block introduced as json or java yields just its body. DOTALL lets a block span lines, and the lazy quantifier stops at the first closing fence rather than swallowing every block into one.

    Known limitations:
        The opening fence must be followed by a newline, so a single-line fenced span is not matched. Nested fences are not handled.
    """
    verbose_print(f"extract_code_blocks called (length={len(text) if text else 0})", verbose)
    
    pattern = r'```(?:\w+)?\n(.*?)```'
    verbose_print("Searching for code block patterns", verbose)
    matches = re.findall(pattern, text, re.DOTALL)
    verbose_print(f"Found {len(matches)} potential code blocks", verbose)
    cleaned_blocks = []
    for i, match in enumerate(matches, start=1):
        cleaned = match.strip()
        verbose_print(f"Processing code block #{i}, length after strip: {len(cleaned)}", verbose)
        if cleaned:
            cleaned_blocks.append(cleaned)
            verbose_print(f"Appended cleaned block #{i}", verbose)
    
    verbose_print(f"Extracted {len(cleaned_blocks)} non-empty code blocks", verbose)
    return cleaned_blocks

def _create_content_summary(content, content_type: str, verbose: bool = False):
    """
    Purpose:
        Describe one input artifact -- whether it is present, how large it is, and a couple of type-specific facts -- for the consistency report.

    Parameters:
        content: A string, a dict of artifacts, or None.
        content_type: Which artifact this is, selecting the type-specific fields.
        verbose: Traces the computed summary.

    Returns:
        A dict that always carries "available". When available is False that is the only key, so callers must check it before reading any other.

    Complexity:
        O(n) in total content length.

    Implementation notes:
        The blutter_files branch replaces "size" with "total_size" -- deleting the original key -- because for a collection the interesting number is the aggregate across files, and leaving both would invite a caller to read the wrong one. The manifest and pubspec branches test for substrings rather than parsing, because this function only reports how complete the input is; a parse failure here would be a confusing reason for a summary to fail.
    """
    verbose_print(f"_create_content_summary called for type '{content_type}'", verbose)
    if not content:
        verbose_print(f"No {content_type} content available", verbose)
        return {'available': False}
    
    verbose_print(f"{content_type.capitalize()} content available", verbose)
    summary = {
        'available': True,
        'size': len(content) if isinstance(content, str) else sum(len(str(c)) for c in content.values())
    }
    verbose_print(f"Computed base summary size: {summary['size']}", verbose)
    
    if content_type == 'blutter_files' and isinstance(content, dict):
        summary.update({
            'file_count': len(content),
            'file_types': list(content.keys()),
            'total_size': summary['size']
        })
        del summary['size']
        verbose_print(f"Blutter files summary: {summary}", verbose)
    elif content_type == 'manifest' and isinstance(content, str):
        summary.update({
            'has_permissions': 'uses-permission' in content.lower(),
            'has_activities': 'activity' in content.lower()
        })
        verbose_print(f"Manifest summary: {summary}", verbose)
    elif content_type == 'pubspec' and isinstance(content, str):
        summary.update({
            'has_dependencies': 'dependencies:' in content.lower(),
            'line_count': len(content.split('\n'))
        })
        verbose_print(f"Pubspec summary: {summary}", verbose)
    
    return summary

def analyze_input_consistency(blutter_files: dict = None, manifest_content: str = None, pubspec_content: str = None, framework_type: str = 'flutter', verbose: bool = False) -> dict:
    """
    Purpose:
        Report whether the inputs gathered for a Flutter analysis are complete and internally consistent, so that a thin result can be explained by missing input rather than read as a clean bill of health.

    Parameters:
        blutter_files: Decompiled Dart artifacts keyed by name.
        manifest_content: AndroidManifest.xml text.
        pubspec_content: pubspec.yaml text.
        framework_type: Framework under analysis; only "flutter" is inspected.
        verbose: Traces every stage.

    Returns:
        A dict with framework_type, input_summary, consistency_checks and recommendations. On failure the same shape plus an "error" key, so callers never have to handle a None.

    Complexity:
        O(n) in the combined size of the inputs, which are concatenated once for the indicator scan.

    Implementation notes:
        A non-Flutter framework returns the empty skeleton immediately. The checks below encode Flutter-specific expectations, and applying them to a React Native app would produce confident nonsense. Completeness is weighted 40/30/30 rather than counted, because the Blutter output is the analysis and the other two are context: having the manifest and pubspec but no decompiled Dart is not two-thirds of a Flutter analysis. Indicator confidence and completeness are reported separately rather than combined into one score, since they answer different questions -- "is this really a Flutter app" and "did we manage to collect enough". The whole body is wrapped because this is advisory reporting. A failure to describe the inputs must not abort the analysis of those inputs, so the error is returned in the normal result shape with a recommendation attached.

    Known limitations:
        Indicators are counted by substring over the concatenated inputs, so a non-Flutter app that merely mentions Flutter scores as one.
    """
    verbose_print(f"analyze_input_consistency called for framework: {framework_type}", verbose)
    verbose_print(f"Inputs lengths: blutter_files={len(blutter_files) if blutter_files else 0}, manifest={len(manifest_content) if manifest_content else 0}, pubspec={len(pubspec_content) if pubspec_content else 0}", verbose)
    
    try:
        analysis = {
            'framework_type': framework_type,
            'input_summary': {},
            'consistency_checks': {},
            'recommendations': []
        }
        
        if framework_type != 'flutter':
            verbose_print(f"Non-Flutter framework type: {framework_type} - limited analysis", verbose)
            return analysis
        
        verbose_print("Analyzing input data availability", verbose)
        input_summary = {
            'blutter_files': _create_content_summary(blutter_files, 'blutter_files', verbose),
            'manifest': _create_content_summary(manifest_content, 'manifest', verbose),
            'pubspec': _create_content_summary(pubspec_content, 'pubspec', verbose)
        }
        analysis['input_summary'] = input_summary
        
        verbose_print("Performing consistency checks", verbose)
        total_content = ""
        if blutter_files:
            total_content += " ".join(str(content) for content in blutter_files.values())
        if manifest_content:
            total_content += " " + manifest_content
        if pubspec_content:
            total_content += " " + pubspec_content

        verbose_print(f"Total content length for indicator analysis: {len(total_content)}", verbose)

        indicators = ['flutter', 'dart', 'libflutter', 'io.flutter']
        flutter_indicators = sum(1 for indicator in indicators if indicator in total_content.lower())
        verbose_print(f"Found {flutter_indicators} Flutter indicators (indicators={indicators})", verbose)

        completeness_weights = {
            'blutter_files': 40,
            'manifest': 30,
            'pubspec': 30
        }
        data_completeness = sum(
            weight for key, weight in completeness_weights.items()
            if input_summary.get(key, {}).get('available')
        )
        verbose_print(f"Total data completeness: {data_completeness}% (weights={completeness_weights})", verbose)

        analysis['consistency_checks'] = {
            'flutter_indicators': {
                'count': flutter_indicators,
                'confidence': 'high' if flutter_indicators >= 3 else 'medium' if flutter_indicators >= 2 else 'low'
            },
            'data_completeness': {
                'percentage': data_completeness,
                'level': 'complete' if data_completeness >= 80 else 'partial' if data_completeness >= 50 else 'minimal'
            }
        }

        verbose_print("Generating recommendations", verbose)
        recommendations = []

        recommendation_checks = [
            (not input_summary.get('blutter_files', {}).get('available'),
             "Consider running Blutter decompilation for better Flutter analysis"),
            (not input_summary.get('manifest', {}).get('available'),
             "Android manifest analysis would improve vulnerability detection"),
            (not input_summary.get('pubspec', {}).get('available'),
             "Pubspec.yaml analysis would help identify dependency vulnerabilities"),
            (analysis['consistency_checks']['flutter_indicators']['confidence'] == 'low',
             "Low Flutter indicators - verify this is actually a Flutter app"),
            (data_completeness < 50,
             "Limited input data may result in incomplete vulnerability analysis")
        ]

        recommendations = [msg for condition, msg in recommendation_checks if condition]
        verbose_print(f"Recommendations computed: {recommendations}", verbose)
        analysis['recommendations'] = recommendations

        verbose_print(f"Input consistency analysis completed with {len(recommendations)} recommendations", verbose)
        return analysis
        
    except Exception as e:
        verbose_print(f"Error in input consistency analysis: {e}", verbose)
        return {
            'error': f"Error in input consistency analysis: {e}",
            'framework_type': framework_type,
            'input_summary': {},
            'consistency_checks': {},
            'recommendations': ['Analysis failed - check input data']
        }
