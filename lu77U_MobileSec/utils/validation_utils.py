"""Input validation helpers for lu77U-MobileSec"""

import re
from typing import List, Set, Optional
from ..config.constants import DEFAULT_STRING_PREFIXES, DEFAULT_STRING_EXACT_MATCHES, FRAMEWORK_VALIDATION_PATTERNS
from .verbose import verbose_print

def _check_against_exclusions(value: str, exact_matches: Set[str], prefixes: List[str], patterns: Optional[List[str]] = None, verbose: bool = False) -> bool:
    """Helper to check if a value matches exclusion criteria. Returns True if user-defined."""
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
    """Check if a string is likely user-defined (not default Android framework strings)"""
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
    """Determine if a string is likely user-defined vs framework string"""
    verbose_print(f"is_likely_user_defined_name called for: '{name}'", verbose)
    result = _check_against_exclusions(name, exact_matches_to_remove, prefixes_to_remove, None, verbose)
    verbose_print(f"Name appears to be user-defined: {result}", verbose)
    return result

def clean_string_for_analysis(text: str, verbose: bool = False) -> str:
    """Clean and prepare string for analysis"""
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
    """Extract code blocks from markdown-formatted text"""
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
    """Helper to create consistent summary structure for content"""
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
    """Analyze input consistency for debugging AI responses"""
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