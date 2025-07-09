#!/usr/bin/env python3
"""
Input validation helpers for lu77U-MobileSec
"""

import re
from typing import List
from ...constants.file_patterns import DEFAULT_STRING_PREFIXES, DEFAULT_STRING_EXACT_MATCHES


def is_likely_user_defined_string(string_value: str) -> bool:
    """
    Check if a string is likely user-defined (not default Android framework strings)
    
    Args:
        string_value: The string to check
        
    Returns:
        bool: True if likely user-defined, False if likely framework string
    """
    if not string_value or len(string_value.strip()) == 0:
        return False
    
    string_value = string_value.strip()
    
    # Check exact matches first
    if string_value in DEFAULT_STRING_EXACT_MATCHES:
        return False
    
    # Check prefixes
    for prefix in DEFAULT_STRING_PREFIXES:
        if string_value.startswith(prefix):
            return False
    
    # Additional filters for obvious framework strings
    framework_patterns = [
        r'^android\.',
        r'^com\.android\.',
        r'^androidx\.',
        r'^com\.google\.',
        r'^\$\{.*\}$',  # Variable references
        r'^@\w+/',       # Resource references
        r'^\d+$',        # Pure numbers
        r'^[a-f0-9]{8,}$', # Hex strings (likely IDs)
    ]
    
    for pattern in framework_patterns:
        if re.match(pattern, string_value, re.IGNORECASE):
            return False
    
    # If it passes all filters, it's likely user-defined
    return True


def is_likely_user_defined_string(name: str, prefixes_to_remove: List[str], 
                                exact_matches_to_remove: set) -> bool:
    """Determine if a string is likely user-defined vs framework string"""
    if name in exact_matches_to_remove:
        return False
    
    for prefix in prefixes_to_remove:
        if name.startswith(prefix):
            return False
    
    return True


def validate_apk_path(apk_path: str) -> tuple[bool, str]:
    """
    Validate APK file path
    
    Args:
        apk_path: Path to APK file
        
    Returns:
        tuple: (is_valid, error_message)
    """
    import os
    
    if not apk_path:
        return False, "APK path is empty"
    
    if not os.path.exists(apk_path):
        return False, f"APK file not found: {apk_path}"
    
    if not apk_path.lower().endswith('.apk'):
        return False, f"File is not an APK: {apk_path}"
    
    if not os.access(apk_path, os.R_OK):
        return False, f"Cannot read APK file: {apk_path}"
    
    return True, ""


def clean_string_for_analysis(text: str) -> str:
    """
    Clean and prepare string for analysis
    
    Args:
        text: Input text to clean
        
    Returns:
        str: Cleaned text
    """
    if not text:
        return ""
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text.strip())
    
    # Remove control characters
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    return text


def extract_code_blocks(text: str) -> List[str]:
    """
    Extract code blocks from markdown-formatted text
    
    Args:
        text: Text potentially containing code blocks
        
    Returns:
        List[str]: List of extracted code blocks
    """
    # Pattern to match code blocks with optional language specification
    pattern = r'```(?:\w+)?\n(.*?)```'
    matches = re.findall(pattern, text, re.DOTALL)
    
    # Clean up the extracted code
    cleaned_blocks = []
    for match in matches:
        cleaned = match.strip()
        if cleaned:
            cleaned_blocks.append(cleaned)
    
    return cleaned_blocks


def analyze_input_consistency(
    blutter_files: dict = None,
    manifest_content: str = None,
    pubspec_content: str = None,
    framework_type: str = 'flutter'
) -> dict:
    """
    Analyze input consistency for debugging AI responses
    
    Args:
        blutter_files: Dictionary of Blutter decompiled files
        manifest_content: Android manifest content
        pubspec_content: Pubspec.yaml content  
        framework_type: Framework type being analyzed
        
    Returns:
        Dictionary with consistency analysis results
    """
    try:
        analysis = {
            'framework_type': framework_type,
            'input_summary': {},
            'consistency_checks': {},
            'recommendations': []
        }
        
        # Analyze input data availability
        input_summary = {}
        
        if framework_type == 'flutter':
            # Flutter-specific input analysis
            if blutter_files:
                input_summary['blutter_files'] = {
                    'available': True,
                    'file_count': len(blutter_files),
                    'file_types': list(blutter_files.keys()),
                    'total_size': sum(len(str(content)) for content in blutter_files.values())
                }
            else:
                input_summary['blutter_files'] = {'available': False}
            
            if manifest_content:
                input_summary['manifest'] = {
                    'available': True,
                    'size': len(manifest_content),
                    'has_permissions': 'uses-permission' in manifest_content.lower(),
                    'has_activities': 'activity' in manifest_content.lower()
                }
            else:
                input_summary['manifest'] = {'available': False}
            
            if pubspec_content:
                input_summary['pubspec'] = {
                    'available': True,
                    'size': len(pubspec_content),
                    'has_dependencies': 'dependencies:' in pubspec_content.lower(),
                    'line_count': len(pubspec_content.split('\n'))
                }
            else:
                input_summary['pubspec'] = {'available': False}
        
        analysis['input_summary'] = input_summary
        
        # Perform consistency checks
        consistency_checks = {}
        
        if framework_type == 'flutter':
            # Check Flutter app indicators
            flutter_indicators = 0
            total_content = ""
            
            if blutter_files:
                total_content += " ".join(str(content) for content in blutter_files.values())
            if manifest_content:
                total_content += " " + manifest_content
            if pubspec_content:
                total_content += " " + pubspec_content
            
            # Count Flutter indicators
            if 'flutter' in total_content.lower():
                flutter_indicators += 1
            if 'dart' in total_content.lower():
                flutter_indicators += 1
            if 'libflutter' in total_content.lower():
                flutter_indicators += 1
            if 'io.flutter' in total_content.lower():
                flutter_indicators += 1
            
            consistency_checks['flutter_indicators'] = {
                'count': flutter_indicators,
                'confidence': 'high' if flutter_indicators >= 3 else 'medium' if flutter_indicators >= 2 else 'low'
            }
            
            # Check data completeness
            data_completeness = 0
            if input_summary.get('blutter_files', {}).get('available'):
                data_completeness += 40
            if input_summary.get('manifest', {}).get('available'):
                data_completeness += 30
            if input_summary.get('pubspec', {}).get('available'):
                data_completeness += 30
            
            consistency_checks['data_completeness'] = {
                'percentage': data_completeness,
                'level': 'complete' if data_completeness >= 80 else 'partial' if data_completeness >= 50 else 'minimal'
            }
        
        analysis['consistency_checks'] = consistency_checks
        
        # Generate recommendations
        recommendations = []
        
        if framework_type == 'flutter':
            if not input_summary.get('blutter_files', {}).get('available'):
                recommendations.append("Consider running Blutter decompilation for better Flutter analysis")
            
            if not input_summary.get('manifest', {}).get('available'):
                recommendations.append("Android manifest analysis would improve vulnerability detection")
            
            if not input_summary.get('pubspec', {}).get('available'):
                recommendations.append("Pubspec.yaml analysis would help identify dependency vulnerabilities")
            
            if consistency_checks.get('flutter_indicators', {}).get('confidence') == 'low':
                recommendations.append("Low Flutter indicators - verify this is actually a Flutter app")
            
            if consistency_checks.get('data_completeness', {}).get('percentage', 0) < 50:
                recommendations.append("Limited input data may result in incomplete vulnerability analysis")
        
        analysis['recommendations'] = recommendations
        
        return analysis
        
    except Exception as e:
        return {
            'error': f"Error in input consistency analysis: {e}",
            'framework_type': framework_type,
            'input_summary': {},
            'consistency_checks': {},
            'recommendations': ['Analysis failed - check input data']
        }
