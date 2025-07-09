#!/usr/bin/env python3
"""
String manipulation utilities for lu77U-MobileSec
"""

import re
from typing import List, Optional


def fix_code_snippet_quotes(text: str) -> str:
    """
    Fix malformed quotes in code snippets from AI responses
    
    Args:
        text: Text that may contain malformed quotes
        
    Returns:
        str: Text with fixed quotes
    """
    if not text:
        return text
    
    # Fix common quote issues in AI responses
    text = text.replace('"', '"').replace('"', '"')  # Smart quotes to straight
    text = text.replace(''', "'").replace(''', "'")  # Smart single quotes to straight
    
    # Fix escaped quotes that shouldn't be escaped
    text = text.replace('\\"', '"')
    text = text.replace("\\'", "'")
    
    return text


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file operations
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unknown"
    
    # Remove/replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Trim whitespace and dots
    filename = filename.strip(' .')
    
    # Ensure it's not empty
    if not filename:
        return "unknown"
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


def truncate_text(text: str, max_length: int = 1000, suffix: str = "...") -> str:
    """
    Truncate text to a maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating
        
    Returns:
        str: Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    truncated = text[:max_length - len(suffix)]
    return truncated + suffix


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text
    
    Args:
        text: Text to search for URLs
        
    Returns:
        List[str]: List of found URLs
    """
    if not text:
        return []
    
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    
    return list(set(urls))  # Remove duplicates


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text
    
    Args:
        text: Text to normalize
        
    Returns:
        str: Text with normalized whitespace
    """
    if not text:
        return ""
    
    # Replace multiple whitespace with single space
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def extract_java_class_name(file_path: str) -> Optional[str]:
    """
    Extract Java class name from file path
    
    Args:
        file_path: Path to Java file
        
    Returns:
        Optional[str]: Class name if found
    """
    if not file_path:
        return None
    
    # Extract filename without extension
    filename = file_path.split('/')[-1]
    if '.' in filename:
        class_name = filename.rsplit('.', 1)[0]
        return class_name
    
    return None


def count_lines(text: str) -> int:
    """
    Count lines in text
    
    Args:
        text: Text to count lines in
        
    Returns:
        int: Number of lines
    """
    if not text:
        return 0
    
    return len(text.split('\n'))
