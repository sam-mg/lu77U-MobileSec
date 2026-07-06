"""String manipulation utilities for lu77U-MobileSec"""

import re
from typing import List, Optional
from .verbose import verbose_print

def sanitize_response_quotes(text: str, verbose: bool = False) -> str:
    """Sanitize malformed quotes in text from AI responses"""
    verbose_print(f"sanitize_response_quotes called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning as is", verbose)
        return text
    
    verbose_print("Replacing smart quotes with straight quotes", verbose)
    text = text.replace('“', '"').replace('”', '"')
    text = text.replace("‘", "'").replace("’", "'")
    
    verbose_print("Fixing escaped quotes", verbose)
    text = text.replace('\\"', '"')
    text = text.replace("\\'", "'")
    
    verbose_print(f"Quote sanitization completed, result length: {len(text)}", verbose)
    return text

def sanitize_filename(filename: str, verbose: bool = False) -> str:
    """Sanitize filename for safe file operations"""
    verbose_print(f"sanitize_filename called for: {filename}", verbose)
    
    if not filename:
        verbose_print("Empty filename provided, returning 'unknown'", verbose)
        return "unknown"
    
    verbose_print("Removing invalid characters", verbose)
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    verbose_print("Removing control characters", verbose)
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    verbose_print("Trimming whitespace and dots", verbose)
    filename = filename.strip(' .')
    
    if not filename:
        verbose_print("Filename became empty after sanitization, returning 'unknown'", verbose)
        return "unknown"
    
    if len(filename) > 200:
        verbose_print(f"Filename too long ({len(filename)}), truncating to 200 chars", verbose)
        filename = filename[:200]
    
    verbose_print(f"Sanitized filename: {filename}", verbose)
    return filename

def truncate_text(text: str, max_length: int = 1000, suffix: str = "...", verbose: bool = False) -> str:
    """Truncate text to a maximum length"""
    verbose_print(f"truncate_text called (length={len(text) if text else 0}, max_length={max_length})", verbose)
    
    if not text or len(text) <= max_length:
        verbose_print("Text doesn't need truncation", verbose)
        return text
    
    verbose_print(f"Truncating text with suffix '{suffix}'", verbose)
    truncated = text[:max_length - len(suffix)]
    result = truncated + suffix
    verbose_print(f"Text truncated to length {len(result)}", verbose)
    return result

def extract_urls_from_text(text: str, verbose: bool = False) -> List[str]:
    """Extract URLs from text"""
    verbose_print(f"extract_urls_from_text called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning empty list", verbose)
        return []
    
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    verbose_print("Searching for URL patterns", verbose)
    urls = re.findall(url_pattern, text)
    
    unique_urls = list(set(urls))
    verbose_print(f"Found {len(urls)} URLs, {len(unique_urls)} unique", verbose)
    return unique_urls

def normalize_whitespace(text: str, verbose: bool = False) -> str:
    """Normalize whitespace in text"""
    verbose_print(f"normalize_whitespace called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning empty string", verbose)
        return ""
    
    verbose_print("Replacing multiple whitespace with single space", verbose)
    text = re.sub(r'\s+', ' ', text)
    
    verbose_print("Stripping leading/trailing whitespace", verbose)
    text = text.strip()
    
    verbose_print(f"Whitespace normalization completed, result length: {len(text)}", verbose)
    return text

def extract_java_class_name(file_path: str, verbose: bool = False) -> Optional[str]:
    """Extract Java class name from file path"""
    verbose_print(f"extract_java_class_name called for: {file_path}", verbose)
    
    if not file_path:
        verbose_print("Empty file path provided, returning None", verbose)
        return None
    
    filename = file_path.split('/')[-1]
    verbose_print(f"Extracted filename: {filename}", verbose)
    
    if '.' in filename:
        class_name = filename.rsplit('.', 1)[0]
        verbose_print(f"Extracted class name: {class_name}", verbose)
        return class_name
    
    verbose_print("No extension found in filename, returning None", verbose)
    return None

def count_lines(text: str, verbose: bool = False) -> int:
    """Count lines in text"""
    verbose_print(f"count_lines called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning 0", verbose)
        return 0
    
    line_count = len(text.split('\n'))
    verbose_print(f"Found {line_count} lines", verbose)
    return line_count