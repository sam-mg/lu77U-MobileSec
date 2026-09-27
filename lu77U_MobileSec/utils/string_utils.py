#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.string_utils

Purpose:
    Text helpers for handling untrusted strings: model output that must be parsed, APK-derived names that become filenames, and long blobs that must be trimmed before they reach a prompt or a report.

Responsibilities:
    Normalise quotes, sanitise filenames, truncate, extract URLs, collapse whitespace, derive a class name from a path, and count lines.

Dependencies:
    re, .verbose.

Security considerations:
    sanitize_filename is a path-traversal control and is the reason this module is security-relevant. Every other function here is formatting.
"""

import re
from typing import List, Optional
from .verbose import verbose_print

def sanitize_response_quotes(text: str, verbose: bool = False) -> str:
    """
    Purpose:
        Normalise the quote characters in model output so that it has a chance of parsing as JSON.

    Parameters:
        text: Raw model output. Empty and None pass through unchanged.
        verbose: Traces each stage.

    Returns:
        The text with typographic quotes replaced by ASCII ones and backslash-escaped quotes unescaped.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Models emit curly quotes when they slip into prose mode mid-JSON, and over-escape quotes when they have been asked for JSON inside a string. Both produce output that is one character away from parsing.

    Known limitations:
        Unescaping applies to the whole string, including inside JSON string values where a backslash-escaped quote is correct and required. On a well-formed response that carries an embedded quote this corrupts the document rather than repairing it, so this should be attempted only after a direct parse has already failed.
    """
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
    """
    Purpose:
        Turn an arbitrary, untrusted string into a single safe filename component.

    Parameters:
        filename: Candidate name, typically an APK package or application name recovered from the manifest.
        verbose: Traces each stage.

    Returns:
        A non-empty filename component, never a path. "unknown" when the input was empty or was reduced to nothing.

    Postconditions:
        The result contains no path separator, no character illegal on Windows, and no control character; it neither starts nor ends with a dot or a space; and it is at most 200 characters.

    Complexity:
        O(n) in name length.

    Security considerations:
        This is a path-traversal control, not a cosmetic cleanup. The input is attacker-controlled: an app can declare any package or label it likes, including one containing "../" or a NUL. Replacing separators defeats traversal, and stripping leading dots prevents a name that hides the output file or that reduces to a relative-path token. The result is a component only. Callers must still join it to a known output directory; this function cannot make an absolute path safe.

    Implementation notes:
        The stripped set includes Windows-illegal characters (< > : " | ? *) even on POSIX, so that an output tree produced on one platform stays copyable to another. The emptiness check is repeated after sanitisation because an input consisting only of dots or separators sanitises down to nothing, and an empty filename would silently become a directory write. The 200-character cap leaves room for the timestamp and extension the caller appends, within the common 255-byte filesystem limit.
    """
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
    """
    Purpose:
        Trim a long string to a bounded length with a visible marker, so that prompts and report fields stay within budget.

    Parameters:
        text: Text to trim. Empty passes through.
        max_length: Maximum length of the result, including the suffix.
        suffix: Marker appended when truncation occurred.
        verbose: Traces the decision.

    Returns:
        The original text when it already fits, otherwise a string of exactly max_length characters.

    Complexity:
        O(n) in the truncated length.

    Known limitations:
        max_length smaller than the suffix produces a negative slice bound, which silently yields a string longer than max_length rather than raising. Callers are expected to pass a sensible bound.
    """
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
    """
    Purpose:
        Pull HTTP and HTTPS URLs out of arbitrary text, for endpoint inventory and for flagging cleartext traffic.

    Parameters:
        text: Text to scan, typically decompiled source or a resource string.
        verbose: Reports the match count.

    Returns:
        A list of unique URLs. Empty for empty input.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Trailing .,;:! characters are stripped because a URL at the end of a sentence or a log line absorbs the punctuation; a URL that legitimately ends in one of those is rare enough to accept as a trade.

    Known limitations:
        Ordering is not stable -- uniqueness goes through a set, so the result order varies between runs. Callers that render URLs to a report must sort them, or the report will differ between two runs over the same APK. Only http and https are matched; ws, ftp and custom schemes are missed.

    Security considerations:
        Returned URLs are attacker-controlled and must never be fetched automatically, only reported.
    """
    verbose_print(f"extract_urls_from_text called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning empty list", verbose)
        return []
    
    url_pattern = r'https?://[A-Za-z0-9\-._~%!$&\'()*+,;=:@/?#\[\]]+'
    verbose_print("Searching for URL patterns", verbose)
    urls = [url.rstrip('.,;:!') for url in re.findall(url_pattern, text)]
    
    unique_urls = list(set(urls))
    verbose_print(f"Found {len(urls)} URLs, {len(unique_urls)} unique", verbose)
    return unique_urls

def normalize_whitespace(text: str, verbose: bool = False) -> str:
    """
    Purpose:
        Collapse every run of whitespace to a single space and trim the ends.

    Parameters:
        text: Text to normalise.
        verbose: Traces the stages.

    Returns:
        The normalised text; an empty string for empty or None input, which differs from truncate_text's pass-through of the original object.

    Complexity:
        O(n) in text length.

    Implementation notes:
        The pattern covers newlines and tabs, so this flattens a multi-line snippet to one line. That is the intent where the destination is a single-line report field, and destructive where the destination is a code block.
    """
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
    """
    Purpose:
        Derive a Java or Kotlin class name from a source file path.

    Parameters:
        file_path: Path to a source file, using forward slashes.
        verbose: Traces the extraction.

    Returns:
        The basename with its extension removed, or None when the path is empty or the basename carries no extension.

    Complexity:
        O(n) in path length.

    Implementation notes:
        Splits on "/" only, not os.sep. The paths handled here come from decompiler output and from APK entries, which use forward slashes on every platform; using os.path would break these on Windows rather than fix them. A basename with no dot returns None rather than itself, because such a path is a directory or a malformed entry, not a source file.

    Known limitations:
        The file stem is not necessarily the class name -- a Kotlin file may declare several top-level classes, or none matching the filename.
    """
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
    """
    Purpose:
        Count lines in a string for size reporting and chunking decisions.

    Parameters:
        text: Text to measure.
        verbose: Reports the count.

    Returns:
        The number of lines; 0 for empty input.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Splits on the newline character only, so a file with CRLF endings counts correctly while a legacy CR-only file counts as one line. Text with a trailing newline counts one more line than it visually has, which matches how editors number a final empty line.
    """
    verbose_print(f"count_lines called (length={len(text) if text else 0})", verbose)
    
    if not text:
        verbose_print("Empty text provided, returning 0", verbose)
        return 0
    
    line_count = len(text.split('\n'))
    verbose_print(f"Found {line_count} lines", verbose)
    return line_count
