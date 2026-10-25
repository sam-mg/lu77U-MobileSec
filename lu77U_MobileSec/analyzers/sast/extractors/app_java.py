#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.app_java

Purpose:
    Walk the app's own decompiled Java, skipping the libraries and framework embeddings it bundles, for the extractors that match code patterns.

Responsibilities:
    Yield each app-owned Java file that contains at least one of a rule's marker strings, with its path relative to the analysis root, and provide the line, excerpt and argument-splitting helpers those rules share.

Dependencies:
    pathlib.

Implementation notes:
    A pattern rule that reads library code reports the library's choices as the app's: a bundled OAuth library carries the string "plain" for PKCE, an HTTP library carries a permissive hostname verifier for its own plumbing. The library list here is the union of what the older extractors each skip, so the newer rules share one definition. Files are prefiltered on raw bytes before decoding, because most of a large app's classes contain none of the markers.
"""

from pathlib import Path
from typing import Iterable, Iterator, List, Tuple

MAX_FILES = 60000

LIBRARY_PATHS = (
    "/androidx/", "/android/support/", "/com/google/android/gms/", "/com/google/firebase/",
    "/kotlin/", "/kotlinx/", "/okhttp3/", "/okio/", "/retrofit2/", "/io/reactivex/",
    "/io/flutter/", "/net/openid/appauth/", "/org/apache/",
    "/com/fasterxml/", "/com/squareup/", "/org/bouncycastle/", "/framework_modules/",
    "/com/facebook/",
)


def is_library(rel: str) -> bool:
    """
    Purpose:
        Recognise a path that belongs to a bundled library or framework embedding.

    Parameters:
        rel: The path relative to the analysis root.

    Returns:
        True when the file should be skipped.

    Implementation notes:
        Matched against the path with a leading separator so a fragment matches whole path components.
    """
    probe = "/" + rel.replace("\\", "/")
    return any(fragment in probe for fragment in LIBRARY_PATHS)


def iter_app_java(source_root, markers: Iterable[bytes]) -> Iterator[Tuple[str, str]]:
    """
    Purpose:
        Yield the app's own Java files that mention any marker.

    Parameters:
        source_root: The analysis root.
        markers: Byte strings, at least one of which a file must contain.

    Returns:
        (relative path, decoded text) pairs.

    Implementation notes:
        Bounded at MAX_FILES so a pathological tree cannot stall the rule pass.
    """
    root = Path(source_root)
    wanted = tuple(markers)
    for index, path in enumerate(root.rglob("*.java")):
        if index >= MAX_FILES:
            return
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if is_library(rel):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if wanted and not any(marker in data for marker in wanted):
            continue
        yield rel, data.decode("utf-8", errors="ignore")


def line_of(text: str, offset: int) -> int:
    """
    Purpose:
        Turn a character offset into a 1-based line number.

    Parameters:
        text: The file's text.
        offset: The offset.

    Returns:
        The line number.
    """
    return text.count("\n", 0, offset) + 1


def excerpt(text: str, line: int, before: int = 1, after: int = 2) -> str:
    """
    Purpose:
        Cut the lines around a match for a finding's evidence.

    Parameters:
        text: The file's text.
        line: The 1-based line of the match.
        before: Lines to include above it.
        after: Lines to include below it.

    Returns:
        The excerpt.
    """
    lines = text.splitlines()
    return "\n".join(lines[max(0, line - 1 - before):line + after])


def call_args(text: str, start: int) -> List[str]:
    """
    Purpose:
        Split the arguments of a call whose opening parenthesis ends just before start.

    Parameters:
        text: The source.
        start: The offset just after the opening parenthesis.

    Returns:
        The argument expressions, stripped; parentheses, brackets and string literals are respected.
    """
    args, depth, quote, current = [], 0, "", []
    for char in text[start:start + 2000]:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                args.append("".join(current).strip())
                return args
            depth -= 1
        elif char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    return args
