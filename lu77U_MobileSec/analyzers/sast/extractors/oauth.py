#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.oauth

Purpose:
    Find OAuth 2.0 flows in the app's own code that a native app should not use: the implicit grant, the password grant, and PKCE with the plain method.

Responsibilities:
    Match the parameter values that name each flow in the app's Java, its React Native modules and its recovered Dart source, and emit one finding per site.

Dependencies:
    re, pathlib, the app-code walker.

Implementation notes:
    The flows are identified by their wire parameters -- response_type=token, grant_type=password, code_challenge_method=plain -- written either as a query string or as a key and value pair, which is how both hand-built authorize URLs and builder calls look once decompiled. OAuth libraries carry every one of these strings for their own completeness, so library paths are skipped and only the app's own code is read.
"""

import re
from pathlib import Path
from typing import Iterator, List, Tuple

from .app_java import MAX_FILES, excerpt, is_library, iter_app_java, line_of
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_PAIR = r"(?:=|[\"']?\s*[,:]\s*[\"'])"
_RULES = (
    (re.compile(r"response_type" + _PAIR + r"token\b"),
     "OAuth implicit grant is used (response_type=token)",
     "The app requests tokens with the implicit grant, which returns the access token in the redirect URL.",
     "The token travels in a URL a second app registered for the same redirect scheme can receive, and it has no "
     "PKCE or client binding, so whoever catches the redirect holds a working token."),
    (re.compile(r"grant_type" + _PAIR + r"password\b"),
     "OAuth password grant is used (grant_type=password)",
     "The app sends the user's password to the token endpoint itself rather than through the identity provider's page.",
     "The app handles raw credentials, so any compromise of the app or its traffic yields the password, and the "
     "identity provider's protections - MFA, phishing-resistant login - are bypassed."),
    (re.compile(r"code_challenge_method" + _PAIR + r"plain\b"),
     "PKCE uses the plain method (code_challenge_method=plain)",
     "The authorization request sends the PKCE verifier itself as the challenge, so the challenge reveals it.",
     "Anyone who sees the authorization request - a logging proxy, a second app catching the redirect with the "
     "request - learns the verifier and redeems the code, which is what PKCE exists to prevent."),
)
_MARKERS = (b"response_type", b"grant_type", b"code_challenge_method")
_SCRIPT_DIRS = ("app_modules", "dart_source")


def _app_texts(root: Path) -> Iterator[Tuple[str, str]]:
    """
    Purpose:
        Yield the app's own code that could carry OAuth parameters: Java, React Native app modules and recovered Dart source.

    Parameters:
        root: The analysis root.

    Returns:
        (relative path, text) pairs.
    """
    yield from iter_app_java(root, _MARKERS)
    count = 0
    for directory in _SCRIPT_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            count += 1
            if count > MAX_FILES:
                return
            if path.suffix not in (".js", ".dart") or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if is_library(rel):
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if any(marker in data for marker in _MARKERS):
                yield rel, data.decode("utf-8", errors="ignore")


def analyze_oauth(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report native-app OAuth flows that leak or expose tokens or credentials.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the outcome.

    Returns:
        The findings.

    Side effects:
        Reads the app's code files.
    """
    out: List[SastFinding] = []
    for rel, text in _app_texts(Path(source_root)):
        for pattern, title, description, impact in _RULES:
            for match in pattern.finditer(text):
                line = line_of(text, match.start())
                out.append(SastFinding(
                    title=title, severity="Medium", vuln_class="AUTH-01", file=rel, line=line,
                    detector="oauth", confidence="MEDIUM", description=description, impact=impact,
                    recommendation=("Use the authorization code grant with PKCE (S256) through the system browser "
                                    "or a Custom Tab, with a verified App Link as the redirect URI (RFC 8252)."),
                    evidence=excerpt(text, line), cwe="CWE-287",
                    owasp_mobile="M3: Insecure Authentication/Authorization"))
    verbose_print(f"SAST oauth: {plural(len(out), 'finding')}", verbose)
    return out
