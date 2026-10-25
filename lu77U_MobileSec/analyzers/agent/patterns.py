#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.patterns

Purpose:
    The shared table of credential and endpoint patterns, used to find secrets, inventory endpoints, and summarise a code node's notable strings.

Responsibilities:
    Declare the patterns and provide matching over text.

Dependencies:
    re only.

Implementation notes:
    One table serves the rule engine, the code graph and the gates, so what counts as a secret cannot differ between the engine that reports one and the gate that judges it. Patterns are marked public where the value they match is designed to ship in the app. That flag is what lets the gates demote a Firebase URL or a Google API key from a leaked credential to an informational identifier, which is both correct and the difference between a useful report and an alarming one.

Security considerations:
    Matching identifies where credentials are; the helpers here return locations and pattern names rather than embedding the matched values in findings.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

STRING_LITERAL_RE = re.compile(r'''["']([^"'\n]{4,160})["']''')

SECRET_RE = re.compile(
    r"(secret|passw|api[_-]?key|token|credential|private[_-]?key|"
    r"-----BEGIN|https?://|[A-Za-z0-9+/]{24,}={0,2})",
    re.IGNORECASE,
)

REQUIRE_RE = re.compile(r"""require\(\s*['"]?([\w./@-]+)['"]?\s*\)""")

MAX_STRINGS_PER_NODE = 6
MAX_REFS_PER_NODE = 8


@dataclass(frozen=True)
class SecretPattern:
    """
    Purpose:
        One credential pattern.

    Attributes:
        name: What the pattern identifies, used as the finding's label.
        regex: The compiled pattern.
        severity: How serious a match is.
        public: Whether the matched value is designed to be shipped in the app.

    Invariants:
        Frozen and compiled once at import.

    Thread-safety:
        Immutable; compiled patterns are safe to share.
    """
    name: str
    regex: "re.Pattern[str]"
    severity: str
    public: bool = False


def _p(name: str, pattern: str, severity: str, public: bool = False) -> SecretPattern:
    """
    Purpose:
        Shorthand constructor so the pattern table reads as a table.

    Parameters:
        name: The pattern's label.
        pattern: The expression.
        severity: How serious a match is.
        public: Whether the value is designed to ship.

    Returns:
        The constructed pattern.
    """
    return SecretPattern(name, re.compile(pattern), severity, public)


SECRET_PATTERNS: Tuple[SecretPattern, ...] = (
    _p("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "Critical"),
    _p("AWS Secret Access Key",
       r"(?i)(?:aws_secret_access_key|aws_secret)['\"\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?",
       "Critical"),
    _p("AWS Session Token",
       r"(?i)aws[_\-]?session[_\-]?token['\"\s:=]+['\"]?[A-Za-z0-9/+=]{100,}", "Critical"),
    _p("Azure Storage Key",
       r"(?i)(?:AccountKey|azure[_\-]?storage[_\-]?key)['\"\s:=]+['\"]?[A-Za-z0-9+/=]{86,88}['\"]?",
       "Critical"),
    _p("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "High"),
    _p("Google OAuth Client ID",
       r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com", "Informational", public=True),

    _p("Firebase Server Key", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "High"),
    _p("Firebase Database URL", r"https://[a-z0-9-]+\.firebaseio\.com",
       "Informational", public=True),
    _p("Firebase App ID", r"[0-9]+:[0-9]+:(?:android|ios):[a-f0-9]+",
       "Informational", public=True),

    _p("Stripe Secret Key", r"sk_(?:live|test)_[A-Za-z0-9]{20,}", "Critical"),
    _p("Stripe Publishable Key", r"pk_(?:live|test)_[A-Za-z0-9]{20,}", "Medium"),
    _p("Square Access Token", r"sq0atp-[A-Za-z0-9\-_]{22}", "High"),

    _p("Slack Token", r"xox[bpors]-[0-9]{10,}-[A-Za-z0-9\-]{10,}", "High"),
    _p("Slack Webhook",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "High"),
    _p("SendGrid API Key", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "High"),
    _p("Twilio Auth Token",
       r"(?i)twilio[_\-]?auth[_\-]?token['\"\s:=]+['\"]?([a-f0-9]{32})['\"]?", "High"),
    _p("Twilio Account SID", r"AC[a-f0-9]{32}", "Medium"),

    _p("GitHub Token", r"gh[psur]_[A-Za-z0-9]{36}", "High"),
    _p("GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}", "High"),
    _p("GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "High"),
    _p("GitLab Token", r"glpat-[A-Za-z0-9\-]{20}", "High"),

    _p("RSA Private Key", r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Critical"),
    _p("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "Critical"),
    _p("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "Critical"),

    _p("JWT", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "High"),
    _p("Bearer Token", r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", "High"),

    _p("Hardcoded Password",
       r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\r\n();]{8,})["']""", "High"),
    _p("Generic API Key",
       r"""(?i)(?:api[_\-]?key|apikey)["\s:=]+["'`]([A-Za-z0-9\-_]{20,})["'`]""", "Medium"),
    _p("Generic Secret",
       r"""(?i)(?:secret|client_secret)["\s:=]+["'`]([A-Za-z0-9\-_!@#$%^&*]{16,})["'`]""",
       "Medium"),
    _p("Private Network Address",
       r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", "Informational"),
)

API_ENDPOINT_RE = re.compile(
    r"https?://[A-Za-z0-9.\-]+(?::\d+)?"
    r"(/[A-Za-z0-9._~\-/]*)?",
)

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)/(?:api/v?\d*|auth|login|register|signup|logout|token|refresh|oauth|"
    r"password|verify|otp|2fa|mfa|sso|admin|internal|debug|graphql|payment|"
    r"checkout|billing|invoice|upload|export)\b"
)


def classify_secret(value: str) -> Optional[SecretPattern]:
    """
    Purpose:
        Identify what kind of credential a value is.

    Parameters:
        value: The candidate value.

    Returns:
        The matching pattern, or None.

    Implementation notes:
        The first match wins, so the table is ordered with the specific patterns before the general ones -- a provider-specific key must not be classified by the generic key pattern, because the specific one carries the right severity and the public flag.
    """
    if not value:
        return None
    for pattern in SECRET_PATTERNS:
        if pattern.regex.search(value):
            return pattern
    return None


def find_secrets(text: str, max_results: int = 50) -> List[dict]:
    """
    Purpose:
        Find credential matches in text.

    Parameters:
        text: The text to scan.
        max_results: How many matches to return.

    Returns:
        The matches, with their pattern and location.

    Complexity:
        O(n) in text length per pattern.

    Implementation notes:
        Deduplicated, since the same key appears repeatedly in decompiled output and reporting each occurrence adds nothing. Bounded, because a file of test fixtures can match hundreds of times and the caller only needs enough to act on.
    """
    out: List[dict] = []
    seen = set()
    if not text:
        return out
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            key = (pattern.name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "name": pattern.name,
                "severity": pattern.severity,
                "public": pattern.public,
                "value": value[:100] + ("..." if len(value) > 100 else ""),
                "line": text[:match.start()].count("\n") + 1,
            })
            if len(out) >= max_results:
                return out
    return out


def find_endpoints(text: str, max_results: int = 50) -> List[dict]:
    """
    Purpose:
        Find API endpoints referenced in text.

    Parameters:
        text: The text to scan.
        max_results: How many to return.

    Returns:
        The endpoints, with their location.

    Implementation notes:
        Trailing punctuation is stripped, because a URL at the end of a sentence or a log message absorbs it. Endpoints are inventory rather than findings: they tell the agent what the app talks to, which is what makes a cleartext or pinning finding concrete.
    """
    out: List[dict] = []
    seen = set()
    if not text:
        return out
    for match in API_ENDPOINT_RE.finditer(text):
        url = match.group(0).rstrip(".,;:'\")")
        if url in seen:
            continue
        seen.add(url)
        out.append({
            "url": url,
            "cleartext": url.lower().startswith("http://"),
            "sensitive_path": bool(_SENSITIVE_PATH_RE.search(url)),
            "line": text[:match.start()].count("\n") + 1,
        })
        if len(out) >= max_results:
            break
    return out


def collect_node_strings(content: str, limit: int = MAX_STRINGS_PER_NODE) -> List[str]:
    """
    Purpose:
        Collect the notable string literals in a unit of code, for the graph node's summary.

    Parameters:
        content: The unit's source.
        limit: How many strings to keep.

    Returns:
        The selected strings.

    Implementation notes:
        Filtered to the ones matching credential-shaped patterns rather than every literal, because a node summary is prompt context and an unfiltered list of strings would be both enormous and uninformative. Deduplicated and bounded for the same reason.

    Security considerations:
        These strings reach the model as part of the node summary, so a node containing a credential sends it to the provider. That is inherent to analysing the app at all -- the same value is in the source the agent reads -- but it means the node summary is as sensitive as the code it describes.
    """
    strings: List[str] = []
    if not content:
        return strings
    for match in STRING_LITERAL_RE.finditer(content):
        literal = match.group(1)
        if SECRET_RE.search(literal) and literal not in strings:
            strings.append(literal[:80])
            if len(strings) >= limit:
                break
    return strings
