"""Provider-agnostic structured-output schema and shared prompt fragments."""

import json as _json
import re as _re
from typing import Optional, Tuple

def parse_line_span(value) -> Optional[Tuple[int, int]]:
    """Parse a line reference into an inclusive ``(start, end)`` line span.

    Accepts what models actually emit: a single line (``"8"``, ``"line 8"``),
    an inclusive range (``"6-7"``, ``"lines 6 to 9"``), or an integer. Returns
    ``None`` when no digits are present (e.g. prose like ``"application tag"``).
    The first two integers found define the span; they are ordered so
    ``start <= end``.
    """
    if value is None:
        return None
    nums = _re.findall(r"\d+", str(value))
    if not nums:
        return None
    if len(nums) == 1:
        n = int(nums[0])
        return (n, n)
    a, b = int(nums[0]), int(nums[1])
    return (a, b) if a <= b else (b, a)

def coerce_to_vuln_list(payload):
    """Normalize a provider's structured output to a list of vuln dicts.

    Accepts a JSON string, a dict (possibly wrapping the list under a key like
    ``vulnerabilities``), or a list. Returns a Python list when it can, else the
    original value (so the downstream ``response_parser`` can still try)."""
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return payload
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "results", "findings", "issues"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return [payload]
    return payload

VULNERABILITY_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short, specific vulnerability name (e.g. 'Hardcoded API key')"
            },
            "cvss_vector": {
                "type": "string",
                "description": (
                    "REQUIRED. The CVSS v3.1 base vector for this finding, in official "
                    "notation, e.g. 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'. Score every one "
                    "of the 8 base metrics from the vulnerability's actual exploitation "
                    "conditions and impact (see https://www.first.org/cvss/calculator/3.1): "
                    "AV (Attack Vector) N=Network/A=Adjacent/L=Local/P=Physical; "
                    "AC (Attack Complexity) L=Low/H=High; "
                    "PR (Privileges Required) N=None/L=Low/H=High; "
                    "UI (User Interaction) N=None/R=Required; "
                    "S (Scope) U=Unchanged/C=Changed (does exploiting this let you affect "
                    "a component beyond its own security scope?); "
                    "C/I/A (Confidentiality/Integrity/Availability impact) N=None/L=Low/"
                    "H=High. Severity is computed FROM this score, not chosen separately — "
                    "do not guess a severity word instead of scoring the metrics."
                )
            },
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": (
                    "Fallback only, used if cvss_vector is missing or invalid — the "
                    "authoritative severity is always computed from cvss_vector."
                )
            },
            "file": {
                "type": "string",
                "description": "Path of the file exactly as shown in the file tree / file view"
            },
            "line": {
                "type": "string",
                "description": "1-based line number (e.g. '8') or inclusive range (e.g. '6-7') of "
                               "the vulnerable line(s), as shown in the numbered file view. Do NOT "
                               "include the code itself; it is extracted from the source automatically."
            },
            "description": {
                "type": "string",
                "description": "Technical explanation with security context"
            },
            "recommendation": {
                "type": "string",
                "description": "Specific fix or mitigation strategy"
            },
            "impact": {
                "type": "string",
                "description": "Specific security consequences and attack scenarios"
            },
            "cwe": {
                "type": "string",
                "description": "CWE identifier if applicable (e.g., CWE-89)"
            },
            "owasp_mobile": {
                "type": "string",
                "description": "OWASP Mobile Top 10 category if applicable (e.g., M2)"
            },
            "exploitation": {
                "type": "string",
                "description": "How this vulnerability could be exploited"
            }
        },
        "required": [
            "title", "cvss_vector", "file", "line", "description", "recommendation"
        ]
    }
}

VULNERABILITY_ITEM_SCHEMA = VULNERABILITY_SCHEMA["items"]

DEFAULT_SYSTEM_MESSAGE = """You are a security expert specialized in Android and mobile app vulnerabilities.

You MUST return a JSON array. Each object MUST contain these required fields:
- title: Short, specific vulnerability name, e.g. "Hardcoded API key" (string)
- cvss_vector: The CVSS v3.1 base vector, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" —
  score all 8 base metrics (AV/AC/PR/UI/S/C/I/A) from the finding's actual exploitation
  conditions and impact, per https://www.first.org/cvss/calculator/3.1. Severity is
  DERIVED from this score automatically — do not pick a severity word instead of
  scoring the metrics (string)
- file: File path exactly as shown in the source (string)
- line: The 1-based line number, e.g. "8", or an inclusive range, e.g. "6-7", of the
  vulnerable line(s) (string)
- description: Technical explanation with security context (string)
- recommendation: Specific fix or mitigation strategy (string)

Each object MAY also include, when applicable: severity (only as a fallback if you
truly cannot score a valid cvss_vector — the computed score always wins when both are
present), impact (string), cwe (e.g. "CWE-89"), owasp_mobile (e.g. "M2"), exploitation
(string).

Do NOT include the source code of the vulnerability — the code snippet is extracted
automatically from the file at the line(s) you cite. Every finding MUST have a title,
a cvss_vector, and a line. Do not use any other field names."""