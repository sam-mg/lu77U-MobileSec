#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.schema

Purpose:
    Define the contract between the tool and any language model: the JSON schema a finding must satisfy, the system message that states it in prose, and the helpers that coerce near-miss responses back into that shape.

Responsibilities:
    Declare the field length limits, build VULNERABILITY_SCHEMA and DEFAULT_SYSTEM_MESSAGE from them, and parse line spans and response containers.

Dependencies:
    ..utils.json_utils for duplicate-tolerant parsing, ..validation.taxonomy for the vulnerability class codes, imported defensively.

Implementation notes:
    The schema and the prose system message are generated from the same limit constants, so a cap can never be enforced in one and stated differently in the other. A model told 240 characters and validated at 200 would be set up to fail. Findings ask for a CVSS vector rather than a severity word, because a model will assert a severity that its own reasoning does not support. Severity is computed from the vector downstream, which makes the number reproducible and checkable. The schema likewise asks for a single vuln_class code instead of separate CWE and OWASP fields. One code is easier for a model to get right than three related identifiers, and the taxonomy expands it into the rest, so the three can never disagree. The taxonomy is imported inside functions with a broad guard, because this module is imported early and a taxonomy import failure must degrade the schema to a prose hint rather than prevent the tool from starting.

Security considerations:
    The schema is the only thing constraining what a model may put into a report. The length caps bound a hostile or degenerate response, and the enum on vuln_class -- when the taxonomy loaded -- keeps classification within a known set. Everything a model returns remains untrusted text that the renderer must still escape.
"""

import re as _re
from typing import Optional, Tuple

from ..utils.json_utils import loads_richest as _loads_richest

def _vuln_class_hint() -> str:
    """
    Purpose:
        Produce the human-readable list of valid vulnerability class codes, for embedding in the schema description when the enum could not be built.

    Returns:
        The taxonomy's hint text, or a pointer to the skill documentation when the taxonomy is unavailable.

    Implementation notes:
        Guarded broadly and called once at import. The fallback text still tells the model where the codes are defined, so a taxonomy failure degrades the guidance rather than removing it.
    """
    try:
        from ..validation.taxonomy import schema_hint
        return schema_hint()
    except Exception:
        return "see the vulnerability_classes skill"

_VULN_CLASS_HINT = _vuln_class_hint()


def _vuln_class_codes() -> list:
    """
    Purpose:
        Collect the valid vulnerability class codes for use as a JSON-schema enum.

    Returns:
        The code list, or an empty list when the taxonomy is unavailable.

    Implementation notes:
        An empty result is meaningful: the schema omits the enum entirely in that case and falls back to describing the codes in prose. Emitting an empty enum instead would make every value invalid and reject every finding.
    """
    try:
        from ..validation.taxonomy import ALL_CODES
        return list(ALL_CODES)
    except Exception:
        return []

_VULN_CLASS_CODES = _vuln_class_codes()

_TRAILING_LINE_RE = _re.compile(r":\s*(\d+(?:\s*[-–]\s*\d+)?)\s*$")


def parse_line_span(value) -> Optional[Tuple[int, int]]:
    """
    Purpose:
        Extract a line number or inclusive line range from whatever a model put in the line field.

    Parameters:
        value: A string, an int, or None. Anything else is coerced with str.

    Returns:
        A (start, end) tuple with start <= end, or None when no number could be found. A single line yields equal elements, so callers never have to handle two shapes.

    Complexity:
        O(n) in the length of the text.

    Implementation notes:
        Models put file paths in the line field often enough to handle deliberately. When the value looks like a path, only a trailing colon-number suffix is considered, so that digits inside a directory name or a version number are not mistaken for a line number. A path with no such suffix yields None rather than a wrong line. Both a hyphen and an en dash are accepted in ranges, because models emit typographic dashes in otherwise well-formed output. A reversed range is swapped rather than rejected, since the intent is unambiguous. Only the first two numbers are used; extra digits are ignored rather than treated as an error.

    Security considerations:
        Returned line numbers index into decompiled source. They are untrusted and may point outside the file, so the code that extracts a snippet must bound-check rather than trust this result.
    """
    if value is None:
        return None
    text = str(value)
    if "/" in text or "\\" in text:
        match = _TRAILING_LINE_RE.search(text)
        text = match.group(1) if match else ""
    nums = _re.findall(r"\d+", text)
    if not nums:
        return None
    if len(nums) == 1:
        n = int(nums[0])
        return (n, n)
    a, b = int(nums[0]), int(nums[1])
    return (a, b) if a <= b else (b, a)

def _unfence(text: str) -> str:
    """
    Purpose:
        Take a JSON document out of the markdown code fence a model wrapped it in.

    Parameters:
        text: The model's response text.

    Returns:
        The fenced body when the text is one fenced block, otherwise the text unchanged.

    Implementation notes:
        String operations rather than a regular expression, so a long unterminated fence in untrusted model output costs linear time.
    """
    stripped = text.strip()
    newline = stripped.find("\n")
    if not stripped.startswith("```") or newline < 0:
        return text
    body = stripped[newline + 1:].rstrip()
    return body[:-3] if body.endswith("```") else body


def coerce_to_vuln_list(payload):
    """
    Purpose:
        Reduce a model response to a plain list of finding objects, whatever container it arrived in.

    Parameters:
        payload: A JSON string, a dict wrapping the findings, a list, or anything else.

    Returns:
        A list of findings when one could be identified; otherwise the payload unchanged, so the caller can decide how to fail.

    Complexity:
        O(n) in payload size when a parse is needed.

    Implementation notes:
        Four wrapper keys are recognised -- vulnerabilities, results, findings, issues -- because models choose a plausible container name of their own and rejecting all but one would discard valid responses over a naming preference. A dict keyed by the ids the prompt gave ("0": {...}, "1": {...}) is the list written as an object, and becomes that list with each key as its item's id unless the item names one. Any other dict with no recognised wrapper is treated as a single finding rather than as an error, which covers the common case of exactly one issue returned unwrapped. A response wrapped in a markdown code fence is unwrapped before parsing: a fenced answer once came back unparsed from every pass that reads through here, and a scan published no exploit chains although the model had confirmed four, kept every title the review pass had rewritten as a cut-off sentence, and lost its review verdicts. A string that will not parse is returned as-is instead of raising, leaving the more tolerant recovery stages in the response parser free to try.
    """
    if isinstance(payload, str):
        try:
            payload = _loads_richest(_unfence(payload))
        except Exception:
            return payload
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "results", "findings", "issues"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        if payload and all(str(k).isdigit() and isinstance(v, dict) for k, v in payload.items()):
            return [dict({"id": int(k)}, **v) for k, v in payload.items()]
        return [payload]
    return payload

_TITLE_MAX = 80
_DESCRIPTION_MAX = 240
_RECOMMENDATION_MAX = 200
_IMPACT_MAX = 120
_EXPLOITATION_MAX = 120
_CVSS_VECTOR_MAX = 64

VULNERABILITY_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "maxLength": _TITLE_MAX,
                "description": "Short, specific vulnerability name (e.g. 'Hardcoded API key')"
            },
            "cvss_vector": {
                "type": "string",
                "maxLength": _CVSS_VECTOR_MAX,
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
                    "H=High. Severity is computed FROM this score, not chosen separately - "
                    "do not guess a severity word instead of scoring the metrics."
                )
            },
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": (
                    "Fallback only, used if cvss_vector is missing or invalid - the "
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
                "maxLength": _DESCRIPTION_MAX,
                "description": (
                    f"Technical explanation with security context. At most two sentences "
                    f"({_DESCRIPTION_MAX} chars) - what is wrong and why it is reachable; "
                    "the code itself is attached automatically, do not restate it."
                )
            },
            "recommendation": {
                "type": "string",
                "maxLength": _RECOMMENDATION_MAX,
                "description": f"Specific fix or mitigation strategy, one short sentence "
                               f"({_RECOMMENDATION_MAX} chars max)."
            },
            "impact": {
                "type": "string",
                "maxLength": _IMPACT_MAX,
                "description": f"Specific security consequence, one short sentence "
                               f"({_IMPACT_MAX} chars max)."
            },
            "exploitation": {
                "type": "string",
                "maxLength": _EXPLOITATION_MAX,
                "description": f"How this could be exploited, one short sentence "
                               f"({_EXPLOITATION_MAX} chars max)."
            },
            "vuln_class": {
                "type": "string",
                **({"enum": _VULN_CLASS_CODES} if _VULN_CLASS_CODES else {}),
                "description": (
                    "REQUIRED. Catalogue code for this finding's vulnerability class. "
                    "Prefixes are OWASP MASVS control groups. Use the exact code - it is "
                    "what pairs findings into exploit chains (a wrong one invents a chain "
                    "that does not exist) AND fills this finding's CWE / OWASP Mobile "
                    "category automatically, so neither is asked for separately."
                    + ("" if _VULN_CLASS_CODES else " Valid codes: " + _VULN_CLASS_HINT)
                )
            }
        },
        "required": [
            "title", "cvss_vector", "file", "line", "description", "recommendation",
            "vuln_class",
        ]
    }
}

VULNERABILITY_ITEM_SCHEMA = VULNERABILITY_SCHEMA["items"]

DEFAULT_SYSTEM_MESSAGE = f"""You are a security expert specialized in Android and mobile app vulnerabilities.

You MUST return a JSON array. Each object MUST contain these required fields:
- title: Short, specific vulnerability name, e.g. "Hardcoded API key" (string, {_TITLE_MAX} chars max)
- cvss_vector: The CVSS v3.1 base vector, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -
  score all 8 base metrics (AV/AC/PR/UI/S/C/I/A) from the finding's actual exploitation
  conditions and impact, per https://www.first.org/cvss/calculator/3.1. Severity is
  DERIVED from this score automatically - do not pick a severity word instead of
  scoring the metrics (string)
- file: File path exactly as shown in the source (string)
- line: The 1-based line number, e.g. "8", or an inclusive range, e.g. "6-7", of the
  vulnerable line(s) (string)
- description: Technical explanation with security context. At most two sentences,
  {_DESCRIPTION_MAX} chars max (string)
- recommendation: Specific fix or mitigation strategy, one short sentence,
  {_RECOMMENDATION_MAX} chars max (string)
- vuln_class: Catalogue code for this finding's vulnerability class (e.g. "CODE-01" for
  SQL injection, "SECRET-01" for a hardcoded credential - see the vulnerability_classes
  skill for the full list). This one code fills CWE and OWASP Mobile automatically; do
  NOT also include cwe or owasp_mobile fields (string)

Each object MAY also include, when applicable: severity (only as a fallback if you
truly cannot score a valid cvss_vector - the computed score always wins when both are
present), impact (one short sentence, {_IMPACT_MAX} chars max), exploitation (one short
sentence, {_EXPLOITATION_MAX} chars max).

Do NOT include the source code of the vulnerability - the code snippet is extracted
automatically from the file at the line(s) you cite. Every finding MUST have a title,
a cvss_vector, a line, and a vuln_class. Do not use any other field names."""
