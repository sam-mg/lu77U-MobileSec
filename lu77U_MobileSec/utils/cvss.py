"""CVSS v3.1 base-score calculator (https://www.first.org/cvss/calculator/3.1)."""

import re
from typing import Dict, Optional, Tuple

#: Metric weight tables straight from the CVSS v3.1 specification (section 8.1).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_SCOPE = ("U", "C")

_METRIC_VALUES = {
    "AV": set(_AV), "AC": set(_AC), "PR": set(_PR_UNCHANGED),
    "UI": set(_UI), "S": set(_SCOPE), "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}
_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_SEVERITY_BANDS: Tuple[Tuple[float, float, str], ...] = (
    (0.0, 0.0, "Informational"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
)

def parse_vector(vector: str) -> Optional[Dict[str, str]]:
    """Parse a CVSS v3.1 base vector string into a ``{metric: value}`` dict, or
    ``None`` if it's missing any of the 8 required metrics or has an invalid
    value. Tolerant of the optional ``CVSS:3.1/`` (or ``3.0``) prefix, of
    extra temporal/environmental metrics appended (ignored — base score only),
    and of metrics appearing out of the canonical order."""
    if not vector or not isinstance(vector, str):
        return None
    text = vector.strip()
    text = re.sub(r"^CVSS:3\.[01]/", "", text, flags=re.IGNORECASE)
    metrics: Dict[str, str] = {}
    for part in text.split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if key in _METRIC_VALUES and value in _METRIC_VALUES[key]:
            metrics[key] = value
    if not all(m in metrics for m in _REQUIRED_METRICS):
        return None
    return metrics

def calculate_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.1 base score (0.0-10.0) from a vector string,
    following FIRST's published formula exactly. Returns ``None`` if the
    vector can't be parsed (missing/invalid metrics) — callers should treat
    that as "no score available", not as a score of 0."""
    metrics = parse_vector(vector)
    if metrics is None:
        return None
    return _score_from_metrics(metrics)

def _score_from_metrics(m: Dict[str, str]) -> float:
    scope = m["S"]
    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))

    if scope == "U":
        impact = 6.42 * iss
        pr_value = _PR_UNCHANGED[m["PR"]]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr_value = _PR_CHANGED[m["PR"]]

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_value * _UI[m["UI"]]

    if scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))

def _roundup(value: float) -> float:
    """CVSS's specified round-up-to-1-decimal function (spec section 8.1) —
    NOT ordinary rounding. 9.761 rounds up to 9.8, not down to 9.8 by chance;
    9.760 (already exactly 1 decimal) stays 9.8 without an artificial bump."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0

def severity_from_score(score: Optional[float]) -> Optional[str]:
    """Map a CVSS base score onto FIRST's qualitative severity rating scale."""
    if score is None:
        return None
    for lo, hi, label in _SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return None

def severity_from_vector(vector: str) -> Tuple[Optional[str], Optional[float]]:
    """Convenience: ``(severity, score)`` computed directly from a vector
    string, or ``(None, None)`` if the vector isn't valid CVSS v3.1."""
    score = calculate_base_score(vector)
    return severity_from_score(score), score