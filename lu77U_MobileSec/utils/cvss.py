#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.cvss

Purpose:
    Implement CVSS v3.1 base scoring locally, so that a severity printed in a report is derived from the vector beside it rather than taken on trust from whatever produced the finding.

Responsibilities:
    Parse a CVSS vector string, compute the base score, map a score to a severity band, and complete a partial vector on request.

Dependencies:
    re only -- no third-party CVSS library and no network lookup.

Implementation notes:
    The constant tables and the two impact formulas are transcribed from the CVSS v3.1 specification. They are not tunable: changing a number here stops producing CVSS and starts producing a private metric that happens to look like it. This module exists because an AI provider will happily assert "Critical" next to a vector that scores 4.2. Recomputing locally makes the severity and the vector consistent by construction.

Security considerations:
    Severity drives what a reader treats as urgent. A silent error here downgrades real findings, which is why every entry point returns None on unparseable input rather than guessing a default.
"""

import re
from typing import Dict, Optional, Tuple

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
    """
    Purpose:
        Parse a CVSS v3.x vector string into a validated metric map.

    Parameters:
        vector: A vector string, with or without a "CVSS:3.0/" or "CVSS:3.1/" prefix. Non-string input is accepted and rejected.

    Returns:
        A dict mapping each of the eight base metrics to its validated single-letter value, or None when the string is unusable.

    Postconditions:
        A non-None result contains every metric in _REQUIRED_METRICS, each with a value legal for that metric, so scoring can index it unchecked.

    Complexity:
        O(n) in the number of vector components.

    Implementation notes:
        Unknown keys and illegal values are dropped silently rather than rejected, so a vector that also carries temporal or environmental metrics still yields a base score. Completeness is then enforced once, at the end: if dropping left a required metric missing, the parse fails as a whole. Partial maps are never returned. A vector missing a metric cannot be scored, and handing back half a map would push that check onto every caller. PR is validated against _PR_UNCHANGED, which shares its key set with _PR_CHANGED; the two tables differ only in their weights, so either serves as the legal-value set.

    Security considerations:
        Vectors arrive from model output and from rule metadata and are untrusted. Validation is allowlist-based against the legal value sets, so no unexpected value can reach the scoring tables.
    """
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

_COMPLETION_DEFAULTS = (("AC", "L"), ("PR", "N"), ("UI", "N"), ("S", "U"), ("C", "N"), ("I", "N"), ("A", "N"))


def complete_vector(vector: str) -> Optional[str]:
    """
    Purpose:
        Turn a vector with base metrics left out into a full one, when what it does state is enough to score.

    Parameters:
        vector: A CVSS v3.x vector string, possibly partial.

    Returns:
        A full eight-metric vector, or None when the input names no attack vector or no impact at all.

    Implementation notes:
        Models routinely drop a metric they consider obvious - most often AC - and a vector that fails to parse used to throw away the attack vector and impacts the model did state, leaving a word-based guess in their place. Completion keeps every stated metric and fills the rest with the worst-case exploitability value (AC:L, PR:N, UI:N, S:U: the model named no barrier) and no impact for an unstated C, I or A. It is only attempted when AV and at least one non-None impact are present, since without those there is nothing to score. Kept separate from parse_vector, which still refuses partial input, so the guess is made only where a caller asks for it.
    """
    if not vector or not isinstance(vector, str):
        return None
    text = re.sub(r"^CVSS:3\.[01]/", "", vector.strip(), flags=re.IGNORECASE)
    metrics: Dict[str, str] = {}
    for part in text.split("/"):
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if key in _METRIC_VALUES and value in _METRIC_VALUES[key]:
            metrics[key] = value
    if "AV" not in metrics or not any(metrics.get(m) in ("L", "H") for m in ("C", "I", "A")):
        return None
    for key, default in _COMPLETION_DEFAULTS:
        metrics.setdefault(key, default)
    return "/".join(f"{key}:{metrics[key]}" for key in _REQUIRED_METRICS)


def calculate_base_score(vector: str) -> Optional[float]:
    """
    Purpose:
        Compute the CVSS v3.1 base score for a vector string.

    Parameters:
        vector: A CVSS v3.x vector string.

    Returns:
        The base score in [0.0, 10.0], or None when the vector will not parse.

    Postconditions:
        Rounded up to one decimal place, per the specification.

    Complexity:
        O(n) in vector length, dominated by parsing.
    """
    metrics = parse_vector(vector)
    if metrics is None:
        return None
    return _score_from_metrics(metrics)

def _score_from_metrics(m: Dict[str, str]) -> float:
    """
    Purpose:
        Apply the CVSS v3.1 base-score equations to a validated metric map.

    Parameters:
        m: A complete, validated metric map as returned by parse_vector.

    Returns:
        The base score in [0.0, 10.0].

    Preconditions:
        Every required metric is present and legal. An unvalidated map raises KeyError rather than producing a wrong score, which is the intended failure mode.

    Complexity:
        O(1).

    Implementation notes:
        Scope changes the calculation in three places at once, which is the part of CVSS most often got wrong: the impact formula, the privileges-required table (_PR_CHANGED scores higher, because crossing a scope boundary makes the same privilege level more dangerous), and the final 1.08 multiplier. A non-positive impact returns 0.0 immediately, per the specification. Without that guard the changed-scope polynomial can yield a small negative impact, which would then be added to a positive exploitability term and produce a nonsense score.
    """
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
    """
    Purpose:
        Round a score up to one decimal place using the exact procedure the CVSS v3.1 specification mandates.

    Parameters:
        value: The unrounded score.

    Returns:
        The score rounded up to one decimal place.

    Complexity:
        O(1).

    Implementation notes:
        This is not round() and not math.ceil(value * 10) / 10. The specification defines rounding in integer space precisely to avoid binary floating-point error: a value that is mathematically 8.6 but stored as 8.599999999999999 must still round to 8.6, where a naive ceiling would produce 8.7. Scaling by 100000 and testing divisibility by 10000 asks "is this value already exactly at a tenth?" with the float noise absorbed by the extra digits. Only when it is not does the value round up to the next tenth. Deviating from this makes scores disagree with every other CVSS calculator at the boundaries, which is the kind of difference that destroys trust in a report.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0

def severity_from_score(score: Optional[float]) -> Optional[str]:
    """
    Purpose:
        Map a numeric base score to its CVSS qualitative severity label.

    Parameters:
        score: A base score in [0.0, 10.0], or None.

    Returns:
        "Informational", "Low", "Medium", "High" or "Critical"; None when the input is None or falls outside every band.

    Postconditions:
        Bands match the CVSS v3.1 qualitative scale, with 0.0 reported as Informational rather than None so that a scored-but-harmless finding is distinguishable from an unscored one.

    Complexity:
        O(1).

    Implementation notes:
        Band edges are inclusive on both sides and the bands are contiguous over the legal range, so only an out-of-range score -- negative, or above 10 -- can fall through to None.
    """
    if score is None:
        return None
    for lo, hi, label in _SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return None

def severity_from_vector(vector: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Purpose:
        Convenience entry point returning both the qualitative severity and the numeric score for a vector, which is what report rendering needs.

    Parameters:
        vector: A CVSS v3.x vector string.

    Returns:
        A (severity, score) tuple. Both elements are None when the vector will not parse; both are populated otherwise.

    Postconditions:
        The two elements always agree, because the label is derived from the score rather than supplied alongside it.

    Complexity:
        O(n) in vector length.
    """
    score = calculate_base_score(vector)
    return severity_from_score(score), score
