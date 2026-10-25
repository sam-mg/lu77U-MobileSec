#!/usr/bin/env python3
"""
Module: test_cvss

Purpose:
    CVSS v3.1 base-score calculation, checked against the published reference vectors.

Responsibilities:
    Pin the scores, the parsing tolerances and the severity bands.

Dependencies:
    pytest, and the CVSS scoring helpers.

Implementation notes:
    Severity in a report is computed from the vector rather than asserted by a model, so an error here silently re-grades every finding. The reference vectors are the check that the implementation still agrees with every other CVSS calculator.
"""

import pytest

from lu77U_MobileSec.utils.cvss import (
    calculate_base_score, parse_vector, severity_from_score, severity_from_vector,
)

KNOWN_VECTORS = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "Medium"),
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, "High"),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7, "Low"),
    ("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "Informational"),
]

@pytest.mark.parametrize("vector,score,severity", KNOWN_VECTORS)
def test_known_vectors(vector, score, severity):
    """
    Purpose:
        Pin each published reference vector to its documented score and severity.

    Parameters:
        vector: The CVSS vector under test.
        score: The score the specification gives for it.
        severity: The qualitative band that score falls in.
    """
    assert calculate_base_score(vector) == pytest.approx(score)
    assert severity_from_vector(vector) == (severity, pytest.approx(score))

def test_prefix_is_tolerated():
    """
    Purpose:
        Pin that a vector carrying either version prefix scores the same as the bare form.

    Implementation notes:
        Vectors arrive from model output and from rule metadata in both spellings, so rejecting the prefixed form would drop scores for a large share of findings.
    """
    bare = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert calculate_base_score("CVSS:3.1/" + bare) == calculate_base_score(bare)
    assert calculate_base_score("CVSS:3.0/" + bare) == calculate_base_score(bare)

def test_metric_order_does_not_matter():
    """
    Purpose:
        Pin that the metrics may appear in any order.

    Implementation notes:
        Models do not preserve the canonical ordering, and the specification does not require it.
    """
    ordered = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    shuffled = "C:H/A:H/AV:N/I:H/S:U/UI:N/AC:L/PR:N"
    assert calculate_base_score(shuffled) == calculate_base_score(ordered)

def test_temporal_metrics_are_ignored():
    """
    Purpose:
        Pin that temporal metrics alongside the base ones are ignored rather than rejected.

    Implementation notes:
        A vector carrying temporal metrics is still a valid base vector, and refusing it would discard a finding over extra information.
    """
    base = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert calculate_base_score(base + "/E:P/RL:O/RC:C") == pytest.approx(9.8)

@pytest.mark.parametrize("vector", [
    "",
    None,
    "not a vector",
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
    "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
])
def test_invalid_vectors_return_none(vector):
    """
    Purpose:
        Pin that an unusable vector yields nothing from every entry point.

    Parameters:
        vector: An empty, absent, malformed or incomplete vector.

    Implementation notes:
        Partial results are the danger here: a vector missing a metric cannot be scored, and returning a half-parsed map would push that check onto every caller.
    """
    assert parse_vector(vector) is None
    assert calculate_base_score(vector) is None
    assert severity_from_vector(vector) == (None, None)

def test_missing_score_is_not_zero():
    """
    Purpose:
        Pin that an unparseable vector means no score rather than a score of zero.

    Implementation notes:
        Zero is a real CVSS score meaning harmless, so conflating it with failure would report an unscored finding as verified safe.
    """
    assert calculate_base_score("garbage") is None
    assert severity_from_score(None) is None

@pytest.mark.parametrize("score,severity", [
    (0.0, "Informational"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"),
    (6.9, "Medium"), (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical"),
])
def test_severity_bands(score, severity):
    """
    Purpose:
        Pin each severity band, including both edges.

    Parameters:
        score: A score at or beside a band boundary.
        severity: The band it must fall in.

    Implementation notes:
        The boundaries are asserted from both sides, because an off-by-one there silently shifts findings between bands and changes what a reader treats as urgent.
    """
    assert severity_from_score(score) == severity


@pytest.mark.parametrize("vector,completed", [
    ("AV:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("CVSS:3.1/AV:L/PR:H/C:L", "AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N"),
    ("AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H"),
    ("AV:N/C:N/I:N", None),
    ("C:H/I:H", None),
    ("", None),
])
def test_partial_vectors_are_completed_only_when_scorable(vector, completed):
    """
    Purpose:
        Pin that completion keeps every stated metric, fills the rest with worst-case exploitability and no impact, and refuses a vector with no attack vector or no impact.

    Parameters:
        vector: The model's vector.
        completed: The full vector expected, or None.
    """
    from lu77U_MobileSec.utils.cvss import complete_vector
    assert complete_vector(vector) == completed


def test_the_parser_scores_a_completed_vector():
    """
    Purpose:
        Pin that a finding whose vector omits AC is scored from the completed vector rather than falling back to its severity word.
    """
    from lu77U_MobileSec.utils.response_parser import ResponseParser
    finding = ResponseParser().normalize_vulnerability({
        "title": "Premium unlocked by a local flag", "description": "d", "file": "a.js", "line": "3",
        "severity": "Critical", "cvss_vector": "AV:L/PR:N/UI:N/S:U/C:L/I:N/A:N"})
    assert finding["cvss_vector"] == "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert finding["severity"] == "Medium"
