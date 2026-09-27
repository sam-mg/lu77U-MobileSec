#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.scoring

Purpose:
    Turn a severity histogram into the single 0-100 security score and letter grade shown at the top of every report.

Responsibilities:
    Define the severity weights, the score curve, and the grade bands.

Dependencies:
    math only.

Implementation notes:
    The score decays exponentially rather than linearly, so that it approaches zero without ever reaching it and never has to be clamped. The practical reason is that a linear score bottoms out: an app with twenty critical findings and an app with two hundred both score zero and look identical. HALF_POINT fixes the curve by stating the one fact a reader can check -- 40 weighted points halves the score to 50 -- and _DECAY is derived from it rather than tuned independently. Weights are deliberately non-linear across severities (20/10/5/2/0): one critical finding outweighs three highs, because a report that lets a pile of medium findings mask a single critical one is misleading. Info findings weigh zero, so a verbose informational pass cannot move the score.

Security considerations:
    This score is what a reader uses to decide whether an app is acceptable. Changing a weight or a band silently re-grades every past report it is compared against.
"""

import math
from typing import Any, Mapping

SEVERITY_WEIGHTS: Mapping[str, int] = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}

HALF_POINT = 40.0
_DECAY = HALF_POINT / math.log(2)

_GRADE_BANDS = (("A", 90.0), ("B", 75.0), ("C", 60.0), ("D", 40.0))


def weighted_finding_count(counts: Mapping[str, Any]) -> int:
    """
    Purpose:
        Reduce a severity histogram to a single weighted total.

    Parameters:
        counts: Mapping from lowercase severity name to count. Unknown keys are ignored; missing keys count as zero.

    Returns:
        The weighted total as an int. Zero for an empty or entirely unknown mapping.

    Preconditions:
        Severity keys must already be lowercase; no normalisation happens here.

    Complexity:
        O(1) -- the loop runs over the fixed weight table, not over the input.

    Implementation notes:
        Iterating the weight table rather than the input is what makes unknown severities inert instead of an error. Each value is coerced individually inside a try, so one malformed entry -- a None, a string, a nested dict -- is skipped without discarding the rest of the histogram. The `or 0` guards a present-but-None value, which int() would otherwise reject.
    """
    total = 0
    for name, weight in SEVERITY_WEIGHTS.items():
        try:
            total += int(counts.get(name, 0) or 0) * weight
        except (TypeError, ValueError):
            continue
    return total


def calculate_security_score(counts: Mapping[str, Any]) -> float:
    """
    Purpose:
        Compute the headline 0-100 security score.

    Parameters:
        counts: Severity histogram, as accepted by weighted_finding_count.

    Returns:
        A float in (0, 100], rounded to one decimal. Exactly 100.0 when there are no weighted findings; strictly positive otherwise.

    Postconditions:
        Monotonically non-increasing as findings are added. Never negative, so no clamping is applied or needed.

    Complexity:
        O(1).

    Implementation notes:
        The curve is 100 * exp(-weighted / _DECAY), where _DECAY is set so that HALF_POINT weighted points score exactly 50. The value can round to 0.0 for a very large weighted total but never reaches zero mathematically, which preserves ordering between two badly-scoring apps.
    """
    weighted = weighted_finding_count(counts)
    return round(100.0 * math.exp(-weighted / _DECAY), 1)


def grade_for(score: float) -> str:
    """
    Purpose:
        Map a numeric score to the letter grade printed beside it.

    Parameters:
        score: Numeric score, or anything coercible to float.

    Returns:
        One of "A", "B", "C", "D" or "F". "F" for None or any value that will not coerce.

    Postconditions:
        Bands are inclusive at their floor: 90 is an A, 89.9 is a B.

    Complexity:
        O(1).

    Implementation notes:
        A non-numeric input grades as F rather than raising, because this is called while rendering a report and an unreadable score is a failure to demonstrate safety, not a reason to abandon the report.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "F"
    for letter, floor in _GRADE_BANDS:
        if value >= floor:
            return letter
    return "F"


def legacy_security_score(counts: Mapping[str, Any]) -> float:
    """
    Purpose:
        Compute the previous linear score, retained so that reports generated before the exponential curve can still be reproduced and compared.

    Parameters:
        counts: Severity histogram, as accepted by weighted_finding_count.

    Returns:
        A float in [0.0, 100.0].

    Complexity:
        O(1).

    Deprecation:
        Superseded by calculate_security_score. New code must not call this; it saturates at 0.0, so it cannot distinguish a badly-scoring app from a catastrophically-scoring one.
    """
    return float(max(0.0, min(100.0, 100.0 - weighted_finding_count(counts))))
