#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.json_utils

Purpose:
    Parse JSON that came from a language model, where the same key can legitimately appear more than once in one object and the standard last-wins rule throws away the better value.

Responsibilities:
    Provide a drop-in json.loads that keeps the richest value per duplicate key, and report how often that rescue was needed.

Dependencies:
    json, .verbose.

Implementation notes:
    Models stream long JSON and sometimes restate a key -- typically emitting a short or empty "description" and then the full one, or the reverse. Python's default object hook keeps the last occurrence, which silently discards the useful text in the first case. Choosing the richer value recovers a usable finding from output that would otherwise be technically valid and practically empty.

Known limitations:
    recovered_duplicates is module-global and never reset, so it counts for the life of the process rather than per parse. report_recoveries therefore reports a cumulative total; it is a diagnostic signal, not a per-response metric.

Security considerations:
    Model output is untrusted input. Parsing stays inside the standard json module -- no eval, no literal_eval fallback -- so malformed output can only raise, never execute.
"""

import json
from typing import Any, List, Tuple

from .verbose import verbose_print

_EMPTY = (None, "", [], {})

recovered_duplicates = 0


def _keep_richest(pairs: List[Tuple[str, Any]]) -> dict:
    """
    Purpose:
        Object hook that resolves duplicate keys by keeping the more informative value instead of the last one seen.

    Parameters:
        pairs: Key/value pairs for one JSON object, in document order, as supplied by json's object_pairs_hook.

    Returns:
        A dict with one entry per distinct key.

    Postconditions:
        For a duplicated key, the retained value is the longer string when both occurrences are strings, and the non-empty one when exactly one occurrence is empty. In every other case the later value wins, matching standard json behaviour.

    Side effects:
        Increments the module-global recovered_duplicates each time an earlier value is preferred over a later one.

    Complexity:
        O(n) in the number of pairs.

    Implementation notes:
        "Empty" is defined by _EMPTY as None, "", [] and {} -- the shapes a model emits when it has nothing to say. The membership test uses `in` rather than a falsiness check on purpose, so that 0 and False survive as real values; a CVSS score of 0 or an exploitable=False flag is information, not absence. Note that `value in _EMPTY` compares by equality, so 0 == False would match None only if None were equal to them, which it is not; the tuple contains no numeric members precisely to keep that comparison safe.
    """
    global recovered_duplicates
    out: dict = {}
    for key, value in pairs:
        if key not in out:
            out[key] = value
            continue

        previous = out[key]
        if isinstance(value, str) and isinstance(previous, str):
            if len(value) <= len(previous):
                recovered_duplicates += 1
                continue
        elif value in _EMPTY and previous not in _EMPTY:
            recovered_duplicates += 1
            continue
        out[key] = value
    return out


def loads_richest(text: str, **kwargs) -> Any:
    """
    Purpose:
        Parse JSON with duplicate-key recovery, as a drop-in for json.loads.

    Parameters:
        text: JSON document, typically raw model output.
        kwargs: Forwarded to json.loads unchanged.

    Returns:
        The decoded object.

    Raises:
        json.JSONDecodeError: When text is not valid JSON. Not caught here -- the caller decides whether to retry the model or fail the analysis.

    Side effects:
        May increment the module-global duplicate counter via the object hook.

    Security considerations:
        Accepts untrusted model output; passing object_pairs_hook does not change json's parsing guarantees.
    """
    return json.loads(text, object_pairs_hook=_keep_richest, **kwargs)


def report_recoveries(verbose: bool = False) -> int:
    """
    Purpose:
        Surface how many duplicate keys had to be resolved, so that a provider producing consistently malformed JSON is visible rather than silently patched over.

    Parameters:
        verbose: Gates the printed line; the count is returned either way.

    Returns:
        The cumulative number of recovered duplicates for this process.

    Side effects:
        Writes one line to the verbose stream when the count is non-zero.

    Known limitations:
        The count is process-cumulative, never reset, and shared across every provider and every response in the run.
    """
    if recovered_duplicates:
        verbose_print(
            f"Recovered the richer value for {recovered_duplicates} duplicated "
            "JSON key(s) in model output", verbose)
    return recovered_duplicates
