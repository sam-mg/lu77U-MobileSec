#!/usr/bin/env python3
"""
Module: conftest

Purpose:
    Shared pytest setup for the whole suite.

Responsibilities:
    Isolate the validator's process-lifetime verdict cache around every test.

Dependencies:
    pytest, and the validator's cache control.
"""

import pytest

from lu77U_MobileSec.validation.validator import clear_verdict_cache


@pytest.fixture(autouse=True)
def _isolate_verdict_cache():
    """
    Purpose:
        Clear the validator's verdict cache around every test, so a verdict cannot leak between them.

    Returns:
        Yields once, with the cache cleared before and after the test runs.

    Side effects:
        Empties a process-wide cache twice per test.

    Implementation notes:
        The validator caches model verdicts for the life of the process, so an identical claim in a later scan reuses its answer. Tests reuse identical fixture dicts, so without this the cache would carry a verdict, and a mocked provider call, from one test into the next and make results depend on ordering.
    """
    clear_verdict_cache()
    yield
    clear_verdict_cache()
