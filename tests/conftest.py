#!/usr/bin/env python3
"""
Module: conftest

Purpose:
    Shared pytest setup for the whole suite.

Responsibilities:
    Isolate the validator's process-lifetime verdict cache and the providers' memory of spent keys around every test, and keep every test from launching a real Ghidra.

Dependencies:
    pytest, the validator's cache control, the provider base class, and the Ghidra runner.
"""

import pytest

from lu77U_MobileSec.ai import base_provider
from lu77U_MobileSec.decompiler import ghidra_runner
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


@pytest.fixture(autouse=True)
def _isolate_spent_keys():
    """
    Purpose:
        Forget which keys earlier tests saw run out, around every test.

    Returns:
        Yields once, with the memory cleared before and after the test runs.

    Side effects:
        Empties a process-wide map twice per test.

    Implementation notes:
        Providers remember spent keys for the life of the process, and tests reuse the same fake keys, so a key one test exhausted would otherwise make the next test's provider start on a later key.
    """
    with base_provider._SPENT_KEYS_LOCK:
        base_provider._SPENT_KEYS.clear()
    yield
    with base_provider._SPENT_KEYS_LOCK:
        base_provider._SPENT_KEYS.clear()


@pytest.fixture(autouse=True)
def _no_real_ghidra(monkeypatch):
    """
    Purpose:
        Report Ghidra as unconfigured and empty its result cache for every test, so no test launches the real tool.

    Parameters:
        monkeypatch: Replaces the runner's launcher lookup.

    Returns:
        Yields once, with the cache cleared before and after the test runs.

    Side effects:
        Empties the runner's process-wide cache twice per test.

    Implementation notes:
        The suite reads the developer's real settings file, and a developer who has configured Ghidra would otherwise have every native-library test start a JVM over a fake ELF - slow, and dependent on what is installed. A test that exercises the runner patches the lookup again itself, which overrides this.
    """
    monkeypatch.setattr(ghidra_runner, "resolve_analyze_headless", lambda: None)
    ghidra_runner._cache.clear()
    yield
    ghidra_runner._cache.clear()
