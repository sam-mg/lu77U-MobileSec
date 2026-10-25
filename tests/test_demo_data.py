#!/usr/bin/env python3
"""
Module: test_demo_data

Purpose:
    The static demo's settings snapshot, which must carry every field the real settings endpoint returns.

Responsibilities:
    Pin that the demo snapshot has the same top-level and per-provider fields as the live endpoint, that a tool the readiness block calls configured has a path, that the snapshot names the model the published scans ran on, and that the published Ghera scans are the scored ones, named by their path in the benchmark's repository and listed after the showcase apps.

Dependencies:
    pytest, the demo data builder script, the settings service and the user settings module.

Implementation notes:
    The demo once lacked four Settings fields and the review budget, and showed Blutter, hermes-decomp and Ghidra as configured with empty paths, because its snapshot was written by hand beside the real one. The live endpoint is run here against an empty settings file in a temporary directory, with the keychain and the CLI probe stubbed, so nothing reads the user's configuration.
"""

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def demo():
    """
    Purpose:
        Load the demo builder script as a module.

    Returns:
        The module.
    """
    spec = importlib.util.spec_from_file_location("build_demo_data", REPO_ROOT / "scripts" / "build_demo_data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def live(monkeypatch, tmp_path):
    """
    Purpose:
        Produce the real settings endpoint's snapshot against an empty settings file.

    Parameters:
        monkeypatch: Redirects the settings file and stubs the keychain and CLI probe.
        tmp_path: Holds the empty settings file.

    Returns:
        The snapshot.

    Security considerations:
        The user's real settings and stored keys are never read.
    """
    from lu77U_MobileSec.config import credentials, user_settings
    from lu77U_MobileSec.web.services import settings_service

    monkeypatch.setattr(user_settings, "get_settings_path", lambda: tmp_path / "settings.json")
    monkeypatch.setattr(user_settings, "_cache", None)
    monkeypatch.setattr(credentials, "get_api_keys", lambda *_: [])
    monkeypatch.setattr(credentials, "get_api_key_entries", lambda *_: [])
    monkeypatch.setattr(settings_service, "_cli_status_fields", lambda *_: {
        "binary_path": "", "cli_binary": "x", "cli_found": False, "cli_resolved_path": None,
        "signin_hint": ""})
    snapshot = settings_service.get_settings()
    monkeypatch.setattr(user_settings, "_cache", None)
    return snapshot


def test_the_demo_snapshot_has_every_live_field(demo, live):
    """
    Purpose:
        Pin that the demo snapshot carries every top-level, budget and per-provider field the live endpoint returns.

    Parameters:
        demo: The demo builder.
        live: The live endpoint's snapshot.
    """
    snapshot = demo.build_settings("gemma4:31b")
    assert set(live) <= set(snapshot)
    assert set(live["agent_budget"]) == set(snapshot["agent_budget"])
    for name, provider in live["providers"].items():
        assert set(provider) <= set(snapshot["providers"][name]), name


def test_configured_tools_have_paths_and_the_model_matches(demo):
    """
    Purpose:
        Pin that every tool the readiness block calls configured has a path, and that the Ollama model is the one given.

    Parameters:
        demo: The demo builder.
    """
    snapshot = demo.build_settings("gemma4:31b")
    for tool in ("jadx", "blutter", "hermes_decomp", "rn_decompiler", "ghidra"):
        assert bool(snapshot[f"{tool}_path"]) == snapshot["status"][f"{tool}_configured"], tool
    assert snapshot["providers"]["ollama"]["model"] == "gemma4:31b"


def test_the_published_benchmark_scans_are_the_scored_ones(demo, tmp_path):
    """
    Purpose:
        Every scored scan is published under its repository path, each benchmark's vulnerable app next to its fixed one; an unscored benchmark publishes nothing.

    Parameters:
        demo: The builder module.
        tmp_path: Holds the results file.
    """
    assert demo.benchmark_scans(tmp_path / "missing.json") == []
    results = {"variants": {
        "Secure": {"benchmarks": {"Web/B-Lean": {"folder": "scan-b-secure", "apk": "B-Lean-secure.apk"},
                                  "Crypto/A-Lean": {"folder": "scan-a-secure", "apk": "A-Lean-secure.apk"}}},
        "Benign": {"benchmarks": {
            "Web/B-Lean": {"folder": "scan-b", "apk": "B-Lean-benign.apk"},
            "Crypto/A-Lean": {"folder": "scan-a", "apk": "A-Lean-benign.apk"},
        }},
    }}
    path = tmp_path / "ghera_results.json"
    path.write_text(json.dumps(results))
    assert demo.benchmark_scans(path) == [
        ("scan-a", f"{demo.GHERA_SOURCE}/Crypto/A-Lean/benign.apk"),
        ("scan-a-secure", f"{demo.GHERA_SOURCE}/Crypto/A-Lean/secure.apk"),
        ("scan-b", f"{demo.GHERA_SOURCE}/Web/B-Lean/benign.apk"),
        ("scan-b-secure", f"{demo.GHERA_SOURCE}/Web/B-Lean/secure.apk"),
    ]


def test_the_showcase_scans_are_marked_and_listed_first(demo, tmp_path):
    """
    Purpose:
        Pin that every SOURCE_SCANS entry is marked as a showcase scan and comes before the scored Ghera scans.

    Parameters:
        demo: The builder module.
        tmp_path: Holds the results file.
    """
    path = tmp_path / "ghera_results.json"
    path.write_text(json.dumps({"variants": {"Benign": {"benchmarks": {
        "Crypto/A-Lean": {"folder": "scan-a", "apk": "A-Lean-benign.apk"}}}}}))
    published = demo.published_scans(path)
    assert [s for s in published if s[2]] == [(name, shown, True) for name, shown in demo.SOURCE_SCANS]
    assert [s for s in published if not s[2]] == [
        ("scan-a", f"{demo.GHERA_SOURCE}/Crypto/A-Lean/benign.apk", False)]


def test_the_showcase_apps_stay_ahead_of_the_benchmark_scans(demo):
    """
    Purpose:
        Pin that the benchmark scans, though newer, are listed after the showcase apps, which stay newest first among themselves, and keep their benchmark order.

    Parameters:
        demo: The builder module.
    """
    showcase = [{"id": "diva", "created_at": "2026-07-01"}, {"id": "dvfa", "created_at": "2026-09-01"}]
    benchmarks = [{"id": "crypto-a", "created_at": "2026-10-22T02:00"}, {"id": "crypto-a-secure", "created_at": "2026-10-22T01:00"}]
    assert [m["id"] for m in demo.listing(showcase, benchmarks)] == ["dvfa", "diva", "crypto-a", "crypto-a-secure"]
