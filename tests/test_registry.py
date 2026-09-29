#!/usr/bin/env python3
"""
Module: test_registry

Purpose:
    The framework-name to analyzer-class dispatch table, and the contract every registered analyzer has to honour.

Responsibilities:
    Pin the dispatch mapping including its case-insensitivity and its unknowns, the shared analyzer interface, the preflight behaviour when external tools are unconfigured, and the wiring each framework profile needs to be complete.

Dependencies:
    pytest, the analyzer registry, the five shipped analyzers and their base class, the skills loader and the prompt catalogue.

Implementation notes:
    A half-finished framework addition is the failure this file exists to catch: registering an analyzer without its agent prompt or its core skill produces a scan that runs, reports nothing useful, and raises no error anywhere.
"""

import pytest

from lu77U_MobileSec.analyzers.base import BaseAnalyzer
from lu77U_MobileSec.analyzers.cordova_analyzer import CordovaAnalyzer
from lu77U_MobileSec.analyzers.flutter_analyzer import FlutterAnalyzer
from lu77U_MobileSec.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer
from lu77U_MobileSec.analyzers.react_native_analyzer import ReactNativeAnalyzer
from lu77U_MobileSec.analyzers.registry import get_analyzer_class
from lu77U_MobileSec.analyzers.xamarin_analyzer import XamarinAnalyzer

_ALL_ANALYZERS = [JavaKotlinAnalyzer, FlutterAnalyzer, ReactNativeAnalyzer,
                  CordovaAnalyzer, XamarinAnalyzer]

class TestDispatch:
    """
    Purpose:
        The framework name to analyzer class lookup.
    """
    @pytest.mark.parametrize("framework,expected", [
        ("Java", JavaKotlinAnalyzer),
        ("Kotlin", JavaKotlinAnalyzer),
        ("java", JavaKotlinAnalyzer),
        ("  Kotlin  ".strip(), JavaKotlinAnalyzer),
        ("generic", JavaKotlinAnalyzer),
        ("Unknown", JavaKotlinAnalyzer),
        ("Native (C/C++)", JavaKotlinAnalyzer),
        ("Flutter", FlutterAnalyzer),
        ("FLUTTER", FlutterAnalyzer),
        ("React Native", ReactNativeAnalyzer),
        ("Expo", ReactNativeAnalyzer),
        ("Cordova", CordovaAnalyzer),
        ("CORDOVA", CordovaAnalyzer),
        ("Xamarin", XamarinAnalyzer),
        (".NET MAUI", XamarinAnalyzer),
        ("MAUI", XamarinAnalyzer),
    ])
    def test_known_frameworks(self, framework, expected):
        """
        Purpose:
            Pin the class each recognised framework name dispatches to.

        Parameters:
            framework: The framework name as detection reports it, in the casings and aliases seen in practice.
            expected: The analyzer class that name must resolve to.

        Implementation notes:
            The lowercase and uppercase spellings are present because detection is not the only caller; names also arrive from saved scan metadata and from the command line, where the casing is whatever the user typed.
        """
        assert get_analyzer_class(framework) is expected

    @pytest.mark.parametrize("framework", [
        "Kony", "Kony Visualizer", "LibGDX", "Unity", "Unreal Engine",
        "", None, "made up framework",
    ])
    def test_unregistered_frameworks_return_none(self, framework):
        """
        Purpose:
            Pin that an unrecognised, empty or absent framework name resolves to nothing rather than to a default analyzer.

        Parameters:
            framework: A name with no analyzer behind it.

        Implementation notes:
            Returning None is what lets the caller report the framework as unsupported; silently falling back to the Java/Kotlin analyzer would run a DEX-shaped analysis over a bundle it cannot read and report the empty result as a clean app.
        """
        assert get_analyzer_class(framework) is None

class TestAnalyzerContract:
    """
    Purpose:
        The interface every registered analyzer must honour, with a distinct profile and framework label.
    """
    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_subclasses_base_analyzer(self, cls):
        """
        Purpose:
            Pin that each registered analyzer derives from the shared base class.

        Parameters:
            cls: The analyzer class being checked.
        """
        assert issubclass(cls, BaseAnalyzer)

    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_has_a_distinct_profile_and_label(self, cls):
        """
        Purpose:
            Pin that each analyzer carries a profile and a human-readable framework label.

        Parameters:
            cls: The analyzer class being checked.
        """
        instance = cls(verbose=False)
        assert instance.profile is not None
        assert instance.framework_label

    def test_profiles_are_pairwise_distinct(self):
        """
        Purpose:
            Pin that no two analyzers share a profile key.

        Implementation notes:
            The profile key indexes the agent prompt and the core skill, so a duplicate silently gives one framework another's guidance.
        """
        keys = {cls(verbose=False).profile.key for cls in _ALL_ANALYZERS}
        assert len(keys) == len(_ALL_ANALYZERS)

    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_preflight_returns_bool_and_str(self, cls):
        """
        Purpose:
            Pin that preflight returns a readiness flag and a reason, and that an unready analyzer explains itself.

        Parameters:
            cls: The analyzer class being checked.

        Implementation notes:
            A False readiness with an empty reason surfaces to the user as a scan that refuses to start with nothing on screen saying why.
        """
        instance = cls(verbose=False)
        ready, reason = instance.preflight()
        assert isinstance(ready, bool)
        assert isinstance(reason, str)
        if not ready:
            assert reason

    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_accepts_every_kwarg_analysis_service_passes(self, cls):
        """
        Purpose:
            Pin that every analyzer accepts the full keyword set the analysis service constructs it with.

        Parameters:
            cls: The analyzer class being checked.

        Implementation notes:
            The service passes verbose, progress and is_cancelled. A subclass that forgets one raises TypeError at construction, which fails every scan of that framework before any work starts; that is a regression this pins, not a hypothetical.
        """
        stop = lambda: True
        instance = cls(verbose=False, progress=lambda *_, **__: None, is_cancelled=stop)
        assert instance.is_cancelled is stop

    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_is_cancelled_defaults_to_never_cancelled(self, cls):
        """
        Purpose:
            Pin that an analyzer built without a cancellation callback reports itself as never cancelled.

        Parameters:
            cls: The analyzer class being checked.
        """
        assert cls(verbose=False).is_cancelled() is False

    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_is_cancelled_reaches_the_agent_loop(self, cls, monkeypatch):
        """
        Purpose:
            Pin that the cancellation callback is handed through to the agent loop.

        Parameters:
            cls: The analyzer class being checked.
            monkeypatch: Replaces the agent loop entry point with a recorder.

        Implementation notes:
            The loop polls the callback once per turn, and that poll is the only way to interrupt a loop with no fixed end. A callback that stops at the analyzer leaves a cancelled scan running until its budget expires.
        """
        seen = {}

        def fake_run(provider_unused, source_root_unused, static_signals_unused=None, **kwargs):
            """
            Purpose:
                Stand in for the agent loop and record the keywords it was called with.

            Parameters:
                provider_unused: The AI provider, unused here.
                source_root_unused: The decompiled source root, unused here.
                static_signals_unused: The static pre-pass signals, unused here.
                kwargs: Everything else the analyzer passed through, recorded so the test can assert the cancellation callback arrived.

            Returns:
                An empty finding list, a success flag and an empty error string, matching the real return shape.
            """
            seen.update(kwargs)
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", fake_run)
        stop = lambda: True
        cls(verbose=False, is_cancelled=stop).run_agent("/tmp/src", None)
        assert seen.get("is_cancelled") is stop

class TestUnconfiguredToolsDegradeCleanly:
    """
    Purpose:
        Preflight behaviour when the external tools an analyzer depends on are not configured.

    Implementation notes:
        Blutter and the React Native decompilers are separate installs this package does not ship. Without them the affected analyzers must name what is missing rather than crash or quietly produce an empty scan.
    """
    def test_flutter_without_blutter(self, monkeypatch):
        """
        Purpose:
            Pin that Flutter preflight refuses with a reason naming Blutter when Blutter is unconfigured.

        Parameters:
            monkeypatch: Reports Blutter as unconfigured.
        """
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.blutter_checker.check_blutter_configured",
            lambda **_: False)
        ready, reason = FlutterAnalyzer(verbose=False).preflight()
        assert ready is False
        assert "blutter" in reason.lower() or "Blutter" in reason

    def test_react_native_without_either_tool(self, monkeypatch):
        """
        Purpose:
            Pin that React Native preflight refuses and names both missing tools when neither is configured.

        Parameters:
            monkeypatch: Reports both Hermes and the React Native decompiler as unconfigured.
        """
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.hermes_checker.check_hermes_configured",
            lambda **_: False)
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.rn_decompiler_checker.check_rn_decompiler_configured",
            lambda **_: False)
        ready, reason = ReactNativeAnalyzer(verbose=False).preflight()
        assert ready is False
        assert "hermes" in reason.lower()
        assert "rn_decompiler_path" in reason or "react-native-decompiler" in reason.lower()

    def test_react_native_ready_with_only_hermes_configured(self, monkeypatch):
        """
        Purpose:
            Pin that Hermes alone is enough for React Native to report itself ready.

        Parameters:
            monkeypatch: Reports Hermes as configured and the React Native decompiler as not.

        Implementation notes:
            The two tools handle different bundle shapes and either one alone still yields readable source, so requiring both would refuse scans that would have worked.
        """
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.hermes_checker.check_hermes_configured",
            lambda **_: True)
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.rn_decompiler_checker.check_rn_decompiler_configured",
            lambda **_: False)
        ready, _ = ReactNativeAnalyzer(verbose=False).preflight()
        assert ready is True

    def test_cordova_is_always_ready(self):
        """
        Purpose:
            Pin that Cordova preflight never blocks.

        Implementation notes:
            A Cordova app's code sits in assets/www, which is extracted with the standard library's zipfile, so there is no external tool whose absence could make the analyzer unready.
        """
        ready, reason = CordovaAnalyzer(verbose=False).preflight()
        assert ready is True
        assert reason == ""

class TestEveryProfileIsFullyWired:
    """
    Purpose:
        That every registered profile has both an agent system prompt and an always-loaded core skill behind it.

    Implementation notes:
        This is the half-finished framework addition the suite exists to catch: the analyzer registers and the scan runs, but the agent gets the Java/Kotlin default prompt or no output contract at all, and nothing reports the mismatch.
    """
    @pytest.mark.parametrize("cls", _ALL_ANALYZERS)
    def test_profile_has_agent_prompt_and_core_skill(self, cls):
        """
        Purpose:
            Pin that each profile resolves to a real framework-specific agent prompt and to a core skill whose file exists on disk.

        Parameters:
            cls: The analyzer class whose profile is being checked.

        Implementation notes:
            The prompt is checked by identifier and by length, because a profile with no entry falls back to the Java/Kotlin prompt, which is a real prompt and would pass a mere existence check.
        """
        from lu77U_MobileSec.analyzers.agent.skills_loader import CORE_SKILLS, skill_path
        from lu77U_MobileSec.config.prompts import VulnerabilityPrompts

        key = cls(verbose=False).profile.key
        prompt_id = VulnerabilityPrompts._AGENT_SYSTEM_BY_PROFILE.get(key)
        assert prompt_id in VulnerabilityPrompts.PROMPT_IDS
        assert len(VulnerabilityPrompts.get_agent_system(key)) > 500
        assert key in CORE_SKILLS
        assert skill_path(CORE_SKILLS[key]) is not None
