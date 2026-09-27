#!/usr/bin/env python3
"""
Module: test_code_graph_prefetch

Purpose:
    The split that lets the androguard analysis run concurrently with decompilation instead of after it.

Responsibilities:
    Pin that a preloaded analysis is reused, and that an absent or failed prefetch still produces a graph.

Dependencies:
    unittest.mock, and the code graph entry points.

Implementation notes:
    The androguard analysis and the decompiler both just read the raw APK, so they are independent, but a real scan paid for them strictly in sequence. Splitting the analysis out lets a caller start it on its own thread before decompilation begins, which removes that wait from every scan of a large app.
"""

from unittest.mock import patch

from lu77U_MobileSec.analyzers.agent.code_graph import (
    analyze_apk_for_code_graph, build_code_graph)


class _FakeAnalysis:
    """
    Purpose:
        Stand in for androguard's APK object, answering the package query and refusing the manifest.

    Implementation notes:
        The manifest raises deliberately, so the tests also cover the graph builder tolerating an unreadable manifest rather than only the happy path.
    """
    def get_package(self):
        """
        Purpose:
            Return a fixed package name.

        Returns:
            The package name.
        """
        return "com.example.app"

    def get_android_manifest_xml(self):
        """
        Purpose:
            Refuse the manifest, standing in for an APK whose manifest cannot be read.

        Raises:
            RuntimeError: Always, so callers exercise their manifest failure path.
        """
        raise RuntimeError("no manifest in this fake")


class _FakeDx:
    """
    Purpose:
        Stand in for androguard's analysis object with no classes.
    """
    def get_classes(self):
        """
        Purpose:
            Return no classes.

        Returns:
            An empty list.
        """
        return []


def _fake_analyze_apk(apk_path):
    """
    Purpose:
        Stand in for the androguard entry point, returning the fake objects.

    Parameters:
        apk_path: Accepted to match the real signature; unused.

    Returns:
        The fake APK, a placeholder for the DEX list, and the fake analysis.
    """
    return _FakeAnalysis(), object(), _FakeDx()


class TestAnalyzeApkForCodeGraph:
    """
    Purpose:
        The prefetch entry point's success and failure behaviour.
    """
    def test_returns_the_a_dx_pair_on_success(self):
        """
        Purpose:
            Pin that a successful prefetch returns the pair the graph builder needs.
        """
        with patch("androguard.misc.AnalyzeAPK", side_effect=_fake_analyze_apk):
            result = analyze_apk_for_code_graph("app.apk")
        assert result is not None
        a, dx = result
        assert a.get_package() == "com.example.app"

    def test_returns_none_on_failure_rather_than_raising(self):
        """
        Purpose:
            Pin that a failed prefetch returns nothing instead of raising.

        Implementation notes:
            The prefetch runs on a background thread, so an exception there would surface far from the caller and could take down a scan that was otherwise fine.
        """
        with patch("androguard.misc.AnalyzeAPK", side_effect=RuntimeError("bad apk")):
            assert analyze_apk_for_code_graph("app.apk") is None


class TestBuildCodeGraphSkipsAnalyzeApkWhenPreloaded:
    """
    Purpose:
        That the graph builder reuses a preloaded analysis rather than repeating it.
    """
    def test_preloaded_result_means_analyzeapk_is_never_called_again(self):
        """
        Purpose:
            Pin that handing the builder a preloaded analysis does not trigger a second one.

        Implementation notes:
            This is the whole point of the split. A second load would cost the time the prefetch was meant to save, and the saving is invisible unless something pins it.
        """
        with patch("androguard.misc.AnalyzeAPK",
                  side_effect=_fake_analyze_apk) as mocked:
            preloaded = analyze_apk_for_code_graph("app.apk")
            assert mocked.call_count == 1

            build_code_graph("app.apk", preloaded=preloaded)
            assert mocked.call_count == 1

    def test_no_preload_falls_back_to_running_it_inline(self):
        """
        Purpose:
            Pin that the builder still loads the APK itself when handed no prefetch.

        Implementation notes:
            The degrade path. A skipped prefetch must cost time, not the graph.
        """
        with patch("androguard.misc.AnalyzeAPK",
                  side_effect=_fake_analyze_apk) as mocked:
            build_code_graph("app.apk", preloaded=None)
            assert mocked.call_count == 1

    def test_a_failed_prefetch_degrades_to_the_inline_path(self):
        """
        Purpose:
            Pin that a prefetch which failed leaves the builder to load the APK itself.

        Implementation notes:
            A failed prefetch returns nothing, which is indistinguishable at the call site from never having prefetched, so the builder takes the same inline path either way.
        """
        with patch("androguard.misc.AnalyzeAPK", side_effect=RuntimeError("boom")):
            preloaded = analyze_apk_for_code_graph("app.apk")
        assert preloaded is None

        with patch("androguard.misc.AnalyzeAPK",
                  side_effect=_fake_analyze_apk) as mocked:
            build_code_graph("app.apk", preloaded=preloaded)
            assert mocked.call_count == 1
