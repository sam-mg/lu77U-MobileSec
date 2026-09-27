#!/usr/bin/env python3
"""
Module: test_report_integrity

Purpose:
    Report fields that were silently wrong on every scan the tool ever ran.

Responsibilities:
    Pin the evidence carried alongside a framework verdict, the labels the fallback detection path produces, the one shared security score and its grade, the notice a truncated scan renders, how a refuted finding is counted and shown, the permissions reaching the report, and the accounting of what a scan cost.

Dependencies:
    pytest, the detection results, the report exporters and builders, the scoring helpers, the web serialisers and the provider base class.

Implementation notes:
    None of these need an application file, a network call or a live quota. Each corresponds to a defect found by auditing one real 95-minute scan against the source that produced it, and each would have caught its defect the day it was introduced, because they are pass-through and arithmetic checks. That is exactly the kind of fault that survives a hand review of the output, because the field is present and merely empty.
"""

import pytest

from lu77U_MobileSec.detection.results.framework_results import (
    FrameworkDetectionResult)
from lu77U_MobileSec.report_generator.json_exporter import JSONExporter
from lu77U_MobileSec.utils.scoring import (
    calculate_security_score, grade_for, weighted_finding_count)


def _detection(frameworks, scores=None):
    """
    Purpose:
        Build a framework detection result from the detectors' raw output.

    Parameters:
        frameworks: The per-detector results.
        scores: The confidence per framework, or None to derive it from the results.

    Returns:
        The detection result.
    """
    result = FrameworkDetectionResult()
    result.detected_frameworks = frameworks
    result.confidence_scores = scores if scores is not None else {
        f["framework"]: f["confidence"] for f in frameworks if isinstance(f, dict)}
    return result


class TestFrameworkIndicators:
    """
    Purpose:
        The evidence shown alongside a framework verdict.

    Implementation notes:
        That field was empty on every scan the tool ever produced. Each detector returns its evidence under one name, the exporter reads another, and in between the ranking rebuilt its results from the confidence map, which is a name to score mapping that never carried the evidence at all. The result was a high-confidence verdict displayed with an empty evidence list in every output format.
    """
    def test_indicators_reach_the_exported_report(self):
        """
        Purpose:
            Pin that a detector's evidence survives the ranking step.
        """
        detection = _detection([
            {"framework": "Java", "confidence": 0.8,
             "indicators": ["classes.dex", "AndroidManifest.xml"]},
        ])
        top = detection.get_top_frameworks()
        assert top[0]["indicators_found"] == ["classes.dex", "AndroidManifest.xml"]

    def test_the_exporter_carries_them_through(self):
        """
        Purpose:
            Pin that the evidence reaches the exported report.
        """
        class _Result:
            """
            Purpose:
                The smallest stand-in for an analysis result the exporter reads.

            Attributes:
                framework_results: The framework detection result.
            """
            framework_results = _detection([
                {"framework": "Flutter", "confidence": 0.9,
                 "indicators": ["libflutter.so"]},
            ])

        data = JSONExporter()._build_framework_data(_Result())
        assert data["frameworks"][0]["indicators_found"] == ["libflutter.so"]

    def test_two_detectors_claiming_one_framework_keep_both_sets(self):
        """
        Purpose:
            Pin that when two detectors claim the same framework, the evidence from both is kept.

        Implementation notes:
            Two detectors agreeing is stronger evidence than either alone, so discarding one of the two sets throws away the part that made the verdict convincing.
        """
        detection = _detection(
            [{"framework": "Java", "confidence": 0.8, "indicators": ["classes.dex"]},
             {"framework": "Java", "confidence": 0.6, "indicators": ["MainActivity"]}],
            scores={"Java": 0.8})
        assert detection.get_top_frameworks()[0]["indicators_found"] == [
            "classes.dex", "MainActivity"]

    def test_a_malformed_detector_result_does_not_break_the_report(self):
        """
        Purpose:
            Pin that a result which is not shaped like the others yields no evidence rather than failing the report.
        """
        detection = _detection(
            ["not a dict", {"framework": "Java", "confidence": 0.8}],
            scores={"Java": 0.8})
        assert detection.get_top_frameworks()[0]["indicators_found"] == []

    def test_indicators_are_capped(self):
        """
        Purpose:
            Pin that the evidence list is capped.

        Implementation notes:
            A detector matching on file names can produce thousands of entries on a large application, which would bury the report section it appears in.
        """
        detection = _detection([
            {"framework": "Xamarin", "confidence": 0.9,
             "indicators": [f"ind-{i}" for i in range(200)]},
        ])
        found = detection.get_top_frameworks()[0]["indicators_found"]
        assert len(found) == FrameworkDetectionResult.MAX_INDICATORS


class TestDetectorFallbackKeys:
    """
    Purpose:
        The labels the fallback detection path produces.

    Implementation notes:
        The primary path keys its confidence map by the framework's display name and the fallback keyed it by the detector's registry name, so any scan that took the fallback produced a report labelled differently from every other scan and, once evidence is looked up by display name, an empty evidence list for exactly those scans.
    """
    def test_fallback_uses_the_framework_name_not_the_registry_key(self, monkeypatch):
        """
        Purpose:
            Pin that the fallback keys its results by the display name, and that the evidence lookup still works.

        Parameters:
            monkeypatch: Unused directly; the detector is assembled by hand instead.

        Implementation notes:
            The detector is built without running its constructor, because constructing it for real would load every detector and the surrounding machinery to exercise one branch.
        """
        from lu77U_MobileSec.detection import detector as detector_mod

        class _Boom:
            """
            Purpose:
                A primary detector that always fails, forcing the fallback path.
            """
            def detect_all_frameworks(self, path):
                """
                Purpose:
                    Fail, standing in for the primary detector being unavailable.

                Parameters:
                    path: The application file, unused here.

                Raises:
                    RuntimeError: Always.
                """
                raise RuntimeError("hybrid detector is down")

        class _Java:
            """
            Purpose:
                A single framework detector returning one confident result with evidence.
            """
            def detect(self, path):
                """
                Purpose:
                    Report the framework with its confidence and evidence.

                Parameters:
                    path: The application file, unused here.

                Returns:
                    The detector's result.
                """
                return {"framework": "Java", "confidence": 0.8,
                        "indicators": ["classes.dex"]}

        instance = object.__new__(detector_mod.MobileSecurityDetector)
        instance.verbose = False
        instance.hybrid_detector = _Boom()
        instance.detectors = {"java": _Java()}

        result = instance._run_framework_detection("/nope")
        assert "Java" in result.confidence_scores
        assert "java" not in result.confidence_scores
        assert result.get_top_frameworks()[0]["indicators_found"] == ["classes.dex"]


class TestSecurityScore:
    """
    Purpose:
        One scoring formula, shared by every output, that can still tell two bad applications apart.
    """
    def test_all_three_report_formats_agree(self):
        """
        Purpose:
            Pin that the exported report, the web response and the shared helper all produce the same score.

        Implementation notes:
            Three copies of a formula drift, and a user comparing the score in the browser with the one in the exported file has no way to tell which is right.
        """
        from lu77U_MobileSec.web import serializers

        counts = {"critical": 1, "high": 13, "medium": 26, "low": 5, "info": 3}
        shared = calculate_security_score(counts)
        assert JSONExporter()._calculate_security_score(
            {"analyzed": True, "by_severity": counts}) == shared
        assert serializers.calculate_security_score(counts) == shared

    def test_a_real_world_scan_is_not_floored(self):
        """
        Purpose:
            Pin that a heavily affected but real application scores above the floor, and still above an application twice as bad.

        Implementation notes:
            The old linear penalty scored this exact scan at zero, which is the same number an application twice as bad would get, so the score stopped carrying any information exactly where it mattered most.
        """
        observed = {"critical": 1, "high": 13, "medium": 26, "low": 5, "info": 3}
        twice_as_bad = {k: v * 2 for k, v in observed.items()}
        assert calculate_security_score(observed) > 0
        assert calculate_security_score(observed) > calculate_security_score(twice_as_bad)

    @pytest.mark.parametrize("counts", [
        {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        {"critical": 5, "high": 20, "medium": 40, "low": 9, "info": 2},
    ])
    def test_score_stays_in_range(self, counts):
        """
        Purpose:
            Pin that the score stays within its bounds across the range of inputs.

        Parameters:
            counts: The finding counts by severity.
        """
        assert 0.0 <= calculate_security_score(counts) <= 100.0

    def test_more_findings_never_score_better(self):
        """
        Purpose:
            Pin that the score never rises as findings are added, that it strictly falls over the range a reader can act on, and that the weighted count keeps separating cases beyond it.

        Implementation notes:
            The headline score is rounded to one decimal, so far out in the tail two adjacent counts can print the same number. That compression is why the weighted count is exported beside it: it keeps separating two bad applications however bad they get, and is what a comparison across applications should sort on.
        """
        previous_score = 100.0
        previous_weight = -1
        for highs in range(1, 60):
            counts = {"critical": 0, "high": highs, "medium": 0, "low": 0, "info": 0}
            score = calculate_security_score(counts)
            weight = weighted_finding_count(counts)
            assert score <= previous_score
            if previous_score > 1.0:
                assert score < previous_score
            assert weight > previous_weight
            previous_score, previous_weight = score, weight

    def test_informational_carries_no_weight(self):
        """
        Purpose:
            Pin that findings recorded for information alone neither add weight nor move the score.
        """
        assert weighted_finding_count(
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 50}) == 0
        assert calculate_security_score(
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 50}) == 100.0

    def test_a_malformed_count_does_not_break_the_report(self):
        """
        Purpose:
            Pin that counts of the wrong type are ignored rather than failing the report.
        """
        assert weighted_finding_count({"critical": None, "high": "x", "medium": 2}) == 10

    def test_grades_track_the_score(self):
        """
        Purpose:
            Pin the grade at the top of the range, at a boundary, and near the floor.
        """
        assert grade_for(100.0) == "A"
        assert grade_for(80.0) == "B"
        assert grade_for(0.7) == "F"

    def test_an_unanalysed_scan_has_no_score_rather_than_a_perfect_one(self):
        """
        Purpose:
            Pin that a scan which analysed nothing reports no score at all.

        Implementation notes:
            The web response used to seed the top score when nothing had been analysed, which is the wrong direction to be wrong in: it reports a clean bill of health for an application that was never examined. The interface already renders an absent score as a dash.
        """
        from lu77U_MobileSec.web import serializers

        data = serializers.build_result(
            json_path=None, detection_result=None, analyzer_results={},
            supported=True, framework_name="Java/Kotlin")
        assert data["summary"]["security_score"] is None


class TestCoverageReporting:
    """
    Purpose:
        That a truncated scan says so in its report.
    """
    def test_a_degraded_scan_renders_a_banner(self):
        """
        Purpose:
            Pin that an incomplete scan renders a notice naming how many regions did not finish.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        html = ComprehensiveHTMLBuilder()._build_coverage_notice({
            "agent_coverage": {
                "complete": False, "regions_incomplete": 2, "regions_total": 2,
                "degraded_reason": "AI provider became unavailable (fatal_quota)"}})
        assert "Incomplete analysis" in html
        assert "2 of 2 code regions" in html

    @pytest.mark.parametrize("results", [
        {"agent_coverage": {"complete": True}},
        {"agent_coverage": {}},
        {},
        None,
    ])
    def test_a_complete_scan_renders_nothing(self, results):
        """
        Purpose:
            Pin that a complete scan, or one with no coverage information at all, renders no notice.

        Parameters:
            results: A results mapping reporting completion, or carrying nothing.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        assert ComprehensiveHTMLBuilder()._build_coverage_notice(results) == ""


class TestRefutedFindings:
    """
    Purpose:
        A finding the mechanical evidence check refuted: out of every count and out of the score, but never out of the report.

    Implementation notes:
        Removing it entirely would hide a disagreement the reader may want to settle themselves, and counting it would let a refuted claim drag the score down.
    """
    def _findings(self):
        """
        Purpose:
            Build one finding that passed the evidence check and one it refuted.

        Returns:
            The two findings.
        """
        return [
            {"title": "Exported provider leaks contacts", "severity": "High",
             "gate_result": {"verdict": "PASS", "mechanically_refuted": False}},
            {"title": "Hardcoded AES key in D.java", "severity": "High",
             "gate_result": {"verdict": "FALSE_POSITIVE", "mechanically_refuted": True,
                             "final_severity": "Informational"}},
        ]

    def test_refuted_findings_are_excluded_from_severity_counts(self):
        """
        Purpose:
            Pin that a refuted finding is left out of the counts and listed separately with its title intact.
        """
        data = JSONExporter()._build_vulnerability_data(
            {"vulnerabilities": self._findings(), "analysis_success": True})
        assert data["by_severity"]["high"] == 1
        assert data["total_vulnerabilities"] == 1
        assert data["refuted_count"] == 1
        assert len(data["refuted"]) == 1
        assert data["refuted"][0]["title"] == "Hardcoded AES key in D.java"

    def test_refuted_findings_do_not_move_the_security_score(self):
        """
        Purpose:
            Pin that adding a refuted finding leaves the score unchanged.
        """
        without = JSONExporter()._calculate_security_score(
            JSONExporter()._build_vulnerability_data(
                {"vulnerabilities": self._findings()[:1], "analysis_success": True}))
        with_refuted = JSONExporter()._calculate_security_score(
            JSONExporter()._build_vulnerability_data(
                {"vulnerabilities": self._findings(), "analysis_success": True}))
        assert without == with_refuted

    def test_the_html_report_keeps_refuted_findings_out_of_statistics(self):
        """
        Purpose:
            Pin that the rendered report counts only the findings that stood and lists the refuted one in its own section.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        builder = ComprehensiveHTMLBuilder()
        all_findings = self._findings()
        kept = [v for v in all_findings
               if not (v.get("gate_result") or {}).get("mechanically_refuted")]
        refuted = [v for v in all_findings
                  if (v.get("gate_result") or {}).get("mechanically_refuted")]

        stats_html = builder._build_statistics_section(kept)
        assert "<strong>1</strong> vulnerabilit" in stats_html

        refuted_html = builder._build_refuted_section(refuted)
        assert "Refuted Findings (1)" in refuted_html
        assert "Hardcoded AES key in D.java" in refuted_html

    def test_a_refuted_finding_gets_the_mechanical_label(self):
        """
        Purpose:
            Pin that a refuted finding is labelled as refuted by the mechanical check rather than by a model.

        Implementation notes:
            The distinction matters to a reader deciding whether to look again: a mechanical refutation is reproducible and a model's opinion is not.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        label_html = ComprehensiveHTMLBuilder()._format_gate_result({
            "gate_result": {"verdict": "FALSE_POSITIVE", "mechanically_refuted": True,
                            "reasons": ["the code does not contain AES"]}})
        assert "Refuted mechanically" in label_html

    def test_no_refuted_findings_renders_no_section(self):
        """
        Purpose:
            Pin that with nothing refuted no section is rendered at all.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        assert ComprehensiveHTMLBuilder()._build_refuted_section([]) == ""


class TestPermissions:
    """
    Purpose:
        The permissions an application declares, as they reach the report.

    Implementation notes:
        That field was empty on every scan, and not for the reason it looked like: the result object had no such field at all, so the exporter's guarded read always returned its own default, while the deterministic pass read the same manifest and reported dangerous permissions from it. Two halves of one report disagreeing about whether the application declares anything.
    """
    _XML = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.READ_CONTACTS"/>'
        '</manifest>'
    )

    def _apk(self, permissions, xml=None):
        """
        Purpose:
            Build a stand-in application exposing the permissions and the manifest the test wants.

        Parameters:
            permissions: What the bytecode library reports, which may be empty.
            xml: The raw manifest text, or None to make reading it fail.

        Returns:
            The stand-in application.
        """
        outer = self

        class _Axml:
            """
            Purpose:
                The manifest accessor, which either returns the raw text or fails.
            """
            def get_xml(self):
                """
                Purpose:
                    Return the raw manifest text.

                Returns:
                    The manifest text.

                Raises:
                    RuntimeError: When the test configured the manifest as unreadable.
                """
                if xml is None:
                    raise RuntimeError("manifest unavailable")
                return xml

        class _Apk:
            """
            Purpose:
                The application, exposing only what the extraction reads.
            """
            def get_permissions(self):
                """
                Purpose:
                    Report the permissions the bytecode library found.

                Returns:
                    The permissions, which may be empty.
                """
                return permissions

            def get_android_manifest_axml(self):
                """
                Purpose:
                    Return the manifest accessor.

                Returns:
                    The accessor.
                """
                return _Axml()

        return _Apk()

    def _extractor(self):
        """
        Purpose:
            Build the extractor under test.

        Returns:
            The extractor.
        """
        from lu77U_MobileSec.detection.extractors.basic_info_extractor import (
            BasicInfoExtractor)

        return BasicInfoExtractor(verbose=False)

    def test_the_result_object_has_somewhere_to_put_them(self):
        """
        Purpose:
            Pin that the result object has a permissions field at all.

        Implementation notes:
            Its absence is the whole defect, and a guarded read of a field that does not exist looks identical to a field that is genuinely empty.
        """
        from lu77U_MobileSec.detection.results.basic_info_results import (
            BasicInfoResult)

        assert BasicInfoResult().permissions == []

    def test_androguard_permissions_are_used_when_present(self):
        """
        Purpose:
            Pin that the permissions the bytecode library reports are used when it reports any.
        """
        found = self._extractor()._extract_permissions(
            self._apk(["android.permission.CAMERA"], self._XML))
        assert found == ["android.permission.CAMERA"]

    def test_an_undecodable_manifest_falls_back_to_the_raw_xml(self):
        """
        Purpose:
            Pin that an empty result from the bytecode library falls back to reading the manifest text directly.

        Implementation notes:
            An empty result means the manifest could not be decoded, not that the application declares nothing, and those two have to be told apart or a heavily permissioned application reads as asking for nothing.
        """
        found = self._extractor()._extract_permissions(self._apk([], self._XML))
        assert found == ["android.permission.CAMERA",
                         "android.permission.READ_CONTACTS"]

    def test_no_permissions_anywhere_is_still_empty(self):
        """
        Purpose:
            Pin that an application genuinely declaring nothing yields an empty list.
        """
        assert self._extractor()._extract_permissions(
            self._apk([], "<manifest/>")) == []

    def test_a_broken_manifest_does_not_raise(self):
        """
        Purpose:
            Pin that a manifest that cannot be read at all yields an empty list rather than failing the scan.
        """
        assert self._extractor()._extract_permissions(self._apk([], None)) == []

    def test_they_reach_application_info(self):
        """
        Purpose:
            Pin that extracted permissions reach the exported report.
        """
        from lu77U_MobileSec.detection.results.basic_info_results import (
            BasicInfoResult)

        info = BasicInfoResult()
        info.permissions = self._extractor()._extract_permissions(
            self._apk([], self._XML))

        class _Result:
            """
            Purpose:
                The smallest stand-in for an analysis result the exporter reads.

            Attributes:
                basic_info: The extracted application information.
            """
            basic_info = info

        assert JSONExporter()._build_app_info(_Result())["permissions"] == [
            "android.permission.CAMERA", "android.permission.READ_CONTACTS"]

    def test_the_manifest_parser_no_longer_clobbers_a_good_value(self):
        """
        Purpose:
            Pin that the manifest parser no longer replaces a populated permission list with an empty one.

        Implementation notes:
            Asserted against the parser's source rather than by running it, because reproducing the overwrite needs the whole parse to run against a real manifest. The trade-off is that rewording that line fails this test without anything being broken, which is the cheaper failure of the two.
        """
        import inspect

        from lu77U_MobileSec.detection.extractors import manifest_parser

        source = inspect.getsource(manifest_parser.ManifestParser)
        assert "permissions if permissions else []" not in source


class TestLlmUsageAccounting:
    """
    Purpose:
        What a scan cost, recorded as it goes.

    Implementation notes:
        It used to be unknowable until the provider's quota ran out, which is the one moment the number is no longer useful.
    """
    def _provider(self):
        """
        Purpose:
            Build a minimal concrete provider.

        Returns:
            The provider.
        """
        from lu77U_MobileSec.ai.base_provider import BaseAIProvider

        class _P(BaseAIProvider):
            """
            Purpose:
                A minimal concrete provider, so the accounting under test is the base class's own.

            Attributes:
                name: The provider name the base class requires.
            """
            name = "test"

            def analyze(self, *a, **kw):
                """
                Purpose:
                    Answer any request with an empty finding list.

                Parameters:
                    a: Positional arguments, ignored.
                    kw: Keyword arguments, ignored.

                Returns:
                    A response holding an empty list.
                """
                return {"response": "[]"}

            def list_models(self):
                """
                Purpose:
                    Satisfy the base class's model listing requirement.

                Returns:
                    An empty list.
                """
                return []

            def validate_credentials(self):
                """
                Purpose:
                    Satisfy the base class's credential check requirement.

                Returns:
                    True, since there is nothing to validate against.
                """
                return True

        return _P()

    def test_calls_and_tokens_accumulate(self):
        """
        Purpose:
            Pin that calls, elapsed time and both token counts accumulate across calls.
        """
        provider = self._provider()
        provider.record_usage(2.5, {"prompt_eval_count": 14000, "eval_count": 300})
        provider.record_usage(1.5, {"prompt_eval_count": 900, "eval_count": 120})
        summary = provider.usage_summary()
        assert summary["calls"] == 2
        assert summary["failed"] == 0
        assert summary["wall_clock_s"] == 4.0
        assert summary["prompt_tokens"] == 14900
        assert summary["completion_tokens"] == 420

    def test_failures_are_counted_separately(self):
        """
        Purpose:
            Pin that a failed call counts towards the total and towards the failures.

        Implementation notes:
            A failed call still cost time and, on most providers, still cost tokens, so leaving it out of the total understates what the scan spent.
        """
        provider = self._provider()
        provider.record_usage(ok=True)
        provider.record_usage(ok=False)
        summary = provider.usage_summary()
        assert summary["calls"] == 2 and summary["failed"] == 1

    def test_missing_or_malformed_metrics_are_survivable(self):
        """
        Purpose:
            Pin that absent or wrongly typed metrics are recorded as a call rather than failing.

        Implementation notes:
            Metrics come from the provider's response and differ between providers and versions, so the accounting has to survive a shape it has not seen.
        """
        provider = self._provider()
        provider.record_usage(None, None)
        provider.record_usage("nonsense", {"prompt_eval_count": "lots"})
        assert provider.usage_summary()["calls"] == 2

    def test_concurrent_calls_do_not_lose_counts(self):
        """
        Purpose:
            Pin that counts recorded from several threads at once all survive.

        Implementation notes:
            The fan-out records from every region at the same time, and incrementing a counter is not a single indivisible step, so without a lock the totals silently come out low.
        """
        import threading

        provider = self._provider()

        def hammer():
            """
            Purpose:
                Record many calls in a tight loop from one thread.

            Side effects:
                Records calls against the shared provider.
            """
            for _ in range(200):
                provider.record_usage(0.01, {"eval_count": 1})

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        summary = provider.usage_summary()
        assert summary["calls"] == 800
        assert summary["completion_tokens"] == 800

    def test_the_summary_carries_what_a_reader_needs(self):
        """
        Purpose:
            Pin that the summary carries every field the report and the interface read off it.
        """
        provider = self._provider()
        summary = provider.usage_summary()
        assert set(summary) >= {"provider", "calls", "failed", "wall_clock_s",
                                "prompt_tokens", "completion_tokens", "model",
                                "unavailable"}


class TestPerCallMetricsJsonl:
    """
    Purpose:
        The per-call record written alongside the totals.

    Implementation notes:
        Aggregated totals cannot show whether the provider's own prompt caching is working from one turn to the next; only the raw sequence of calls can, and this is the only place it is recorded.
    """
    def _provider_with_output_manager(self, tmp_path):
        """
        Purpose:
            Build a provider wired to an output directory it can write its per-call record into.

        Parameters:
            tmp_path: Directory the output directory is created under.

        Returns:
            The provider and its output manager.
        """
        import json as _json

        from lu77U_MobileSec.ai.base_provider import BaseAIProvider
        from lu77U_MobileSec.utils.output_manager import OutputManager

        class _P(BaseAIProvider):
            """
            Purpose:
                A minimal concrete provider, so the accounting under test is the base class's own.

            Attributes:
                name: The provider name the base class requires.
            """
            name = "test"

            def analyze(self, *a, **kw):
                """
                Purpose:
                    Answer any request with an empty finding list.

                Parameters:
                    a: Positional arguments, ignored.
                    kw: Keyword arguments, ignored.

                Returns:
                    A response holding an empty list.
                """
                return {"response": "[]"}

            def list_models(self):
                """
                Purpose:
                    Satisfy the base class's model listing requirement.

                Returns:
                    An empty list.
                """
                return []

            def validate_credentials(self):
                """
                Purpose:
                    Satisfy the base class's credential check requirement.

                Returns:
                    True, since there is nothing to validate against.
                """
                return True

        om = OutputManager()
        om.create_output_directory(str(tmp_path / "app.apk"))
        provider = _P(output_manager=om)
        return provider, om

    def test_a_call_appends_one_jsonl_line(self, tmp_path):
        """
        Purpose:
            Pin that one recorded call writes one line carrying its counts, its stop reason and its provider.

        Parameters:
            tmp_path: Directory the output directory is created under.
        """
        import json

        provider, om = self._provider_with_output_manager(tmp_path)
        provider.record_call_metrics(
            {"prompt_eval_count": 14000, "eval_count": 300}, elapsed=12.5,
            done_reason="stop")
        lines = om.get_llm_metrics_path().read_text().splitlines()
        assert len(lines) == 1
        row = json.loads(lines[0])
        assert row["prompt_eval_count"] == 14000
        assert row["eval_count"] == 300
        assert row["done_reason"] == "stop"
        assert row["provider"] == "test"

    def test_the_region_is_the_calling_threads_name(self, tmp_path):
        """
        Purpose:
            Pin that the record names the region the call was made from.

        Parameters:
            tmp_path: Directory the output directory is created under.

        Implementation notes:
            Each region runs on its own named thread, so the thread's name is the region, and without it the interleaved records from a fan-out cannot be told apart.
        """
        import json
        import threading

        provider, om = self._provider_with_output_manager(tmp_path)
        result = {}

        def _call():
            """
            Purpose:
                Record one call from inside the named thread.

            Side effects:
                Writes one record and marks the call as done.
            """
            provider.record_call_metrics({"prompt_eval_count": 1, "eval_count": 1})
            result["done"] = True

        thread = threading.Thread(target=_call, name="region-1-a")
        thread.start()
        thread.join()
        row = json.loads(om.get_llm_metrics_path().read_text().splitlines()[0])
        assert row["region"] == "region-1-a"

    def test_multiple_calls_append_multiple_lines(self, tmp_path):
        """
        Purpose:
            Pin that each call appends its own line rather than replacing the previous one.

        Parameters:
            tmp_path: Directory the output directory is created under.
        """
        provider, om = self._provider_with_output_manager(tmp_path)
        for i in range(5):
            provider.record_call_metrics({"prompt_eval_count": i, "eval_count": i})
        assert len(om.get_llm_metrics_path().read_text().splitlines()) == 5

    def test_concurrent_calls_do_not_corrupt_the_file(self, tmp_path):
        """
        Purpose:
            Pin that calls recorded from many threads at once produce exactly that many lines, each of them intact.

        Parameters:
            tmp_path: Directory the output directory is created under.

        Implementation notes:
            Every line is parsed rather than only counted, because interleaved writes produce the right number of newlines and unreadable content between them.
        """
        import json
        import threading

        provider, om = self._provider_with_output_manager(tmp_path)

        def _call(i):
            """
            Purpose:
                Record one call.

            Parameters:
                i: A value making this call's record distinguishable.

            Side effects:
                Writes one record.
            """
            provider.record_call_metrics({"prompt_eval_count": i, "eval_count": i})

        threads = [threading.Thread(target=_call, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = om.get_llm_metrics_path().read_text().splitlines()
        assert len(lines) == 50
        for line in lines:
            json.loads(line)

    def test_no_output_manager_is_a_silent_no_op(self):
        """
        Purpose:
            Pin that a provider with nowhere to write records does nothing rather than failing.

        Implementation notes:
            The command-line path builds providers without an output directory, so raising here would fail every scan that did not go through the web interface.
        """
        from lu77U_MobileSec.ai.base_provider import BaseAIProvider

        class _P(BaseAIProvider):
            """
            Purpose:
                A minimal concrete provider, so the accounting under test is the base class's own.

            Attributes:
                name: The provider name the base class requires.
            """
            name = "test"

            def analyze(self, *a, **kw):
                """
                Purpose:
                    Answer any request with an empty finding list.

                Parameters:
                    a: Positional arguments, ignored.
                    kw: Keyword arguments, ignored.

                Returns:
                    A response holding an empty list.
                """
                return {"response": "[]"}

            def list_models(self):
                """
                Purpose:
                    Satisfy the base class's model listing requirement.

                Returns:
                    An empty list.
                """
                return []

            def validate_credentials(self):
                """
                Purpose:
                    Satisfy the base class's credential check requirement.

                Returns:
                    True, since there is nothing to validate against.
                """
                return True

        provider = _P()
        provider.record_call_metrics({"prompt_eval_count": 1, "eval_count": 1})

    def test_ollama_writes_a_metrics_line_on_a_successful_call(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a real provider writes a record on a successful call, carrying the counts the model reported.

        Parameters:
            tmp_path: Directory the output directory is created under.
            monkeypatch: Removes the backoff delay.
        """
        import json

        import lu77U_MobileSec.ai.ollama_provider as op
        from lu77U_MobileSec.utils.output_manager import OutputManager

        monkeypatch.setattr(op.time, "sleep", lambda s: None)

        def _chunk(content="", done=False, done_reason=None, **metrics):
            """
            Purpose:
                Build one streamed response chunk in the shape the client yields.

            Parameters:
                content: The visible text in this chunk.
                done: Whether this is the final chunk.
                done_reason: Why generation ended, carried only on the final chunk.
                metrics: Counters carried on the final chunk.

            Returns:
                The chunk.
            """
            part = {"message": {"content": content}, "done": done}
            if done:
                part["done_reason"] = done_reason
                part.update(metrics)
            return part

        class _Client:
            """
            Purpose:
                A client that answers once with counts attached.
            """
            def chat(self_, *a, **kw):
                """
                Purpose:
                    Yield a single complete answer carrying its counts.

                Parameters:
                    self_: The client instance, named apart from the usual receiver so it does not shadow the enclosing test's own.
                    a: Positional arguments, ignored.
                    kw: Keyword arguments, ignored.

                Returns:
                    A single final chunk.
                """
                yield _chunk("[]", done=True, done_reason="stop",
                            prompt_eval_count=500, eval_count=10)

        om = OutputManager()
        om.create_output_directory(str(tmp_path / "app.apk"))
        prov = op.OllamaProvider(config={"mode": "cloud"}, api_keys=["k"],
                                 output_manager=om)
        prov._client = _Client()
        prov.analyze("p", system_message="s")

        row = json.loads(om.get_llm_metrics_path().read_text().splitlines()[0])
        assert row["prompt_eval_count"] == 500
        assert row["eval_count"] == 10


class TestAnalysisAliasMatchesAnalyzerDetails:
    """
    Purpose:
        The two views of a scan's outcome that the stored result carries, and that they cannot drift apart.

    Implementation notes:
        The stored result carries the same five values twice, kept because the interface reads some of them directly, but derived from one place so the two views stay in step.
    """
    def _analyzer_results(self):
        """
        Purpose:
            Build one completed analysis result.

        Returns:
            The result.
        """
        return {
            "framework": "Java/Kotlin", "analysis_time": 42.5,
            "files_analyzed": 137, "decompilation_status": "Successful",
            "error": None, "unsupported_framework": False,
        }

    def test_the_five_shared_fields_match_analyzer_details(self):
        """
        Purpose:
            Pin that each shared field in the second view matches the first.
        """
        from lu77U_MobileSec.web.serializers import _analysis_alias

        analyzer_results = self._analyzer_results()
        alias = _analysis_alias(analyzer_results, supported=True,
                                framework_name="Java/Kotlin")
        for field in ("framework", "analysis_time", "files_analyzed",
                     "decompilation_status", "error"):
            assert alias[field] == analyzer_results[field]

    def test_success_is_derived_from_decompilation_status(self):
        """
        Purpose:
            Pin that success is read off the decompilation outcome rather than stated separately.

        Implementation notes:
            A separate flag is one more thing that can disagree with what actually happened, and the decompilation outcome is already the thing that decides it.
        """
        from lu77U_MobileSec.web.serializers import _analysis_alias

        ok = _analysis_alias(dict(self._analyzer_results()), True, "x")
        failed = _analysis_alias(
            dict(self._analyzer_results(), decompilation_status="Failed"), True, "x")
        assert ok["success"] is True
        assert failed["success"] is False

    def test_build_result_uses_the_same_alias_function(self, tmp_path):
        """
        Purpose:
            Pin that the stored result is built by the same function rather than by a second copy of the logic.

        Parameters:
            tmp_path: Temporary directory, accepted so the signature matches the others here.
        """
        from lu77U_MobileSec.web.serializers import _analysis_alias, build_result

        analyzer_results = self._analyzer_results()
        result = build_result(
            json_path=None, detection_result=None,
            analyzer_results=analyzer_results, supported=True,
            framework_name="Java/Kotlin")
        assert result["analysis"] == _analysis_alias(
            analyzer_results, True, "Java/Kotlin")
