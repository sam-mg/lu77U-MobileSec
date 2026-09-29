#!/usr/bin/env python3
"""
Module: test_chain_annotation

Purpose:
    Relating findings to each other without a model and without guessing.

Responsibilities:
    Pin the cross-references raised from pattern matches and from shared files, that nothing is presented as confirmed without a model, that the existing refusal to publish unconfirmed chains is untouched, that a confirmed chain upgrades its own references, and that the references render in the report.

Dependencies:
    pytest, the validation package's chain and annotation entry points, and the report builder.

Implementation notes:
    On a real scan every one of 48 findings had no chain at all, and one component was reported as three separate rows at two severities with nothing tying them together. Two causes: the confirmation call was a casualty of the same exhausted quota that ended the scan, and the chain builder discards every candidate it cannot get confirmed, so the pairing was computed and thrown away. The answer is a cross-reference rather than a chain. The builder is right that publishing an unconfirmed pattern match at a serious severity is worse than publishing nothing; what was missing is the part that is safe to state unconfirmed.
"""

import pytest

from lu77U_MobileSec.validation import (
    annotate_related_findings, build_chains, find_candidate_chains)


def _f(title, vuln_class, file, line="1", severity="Medium"):
    """
    Purpose:
        Build one finding.

    Parameters:
        title: The finding title.
        vuln_class: The class code the chain patterns match on.
        file: The file the finding is attributed to.
        line: The line the finding is attributed to.
        severity: The finding's severity.

    Returns:
        The finding.
    """
    return {"title": title, "vuln_class": vuln_class, "file": file,
            "line": line, "severity": severity}


def _webview_app():
    """
    Purpose:
        Build the finding set from the real application this module exists because of: a deep link, one component carrying three separate findings, a stored credential and an unpinned connection.

    Returns:
        The findings, in a fixed order the tests index into.
    """
    return [
        _f("Exported activity accepts a deep link", "PLATFORM-02",
           "AndroidManifest.xml", "40"),
        _f('WebView exposes a JavaScript bridge as "DBLAndroid"', "PLATFORM-04",
           "sources/x/DBLWebViewActivity.java", "88", "High"),
        _f("WebView file access is enabled", "PLATFORM-05",
           "sources/x/DBLWebViewActivity.java", "214"),
        _f("Hardcoded Password", "SECRET-01", "sources/H0/f.java", "22", "High"),
        _f("Certificate pinning is not configured", "NETWORK-01",
           "res/xml/network_security_config.xml", "3"),
    ]


def _related(finding, pattern=None):
    """
    Purpose:
        Read a finding's cross-references, optionally narrowed to one kind.

    Parameters:
        finding: The finding to read.
        pattern: Either the shared-file kind, the pattern-match kind, or None for both.

    Returns:
        The matching references, or an empty list when there are none.
    """
    items = finding.get("related_findings") or []
    if pattern == "chain":
        return [r for r in items if r["pattern"] != "same-file"]
    if pattern == "same-file":
        return [r for r in items if r["pattern"] == "same-file"]
    return items


class TestChainCandidatesSurfaceWithoutAModel:
    """
    Purpose:
        The cross-references raised from pattern matches alone.
    """
    def test_a_deep_link_reaching_a_js_bridge_is_cross_referenced(self):
        """
        Purpose:
            Pin that a deep link and the bridge it can reach are cross-referenced, naming the component.

        Implementation notes:
            This is the pairing that was computed and discarded on the real scan, which is why the pattern is asserted by name rather than by the reference merely existing.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        deep_link = findings[0]
        chains = _related(deep_link, "chain")
        assert any(r["pattern"] == "CHAIN-01" for r in chains), \
            "the priority deep-link-to-WebView chain did not surface"
        assert any("DBLWebViewActivity" in r["with"]["file"] for r in chains)

    def test_unpinned_tls_pairs_with_the_credential_it_carries(self):
        """
        Purpose:
            Pin that an unpinned connection is cross-referenced with the stored credential that travels over it.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        pinning = findings[4]
        assert any(r["pattern"] == "CHAIN-09"
                   for r in _related(pinning, "chain"))

    def test_cross_references_are_reciprocal(self):
        """
        Purpose:
            Pin that a reference appears on both findings rather than only on one.

        Implementation notes:
            A reader arrives at either finding first, so a one-way reference hides the relationship from whichever of the two they happen to open.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        deep_link, bridge = findings[0], findings[1]
        assert any(r["with"]["title"] == bridge["title"]
                   for r in _related(deep_link, "chain"))
        assert any(r["with"]["title"] == deep_link["title"]
                   for r in _related(bridge, "chain"))

    def test_nothing_is_marked_confirmed_without_a_model(self):
        """
        Purpose:
            Pin that every reference raised without a model is marked unconfirmed.

        Implementation notes:
            This is what the whole separation rests on: a pattern match is a hypothesis, and presenting it as a verdict is the report padding the confirmation step exists to prevent.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        for finding in findings:
            assert all(r["confirmed"] is False for r in _related(finding))


class TestSameFileGrouping:
    """
    Purpose:
        The cross-references raised from findings sharing a file.
    """
    def test_findings_on_one_class_are_tied_together(self):
        """
        Purpose:
            Pin that two findings in the same file reference each other.

        Implementation notes:
            This is the case the real scan surfaced as three unconnected rows at two severities, leaving the reader to notice for themselves that they were about one component.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        bridge = findings[1]
        same_file = _related(bridge, "same-file")
        assert [r["with"]["title"] for r in same_file] == [
            "WebView file access is enabled"]

    def test_a_lone_finding_in_its_file_gets_no_same_file_reference(self):
        """
        Purpose:
            Pin that a finding alone in its file gets no shared-file reference.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        assert _related(findings[3], "same-file") == []

    def test_references_are_capped(self):
        """
        Purpose:
            Pin that no finding carries more references than the cap allows.

        Implementation notes:
            Findings cluster in a handful of large files, so without a cap one such file would give every one of its findings a reference to all the others, which is noise rather than a relationship.
        """
        from lu77U_MobileSec.validation.chains import MAX_RELATED

        findings = [_f(f"Issue {i}", "PLATFORM-05", "sources/x/Big.java", str(i))
                    for i in range(20)]
        annotate_related_findings(findings)
        assert all(len(_related(f)) <= MAX_RELATED for f in findings)


class TestGuessSuppressionIsPreserved:
    """
    Purpose:
        That the existing refusal to publish unconfirmed chains was not traded away for the new cross-references.
    """
    def test_build_chains_still_publishes_nothing_without_a_provider(self):
        """
        Purpose:
            Pin that with candidates available but no model to confirm them, no chain is published.

        Implementation notes:
            The precondition is asserted first, so a version of this that passed because no candidate was found would fail instead.
        """
        findings = _webview_app()
        assert find_candidate_chains(findings), "precondition: candidates exist"
        assert build_chains(findings, provider=None) == []

    def test_annotation_adds_no_severity_and_no_chain_field(self):
        """
        Purpose:
            Pin that annotating changes no finding's severity and sets no chain on any of them.

        Implementation notes:
            A cross-reference is a pointer between findings, not a new conclusion, so raising a severity on the strength of one would be exactly the unconfirmed verdict the builder refuses to publish.
        """
        findings = _webview_app()
        before = [dict(f) for f in findings]
        annotate_related_findings(findings)
        for old, new in zip(before, findings):
            assert new["severity"] == old["severity"]
            assert new.get("chain") is None


class TestConfirmationUpgradesTheReference:
    """
    Purpose:
        What happens to a cross-reference once a model confirms the chain behind it.
    """
    def test_a_confirmed_chain_flips_its_own_cross_reference(self):
        """
        Purpose:
            Pin that confirming one chain marks that chain's own references confirmed, with a reason naming the confirmation.
        """
        findings = _webview_app()
        annotate_related_findings(findings)

        class _Provider:
            """
            Purpose:
                A provider that confirms only the first proposal it is given.

            Attributes:
                unavailable: Always absent, marking the provider as healthy.
            """
            unavailable = None

            def analyze(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Confirm the first proposal and nothing else.

                Parameters:
                    _unused_args: The prompt, unused here.
                    _unused_kwargs: The system prompt, schema, images, response limit and conversation key, unused here.

                Returns:
                    A response confirming the first proposal with a short reason and a flow.
                """
                import json
                return {"response": json.dumps([{
                    "id": 0, "confirmed": True, "reason": "reachable",
                    "flow": ["open the deep link", "reach the bridge"]}])}

        chains = build_chains(findings, provider=_Provider())
        assert len(chains) == 1
        confirmed = [r for f in findings for r in _related(f) if r["confirmed"]]
        assert confirmed, "a confirmed chain left its components marked unconfirmed"
        assert all("confirmed chain" in r["reason"] for r in confirmed)


class TestRobustness:
    """
    Purpose:
        Inputs the annotation has to survive.
    """
    @pytest.mark.parametrize("findings", [[], None])
    def test_empty_input_is_handled(self, findings):
        """
        Purpose:
            Pin that an empty or absent finding list annotates nothing rather than raising.

        Parameters:
            findings: An empty list or nothing at all.
        """
        assert annotate_related_findings(findings) == 0

    def test_findings_without_a_file_are_skipped_for_grouping(self):
        """
        Purpose:
            Pin that findings with no file are not grouped together as though they shared one.

        Implementation notes:
            An empty file is what a finding about the application as a whole carries, and treating those as one file would relate every such finding to every other.
        """
        findings = [_f("A", "PLATFORM-05", ""), _f("B", "PLATFORM-05", "")]
        annotate_related_findings(findings)
        assert all(_related(f, "same-file") == [] for f in findings)

    def test_annotation_is_idempotent(self):
        """
        Purpose:
            Pin that annotating twice leaves the same references rather than duplicating them.

        Implementation notes:
            The annotation runs once per scan today, but a resumed scan re-runs the phases after the point it stopped, so a second pass is reachable in normal operation.
        """
        findings = _webview_app()
        annotate_related_findings(findings)
        counts = [len(_related(f)) for f in findings]
        annotate_related_findings(findings)
        assert [len(_related(f)) for f in findings] == counts


class TestReportRendering:
    """
    Purpose:
        How the cross-references appear in the generated report.
    """
    def test_related_findings_render_in_the_html_report(self):
        """
        Purpose:
            Pin that a finding's references reach the rendered report, naming the finding they point at.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        findings = _webview_app()
        annotate_related_findings(findings)
        html = ComprehensiveHTMLBuilder()._format_related(findings[1])
        assert "Related findings" in html
        assert "WebView file access is enabled" in html

    def test_a_finding_with_no_references_renders_nothing(self):
        """
        Purpose:
            Pin that a finding with no references renders no section at all rather than an empty one.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        assert ComprehensiveHTMLBuilder()._format_related({}) == ""
