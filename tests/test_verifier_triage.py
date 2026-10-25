#!/usr/bin/env python3
"""
Module: test_verifier_triage

Purpose:
    What decides which findings get device steps and in what order: the cheap triage request, the Android-version limit, the opening context and the agent's proof rules.

Responsibilities:
    Pin that the triage answer is read under the schema's key, under another name when it is the object's only list, and that anything else falls back to verifying every finding; that a finding limited to older Android is set aside on a newer device; that the agent sees the device's version and the most severe findings first; and that its prompt carries the proof rules.

Dependencies:
    pytest and the dynamic verifier.

Implementation notes:
    Triage had failed on every scan: a 300-token cap truncated it twice, and the third answer, from a model the schema was not enforced on, named its list "runtime_verification_needed". Each failure sent every finding to the device, and a Ghera scan's exported activity, the finding that most needed the device, was not reached within the step budget.
"""

import pytest

from lu77U_MobileSec.dynamic_analysis.verifier import _classify_needs_verification

FINDINGS = [{"_verify_id": f"F{i}", "title": f"Finding {i}", "description": "d"} for i in (1, 2, 3)]


class _Provider:
    """
    Purpose:
        A provider that answers the triage request with a fixed response and records the prompt.

    Attributes:
        response: The raw text to return.
        prompts: Prompts received, in order.
    """

    def __init__(self, response):
        """
        Purpose:
            Hold the canned response.

        Parameters:
            response: The raw text to return.
        """
        self.response = response
        self.prompts = []

    def analyze(self, prompt, **unused_kwargs):
        """
        Purpose:
            Record the prompt and return the canned response.

        Parameters:
            prompt: The triage prompt.
            unused_kwargs: System message, schema and cap, ignored.

        Returns:
            A provider-shaped success dict.

        Side effects:
            Records the prompt.
        """
        self.prompts.append(prompt)
        return {"response": self.response}


@pytest.mark.parametrize("response, expected", [
    ('{"need_runtime_verification": ["F1", "F3"]}', {"F1", "F3"}),
    ('```json\n{"runtime_verification_needed": ["F2"]}\n```', {"F2"}),
    ('{"need_runtime_verification": ["F9", "F1"]}', {"F1"}),
    ('{"first": ["F1"], "second": ["F2"]}', {"F1", "F2", "F3"}),
    ('not json at all', {"F1", "F2", "F3"}),
])
def test_the_triage_answer_is_read(response, expected):
    """
    Purpose:
        The schema's key, a lone list under another name, an unknown id dropped, two lists and no JSON each give the expected selection.

    Parameters:
        response: The model's raw answer.
        expected: The ids that should be taken to the device.
    """
    provider = _Provider(response)
    assert _classify_needs_verification(provider, FINDINGS, verbose=False) == expected


def test_the_prompt_names_the_key():
    """
    Purpose:
        A model the schema is not enforced on is told the field name rather than left to choose one.
    """
    provider = _Provider('{"need_runtime_verification": []}')
    assert _classify_needs_verification(provider, FINDINGS, verbose=False) == set()
    assert '"need_runtime_verification"' in provider.prompts[0]


@pytest.mark.parametrize("release, limited", [("11", True), ("10", False), ("12.1", True), (None, False)])
def test_a_finding_limited_to_older_android_is_not_reproducible_on_newer(release, limited):
    """
    Purpose:
        Pin that a finding stating it applies to Android 10 and lower is set aside on a newer device with that reason, and taken to the device otherwise.

    Parameters:
        release: The device's Android version.
        limited: Whether the finding is set aside.
    """
    from lu77U_MobileSec.dynamic_analysis.verifier import version_limited
    finding = {"title": "Task hijacking (StrandHogg) possible on Android 10 and lower", "description": ""}
    reason = version_limited(finding, release)
    assert bool(reason) is limited
    if reason:
        assert "Android 10 and lower" in reason and f"Android {release}" in reason
    assert version_limited({"title": "SQL injection in NotesProvider", "description": ""}, "11") is None


def test_the_agent_sees_the_device_version_and_the_most_severe_first():
    """
    Purpose:
        Pin that the opening context states the device's Android version and lists findings most severe first.
    """
    from lu77U_MobileSec.dynamic_analysis.verifier import _build_initial_context
    findings = [{"_verify_id": "F1", "severity": "Informational", "title": "Note"},
                {"_verify_id": "F2", "severity": "High", "title": "SQL injection in NotesProvider"},
                {"_verify_id": "F3", "severity": "Medium", "title": "Exported activity"}]
    context = _build_initial_context("com.x.y", findings, release="11")
    assert "Android 11" in context
    assert context.index("id=F2") < context.index("id=F3") < context.index("id=F1")


@pytest.mark.parametrize("rule", [
    "Chain steps that must happen in order with &&",
    "never a guessed",
    "send it an explicit Intent (-n) without that action",
    "refute only on a real attempt",
    "tap through to it",
    "not by a hook firing",
    "Prefer read-only proofs",
    "content query|read|insert|update|delete|call",
    "does not prove that finding",
    "never as proof that something happens at runtime",
    "cannot be reproduced here",
    "most severe first",
])
def test_the_verifier_prompt_carries_the_rule(rule):
    """
    Purpose:
        Pin the proof rules the verification agent is given: chained steps, provider commands, the attacker's own input, metadata is not runtime proof, the device's Android version, and severity order.

    Parameters:
        rule: A phrase the prompt must contain.

    Implementation notes:
        Without them a DIVA run proved an exported-activity bypass by having Frida rewrite the app's own return value, called task hijacking verified from dumpsys on Android 11, and spent its steps re-sending chained commands while a High SQL injection went unreached.
    """
    from lu77U_MobileSec.config.prompts import VulnerabilityPrompts
    assert rule in VulnerabilityPrompts.get_dynamic_verification_system("com.x.y")


@pytest.mark.parametrize("vuln_class, configuration", [
    ("BUILD-02", True), ("BUILD-01", True), ("NETWORK-03", True), ("STORAGE-04", True),
    ("PLATFORM-12", True), ("PLATFORM-01", False), ("CODE-01", False), ("", False),
])
def test_configuration_findings_never_take_device_steps(vuln_class, configuration):
    """
    Purpose:
        Pin which findings are left out of device triage as configuration the device cannot add to.

    Parameters:
        vuln_class: The finding's class.
        configuration: Whether it is left out.
    """
    from lu77U_MobileSec.dynamic_analysis.verifier import configuration_finding
    assert configuration_finding({"vuln_class": vuln_class}) is configuration


class TestRefutation:
    """
    Purpose:
        A device verdict that the claimed harm does not happen, and what it does to the finding.
    """

    def test_a_refutation_is_recorded_with_its_evidence(self):
        """
        Purpose:
            Pin that the verifier accepts "refuted" with evidence, as it does "verified", and still refuses an unknown status.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import _record_verdict
        verdicts = {}
        msg = _record_verdict({"status": "refuted", "finding_id": "F1",
                               "evidence": "'am broadcast -n app/.R' ran; 'run-as app ls files' still lists myfile"},
                              {"F1"}, verdicts)
        assert msg.startswith("Recorded verdict") and verdicts["F1"]["status"] == "refuted"
        assert verdicts["F1"]["evidence"].startswith("'am broadcast")
        assert _record_verdict({"status": "maybe", "finding_id": "F1"}, {"F1"}, {}).startswith("ERROR")

    @pytest.mark.parametrize("status, informational", [("refuted", True), ("verified", False), ("not_verified", False)])
    def test_a_refuted_finding_is_graded_informational(self, status, informational):
        """
        Purpose:
            Pin that grading sets a refuted finding aside with the device evidence as its reason and leaves the other verdicts alone.

        Parameters:
            status: The device verdict.
            informational: Whether the finding is set aside.
        """
        from lu77U_MobileSec.validation.gates import GateResult, check_device_refutation
        finding = {"severity": "Medium", "dynamic_verification": {
            "status": status, "evidence": "explicit broadcast as uid 2000 deleted nothing", "reason": "x"}}
        result = GateResult(original_severity="Medium", final_severity="Medium")
        check_device_refutation(finding, result)
        assert (result.verdict == "INFORMATIONAL") is informational
        if informational:
            assert result.reasons == ["Refuted on the device: explicit broadcast as uid 2000 deleted nothing"]

    def test_the_report_shows_a_refutation(self):
        """
        Purpose:
            Pin that the HTML report labels a refuted finding and shows what disproved it.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import ComprehensiveHTMLBuilder
        pill, callout = ComprehensiveHTMLBuilder()._format_dynamic_verification(
            {"dynamic_verification": {"status": "refuted", "evidence": "the file was still there"}})
        assert "Dynamic Refuted" in pill and "the file was still there" in callout


class TestProofReview:
    """
    Purpose:
        The second look at device evidence, after the agent loop.
    """

    @staticmethod
    def _findings():
        """
        Purpose:
            Build one fabricated proof, one sound proof and one unverified finding.

        Returns:
            The findings.
        """
        return [
            {"title": "Credit card in logs", "description": "LogActivity logs the card number.",
             "dynamic_verification": {"status": "verified", "evidence": "A Frida script called Log.e with a card number."}},
            {"title": "SQL injection in NotesProvider", "description": "The selection is concatenated.",
             "dynamic_verification": {"status": "verified", "evidence": "content query with a UNION returned injected rows"}},
            {"title": "Buffer overflow", "description": "strcpy into a fixed buffer.",
             "dynamic_verification": {"status": "not_verified", "reason": "Not reached."}},
        ]

    def test_a_proof_the_review_rejects_is_set_aside_with_its_reason(self):
        """
        Purpose:
            Pin that a verdict the review says the evidence does not support becomes not verified with the reason and keeps its evidence aside, a supported one stands, and an unverified finding is not sent.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import review_proofs
        findings = self._findings()
        provider = _Provider('{"reviews": [{"id": "P0", "holds": false, "reason": "The script called Log.e itself."},'
                             ' {"id": "P1", "holds": true}]}')
        assert review_proofs(provider, findings) == {"reviewed": 2, "rejected": 1}
        fabricated, sound, unverified = findings
        assert fabricated["dynamic_verification"]["status"] == "not_verified"
        assert "called Log.e itself" in fabricated["dynamic_verification"]["reason"]
        assert fabricated["dynamic_verification"]["rejected_evidence"].startswith("A Frida script")
        assert sound["dynamic_verification"]["status"] == "verified"
        assert unverified["dynamic_verification"]["reason"] == "Not reached."
        assert "[P2]" not in provider.prompts[0]

    def test_a_failed_review_keeps_the_verdicts(self):
        """
        Purpose:
            Pin that an unreadable review answer leaves every verdict as the agent gave it.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import review_proofs
        findings = self._findings()
        assert review_proofs(_Provider("not json"), findings) == {"reviewed": 0, "rejected": 0}
        assert [f["dynamic_verification"]["status"] for f in findings] == ["verified", "verified", "not_verified"]

    @pytest.mark.parametrize("label", ["[P0]", "P0", "p0", "0", "[ P0 ]"])
    def test_an_echoed_label_is_read_in_any_form(self, label):
        """
        Purpose:
            Pin that a review entry is matched to its verdict however the model echoes the label.

        Parameters:
            label: The id as written back.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import review_proofs
        findings = self._findings()
        provider = _Provider('{"reviews": [{"id": "%s", "holds": false, "reason": "Frida called Log.e."}]}' % label)
        assert review_proofs(provider, findings) == {"reviewed": 1, "rejected": 1}
        assert findings[0]["dynamic_verification"]["status"] == "not_verified"
