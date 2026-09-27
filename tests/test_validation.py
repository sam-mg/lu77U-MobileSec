#!/usr/bin/env python3
"""
Module: test_validation

Purpose:
    The gates that grade a finding, the pass that asks a model to review it, and the chains built between findings.

Responsibilities:
    Pin every mechanical gate and its verdict order, the evidence checks that refute a fabricated claim, the model review passes for agent and scanner findings, the chain matching and confirmation, the deduplication of one defect reported twice, the class inference, and how all of it renders in the report.

Dependencies:
    pytest, the validation package, the finding schema, the report builders, the exporters and the deterministic scanners.

Implementation notes:
    The load-bearing property throughout is that nothing is ever deleted. Comparable tools kill weak findings outright, but here the audience owns the application, so a finding that fails every gate still reaches the report as an informational note with a reason attached. A regression that quietly started dropping findings would look like a cleaner report and be a worse tool.
"""

import pathlib

import pytest

from lu77U_MobileSec.validation import (
    CHAIN_PATTERNS, apply_gates, build_chains, classify_weak, deduplicate,
    find_candidate_chains, infer_vuln_class, validate_findings)
from lu77U_MobileSec.validation.claim_terms import (
    CLAIM_TERMS, evidence_supports, salient_terms)
from lu77U_MobileSec.validation.gates import (
    VERDICT_ORDER, lower_severity, normalize_severity, severity_rank)
from lu77U_MobileSec.validation.taxonomy import ALL_CODES, VULN_CLASSES
from lu77U_MobileSec.validation.weak_classes import WEAK_CLASS_RULES


def finding(**kw):
    """
    Purpose:
        Build a finding that passes every gate unless a field is overridden.

    Parameters:
        kw: Fields replacing the defaults.

    Returns:
        The finding.

    Implementation notes:
        Built to pass by default so each test states only the one thing it is about, and a new gate that starts firing on the baseline is caught everywhere at once.
    """
    base = {
        "title": "Exported provider leaks the user's contact database",
        "severity": "High",
        "file": "sources/com/x/Leak.java",
        "line": "42",
        "description": "The provider is exported and returns every row of the "
                       "contacts table to any caller, with no permission check.",
        "impact": "Any installed app reads the user's full contact list.",
        "code_snippet": "return db.query(\"contacts\", null, null, null, null, null, null);",
        "confidence": "HIGH",
    }
    base.update(kw)
    return base


class TestWeakClasses:
    """
    Purpose:
        The table demoting classes of finding that are not vulnerabilities on their own.
    """
    @pytest.mark.parametrize("title,rule_id", [
        ("Application data is backup-enabled", "WEAK-02"),
        ("Application is debuggable in this build", "WEAK-03"),
        ("No certificate pinning declared in the network security config", "WEAK-01"),
        ("Cleartext HTTP traffic is permitted app-wide", "WEAK-05"),
        ("targetSdkVersion 27 permits cleartext traffic by default", "WEAK-05"),
        ("App has no root detection", "WEAK-04"),
        ("Missing obfuscation on release build", "WEAK-10"),
    ])
    def test_real_finding_titles_match_their_rule(self, title, rule_id):
        """
        Purpose:
            Pin that each demotion rule matches the title its scanner actually emits.

        Parameters:
            title: A title a scanner emits.
            rule_id: The rule that must match it.

        Implementation notes:
            A rule matching only a paraphrase of the real title protects nothing, so the titles here are taken verbatim from the scanners rather than written to fit the rules.
        """
        rule = classify_weak({"title": title})
        assert rule is not None and rule.id == rule_id

    @pytest.mark.parametrize("title", [
        "Exported content provider Leak grants URI permissions without protection",
        "Sensitive endpoint reached over cleartext HTTP",
        "WebView exposes a JavaScript bridge as \"AndroidBridge\"",
        "Hardcoded aws access key id shipped in the app",
        "ProGuard mapping file shipped in the APK",
    ])
    def test_real_vulnerabilities_are_not_matched(self, title):
        """
        Purpose:
            Pin that a genuine vulnerability is not demoted by any rule.

        Parameters:
            title: A title that must not be demoted.
        """
        assert classify_weak({"title": title}) is None

    def test_class_code_matches_regardless_of_wording(self):
        """
        Purpose:
            Pin that a finding carrying the class code is matched whatever its title says.
        """
        rule = classify_weak({"title": "something else entirely",
                                   "vuln_class": "STORAGE-04"})
        assert rule is not None and rule.id == "WEAK-02"

    def test_description_is_not_searched(self):
        """
        Purpose:
            Pin that only the title is matched, not the surrounding prose.

        Implementation notes:
            A finding mentioning a weak class in passing is not itself one, and demoting it for the mention would bury a real issue under a note about something else.
        """
        assert classify_weak({
            "title": "Session token stored in plaintext SharedPreferences",
            "description": "This is worse than the allowBackup issue because …",
        }) is None

    def test_every_rule_explains_itself(self):
        """
        Purpose:
            Pin that every rule carries a reason the report can show.

        Implementation notes:
            A demotion with no reason reads as the tool under-rating an issue rather than as a deliberate judgement the reader can disagree with.
        """
        for rule in WEAK_CLASS_RULES:
            assert len(rule.reason) > 60, f"{rule.id} has no usable rationale"


class TestGates:
    """
    Purpose:
        The mechanical gates applied to every finding before any model sees it.
    """
    def test_a_solid_finding_passes_untouched(self):
        """
        Purpose:
            Pin that a well-supported finding passes with nothing changed.
        """
        result = apply_gates(finding())
        assert result.verdict == "PASS"
        assert result.final_severity == "High"

    def test_chain_eligible_never_submit_becomes_chain_required(self):
        """
        Purpose:
            Pin that a finding which is not worth reporting alone, but can form part of a chain, is held for chaining rather than demoted.
        """
        result = apply_gates(finding(title="Application data is backup-enabled"))
        assert result.verdict == "CHAIN_REQUIRED"
        assert result.final_severity == "Informational"
        assert result.chain_eligible is True

    def test_non_chain_eligible_never_submit_becomes_informational(self):
        """
        Purpose:
            Pin that a finding not worth reporting alone and unable to chain is recorded for information.
        """
        result = apply_gates(finding(title="Application is debuggable in this build"))
        assert result.verdict == "INFORMATIONAL"
        assert result.chain_eligible is False

    def test_low_confidence_downgrades(self):
        """
        Purpose:
            Pin that a finding reported with low confidence is lowered.
        """
        result = apply_gates(finding(confidence="LOW"))
        assert result.verdict == "DOWNGRADE"
        assert result.final_severity == "Medium"

    def test_medium_confidence_with_evidence_passes(self):
        """
        Purpose:
            Pin that middling confidence backed by evidence passes.
        """
        assert apply_gates(finding(confidence="MEDIUM")).verdict == "PASS"

    def test_medium_confidence_without_evidence_downgrades(self):
        """
        Purpose:
            Pin that middling confidence with nothing to back it is lowered.

        Implementation notes:
            Confidence alone is the model's own opinion of itself, so it only carries weight when something checkable comes with it.
        """
        result = apply_gates(finding(confidence="MEDIUM", code_snippet="",
                                     proof_of_concept=""))
        assert result.verdict == "DOWNGRADE"

    def test_assertion_without_support_downgrades(self):
        """
        Purpose:
            Pin that a claim with nothing supporting it is lowered.
        """
        result = apply_gates({"title": "Insecure", "severity": "Critical",
                              "description": "bad"})
        assert result.verdict == "DOWNGRADE"
        assert "without showing it" in " ".join(result.reasons)

    def test_uncheckable_claim_downgrades(self):
        """
        Purpose:
            Pin that a claim nothing could verify either way is lowered.

        Implementation notes:
            A claim that cannot be checked cannot be acted on, and reporting it at full severity spends the reader's attention on something they cannot resolve.
        """
        result = apply_gates({
            "title": "Insecure storage", "severity": "High",
            "description": "The application stores sensitive information in an "
                           "insecure manner across several components."})
        assert result.verdict == "DOWNGRADE"

    def test_the_strongest_verdict_wins(self):
        """
        Purpose:
            Pin that when several gates fire, the strongest verdict is the one applied.

        Implementation notes:
            A finding that is both unreportable alone and low confidence collects two verdicts, and applying the weaker one would let a gate be bypassed by tripping another.
        """
        result = apply_gates(finding(title="Application data is backup-enabled",
                                     confidence="LOW"))
        assert result.verdict == "CHAIN_REQUIRED"
        assert len(result.reasons) >= 2

    def test_sdk_dependent_claims_get_a_warning_not_a_downgrade(self):
        """
        Purpose:
            Pin that a claim depending on a third-party component's behaviour is flagged rather than lowered.

        Implementation notes:
            Whether it holds depends on a version the scan cannot see, so it is neither confirmed nor refutable and the reader is told which it is.
        """
        result = apply_gates(finding(
            title="targetSdkVersion 29 allows implicit component export"))
        assert result.warnings
        assert "targetSdkVersion" in result.warnings[0]

    def test_verdict_order_is_the_documented_one(self):
        """
        Purpose:
            Pin the ordering the verdicts are ranked in.

        Implementation notes:
            Everything above relies on that ranking, so it is asserted directly rather than only through its consequences.
        """
        assert VERDICT_ORDER == ("PASS", "DOWNGRADE", "CHAIN_REQUIRED",
                                 "FALSE_POSITIVE", "INFORMATIONAL")

    @pytest.mark.parametrize("value,expected", [
        ("info", "Informational"), ("INFORMATIONAL", "Informational"),
        ("critical", "Critical"), ("nonsense", "Medium"), (None, "Medium"),
    ])
    def test_severity_normalization(self, value, expected):
        """
        Purpose:
            Pin how severities of varying wording and case are normalised.

        Parameters:
            value: The severity as written.
            expected: What it must normalise to.
        """
        assert normalize_severity(value) == expected

    def test_lowering_stops_at_informational(self):
        """
        Purpose:
            Pin that lowering a finding bottoms out at informational rather than removing it.

        Implementation notes:
            This is the never-delete policy expressed in the arithmetic: there is no severity below the one that keeps a finding in the report.
        """
        assert lower_severity("Informational") == "Informational"
        assert lower_severity("Critical", steps=9) == "Informational"


class TestClaimTermTable:
    """
    Purpose:
        The table mapping a claim in a title to the terms that would appear in code supporting it.
    """
    def test_every_term_has_at_least_one_trigger_and_one_alias(self):
        """
        Purpose:
            Pin that every claim has both something that raises it and something that could support it.

        Implementation notes:
            A claim with no supporting term can never be confirmed and would refute every finding that made it.
        """
        for term in CLAIM_TERMS:
            assert term.triggers, f"{term.id} has no trigger"
            assert term.aliases, f"{term.id} has no alias"

    def test_a_trigger_is_never_a_substring_of_an_unrelated_word(self):
        """
        Purpose:
            Pin that no trigger fires inside an unrelated word.

        Implementation notes:
            A short trigger matching inside a longer identifier raises a claim the finding never made, and the evidence check then refutes it for lacking support it was never supposed to have.
        """
        assert salient_terms("Interesting phrases in the app") == []

    def test_sha_dash_one_and_sha1_are_the_same_claim(self):
        """
        Purpose:
            Pin that the two spellings of one algorithm are treated as the same claim.
        """
        assert (salient_terms("SHA-1 signature check")
                == salient_terms("SHA1 signature check"))

    def test_no_terms_found_supports_anything(self):
        """
        Purpose:
            Pin that a claim with no terms present is unsupported.
        """
        assert evidence_supports([], "irrelevant") is True

    def test_no_evidence_supports_nothing(self):
        """
        Purpose:
            Pin that with no code to look at, nothing is supported.
        """
        assert evidence_supports(["aes"], "") is False


class TestClaimEvidenceGate:
    """
    Purpose:
        Refuting a finding whose cited code contains nothing supporting its claim.

    Implementation notes:
        Both of the real fabrications this guards against were scored near the top of the scale and passed the model's own review, and neither of their cited files contained a single occurrence of the algorithm, the key type, the cipher class or the package the titles named.
    """
    def test_a_title_claiming_aes_with_no_aes_in_the_snippet_is_refuted(self):
        """
        Purpose:
            Pin that a title naming an algorithm with no trace of it in the cited code is refuted.
        """
        result = apply_gates({
            "title": "Hardcoded AES key in D.java",
            "severity": "High",
            "file": "sources/A/D.java",
            "line": 8,
            "code_snippet": "    public final A.C0053s f19a;",
            "description": "The class hardcodes an AES key used for local encryption.",
            "confidence": "HIGH",
        })
        assert result.verdict == "FALSE_POSITIVE"
        assert result.mechanically_refuted is True
        assert result.final_severity == "Informational"

    def test_the_same_title_with_secretkeyspec_in_the_snippet_passes(self):
        """
        Purpose:
            Pin that the same title passes when the cited code holds a supporting term.
        """
        result = apply_gates(finding(
            title="Hardcoded AES key in a helper class",
            code_snippet='SecretKeySpec key = new SecretKeySpec(bytes, "AES");'))
        assert result.verdict == "PASS"
        assert result.mechanically_refuted is False

    def test_a_sha1_title_is_supported_by_a_sha_dash_1_snippet(self):
        """
        Purpose:
            Pin that a claim is supported by either spelling of the term in the code.
        """
        result = apply_gates(finding(
            title="Use of cryptographically broken SHA1 hash function",
            code_snippet='MessageDigest.getInstance("SHA-1")'))
        assert result.verdict == "PASS"

    @pytest.mark.parametrize("title", [
        "App requests 5 dangerous permissions",
        "No network security config declared",
        "Backup is enabled",
        "Application data is backup-enabled",
    ])
    def test_an_abstract_title_is_never_gated(self, title):
        """
        Purpose:
            Pin that a title making no checkable claim is not gated at all.

        Parameters:
            title: A title making no claim about specific code.

        Implementation notes:
            A gate that refuted every title it could not verify would refute most of the real findings in a scan.
        """
        result = apply_gates(finding(title=title, code_snippet=""))
        assert result.mechanically_refuted is False

    def test_a_finding_with_no_code_evidence_is_downgraded_not_refuted(self):
        """
        Purpose:
            Pin that a finding with no code attached is lowered rather than refuted.

        Implementation notes:
            Absent evidence is not contrary evidence, and refuting on it would punish a finding for the enrichment step having failed rather than for being wrong.
        """
        result = apply_gates({
            "title": "Hardcoded AES key shipped in the app",
            "severity": "High",
            "description": "x" * 60,
        })
        assert result.verdict == "DOWNGRADE"
        assert result.mechanically_refuted is False

    def test_a_chain_finding_is_skipped(self):
        """
        Purpose:
            Pin that a chain finding is not put through this gate.

        Implementation notes:
            A chain's claim is about the relationship between findings rather than about any one file, so no single snippet could support it.
        """
        result = apply_gates(finding(
            title="Deep link reaches a JavaScript bridge",
            source="chain-builder",
            chain={"id": "chain-001"},
            code_snippet="two components combine to reach this bridge"))
        assert result.mechanically_refuted is False

    def test_code_context_lines_count_as_evidence(self):
        """
        Purpose:
            Pin that the surrounding lines attached to a finding count as evidence alongside the excerpt.
        """
        result = apply_gates(finding(
            title="Hardcoded AES key in a helper class",
            code_snippet="",
            code_context={"lines": ["byte[] k = new SecretKeySpec(raw, \"AES\").getEncoded();"]}))
        assert result.verdict == "PASS"

    def test_a_jadx_stack_trace_snippet_is_refuted(self):
        """
        Purpose:
            Pin that a finding whose whole cited excerpt is decompiler diagnostic output is refuted.

        Implementation notes:
            That output is the decompiler describing its own failure, so anything read out of it is a claim about the tool rather than about the application.
        """
        result = apply_gates(finding(
            title="Hardcoded token strings in multiple files",
            severity="Medium",
            code_snippet="\tat jadx.plugins.kotlin.metadata.pass."
                         "KotlinMetadataDecompilePass.visit(KotlinMetadataDecompilePass.kt:33)"))
        assert result.verdict == "FALSE_POSITIVE"
        assert result.mechanically_refuted is True

    def test_a_jadx_comment_elsewhere_in_the_window_does_not_refute(self):
        """
        Purpose:
            Pin that diagnostic output merely nearby does not refute a finding whose own line is real code.
        """
        result = apply_gates(finding(
            title="Hardcoded AES key in a helper class",
            code_snippet='SecretKeySpec key = new SecretKeySpec(bytes, "AES");',
            code_context={"lines": ["/* JADX WARN: Removed duplicated region */",
                                    'SecretKeySpec key = new SecretKeySpec(bytes, "AES");']}))
        assert result.verdict == "PASS"

    def test_a_refuted_finding_lands_on_informational(self):
        """
        Purpose:
            Pin that a refuted finding is lowered to the bottom severity.
        """
        result = apply_gates({
            "title": "Hardcoded AES key in D.java", "severity": "High",
            "code_snippet": "    public final A.C0053s f19a;",
            "description": "x" * 60})
        assert result.final_severity == "Informational"

    def test_a_refuted_finding_is_still_returned(self):
        """
        Purpose:
            Pin that a refuted finding is still in the returned list.

        Implementation notes:
            The never-delete policy applied to the strongest verdict there is: even a fabrication is demoted rather than dropped, so the reader can see what was claimed and why it was rejected.
        """
        out = validate_findings([{
            "title": "Hardcoded AES key in D.java", "severity": "High",
            "file": "sources/A/D.java",
            "code_snippet": "    public final A.C0053s f19a;",
            "description": "x" * 60}])
        assert len(out) == 1
        assert out[0]["gate_result"]["mechanically_refuted"] is True

    def test_a_refuted_finding_never_reaches_the_model(self):
        """
        Purpose:
            Pin that a mechanically refuted finding is not sent to the model for review.

        Implementation notes:
            The mechanical refutation is already conclusive, so paying for a review of it spends a request to be told what is already known.
        """
        judge = _Judge([{"id": 0, "verdict": "PASS", "reason": "n/a"}])
        validate_findings([{
            "title": "Hardcoded AES key in D.java", "severity": "High",
            "file": "sources/A/D.java",
            "code_snippet": "    public final A.C0053s f19a;",
            "description": "x" * 60}], provider=judge)
        assert judge.prompts == []

    def test_source_unresolved_downgrades_rather_than_refutes(self):
        """
        Purpose:
            Pin that a finding whose file could not be located is lowered rather than refuted.

        Implementation notes:
            Nothing about the claim was checked, so refuting it would convert a lookup failure into a verdict about the application.
        """
        result = apply_gates(finding(
            title="Hardcoded AES key in a helper class",
            code_snippet="", source_unresolved=True))
        assert result.verdict == "DOWNGRADE"
        assert result.mechanically_refuted is False


class TestValidateFindings:
    """
    Purpose:
        The top-level grading pass over a whole list of findings.
    """
    def test_nothing_is_ever_removed(self):
        """
        Purpose:
            Pin that grading returns as many findings as it was given.
        """
        findings = [finding(title="Application is debuggable in this build"),
                    finding(title="Application data is backup-enabled"),
                    finding()]
        out = validate_findings(list(findings))
        assert len(out) == 3

    def test_findings_come_back_worst_first(self):
        """
        Purpose:
            Pin that the graded list is ordered by severity.
        """
        out = validate_findings([
            finding(title="Application is debuggable in this build"),
            finding(severity="Critical", title="SQL injection in NotesProvider"),
            finding(severity="Low", title="Weak hashing in TokenHelper"),
        ])
        assert [f["severity"] for f in out] == ["Critical", "Low", "Informational"]

    def test_gate_result_is_attached_to_every_finding(self):
        """
        Purpose:
            Pin that every finding carries its verdict, including the ones that passed.

        Implementation notes:
            The report reads that field to decide what to show, and a finding without one is indistinguishable from one that was never graded.
        """
        for f in validate_findings([finding(), finding(severity="Low")]):
            assert set(f["gate_result"]) >= {
                "verdict", "reasons", "original_severity", "final_severity",
                "chain_eligible"}

    def test_original_severity_is_preserved_after_a_downgrade(self):
        """
        Purpose:
            Pin that a lowered finding records the severity it came from.

        Implementation notes:
            Without it the reader cannot tell a finding that was always minor from one the gates decided against.
        """
        out = validate_findings([finding(title="Application data is backup-enabled")])
        gate = out[0]["gate_result"]
        assert gate["original_severity"] == "High"
        assert gate["final_severity"] == "Informational"
        assert out[0]["severity"] == "Informational"

    def test_empty_input_is_returned_unchanged(self):
        """
        Purpose:
            Pin that grading nothing returns nothing rather than failing.
        """
        assert validate_findings([]) == []


class _Judge:
    """
    Purpose:
        A provider returning fixed review verdicts.

    Attributes:
        verdicts: The verdicts to return, in order.
        error: An error response to return instead, or None.
        raises: An exception to raise instead, or None.
    """
    def __init__(self, verdicts=None, error=None, raises=None):
        """
        Purpose:
            Build the provider with its scripted outcome.

        Parameters:
            verdicts: The verdicts to return.
            error: An error response to return instead of verdicts.
            raises: An exception to raise instead of answering.
        """
        self.verdicts = verdicts or []
        self.error = error
        self.raises = raises
        self.prompts = []

    def analyze(self, prompt, system_message=None, schema=None, images=None, max_tokens=None, session_key=None):
        """
        Purpose:
            Return the scripted verdicts, the scripted error, or raise.

        Parameters:
            prompt: The review prompt, unused here.
            system_message: The system prompt, unused here.
            schema: The requested response schema, unused here.
            images: Attached images, unused here.
            max_tokens: The response limit, unused here.
            session_key: The conversation key, unused here.

        Returns:
            The scripted response.

        Raises:
            Exception: Whatever was scripted.
        """
        self.prompts.append(prompt)
        if self.raises:
            raise self.raises
        if self.error:
            return {"error": self.error}
        import json
        return {"response": json.dumps(self.verdicts)}


class TestJudgmentPass:
    """
    Purpose:
        The pass that asks a model to review the graded findings.
    """
    def test_the_judge_can_downgrade(self):
        """
        Purpose:
            Pin that the reviewer can lower a finding.
        """
        judge = _Judge([{"id": 0, "verdict": "DOWNGRADE", "severity": "Low",
                         "reason": "The exported activity only shows the About screen."}])
        out = validate_findings([finding(severity="Critical")], provider=judge)
        assert out[0]["severity"] == "Low"
        assert "About screen" in " ".join(out[0]["gate_result"]["reasons"])

    def test_the_judge_cannot_promote(self):
        """
        Purpose:
            Pin that the reviewer cannot raise a finding.

        Implementation notes:
            A review that can raise severity is a second, unanchored analysis pass, and one that would let the model overrule the mechanical rules it was meant to be checked by.
        """
        judge = _Judge([{"id": 0, "verdict": "PASS", "reason": "actually critical"}])
        out = validate_findings(
            [finding(title="Application is debuggable in this build")], provider=judge)
        assert out[0]["severity"] == "Informational"
        assert out[0]["gate_result"]["verdict"] == "INFORMATIONAL"

    def test_a_downgrade_to_a_higher_severity_still_lowers(self):
        """
        Purpose:
            Pin that a lowering verdict naming a higher severity still lowers the finding by one step.
        """
        judge = _Judge([{"id": 0, "verdict": "DOWNGRADE", "severity": "Critical",
                         "reason": "overstated"}])
        out = validate_findings([finding(severity="Medium")], provider=judge)
        assert out[0]["severity"] == "Low"

    def test_provider_error_keeps_the_mechanical_verdicts(self):
        """
        Purpose:
            Pin that a provider error leaves the mechanical verdicts in place.

        Implementation notes:
            The mechanical pass already produced a usable result, so a failed review costs the refinement rather than the grading.
        """
        judge = _Judge(error="rate limited")
        out = validate_findings(
            [finding(title="Application data is backup-enabled")], provider=judge)
        assert out[0]["gate_result"]["verdict"] == "CHAIN_REQUIRED"

    def test_provider_exception_keeps_the_mechanical_verdicts(self):
        """
        Purpose:
            Pin that a provider raising leaves the mechanical verdicts in place.
        """
        judge = _Judge(raises=RuntimeError("connection reset"))
        out = validate_findings(
            [finding(title="Application is debuggable in this build")], provider=judge)
        assert out[0]["severity"] == "Informational"

    def test_out_of_range_ids_are_ignored(self):
        """
        Purpose:
            Pin that a verdict naming a finding that was not in the batch is ignored.

        Implementation notes:
            The identifiers come back from the model, so one outside the batch would otherwise apply a verdict to an unrelated finding.
        """
        judge = _Judge([{"id": 99, "verdict": "INFORMATIONAL", "reason": "x"},
                        {"id": "bad", "verdict": "INFORMATIONAL", "reason": "x"}])
        out = validate_findings([finding()], provider=judge)
        assert out[0]["severity"] == "High"

    def test_large_batches_are_split(self):
        """
        Purpose:
            Pin that more findings than fit in one request are reviewed across several.
        """
        from lu77U_MobileSec.validation.validator import JUDGMENT_BATCH_SIZE as BATCH_SIZE

        judge = _Judge([])
        validate_findings(
            [finding(title=f"Weak hashing in CryptoHelper{i}")
             for i in range(BATCH_SIZE * 2 + 1)],
            provider=judge)
        assert len(judge.prompts) == 3

    def test_the_judge_sees_the_mechanical_verdict(self):
        """
        Purpose:
            Pin that the reviewer is told what the mechanical pass already decided.

        Implementation notes:
            Without it the model re-derives the same conclusion from scratch, and disagrees with it about as often as it agrees.
        """
        judge = _Judge([])
        validate_findings([finding(title="Application data is backup-enabled")],
                          provider=judge)
        assert "mechanical_verdict" in judge.prompts[0]

    def test_a_verdict_with_no_reason_at_all_still_applies(self):
        """
        Purpose:
            Pin that a verdict carrying no reason still takes effect.

        Implementation notes:
            A reason used to be required and was then discarded for any verdict that changed nothing, which paid for a sentence or two of prose nobody ever read.
        """
        judge = _Judge([{"id": 0, "verdict": "DOWNGRADE", "severity": "Low"}])
        out = validate_findings([finding(severity="Critical")], provider=judge)
        assert out[0]["severity"] == "Low"

    def test_reason_is_not_required_by_the_schema(self):
        """
        Purpose:
            Pin that the response schema does not demand a reason.
        """
        from lu77U_MobileSec.validation.validator import _JUDGMENT_SCHEMA, _VERIFY_SCHEMA

        assert "reason" not in _JUDGMENT_SCHEMA["items"]["required"]
        assert "reason" not in _VERIFY_SCHEMA["items"]["required"]


class TestChainMatching:
    """
    Purpose:
        Finding pairs of findings that together form a known attack pattern.
    """
    def _pair(self):
        """
        Purpose:
            Build a pair of findings matching a known chain pattern.

        Returns:
            The two findings.
        """
        return [
            finding(title="Exported activity accepts a deep link url parameter",
                    vuln_class="PLATFORM-02", file="sources/com/x/DeepLink.java"),
            finding(title="WebView exposes a JavaScript bridge as \"AndroidBridge\"",
                    vuln_class="PLATFORM-04", file="sources/com/x/Web.java"),
        ]

    def test_deeplink_plus_js_bridge_is_a_priority_candidate(self):
        """
        Purpose:
            Pin that a link-reachable component paired with an exposed bridge is raised as a priority candidate.
        """
        candidates = find_candidate_chains(self._pair())
        assert candidates
        assert candidates[0]["pattern"].id == "CHAIN-01"

    def test_priority_chains_are_evaluated_first(self):
        """
        Purpose:
            Pin that priority patterns are put forward for confirmation ahead of the rest.

        Implementation notes:
            Only a limited number of candidates are confirmed, so the ordering decides which ones are examined at all.
        """
        candidates = find_candidate_chains(self._pair())
        priority = [c for c in candidates if c["pattern"].priority]
        assert candidates[:len(priority)] == priority

    def test_matching_works_without_vuln_class_codes(self):
        """
        Purpose:
            Pin that a pair still matches when neither finding carries a class code.

        Implementation notes:
            Models leave optional fields empty constantly, so a table matching only on codes matches almost nothing on real output.
        """
        pair = [finding(title="Deep link handler reads the url intent extra"),
                finding(title="addJavascriptInterface binds a native object")]
        assert find_candidate_chains(pair)

    def test_unrelated_findings_produce_no_candidates(self):
        """
        Purpose:
            Pin that unrelated findings raise no candidate.
        """
        pair = [finding(title="Weak random number generator", vuln_class="CRYPTO-01"),
                finding(title="Verbose logging of request bodies", vuln_class="SECRET-01")]
        assert not any(c["pattern"].priority for c in find_candidate_chains(pair))

    def test_a_finding_is_never_chained_to_itself(self):
        """
        Purpose:
            Pin that a finding is never paired with itself.
        """
        one = [finding(title="Deep link reaches addJavascriptInterface WebView",
                       vuln_class="PLATFORM-02")]
        for candidate in find_candidate_chains(one):
            assert candidate["entry_index"] != candidate["target_index"]

    def test_every_pattern_carries_a_fix(self):
        """
        Purpose:
            Pin that every pattern says what to do about it.

        Implementation notes:
            A chain is reported at a higher severity than either of its parts, so it has to come with something the reader can act on.
        """
        for pattern in CHAIN_PATTERNS:
            assert len(pattern.recommendation) > 60, f"{pattern.id} has no usable fix"
            assert len(pattern.impact) > 80, f"{pattern.id} has no usable impact"


class TestChainBuilding:
    """
    Purpose:
        Turning a confirmed candidate into a finding of its own.
    """
    def _pair(self):
        """
        Purpose:
            Build a pair of findings matching a known chain pattern.

        Returns:
            The two findings.
        """
        return [
            finding(title="Exported activity accepts a deep link url parameter",
                    vuln_class="PLATFORM-02", severity="Medium"),
            finding(title="WebView exposes a JavaScript bridge as \"AndroidBridge\"",
                    vuln_class="PLATFORM-04", severity="Medium"),
        ]

    def test_no_provider_means_no_chains(self):
        """
        Purpose:
            Pin that with no model to confirm them, no chain is published.

        Implementation notes:
            An unconfirmed pattern match is a guess, and a guess published at the top severity is worse than no chain at all.
        """
        assert build_chains(self._pair(), provider=None) == []

    def test_a_confirmed_chain_becomes_its_own_finding(self):
        """
        Purpose:
            Pin that a confirmed candidate is published as a finding.
        """
        judge = _Judge([{"id": 0, "confirmed": True, "reason": "The handler passes "
                         "the url extra straight to loadUrl.",
                         "flow": ["Send the deep link", "WebView loads it",
                                  "Attacker page calls the bridge"]}])
        chains = build_chains(self._pair(), provider=judge)
        assert len(chains) == 1
        chain = chains[0]
        assert chain["severity"] == "Critical"
        assert chain["chain"]["pattern"] == "CHAIN-01"
        assert len(chain["chain"]["flow"]) == 3
        assert chain["source"] == "chain-builder"

    def test_rejected_chains_are_dropped(self):
        """
        Purpose:
            Pin that a candidate the model rejected is not published.
        """
        judge = _Judge([{"id": 0, "confirmed": False, "reason": "unrelated classes"}])
        assert build_chains(self._pair(), provider=judge) == []

    def test_components_are_back_referenced(self):
        """
        Purpose:
            Pin that a published chain names the findings it was built from.
        """
        findings = self._pair()
        judge = _Judge([{"id": 0, "confirmed": True, "reason": "reaches it",
                         "flow": ["a", "b"]}])
        build_chains(findings, provider=judge)
        assert any(f.get("chained_into") for f in findings)

    def test_a_chained_component_says_which_chain_rescued_it(self):
        """
        Purpose:
            Pin that a component held back for chaining records the chain that used it.

        Implementation notes:
            Otherwise a finding demoted for being unreportable alone and then used in a chain reads as having been demoted for no reason.
        """
        findings = validate_findings([
            finding(title="Application data is backup-enabled", vuln_class="STORAGE-04"),
            finding(title="Session token stored in plaintext SharedPreferences",
                    vuln_class="SECRET-01"),
        ])
        judge = _Judge([{"id": 0, "confirmed": True,
                         "reason": "adb backup extracts the prefs file",
                         "flow": ["adb backup", "read the token"]}])
        chains = build_chains(findings, provider=judge)
        assert chains
        backup = next(f for f in findings if "backup" in f["title"].lower())
        assert backup["gate_result"]["verdict"] == "CHAIN_REQUIRED"
        assert any("chain-001" in r for r in backup["gate_result"]["reasons"])

    def test_a_chain_is_never_weaker_than_its_components(self):
        """
        Purpose:
            Pin that a chain is at least as severe as the worst finding in it.

        Implementation notes:
            A chain is those findings plus a demonstrated path between them, so it cannot be less serious than either on its own.
        """
        findings = [
            finding(title="Unprotected broadcast carries the session token",
                    vuln_class="PLATFORM-07", severity="Critical"),
            finding(title="Session token in the broadcast extra", vuln_class="SECRET-01",
                    severity="Critical"),
        ]
        judge = _Judge([{"id": 0, "confirmed": True, "reason": "same broadcast",
                         "flow": ["register", "receive"]}])
        chains = build_chains(findings, provider=judge)
        assert chains and chains[0]["severity"] == "Critical"

    def test_provider_failure_produces_no_chains_and_no_crash(self):
        """
        Purpose:
            Pin that a failing provider yields no chains rather than failing the scan.
        """
        judge = _Judge(raises=RuntimeError("provider down"))
        assert build_chains(self._pair(), provider=judge) == []

    def test_a_chain_inherits_cwe_and_owasp_from_its_higher_severity_component(self):
        """
        Purpose:
            Pin that a chain takes its classification from its most severe component.

        Implementation notes:
            Chains previously carried neither field, which made them a third kind of finding alongside the agent's and the scanners', and both of those carry at least one.
        """
        findings = [
            finding(title="Exported activity accepts a deep link url parameter",
                    vuln_class="PLATFORM-02", severity="Medium",
                    cwe="CWE-926", owasp_mobile="M1"),
            finding(title="WebView exposes a JavaScript bridge as \"AndroidBridge\"",
                    vuln_class="PLATFORM-04", severity="High",
                    cwe="CWE-749", owasp_mobile="M7"),
        ]
        judge = _Judge([{"id": 0, "confirmed": True, "reason": "reaches it",
                         "flow": ["a", "b"]}])
        chains = build_chains(findings, provider=judge)
        assert chains[0]["cwe"] == "CWE-749"
        assert chains[0]["owasp_mobile"] == "M7"

    def test_candidate_count_is_capped(self, monkeypatch):
        """
        Purpose:
            Pin that only a bounded number of candidates are put forward for confirmation.

        Parameters:
            monkeypatch: Lowers the cap so it can be reached with a small finding set.

        Implementation notes:
            Every candidate costs a model call, and the number of pairs grows with the square of the findings.
        """
        from lu77U_MobileSec.validation import chains as chains_mod

        judge = _Judge([])
        many = [finding(title=f"Deep link handler {i} reads the url extra",
                        vuln_class="PLATFORM-02") for i in range(20)]
        many += [finding(title=f"WebView bridge {i}", vuln_class="PLATFORM-04")
                 for i in range(20)]
        build_chains(many, provider=judge)
        import json
        sent = json.loads(judge.prompts[0].split("\n\n", 1)[1])
        assert len(sent) <= chains_mod.MAX_CANDIDATES


class TestPipelineCarriesTheNewFields:
    """
    Purpose:
        That the grading fields survive the rest of the pipeline and that every output scores a scan the same way.
    """
    def test_normalize_keeps_grading_fields(self):
        """
        Purpose:
            Pin that normalisation keeps the grading fields.
        """
        from lu77U_MobileSec.utils.response_parser import ResponseParser

        out = ResponseParser().normalize_vulnerability({
            "title": "Exported provider", "vulnerability_type": "Exported provider",
            "file": "A.java", "line": "12", "description": "d",
            "severity": "High", "vuln_class": "PLATFORM-01",
            "gate_result": {"verdict": "PASS"}, "source": "static-analyzer",
            "surface": "component_exposure", "confidence": "HIGH",
        })
        assert out["vuln_class"] == "PLATFORM-01"
        assert out["gate_result"]["verdict"] == "PASS"
        assert out["source"] == "static-analyzer"
        assert out["surface"] == "component_exposure"

    def test_normalize_keeps_title_and_line_for_the_dedup_key(self):
        """
        Purpose:
            Pin that normalisation keeps the three fields deduplication keys on.

        Implementation notes:
            Dropping any of them collapses the key and merges unrelated findings that happen to share a file.
        """
        from lu77U_MobileSec.utils.response_parser import ResponseParser

        out = ResponseParser().normalize_vulnerability({
            "title": "Hardcoded key", "file": "A.java", "line": "12",
            "description": "d", "severity": "High"})
        assert out["title"] == "Hardcoded key"
        assert out["line"] == "12"

    def test_informational_findings_do_not_move_the_security_score(self):
        """
        Purpose:
            Pin that findings recorded for information do not change the score.
        """
        from lu77U_MobileSec.report_generator.json_exporter import JSONExporter

        exporter = JSONExporter()
        data = {"analyzed": True,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0,
                                "info": 12}}
        assert exporter._calculate_security_score(data) == 100.0

    def test_both_score_functions_agree_on_informational(self):
        """
        Purpose:
            Pin that both scoring paths treat informational findings the same way.
        """
        from lu77U_MobileSec.utils.scoring import SEVERITY_WEIGHTS

        assert SEVERITY_WEIGHTS["info"] == 0

    def test_every_report_format_scores_a_scan_identically(self):
        """
        Purpose:
            Pin that every output format produces the same score for one scan.

        Implementation notes:
            They did not: one copy of the formula weighted the top severity differently from the other two, so the same scan scored differently depending on which output the reader opened.
        """
        from lu77U_MobileSec.report_generator.json_exporter import JSONExporter
        from lu77U_MobileSec.utils.scoring import calculate_security_score
        from lu77U_MobileSec.web import serializers

        counts = {"critical": 1, "high": 13, "medium": 26, "low": 5, "info": 3}
        shared = calculate_security_score(counts)

        json_score = JSONExporter()._calculate_security_score(
            {"analyzed": True, "by_severity": counts})
        assert json_score == shared

        assert serializers.calculate_security_score(counts) == shared

    def test_a_realistic_scan_does_not_floor_the_score(self):
        """
        Purpose:
            Pin that a badly affected application and a far worse one do not both report the same floor.

        Implementation notes:
            The old linear penalty bottomed out at roughly ten serious findings, which is most real applications, so the score could not rank a set of them because everything in it scored the same.
        """
        from lu77U_MobileSec.utils.scoring import calculate_security_score

        bad = {"critical": 1, "high": 13, "medium": 26, "low": 5, "info": 0}
        worse = {"critical": 3, "high": 26, "medium": 52, "low": 10, "info": 0}

        assert calculate_security_score(bad) > 0
        assert calculate_security_score(bad) > calculate_security_score(worse)
        assert calculate_security_score(
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == 100.0


class TestReportRendering:
    """
    Purpose:
        How the grading and chain information renders in the report.

    Implementation notes:
        These matter precisely because nothing is deleted: a demoted finding is still in the report, and without the label explaining why, it reads as the tool under-rating an issue rather than as a judgement the reader can weigh.
    """
    def _html(self, vuln):
        """
        Purpose:
            Render one finding's grading block.

        Parameters:
            vuln: The finding to render.

        Returns:
            The rendered markup.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        return ComprehensiveHTMLBuilder()._format_vulnerability_item(vuln)

    def test_a_chain_renders_its_attack_path_in_order(self):
        """
        Purpose:
            Pin that a chain renders its steps in the order they occur.
        """
        html = self._html(finding(chain={
            "id": "chain-001", "pattern": "CHAIN-01", "priority": True,
            "components": ["Deep link handler", "WebView bridge"],
            "flow": ["Victim opens the link", "WebView loads it", "Bridge is called"]}))
        assert "chain-pill" in html
        assert html.index("Victim opens the link") < html.index("WebView loads it")
        assert "high priority" in html

    def test_a_downgrade_shows_the_severity_it_came_from(self):
        """
        Purpose:
            Pin that a lowered finding shows what it was lowered from.
        """
        html = self._html(finding(gate_result={
            "verdict": "CHAIN_REQUIRED", "reasons": ["Backup is a platform default."],
            "warnings": [], "original_severity": "Medium",
            "final_severity": "Informational", "chain_eligible": True,
            "weak_class_rule": "WEAK-02"}))
        assert "Medium to Informational" in html
        assert "WEAK-02" in html
        assert "Backup is a platform default." in html

    def test_a_clean_pass_renders_no_gate_block(self):
        """
        Purpose:
            Pin that a finding that passed cleanly renders no grading block at all.

        Implementation notes:
            A block on every finding would make the ones that were actually changed impossible to spot.
        """
        html = self._html(finding(gate_result={
            "verdict": "PASS", "reasons": [], "warnings": [],
            "original_severity": "High", "final_severity": "High",
            "chain_eligible": False}))
        assert "callout gate" not in html

    def test_a_chained_component_points_at_its_chain(self):
        """
        Purpose:
            Pin that a component used in a chain links to it.
        """
        html = self._html(finding(
            chained_into=["chain-003"],
            gate_result={"verdict": "CHAIN_REQUIRED", "reasons": ["step only"],
                         "warnings": [], "original_severity": "Medium",
                         "final_severity": "Informational", "chain_eligible": True}))
        assert "chain-003" in html

    def test_findings_without_grading_render_unchanged(self):
        """
        Purpose:
            Pin that a finding from before these fields existed still renders.

        Implementation notes:
            Saved scans are re-rendered when a report is regenerated, so the renderer has to handle both shapes.
        """
        html = self._html({"title": "Old finding", "severity": "High",
                           "description": "d", "file": "A.java"})
        assert "callout gate" not in html and "chain-pill" not in html
        assert "Old finding" in html

    def test_gate_reasons_are_escaped(self):
        """
        Purpose:
            Pin that a reason containing markup is escaped when rendered.

        Security considerations:
            Reasons carry text the model wrote and excerpts of the application's own code, so rendering one unescaped would let a crafted application inject markup into the report the analyst opens.
        """
        html = self._html(finding(gate_result={
            "verdict": "DOWNGRADE", "reasons": ["<script>alert(1)</script>"],
            "warnings": [], "original_severity": "High", "final_severity": "Medium",
            "chain_eligible": False}))
        assert "<script>" not in html

    def test_chain_flow_steps_are_escaped(self):
        """
        Purpose:
            Pin that a chain step containing markup is escaped when rendered.

        Security considerations:
            The steps are written by the model from the application's own identifiers, so the same injection route applies.
        """
        html = self._html(finding(chain={
            "id": "c", "pattern": "P", "priority": False, "components": [],
            "flow": ["<img src=x onerror=alert(1)>"]}))
        assert "<img src=x" not in html

    def test_the_json_export_carries_the_grading_fields(self):
        """
        Purpose:
            Pin that the exported data carries the grading fields as well as the report.
        """
        from lu77U_MobileSec.report_generator.json_exporter import JSONExporter

        data = JSONExporter()._build_vulnerability_data({
            "analysis_success": True,
            "vulnerabilities": [finding(
                vuln_class="PLATFORM-04", source="static-analyzer",
                surface="network_webview", chained_into=["chain-001"],
                gate_result={"verdict": "PASS", "reasons": [],
                             "original_severity": "High", "final_severity": "High",
                             "chain_eligible": False})]})
        entry = data["vulnerabilities"]["high"][0]
        assert entry["vuln_class"] == "PLATFORM-04"
        assert entry["source"] == "static-analyzer"
        assert entry["surface"] == "network_webview"
        assert entry["chained_into"] == ["chain-001"]
        assert entry["gate_result"]["verdict"] == "PASS"


class TestClassCodeHygiene:
    """
    Purpose:
        That class codes are used precisely.

    Implementation notes:
        The codes are what the chain builder matches on, so a code used loosely is not a cosmetic problem: it manufactures chains between findings that have nothing to do with each other.
    """
    def test_build_hygiene_findings_are_not_tagged_as_webview_issues(self):
        """
        Purpose:
            Pin that build configuration findings are not given a component-misconfiguration code.

        Implementation notes:
            Tagging them that way made the matcher pair a platform-version note with an exported component as though it were a link-to-bridge chain.
        """
        from lu77U_MobileSec.analyzers.sast.extractors import manifest as mod

        source = pathlib.Path(mod.__file__).read_text()
        for marker in ('title="Application is debuggable in this build"',
                       'title=f"minSdkVersion {min_sdk}'):
            start = source.index(marker)
            block = source[start:start + 400]
            assert 'vuln_class="AND-11"' not in block, marker

    def test_build_notes_do_not_match_any_chain_pattern(self):
        """
        Purpose:
            Pin that build configuration notes match no chain pattern at all.
        """
        notes = [
            finding(title="Application is debuggable in this build",
                    vuln_class="BUILD-01", description="x" * 60),
            finding(title="minSdkVersion 14 supports Android versions without "
                          "modern protections", vuln_class="BUILD-01",
                    description="y" * 60),
            finding(title="App requests 6 dangerous permission(s)",
                    vuln_class="BUILD-01", description="z" * 60),
        ]
        entry = finding(title="Exported activity MainActivity has no permission "
                              "protection", vuln_class="PLATFORM-01")
        assert find_candidate_chains(notes + [entry]) == []


class TestSecretTitles:
    """
    Purpose:
        The wording of the titles the credential scanner emits.
    """
    def test_a_pattern_name_is_not_prefixed_twice(self):
        """
        Purpose:
            Pin that a title is not given a prefix its pattern name already carries.

        Implementation notes:
            The template prepended a word to a name that already began with it, producing a title that repeated itself.
        """
        from lu77U_MobileSec.analyzers.agent.patterns import SECRET_PATTERNS
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets

        assert any(p.name.lower().startswith("hardcoded") for p in SECRET_PATTERNS)

    def test_real_titles_read_correctly(self, tmp_path):
        """
        Purpose:
            Pin that the titles produced from real matches read correctly.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets

        (tmp_path / "Conf.java").write_text(
            'class Conf { String p = "password=hunter2supersecret";\n'
            '  String k = "AKIAIOSFODNN7EXAMPLE"; }')
        titles = [f.title for f in analyze_secrets(tmp_path)]
        assert titles, "expected the fixture to trip at least one pattern"
        for title in titles:
            assert "hardcoded hardcoded" not in title.lower()
            assert title[0].isupper()


def rule_finding(**kw):
    """
    Purpose:
        Build a finding as a deterministic scanner emits it.

    Parameters:
        kw: Fields replacing the defaults.

    Returns:
        The finding.
    """
    base = dict(finding(), source="static-analyzer", detector="webview",
                confidence="MEDIUM", vuln_class="PLATFORM-04")
    base["code_context"] = {
        "start_line": 40, "end_line": 44,
        "highlight_start": 42, "highlight_end": 42,
        "lines": ["void setup() {", "  WebSettings s = w.getSettings();",
                  "  s.setJavaScriptEnabled(true);", "  w.loadUrl(\"file:///android_asset/i.html\");",
                  "}"],
    }
    base.update(kw)
    return base


class TestTaxonomy:
    """
    Purpose:
        The catalogue of class codes and what each one requires.
    """
    def test_every_class_says_what_to_prove(self):
        """
        Purpose:
            Pin that every class states what would prove a finding of that class.

        Implementation notes:
            A class with no proof requirement gives the review pass nothing to check the finding against, so every finding in it passes review by default.
        """
        for entry in VULN_CLASSES:
            assert entry.proof, f"{entry.code} has no proof requirement"

    def test_codes_are_unique(self):
        """
        Purpose:
            Pin that no code is used for two classes.
        """
        assert len(ALL_CODES) == len(set(ALL_CODES))

    def test_tls_bypass_and_missing_pinning_are_different_classes(self):
        """
        Purpose:
            Pin that disabling certificate checking and simply not pinning are separate classes.

        Implementation notes:
            Conflating them is how a trust-everything certificate handler gets demoted to the same optional-hardening note as the absence of pinning.
        """
        from lu77U_MobileSec.validation.taxonomy import is_standalone

        assert is_standalone("NETWORK-01")
        assert not is_standalone("NETWORK-03")

    def test_build_classes_are_not_standalone(self):
        """
        Purpose:
            Pin that build configuration classes are marked as not being vulnerabilities on their own.
        """
        from lu77U_MobileSec.validation.taxonomy import is_standalone

        for code in ("BUILD-01", "BUILD-02", "BUILD-03", "BUILD-04"):
            assert not is_standalone(code), code

    def test_unknown_codes_are_not_demoted(self):
        """
        Purpose:
            Pin that a code the catalogue does not recognise does not cause a demotion.

        Implementation notes:
            A model inventing a code should cost the finding its classification, not its severity.
        """
        from lu77U_MobileSec.validation.taxonomy import is_standalone

        assert is_standalone("MADE-UP-99")

    def test_every_extractor_code_is_in_the_catalogue(self):
        """
        Purpose:
            Pin that every code the scanners emit exists in the catalogue.

        Implementation notes:
            A code absent from the catalogue has no proof requirement and matches no chain, so the finding silently loses both.
        """
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[1] / "lu77U_MobileSec"
        used = set()
        for f in (root / "analyzers" / "sast" / "extractors").glob("*.py"):
            text = f.read_text()
            used |= set(re.findall(r'vuln_class="([A-Z0-9-]+)"', text))
            used |= set(re.findall(r'else "([A-Z0-9-]+)"', text))
        for f in (root / "rules" / "semgrep").rglob("*.yml"):
            used |= set(re.findall(r"vuln_class: ([A-Z0-9-]+)", f.read_text()))
        assert used <= set(ALL_CODES), f"not in the catalogue: {used - set(ALL_CODES)}"

    def test_the_schema_enum_lists_real_codes(self):
        """
        Purpose:
            Pin that the response schema offers the catalogue's codes as a fixed list.

        Implementation notes:
            The catalogue used to be written out as prose in the field description on every request, which cost more to send, still let the model emit anything, and turned an invalid code into a chain that silently never formed rather than an error.
        """
        from lu77U_MobileSec.ai.schema import VULNERABILITY_ITEM_SCHEMA

        codes = VULNERABILITY_ITEM_SCHEMA["properties"]["vuln_class"]["enum"]
        assert "PLATFORM-01" in codes and "NETWORK-01" in codes
        assert set(codes) == set(ALL_CODES)


class TestRuleVerification:
    """
    Purpose:
        The separate review pass for findings a deterministic scanner produced.

    Implementation notes:
        A pattern matching in a file is evidence that a pattern matched. Whether the application is actually vulnerable needs the code around the match, which the scanner never had, so this pass exists to reject the matches that do not survive reading it.
    """
    def test_rule_findings_are_routed_to_the_verification_pass(self):
        """
        Purpose:
            Pin that a scanner finding goes to the verification pass rather than the severity review.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        assert is_rule_finding({"source": "static-analyzer"})
        assert is_rule_finding({"source": "semgrep"})
        assert not is_rule_finding({"source": "chain-builder"})
        assert not is_rule_finding({})

    def test_the_two_passes_use_different_prompts(self):
        """
        Purpose:
            Pin that the two passes ask different questions.

        Implementation notes:
            An agent finding was written by something that read the code, so the question is how serious it is. A scanner finding came from a pattern, so the question is whether it is true at all.
        """
        judge = _Judge([])
        validate_findings([rule_finding(), finding()], provider=judge)
        assert len(judge.prompts) == 2
        rule_prompt = next(p for p in judge.prompts if "why_the_rule_fired" in p)
        assert "code" in rule_prompt

    def test_the_verification_prompt_carries_real_numbered_source(self):
        """
        Purpose:
            Pin that the verification prompt carries the actual source, with line numbers.

        Implementation notes:
            Line numbers are what let the model say which line it is talking about, and without them a verdict cannot be tied back to the finding's location.
        """
        judge = _Judge([])
        validate_findings([rule_finding()], provider=judge)
        prompt = judge.prompts[0]
        assert "setJavaScriptEnabled(true)" in prompt
        assert "42|" in prompt
        assert ">   42|" in prompt

    def test_a_false_positive_is_demoted_not_deleted(self):
        """
        Purpose:
            Pin that a finding the review rejected is demoted rather than removed.
        """
        judge = _Judge([{"id": 0, "verdict": "FALSE_POSITIVE",
                         "reason": "The WebView only loads the bundled asset on line 43."}])
        out = validate_findings([rule_finding()], provider=judge)
        assert len(out) == 1
        assert out[0]["severity"] == "Informational"
        assert out[0]["gate_result"]["verdict"] == "FALSE_POSITIVE"
        assert "bundled asset" in " ".join(out[0]["gate_result"]["reasons"])

    def test_an_unverifiable_rule_finding_is_downgraded_and_kept(self):
        """
        Purpose:
            Pin that a finding the review could not settle is lowered and kept.
        """
        judge = _Judge([{"id": 0, "verdict": "UNVERIFIED",
                         "reason": "The excerpt does not show what calls this."}])
        out = validate_findings([rule_finding(severity="High")], provider=judge)
        assert out[0]["severity"] == "Medium"
        assert out[0]["gate_result"]["verdict"] == "DOWNGRADE"

    def test_a_confirmed_finding_keeps_its_severity(self):
        """
        Purpose:
            Pin that a confirmed finding keeps the severity it had.
        """
        judge = _Judge([{"id": 0, "verdict": "CONFIRMED",
                         "reason": "The URL on line 43 comes from the Intent."}])
        out = validate_findings([rule_finding(severity="High")], provider=judge)
        assert out[0]["severity"] == "High"
        assert out[0]["gate_result"]["rule_verified"] is True
        assert "Confirmed against the source" in " ".join(out[0]["gate_result"]["reasons"])

    def test_confirmation_can_lower_severity_but_never_raise_it(self):
        """
        Purpose:
            Pin that confirmation may lower a finding and never raises it.
        """
        lower = _Judge([{"id": 0, "verdict": "CONFIRMED", "severity": "Low",
                         "reason": "reachable only from the app's own code"}])
        assert validate_findings([rule_finding(severity="High")],
                                 provider=lower)[0]["severity"] == "Low"

        higher = _Judge([{"id": 0, "verdict": "CONFIRMED", "severity": "Critical",
                          "reason": "worse than reported"}])
        assert validate_findings([rule_finding(severity="Medium")],
                                 provider=higher)[0]["severity"] == "Medium"

    def test_confirmation_does_not_rescue_a_weak_class(self):
        """
        Purpose:
            Pin that confirming a finding of a demoted class does not undo the demotion.

        Implementation notes:
            Confirming that a setting is enabled does not make that setting a vulnerability, so the class judgement survives the code check.
        """
        judge = _Judge([{"id": 0, "verdict": "CONFIRMED",
                         "reason": "allowBackup is indeed true"}])
        out = validate_findings(
            [rule_finding(title="Application data is backup-enabled",
                          vuln_class="STORAGE-04")], provider=judge)
        assert out[0]["severity"] == "Informational"
        assert out[0]["gate_result"]["verdict"] == "CHAIN_REQUIRED"

    def test_a_finding_with_no_source_says_so_in_the_prompt(self):
        """
        Purpose:
            Pin that the prompt states plainly when no source could be attached.

        Implementation notes:
            Deciding without the code has to be visible to the model rather than silent, or it answers as though it had read something.
        """
        judge = _Judge([])
        bare = rule_finding()
        bare.pop("code_context"); bare.pop("code_snippet", None)
        validate_findings([bare], provider=judge)
        assert "no source was recovered" in judge.prompts[0]

    def test_a_failed_verification_batch_keeps_the_mechanical_verdicts(self):
        """
        Purpose:
            Pin that a failed verification leaves the mechanical verdicts in place.
        """
        judge = _Judge(raises=RuntimeError("provider down"))
        out = validate_findings(
            [rule_finding(title="Application is debuggable in this build",
                          vuln_class="BUILD-01")], provider=judge)
        assert out[0]["gate_result"]["verdict"] == "INFORMATIONAL"

    def test_rule_findings_batch_smaller_than_agent_findings(self):
        """
        Purpose:
            Pin that scanner findings are reviewed in smaller batches.

        Implementation notes:
            They carry real source with them, so fewer of them fit in one request.
        """
        from lu77U_MobileSec.validation.validator import (
            JUDGMENT_BATCH_SIZE, VERIFY_BATCH_SIZE)

        assert VERIFY_BATCH_SIZE < JUDGMENT_BATCH_SIZE
        judge = _Judge([])
        validate_findings(
            [rule_finding(title=f"WebView bridge exposed in Screen{i}Activity")
             for i in range(VERIFY_BATCH_SIZE * 2)],
            provider=judge)
        assert len(judge.prompts) == 2

    def test_the_review_reason_reaches_the_report(self):
        """
        Purpose:
            Pin that the reviewer's reason is carried through to the report.
        """
        from lu77U_MobileSec.report_generator.comprehensive_html_builder import (
            ComprehensiveHTMLBuilder)

        judge = _Judge([{"id": 0, "verdict": "FALSE_POSITIVE",
                         "reason": "the URL is a string constant on line 43"}])
        out = validate_findings([rule_finding()], provider=judge)
        html = ComprehensiveHTMLBuilder()._format_vulnerability_item(out[0])
        assert "not confirmed" in html
        assert "string constant on line 43" in html


class TestWhichFindingsNeedVerifying:
    """
    Purpose:
        Which findings are worth checking against source and which are not.

    Implementation notes:
        Only pattern matches need checking. A manifest attribute either is set or is not, and sending that to a pass asking whether the code supports it marks a plain fact as unverifiable for lacking code it never had, turning a false-positive filter into a false-negative one.
    """
    def test_pattern_detectors_are_verified(self):
        """
        Purpose:
            Pin that findings from pattern-matching detectors are verified.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        for detector in ("webview", "injection", "tls", "secrets", "semgrep"):
            assert is_rule_finding({"source": "static-analyzer", "detector": detector})

    def test_value_detectors_are_not_verified(self):
        """
        Purpose:
            Pin that findings reading a declared value are not verified.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        for detector in ("manifest", "network-config", "sdk-inventory"):
            assert not is_rule_finding({"source": "static-analyzer",
                                        "detector": detector}), detector

    def test_an_unknown_detector_is_verified(self):
        """
        Purpose:
            Pin that a detector the routing does not recognise is verified.

        Implementation notes:
            Verifying something that did not need it costs a review slot; trusting a pattern that did costs a false positive in the report, so the unknown case errs towards checking.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        assert is_rule_finding({"source": "static-analyzer", "detector": "brand-new"})

    def test_agent_findings_are_never_verified(self):
        """
        Purpose:
            Pin that a finding the agent produced never goes to this pass.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        assert not is_rule_finding({})
        assert not is_rule_finding({"source": "chain-builder"})

    def test_a_manifest_fact_is_not_downgraded_for_having_no_source(self):
        """
        Purpose:
            Pin that a manifest fact is not lowered for having no source code behind it.
        """
        judge = _Judge([{"id": 0, "verdict": "PASS", "reason": "correct as written"}])
        out = validate_findings([rule_finding(
            title="Exported activity Foo has no permission protection",
            vuln_class="PLATFORM-01", detector="manifest", severity="Medium",
            code_context=None)], provider=judge)
        assert out[0]["severity"] == "Medium"
        assert out[0]["gate_result"]["verdict"] == "PASS"

    def test_the_two_kinds_go_to_different_prompts(self):
        """
        Purpose:
            Pin that the two kinds of finding reach different prompts end to end.
        """
        judge = _Judge([])
        validate_findings([
            rule_finding(detector="webview"),
            rule_finding(detector="manifest", title="Application data is backup-enabled",
                         vuln_class="STORAGE-04"),
        ], provider=judge)
        assert len(judge.prompts) == 2
        assert sum("why_the_rule_fired" in p for p in judge.prompts) == 1


class TestDeduplication:
    """
    Purpose:
        One defect, one row in the report.

    Implementation notes:
        A real scan reported one injection twice, at two severities and two adjacent line numbers, from the same agent, plus the exported-component issue once more from the manifest scanner. Collapsing them is worth roughly a third of that report's rows, which is also why the collapse has to be recorded rather than silent.
    """
    def _sql_pair(self):
        """
        Purpose:
            Build two findings describing one injection in different words.

        Returns:
            The two findings.
        """
        return [
            {"title": "SQL injection in exported NotesProvider", "severity": "Critical",
             "file": "sources/x/NotesProvider.java", "line": "56",
             "description": "The NotesProvider concatenates the URI path segment into SQL."},
            {"title": "SQL injection in NotesProvider", "severity": "High",
             "file": "sources/x/NotesProvider.java", "line": "57",
             "description": "The NotesProvider builds SQL from caller input."},
        ]

    def test_the_same_bug_described_twice_collapses(self):
        """
        Purpose:
            Pin that one defect described twice becomes one finding.
        """
        out = deduplicate(self._sql_pair())
        assert len(out) == 1
        assert out[0]["severity"] == "Critical"
        assert "SQL injection in NotesProvider" in out[0]["duplicate_titles"]

    def test_the_survivor_records_what_was_folded_in(self):
        """
        Purpose:
            Pin that the surviving finding records what was merged into it.

        Implementation notes:
            A silent reduction of nearly a third of a report with no trail is a place where a genuine second finding could disappear unnoticed.
        """
        out = deduplicate(self._sql_pair())
        assert out[0]["deduped_into"] == [
            {"title": "SQL injection in NotesProvider",
             "file": "sources/x/NotesProvider.java", "line": "57"}]

    def test_the_collapse_is_logged_naming_both_sides(self, capsys):
        """
        Purpose:
            Pin that a collapse is logged naming both findings.

        Parameters:
            capsys: Captures the printed output.
        """
        deduplicate(self._sql_pair(), verbose=True)
        out = capsys.readouterr().out
        assert "dropped" in out
        assert "SQL injection in NotesProvider" in out
        assert "SQL injection in exported NotesProvider" in out
        assert "sources/x/NotesProvider.java" in out

    def test_a_finding_with_nothing_absorbed_gets_no_deduped_into_field(self):
        """
        Purpose:
            Pin that a finding that absorbed nothing carries no merge record.
        """
        out = deduplicate([
            {"title": "Unique one", "severity": "High", "file": "A.java",
            "vuln_class": "CODE-01", "description": "x" * 60},
            {"title": "Unique two", "severity": "High", "file": "B.java",
            "vuln_class": "CRYPTO-01", "description": "y" * 60},
        ])
        assert all("deduped_into" not in f for f in out)

    def test_the_same_bug_seen_from_two_files_collapses(self):
        """
        Purpose:
            Pin that one defect reported against two different files still collapses.

        Implementation notes:
            The manifest scanner sees it in the manifest and the agent sees it in the class, so no key based on the path could ever join them.
        """
        out = deduplicate([
            {"title": "Exported provider NotesProvider has no permission protection",
             "severity": "High", "file": "AndroidManifest.xml", "source": "static-analyzer",
             "vuln_class": "PLATFORM-01",
             "description": 'Provider "x.NotesProvider" is reachable by any app.'},
            {"title": "Exported ContentProvider without permission protection",
             "severity": "Medium", "file": "sources/x/NotesProvider.java",
             "description": "The NotesProvider is exported and requires no permission."},
        ])
        assert len(out) == 1
        assert out[0]["severity"] == "High"

    def test_two_detectors_agreeing_raises_confidence(self):
        """
        Purpose:
            Pin that two detectors reporting the same defect raises the surviving finding's confidence.

        Implementation notes:
            Corroboration is evidence rather than noise, and treating it as a duplicate to discard throws that evidence away.
        """
        out = deduplicate([
            {"title": "Exported provider NotesProvider has no permission protection",
             "severity": "High", "file": "AndroidManifest.xml", "source": "static-analyzer",
             "vuln_class": "PLATFORM-01", "description": "x.NotesProvider is exported."},
            {"title": "Exported ContentProvider without permission protection",
             "severity": "Medium", "file": "sources/x/NotesProvider.java",
             "description": "The NotesProvider is exported."},
        ])
        assert out[0]["corroborated_by"] == ["agent", "static-analyzer"]
        assert out[0]["confidence"] == "HIGH"

    def test_the_survivor_keeps_the_highest_severity(self):
        """
        Purpose:
            Pin that the surviving finding keeps the worst severity of the group.
        """
        out = deduplicate(self._sql_pair())
        assert out[0]["severity"] == "Critical"

    def test_a_missing_field_is_taken_from_the_duplicate(self):
        """
        Purpose:
            Pin that a field missing from the survivor is filled in from the finding merged into it.

        Implementation notes:
            A shorter record often carries the classification or the line number the longer one left out.
        """
        out = deduplicate([
            {"title": "SQL injection in NotesProvider", "severity": "Critical",
             "file": "sources/x/NotesProvider.java",
             "description": "The NotesProvider concatenates input into SQL." + "x" * 90},
            {"title": "SQL injection in exported NotesProvider", "severity": "High",
             "file": "sources/x/NotesProvider.java", "cwe": "CWE-89", "line": "56",
             "description": "short"},
        ])
        assert out[0]["cwe"] == "CWE-89" and out[0]["line"] == "56"


    def test_different_components_never_merge(self):
        """
        Purpose:
            Pin that findings about different components are never merged.

        Implementation notes:
            A word capitalised only because it begins a sentence is not a component name, and using it as one grouped every exported-component finding in a scan into a single row.
        """
        out = deduplicate([
            {"title": "Exported activity MainActivity has no permission protection",
             "severity": "Medium", "file": "AndroidManifest.xml", "vuln_class": "PLATFORM-01",
             "description": "MainActivity is reachable."},
            {"title": "Exported provider NotesProvider has no permission protection",
             "severity": "High", "file": "AndroidManifest.xml", "vuln_class": "PLATFORM-01",
             "description": "NotesProvider is reachable."},
        ])
        assert len(out) == 2

    def test_an_acronym_is_not_a_subject(self):
        """
        Purpose:
            Pin that an acronym shared by a whole class of findings is not used to group them.

        Implementation notes:
            It appears in every finding of that kind, so grouping on it merged unrelated defects in unrelated classes.
        """
        out = deduplicate([
            {"title": "SQL query built by string concatenation (rawQuery)",
             "severity": "High", "file": "sources/x/SQLInjectionActivity.java",
             "vuln_class": "CODE-01", "description": "concatenated query"},
            {"title": "SQL statement built by string concatenation (execSQL)",
             "severity": "High", "file": "sources/x/InsecureDataStorage2Activity.java",
             "vuln_class": "CODE-01", "description": "concatenated statement"},
        ])
        assert len(out) == 2

    def test_distinct_manifest_facts_never_merge(self):
        """
        Purpose:
            Pin that unrelated manifest facts are not merged with one another.

        Implementation notes:
            The manifest holds a dozen independent facts in one file, so grouping on the path alone would collapse all of them into one.
        """
        out = deduplicate([
            {"title": "minSdkVersion 15 supports Android versions without modern protections",
             "severity": "Informational", "file": "AndroidManifest.xml",
             "vuln_class": "BUILD-02", "description": "minSdk 15"},
            {"title": "targetSdkVersion 23 allows implicit component export",
             "severity": "Informational", "file": "AndroidManifest.xml",
             "vuln_class": "BUILD-02", "description": "targetSdk 23"},
        ])
        assert len(out) == 2

    def test_unclassifiable_findings_are_never_grouped(self):
        """
        Purpose:
            Pin that two findings neither of which could be classified are left separate.

        Implementation notes:
            Guessing that two unrecognisable findings are the same defect is how a genuine second issue gets deleted.
        """
        out = deduplicate([
            {"title": "Something odd", "severity": "Low", "file": "a.java"},
            {"title": "Something else odd", "severity": "Low", "file": "b.java"},
        ])
        assert len(out) == 2


class TestManifestFactDeduplication:
    """
    Purpose:
        Merging the same manifest fact reported by both engines.

    Implementation notes:
        A real scan reported one manifest fact from both engines in plain English with no component named in either title, four times in one scan. Neither title carried anything the ordinary grouping could key on.
    """
    def test_a_manifest_fact_with_no_named_component_still_merges(self):
        """
        Purpose:
            Pin that two reports of one manifest fact merge even with no component named in either.
        """
        out = deduplicate([
            {"title": "Application is debuggable", "severity": "Informational",
             "source": "agent", "file": "AndroidManifest.xml", "line": "18",
             "description": "The android:debuggable flag is set."},
            {"title": "Application is debuggable in this build", "severity": "Informational",
             "source": "static-analyzer", "file": "AndroidManifest.xml", "line": "0",
             "description": "android:debuggable=\"true\" in the manifest."},
        ])
        assert len(out) == 1
        assert out[0]["corroborated_by"] == ["agent", "static-analyzer"]

    def test_a_cross_severity_manifest_duplicate_keeps_the_higher_severity(self):
        """
        Purpose:
            Pin that the same fact reported at two severities merges and keeps the higher one.

        Implementation notes:
            Left unmerged it is counted twice, so one defect reads as two, at two different severities, in the report's own totals.
        """
        scanner = {"title": "targetSdkVersion 23 trusts user-installed CA certificates",
                   "severity": "High", "source": "static-analyzer", "vuln_class": "NETWORK-01",
                   "file": "AndroidManifest.xml", "line": "0",
                   "description": "targetSdkVersion 23 trusts user CAs by default."}
        agent = {"title": "Trusts user-installed CA certificates due to targetSdkVersion 23",
                 "severity": "Low", "source": "agent", "vuln_class": "NETWORK-01",
                 "file": "AndroidManifest.xml", "line": "0",
                 "description": "Because targetSdkVersion is 23, the app trusts "
                                 "user-installed CA certificates for TLS validation."}
        out = deduplicate([scanner, agent])
        assert len(out) == 1
        assert out[0]["severity"] == "High"
        assert out[0]["corroborated_by"] == ["agent", "static-analyzer"]

    def test_an_illustrative_example_in_the_description_does_not_win_the_subject(self):
        """
        Purpose:
            Pin that a concrete example mentioned in the prose does not become what the finding is grouped on.

        Implementation notes:
            The agent's version of an application-wide fact usually names one example of it, and letting that example decide the grouping meant such a finding never merged with the scanner's.
        """
        scanner = {"title": "targetSdkVersion 23 permits cleartext traffic by default",
                   "severity": "Informational", "source": "static-analyzer",
                   "vuln_class": "NETWORK-02", "file": "AndroidManifest.xml", "line": "0",
                   "description": "targetSdkVersion 23 permits cleartext by default."}
        agent = {"title": "Cleartext traffic permitted due to targetSdkVersion 23",
                 "severity": "Informational", "source": "agent", "vuln_class": "NETWORK-02",
                 "file": "AndroidManifest.xml", "line": "0",
                 "description": "The application's targetSdkVersion is 23, which permits "
                                 "cleartext traffic by default. The WebView in "
                                 "InputValidation2URISchemeActivity loads arbitrary URLs "
                                 "from user input, including cleartext HTTP URLs."}
        out = deduplicate([scanner, agent])
        assert len(out) == 1

    def test_description_prose_about_a_different_fact_does_not_force_a_merge(self):
        """
        Purpose:
            Pin that prose explaining one fact by referring to another does not merge the two.

        Implementation notes:
            A note about a missing configuration explains itself by naming what the platform defaults to, and that mention must not fuse it with a finding about the thing it named.
        """
        nsc = {"title": "No network security config declared", "severity": "Informational",
               "source": "agent", "vuln_class": "NETWORK-02", "file": "AndroidManifest.xml",
               "line": "0", "description": "The application does not declare a network "
                                            "security config, relying on platform defaults "
                                            "for TLS validation and cleartext traffic "
                                            "permissions."}
        cleartext = {"title": "Cleartext traffic permitted due to targetSdkVersion 23",
                     "severity": "Informational", "source": "static-analyzer",
                     "vuln_class": "NETWORK-02", "file": "AndroidManifest.xml", "line": "0",
                     "description": "targetSdkVersion 23 permits cleartext by default."}
        out = deduplicate([nsc, cleartext])
        assert len(out) == 2

    def test_a_plural_acronym_is_not_mistaken_for_a_named_component(self):
        """
        Purpose:
            Pin that a pluralised acronym is not taken for a component name.

        Implementation notes:
            It passes neither the all-capitals check, because of the trailing lowercase letter, nor the single-capital one, so a finding merely mentioning it in its prose seized it as a subject and never reached the manifest-fact grouping at all.
        """
        scanner = {"title": "targetSdkVersion 23 trusts user-installed CA certificates",
                   "severity": "High", "source": "static-analyzer", "vuln_class": "NETWORK-01",
                   "file": "AndroidManifest.xml", "line": "0",
                   "description": "targetSdkVersion 23 trusts user CAs by default."}
        agent = {"title": "Trusts user-installed CA certificates due to targetSdkVersion 23",
                 "severity": "Low", "source": "agent", "vuln_class": "NETWORK-01",
                 "file": "AndroidManifest.xml", "line": "0",
                 "description": "The WebView loads arbitrary URLs, and because "
                                 "targetSdkVersion is 23 the app also trusts "
                                 "user-installed CA certificates."}
        out = deduplicate([scanner, agent])
        assert len(out) == 1
        assert out[0]["severity"] == "High"


class TestVulnClassInference:
    """
    Purpose:
        Inferring a finding's class when the model left the field empty.

    Implementation notes:
        The model leaves that field empty on essentially every finding despite the schema asking for it, which leaves both deduplication and the chain builder with nothing to work with.
    """
    @pytest.mark.parametrize("title,expected", [
        ("SQL injection in exported NotesProvider", "CODE-01"),
        ("Exported activity MainActivity has no permission protection", "PLATFORM-01"),
        ("Hardcoded API credentials in APICredsActivity", "SECRET-01"),
        ("Hardcoded sensitive notes stored in unencrypted SQLite database", "STORAGE-03"),
        ("Sensitive information logged (credit card number)", "SECRET-02"),
        ("Insecure storage of credentials to external storage", "STORAGE-02"),
        ("WebView has JavaScript enabled", "PLATFORM-06"),
        ("Application is debuggable in this build", "BUILD-01"),
        ("targetSdkVersion 23 trusts user-installed CA certificates", "NETWORK-01"),
        ("Class exposes 6 @JavascriptInterface methods to WebView content", "PLATFORM-04"),
    ])
    def test_wording_maps_to_the_right_class(self, title, expected):
        """
        Purpose:
            Pin that each way of wording a finding maps to the right class.

        Parameters:
            title: The finding's title.
            expected: The class it must be inferred as.
        """
        assert infer_vuln_class({"title": title}) == expected

    def test_an_explicit_class_from_the_model_wins(self):
        """
        Purpose:
            Pin that a class the model did supply is kept rather than overwritten.
        """
        assert infer_vuln_class(
            {"title": "SQL injection somewhere", "vuln_class": "PLATFORM-01"}) == "PLATFORM-01"

    def test_the_title_outranks_the_description(self):
        """
        Purpose:
            Pin that the title decides the class and the prose does not.

        Implementation notes:
            A storage finding whose prose happens to mention a network address is still a storage finding, and letting the prose vote mislabelled exactly those.
        """
        assert infer_vuln_class({
            "title": "Hardcoded API credentials in APICreds2Activity",
            "description": "The credential is appended to a url parameter of a deep link.",
        }) == "SECRET-01"

    def test_an_unrecognisable_finding_gets_no_class(self):
        """
        Purpose:
            Pin that a finding matching nothing is left without a class rather than guessed at.

        Implementation notes:
            A wrong class is worse than none, because the chain builder matches on it and would pair the finding with something unrelated.
        """
        assert infer_vuln_class({"title": "Something entirely novel"}) == ""

    def test_every_inferred_code_is_in_the_catalogue(self):
        """
        Purpose:
            Pin that every code the inference can produce exists in the catalogue.
        """
        from lu77U_MobileSec.validation.dedupe import _CLASS_HINTS

        assert {code for code, _ in _CLASS_HINTS} <= set(ALL_CODES)


from lu77U_MobileSec.validation.validator import clear_verdict_cache


class TestEvidenceDepthGate:
    """
    Purpose:
        Capping findings from a region that barely read anything before it stopped.

    Implementation notes:
        Five of seven false top-severity findings came from regions that took between one and twelve turns before the provider failed. A forced write-up from a region that read nothing is generation rather than analysis.
    """
    def test_forced_report_from_a_region_that_read_nothing_is_demoted_not_deleted(self):
        """
        Purpose:
            Pin that a finding from a region that read nothing is demoted and kept.
        """
        f = finding(title="SQL injection via rawQuery with variable table name",
                    severity="Critical", agent_origin="forced_report",
                    region_key="region-3-e", region_files_read=1, region_searches=0)
        out = validate_findings([f], provider=None)
        assert len(out) == 1
        assert out[0]["severity"] == "Informational"
        assert out[0]["gate_result"]["verdict"] == "INFORMATIONAL"
        assert "region-3-e" in " ".join(out[0]["gate_result"]["reasons"])

    def test_a_shallow_region_cannot_emit_a_critical(self):
        """
        Purpose:
            Pin that a region that barely read anything cannot produce a top-severity finding.
        """
        f = finding(severity="Critical", agent_origin="report",
                    region_key="region-7-i", region_files_read=2, cited_file_read=True)
        out = validate_findings([f], provider=None)
        assert severity_rank(out[0]["severity"]) <= severity_rank("High")

    def test_a_finding_whose_cited_file_was_never_opened_is_capped(self):
        """
        Purpose:
            Pin that a finding citing a file the region never opened is capped.

        Implementation notes:
            The claim is about code the agent did not read, so whatever produced it was not the code.
        """
        f = finding(severity="Critical", agent_origin="report",
                    region_key="region-1-a", region_files_read=9, cited_file_read=False)
        out = validate_findings([f], provider=None)
        assert severity_rank(out[0]["severity"]) <= severity_rank("Medium")

    def test_a_scanner_finding_has_no_depth_concept(self):
        """
        Purpose:
            Pin that a deterministic finding is unaffected by this gate.

        Implementation notes:
            A scanner reads the file it reports on by construction, so there is no depth to measure.
        """
        result = apply_gates(finding(source="static-analyzer", severity="Critical"))
        assert result.severity_cap == ""


class TestApiClaimGate:
    """
    Purpose:
        Refuting a finding that names specific interfaces the cited file does not contain.

    Implementation notes:
        One real finding scored near the top of the scale named two methods by name, and the file it cited contained neither of them.
    """
    _TITLE = ("WebView file access enabled (setAllowFileAccessFromFileURLs and "
              "setAllowUniversalAccessFromFileURLs)")

    def test_both_named_apis_absent_is_a_mechanical_false_positive(self):
        """
        Purpose:
            Pin that a finding naming interfaces none of which appear in the cited file is refuted.
        """
        result = apply_gates(finding(
            title=self._TITLE,
            code_snippet="settings2.setAllowFileAccess(true);"))
        assert result.verdict == "FALSE_POSITIVE"
        assert result.mechanically_refuted is True

    def test_a_refuted_api_claim_never_reaches_the_model(self):
        """
        Purpose:
            Pin that such a finding is not sent for review.
        """
        judge = _Judge([])
        validate_findings([finding(title=self._TITLE,
                                   code_snippet="settings2.setAllowFileAccess(true);")],
                         provider=judge)
        assert judge.prompts == []

    def test_a_present_api_name_is_not_refuted(self):
        """
        Purpose:
            Pin that a finding is not refuted when one of the names it gives is present.
        """
        result = apply_gates(finding(
            title="setAllowUniversalAccessFromFileURLs enabled",
            code_snippet="s.setAllowUniversalAccessFromFileURLs(true);"))
        assert result.mechanically_refuted is False

    def test_a_pascalcase_class_name_in_the_title_is_not_an_api_claim(self):
        """
        Purpose:
            Pin that a class name in a title is not read as a claim about an interface.

        Implementation notes:
            Titles routinely name the class a finding is in, and treating that as a claim about a method would refute most of them.
        """
        result = apply_gates(finding(
            title="Exported provider LeakActivity returns contacts",
            code_snippet="return db.query(\"contacts\", null, null, null, null, null, null);"))
        assert result.mechanically_refuted is False


class TestCitationTargetGate:
    """
    Purpose:
        Lowering a finding whose cited excerpt points at nothing substantive.
    """
    def test_a_package_line_as_the_whole_snippet_is_downgraded_and_flagged(self):
        """
        Purpose:
            Pin that a finding whose whole excerpt is a package declaration is lowered and marked.

        Implementation notes:
            One real finding was genuine and cited the wrong line, and another was not genuine at all; both cited a line carrying no code, so the gate lowers and marks rather than refuting.
        """
        result = apply_gates(finding(severity="Critical", code_snippet="package p209s9;"))
        assert result.verdict == "DOWNGRADE"
        assert result.needs_recitation is True
        assert severity_rank(result.final_severity) <= severity_rank("Low")

    def test_a_bare_class_declaration_is_downgraded(self):
        """
        Purpose:
            Pin that a finding whose whole excerpt is a class declaration is lowered.
        """
        result = apply_gates(finding(
            severity="High",
            code_snippet="public final class a extends "
                         "android.hardware.fingerprint.FingerprintManager.AuthenticationCallback {"))
        assert result.verdict == "DOWNGRADE"
        assert result.needs_recitation is True

    def test_real_code_is_untouched(self):
        """
        Purpose:
            Pin that a finding citing real code is left alone.
        """
        result = apply_gates(finding(code_snippet="db.rawQuery(\"SELECT \" + t, null);"))
        assert result.needs_recitation is False


class TestSqlProvenanceGate:
    """
    Purpose:
        Capping an injection finding whose concatenated value cannot be influenced from outside.
    """
    @pytest.mark.parametrize("prov", ["constant", "catalogue"])
    def test_a_non_attacker_operand_caps_at_informational(self, prov):
        """
        Purpose:
            Pin that a value fixed at compile time, returned from a closed set, or read from the database's own catalogue caps the finding at the bottom severity.

        Parameters:
            prov: The origin the value was determined to have.
        """
        result = apply_gates(finding(
            title="SQL injection via rawQuery with variable table/column name",
            severity="Critical", operand_provenance=prov))
        assert result.final_severity == "Informational"

    def test_an_external_operand_is_not_capped(self):
        """
        Purpose:
            Pin that a value that can be influenced from outside is not capped.
        """
        result = apply_gates(finding(
            title="SQL injection via rawQuery", severity="High",
            operand_provenance="external"))
        assert result.severity_cap == ""


class TestWebViewMitigationGate:
    """
    Purpose:
        Capping a component finding when the code immediately around it turns off the very things the finding relies on.
    """
    def test_a_hardened_bridge_cannot_stay_critical(self):
        """
        Purpose:
            Pin that a bridge whose surrounding lines disable the capabilities the finding depends on cannot stay at the top severity.

        Implementation notes:
            One real finding was scored near the top of the scale on a bridge whose four preceding lines switched off pop-ups, content access, file access and file-URL access.
        """
        result = apply_gates(finding(
            title="WebView exposes JavaScript interface 'CleverTap' to loaded content",
            severity="Critical",
            webview_mitigations=["setAllowFileAccess(false)",
                                 "setAllowFileAccessFromFileURLs(false)",
                                 "setAllowContentAccess(false)",
                                 "setWebViewClient(...)"]))
        assert severity_rank(result.final_severity) < severity_rank("High")

    def test_no_mitigations_found_means_no_cap(self):
        """
        Purpose:
            Pin that a finding with nothing mitigating it nearby is left alone.
        """
        result = apply_gates(finding(
            title="WebView exposes a JavaScript bridge", severity="Critical",
            webview_mitigations=[]))
        assert result.severity_cap == ""


class TestVendorCodeGate:
    """
    Purpose:
        Capping a finding in third-party code.
    """
    def test_a_vendor_finding_is_capped_and_labelled(self):
        """
        Purpose:
            Pin that a finding in a bundled library is capped and labelled as such.

        Implementation notes:
            The application's owner cannot change that code, so a top-severity finding there is a demand they cannot meet, and the useful action is upgrading the library rather than fixing the line.
        """
        result = apply_gates(finding(
            title="JavaScript interface added in reCAPTCHA component",
            file="sources/com/google/android/recaptcha/internal/zzez.java",
            severity="Critical", vendor_sdk="com.google"))
        assert severity_rank(result.final_severity) <= severity_rank("Medium")
        assert any("vendor SDK" in r for r in result.reasons)

    def test_first_party_code_is_not_capped(self):
        """
        Purpose:
            Pin that a finding in the application's own code is not capped.
        """
        result = apply_gates(finding(
            file="sources/com/kreditbee/android/helper/X.java", severity="Critical"))
        assert result.severity_cap == ""


class TestPublicIdentifierParity:
    """
    Purpose:
        That the agent cannot reopen at a higher severity what the scanner already settled.
    """
    def test_an_agent_public_identifier_finding_is_capped_informational(self):
        """
        Purpose:
            Pin that an agent finding about a value that is public by design is capped at the bottom severity, as the scanner's already is.
        """
        f = finding(title="Firebase App ID present in strings.xml", severity="Medium",
                    file="res/values/strings.xml",
                    code_snippet='<string name="app_id">1:1234567890:android:abcdef123456</string>')
        out = validate_findings([f], provider=None)
        assert out[0]["severity"] == "Informational"
        assert out[0].get("vuln_class") == "SECRET-03"

    def test_dedup_does_not_promote_a_pinned_low_pair(self):
        """
        Purpose:
            Pin that merging two such findings does not raise the result.

        Implementation notes:
            The merge normally keeps the worst severity of the group, which would otherwise undo the cap the moment the pair collapsed.
        """
        scanner = {"title": "Firebase App ID shipped in the app", "severity": "Informational",
                   "source": "static-analyzer", "vuln_class": "SECRET-03",
                   "file": "res/values/strings.xml", "line": "204",
                   "description": "public identifier, recorded as inventory " * 3,
                   "extra": {"public_identifier": True}}
        agent = {"title": "Firebase App ID exposed in strings.xml", "severity": "Medium",
                 "source": "agent", "vuln_class": "SECRET-03",
                 "file": "res/values/strings.xml", "line": "204",
                 "description": "the firebase app id is hardcoded " * 3}
        out = deduplicate([scanner, agent])
        assert len(out) == 1
        assert out[0]["severity"] == "Informational"


class TestLocationDedupe:
    """
    Purpose:
        Merging a scanner finding and an agent finding that point at the same line.
    """
    def test_same_line_cross_engine_collapses_to_one_at_the_lower_severity(self):
        """
        Purpose:
            Pin that two engines reporting one line collapse into a single finding at the lower severity.

        Implementation notes:
            A real scan shipped exactly this pair worded differently and scored seven points apart, which reads as two defects graded inconsistently.
        """
        scanner = {"title": "Table or column name built from a variable in a SQL statement",
                   "severity": "Informational", "source": "static-analyzer",
                   "vuln_class": "CODE-01", "file": "sources/U1/m.java", "line": "170",
                   "description": "numeric/identifier concat, informational " * 3}
        agent = {"title": "SQL injection via table/column name concatenation",
                 "severity": "High", "source": "agent", "vuln_class": "CODE-01",
                 "file": "sources/U1/m.java", "line": "170",
                 "description": "the table name is concatenated into rawQuery " * 3}
        out = deduplicate([scanner, agent])
        assert len(out) == 1
        assert out[0]["severity"] == "Informational"
        assert any(r.get("pattern") == "same-location"
                   for r in out[0].get("related_findings", []))

    def test_same_source_near_duplicates_are_left_to_the_class_pass(self):
        """
        Purpose:
            Pin that two findings from the same engine on nearby lines are left to the ordinary grouping.

        Implementation notes:
            One engine reporting twice is a different situation from two engines agreeing, and merging on the line alone would hide a genuine second defect on the same line.
        """
        a = {"title": "SQL injection in exported NotesProvider", "severity": "Critical",
             "source": "agent", "file": "sources/x/NotesProvider.java", "line": "56",
             "description": "concatenates the URI path segment into SQL " * 3}
        b = {"title": "SQL injection in NotesProvider", "severity": "High",
             "source": "agent", "file": "sources/x/NotesProvider.java", "line": "57",
             "description": "builds SQL from caller input " * 3}
        out = deduplicate([a, b])
        assert len(out) == 1
        assert out[0]["severity"] == "Critical"


class TestValidatorDeterminism:
    """
    Purpose:
        That an identical claim gets an identical verdict.

    Implementation notes:
        One real finding was rejected in one run and accepted in the next, which makes a scan impossible to reproduce and a verdict impossible to argue with.
    """
    def test_an_identical_claim_is_not_re_reviewed(self):
        """
        Purpose:
            Pin that a claim already reviewed in this run is not sent for review again.
        """
        clear_verdict_cache()
        make = lambda: finding(
            title="Exported activity leaks the session token",
            code_snippet="startActivity(new Intent(this, Next.class).putExtra(\"t\", token));")
        j1 = _Judge([{"id": 0, "verdict": "DOWNGRADE", "severity": "Low",
                      "reason": "only reachable from the app's own code"}])
        first = validate_findings([make()], provider=j1)[0]["severity"]

        j2 = _Judge([{"id": 0, "verdict": "PASS"}])
        second = validate_findings([make()], provider=j2)[0]["severity"]

        assert j2.prompts == []
        assert first == second
        clear_verdict_cache()
