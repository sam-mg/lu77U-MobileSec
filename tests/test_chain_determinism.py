#!/usr/bin/env python3
"""
Module: test_chain_determinism

Purpose:
    Deterministic chain pairings, candidate ranking, and the logging of rejected candidates.

Responsibilities:
    Guard the fix for chains that were generated but never evaluated.

Dependencies:
    The chain builder, the gates, and the shared finding factory.

Implementation notes:
    A real scan contained a textbook chain, with a pinning-absent note and two genuine transport bypasses all present in the same report, and the tool never joined them: hundreds of candidates were generated and only the first two dozen were evaluated, in an order unrelated to severity. These tests are the regression guard for that.
"""

from test_validation import finding

from lu77U_MobileSec.validation.chains import (
    MAX_AUTO_CHAINS, MAX_CANDIDATES, build_chains, find_candidate_chains)
from lu77U_MobileSec.validation.gates import apply_gates


def _weak01_and_bypass(bypass_severity="High"):
    """
    Purpose:
        Build the exact pair a real scan produced: a pinning-absent note and a genuine transport bypass.

    Parameters:
        bypass_severity: Severity to give the bypass finding.

    Returns:
        The two findings, each with its real gate result attached.

    Implementation notes:
        Both are run through the real gates rather than having their verdicts faked, so the weak-class rule is set exactly as it would be in a scan; the pairing keys on that rule, and a faked verdict would test nothing.
    """
    weak = finding(title="No certificate pinning declared for this endpoint",
                   vuln_class="NETWORK-03", severity="Informational")
    weak["gate_result"] = apply_gates(weak).to_dict()
    bypass = finding(title="HostnameVerifier accepts every hostname",
                     vuln_class="NETWORK-01", severity=bypass_severity,
                     file="sources/com/x/Net.java")
    bypass["gate_result"] = apply_gates(bypass).to_dict()
    return weak, bypass


class TestAutoConfirmedPairings:
    """
    Purpose:
        The pairings confirmed deterministically, with no model involved.
    """
    def test_a_weak01_and_a_tls_bypass_chain_with_no_provider(self):
        """
        Purpose:
            Pin that the pairing is made without a provider, and is reported as an auto-confirmed chain at the severity its vector scores.

        Implementation notes:
            This relationship is definitional rather than dependent on data flow, which is why it needs no model: pinning is precisely the control that would have caught the bypass. It was labelled Critical beside a vector that scores 8.1 (an attacker on the same network), so it is High, and the vector it carries agrees.
        """
        from lu77U_MobileSec.utils.cvss import severity_from_vector
        weak, bypass = _weak01_and_bypass()
        chains = build_chains([weak, bypass], provider=None)
        assert len(chains) == 1
        assert chains[0]["chain"]["auto_confirmed"] is True
        assert chains[0]["source"] == "chain-builder"
        assert chains[0]["severity"] == "High"
        assert severity_from_vector(chains[0]["cvss_vector"])[0] == "High"

    def test_user_ca_trust_does_not_pair_as_a_tls_bypass(self):
        """
        Purpose:
            Pin that missing pinning beside user-CA trust makes no auto-confirmed chain, since user-CA trust is not a bypass.
        """
        weak, _bypass = _weak01_and_bypass()
        user_ca = finding(title="targetSdkVersion 23 trusts user-installed CA certificates",
                          vuln_class="NETWORK-05", severity="Medium", file="AndroidManifest.xml")
        user_ca["gate_result"] = apply_gates(user_ca).to_dict()
        assert build_chains([weak, user_ca], provider=None) == []

    def test_the_bypass_is_named_in_the_flow(self):
        """
        Purpose:
            Pin that the attack path names the actual bypass finding rather than a generic description.

        Implementation notes:
            The value of a chain finding is that a reader can follow it through their own code, which needs the real component named.
        """
        weak, bypass = _weak01_and_bypass()
        chains = build_chains([weak, bypass], provider=None)
        flow = " ".join(chains[0]["chain"]["flow"])
        assert "HostnameVerifier accepts every hostname" in flow

    def test_a_weak01_note_with_no_bypass_produces_no_auto_chain(self):
        """
        Purpose:
            Pin that a pinning-absent note alone produces no chain.

        Implementation notes:
            Without a partner the note is a configuration observation, and reporting it as a chain would manufacture a critical finding out of nothing.
        """
        weak, _ = _weak01_and_bypass()
        unrelated = finding(title="Weak random number generator",
                            vuln_class="CRYPTO-01")
        assert build_chains([weak, unrelated], provider=None) == []

    def test_many_bypasses_fold_into_one_chain(self):
        """
        Purpose:
            Pin that one note plus many bypass sites is a single chain listing every site, not one chain per site.

        Implementation notes:
            Several bypasses in one app are the same story told repeatedly, so folding them keeps the report readable while still back-referencing every site.
        """
        weak, _ = _weak01_and_bypass()
        bypasses = [
            finding(title=f"HostnameVerifier accepts every hostname {i}",
                   vuln_class="NETWORK-01", file=f"sources/com/x/Net{i}.java")
            for i in range(MAX_AUTO_CHAINS + 5)
        ]
        chains = build_chains([weak] + bypasses, provider=None)
        assert len(chains) == 1
        flow = " ".join(chains[0]["chain"]["flow"])
        assert "Net0.java" in flow and "Net3.java" in flow
        assert len(chains[0]["chain"]["components"]) >= MAX_AUTO_CHAINS

    def test_auto_chains_survive_alongside_model_confirmed_ones(self):
        """
        Purpose:
            Pin that the deterministic chain still appears when a provider is present and returns nothing.

        Implementation notes:
            The deterministic pairing does not go through candidate generation at all, so a model that confirms nothing must not be able to suppress it.
        """
        weak, bypass = _weak01_and_bypass()

        class _Judge:
            """
            Purpose:
                Stand in for an AI provider during chain confirmation.

            Implementation notes:
                Defined inline because it exists only for this test and carries no state between calls.
            """
            def analyze(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Confirm nothing, so the deterministic chain is the only one that can appear.

                Parameters:
                    _unused_args: The prompt; unused by the fake.
                    _unused_kwargs: The system prompt, schema, images, output cap and session identifier; unused by the fake.

                Returns:
                    The canned response.
                """
                return {"response": "[]"}

        chains = build_chains([weak, bypass], provider=_Judge())
        assert any(c["chain"].get("auto_confirmed") for c in chains)

    def test_weak12_is_not_auto_paired(self):
        """
        Purpose:
            Pin that a requested-permission note is not paired automatically.

        Implementation notes:
            Which permission widens which finding's impact is a judgement about this app, not a fact true of any pair, so it is deliberately left to the model rather than asserted deterministically.
        """
        permissions = finding(title="App requests 5 dangerous permissions",
                              vuln_class="BUILD-03", severity="Informational")
        permissions["gate_result"] = apply_gates(permissions).to_dict()
        other = finding(title="Exported activity leaks account data",
                        vuln_class="PLATFORM-01")
        assert build_chains([permissions, other], provider=None) == []


class TestCandidateRanking:
    """
    Purpose:
        The order candidates are evaluated in, which decides what survives the cap.
    """
    def test_a_higher_severity_pair_is_ranked_before_a_lower_one_in_the_same_tier(self):
        """
        Purpose:
            Pin that with pattern priority tied, the more severe pair is evaluated first.

        Implementation notes:
            The low-severity pair is listed first deliberately, to prove the sort rather than list order decides. The old behaviour evaluated whichever came first in the findings list, which had nothing to do with which pair mattered once confirmed.
        """
        low = finding(title="Weak random number generator seeds a session token",
                      vuln_class="CRYPTO-01", severity="Low")
        low_target = finding(title="Session token stored in plaintext SharedPreferences",
                             vuln_class="SECRET-01", severity="Low")
        high = finding(title="Predictable IV reused across encryptions",
                      vuln_class="CRYPTO-01", severity="Critical")
        high_target = finding(title="Hardcoded credential shipped in the app",
                              vuln_class="STORAGE-04", severity="Critical")
        candidates = find_candidate_chains([low, low_target, high, high_target])
        low_rank = next(i for i, c in enumerate(candidates)
                        if c["entry_index"] == 0 and c["target_index"] == 1)
        high_rank = next(i for i, c in enumerate(candidates)
                         if c["entry_index"] == 2 and c["target_index"] == 3)
        assert high_rank < low_rank

    def test_priority_chains_still_come_first(self):
        """
        Purpose:
            Pin that priority patterns are evaluated ahead of everything else regardless of severity.
        """
        pair = [
            finding(title="Exported activity accepts a deep link url parameter",
                    vuln_class="PLATFORM-02"),
            finding(title="WebView exposes a JavaScript bridge as \"AndroidBridge\"",
                    vuln_class="PLATFORM-04"),
        ]
        candidates = find_candidate_chains(pair)
        priority = [c for c in candidates if c["pattern"].priority]
        assert candidates[:len(priority)] == priority

    def test_the_provider_chain_needs_a_provider_entry(self):
        """
        Purpose:
            Pin that an exported activity feeding SQL injection is not proposed as the exported-provider chain, while an exported provider is.

        Implementation notes:
            A Ghera app's exported activity passed Intent extras to rawQuery, and the chain published "Exported ContentProvider exposes an injectable SQL query" at Critical over an app with no provider.
        """
        sqli = finding(title="SQL injection in MiddleActivity via Intent extras", vuln_class="CODE-01", severity="High")
        activity = finding(title="Exported MiddleActivity lacks permission protection", vuln_class="PLATFORM-01",
                           code_snippet='<activity android:name="edu.ksu.cs.benign.MiddleActivity">')
        provider = finding(title="Exported UserProvider without a permission", vuln_class="PLATFORM-01",
                           code_snippet='<provider android:name="a.UserProvider" android:exported="true">')

        def chain_03(findings):
            """
            Purpose:
                List the CHAIN-03 candidates for a set of findings.

            Parameters:
                findings: The findings.

            Returns:
                The (entry, target) index pairs.
            """
            return [(c["entry_index"], c["target_index"]) for c in find_candidate_chains(findings)
                    if c["pattern"].id == "CHAIN-03"]

        assert chain_03([activity, sqli]) == []
        assert chain_03([provider, sqli]) == [(0, 1)]

    def test_the_cap_was_raised(self):
        """
        Purpose:
            Pin that the candidate cap is above the value that caused real chains to go unevaluated.
        """
        assert MAX_CANDIDATES > 24


class TestRejectionLogging:
    """
    Purpose:
        That a rejected candidate says why it was rejected.
    """
    def test_a_rejected_candidate_logs_its_reason(self, capsys):
        """
        Purpose:
            Pin that a rejection is traced with the model's own reason.

        Parameters:
            capsys: Captures the traced output.

        Implementation notes:
            Without the reason a user cannot tell a correctly-dismissed candidate from a chain the tool failed to spot, which is the difference between trusting the result and having to redo it by hand.
        """
        pair = [
            finding(title="Exported activity accepts a deep link url parameter",
                    vuln_class="PLATFORM-02"),
            finding(title="WebView exposes a JavaScript bridge as \"AndroidBridge\"",
                    vuln_class="PLATFORM-04"),
        ]

        class _Judge:
            """
            Purpose:
                Stand in for an AI provider during chain confirmation.

            Implementation notes:
                Defined inline because it exists only for this test and carries no state between calls.
            """
            def analyze(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Reject the candidate with a stated reason, so the trace can be inspected.

                Parameters:
                    _unused_args: The prompt; unused by the fake.
                    _unused_kwargs: The system prompt, schema, images, output cap and session identifier; unused by the fake.

                Returns:
                    The canned response.
                """
                import json
                return {"response": json.dumps(
                    [{"id": 0, "confirmed": False,
                     "reason": "unrelated Activities, no data flow between them"}])}

        chains = build_chains(pair, provider=_Judge(), verbose=True)
        assert chains == []
        out = capsys.readouterr().out
        assert "rejected" in out
        assert "unrelated Activities" in out



class TestChainSeverity:
    """
    Purpose:
        A chain's severity label and its CVSS vector always agreeing.
    """
    def test_every_pattern_is_labelled_with_the_band_its_vector_scores(self):
        """
        Purpose:
            Pin that no chain pattern declares a severity its own vector does not score.

        Implementation notes:
            Six patterns disagreed, among them the backup-and-credential chain labelled High beside a physical-access vector scoring 5.9.
        """
        from lu77U_MobileSec.utils.cvss import severity_from_vector
        from lu77U_MobileSec.validation.chains import CHAIN_PATTERNS, _AUTO_PAIRINGS
        patterns = list(CHAIN_PATTERNS) + [pattern for _, _, pattern in _AUTO_PAIRINGS]
        assert [p.id for p in patterns if severity_from_vector(p.cvss_vector)[0] != p.severity] == []

    def test_a_component_that_outranks_the_pattern_lends_its_vector(self):
        """
        Purpose:
            Pin that a chain raised to a component's severity carries that component's vector too, so its score still supports its label.
        """
        from lu77U_MobileSec.utils.cvss import severity_from_vector
        from lu77U_MobileSec.validation.chains import CHAIN_PATTERNS, _build_chain_finding
        pattern = next(p for p in CHAIN_PATTERNS if p.id == "CHAIN-05")
        entry = {"title": "Backup", "severity": "Informational"}
        target = {"title": "Token", "severity": "High", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        chain = _build_chain_finding({"pattern": pattern, "entry_index": 0, "target_index": 1},
                                     [entry, target], {"confirmed": True, "flow": ["a"]}, 1)
        assert chain["severity"] == "High"
        assert severity_from_vector(chain["cvss_vector"])[0] == "High"
