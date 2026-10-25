#!/usr/bin/env python3
"""
Module: test_review_pass

Purpose:
    The model review, title and chain passes once their answers are actually read: response parsing, the severity floor on a review's downgrade, how its reasons read, chains that are never weak-classed and are folded per entry, and device evidence written as a numbered list.

Responsibilities:
    Pin each rule the audit of a scan with a working review pass called for, so none silently stops applying.

Dependencies:
    pytest, the response schema helpers, the validator, the gates, deduplication, the chain builder, the weak-class table, the verifier helpers and the response parser.

Implementation notes:
    Every answer the review, title and chain passes received from the model came back inside a markdown code fence and was discarded, so published scans had no review verdicts and no model-confirmed chains. Reading those answers exposed the rest: a review that moved every local-storage finding to Low for needing root, hardcoded secrets taken to Informational under a DOWNGRADE, reasons that named findings by batch id or by a title the report no longer had, a confirmed backup chain demoted by the backup weak rule, and a numbered list of device evidence attached whole to every finding.
"""

import pytest

from lu77U_MobileSec.ai.schema import coerce_to_vuln_list
from lu77U_MobileSec.dynamic_analysis.verifier import _clean_ids, _evidence_for
from lu77U_MobileSec.utils.response_parser import fit_field
from lu77U_MobileSec.validation import apply_gates, classify_weak
from lu77U_MobileSec.validation.chains import _merge_shared_entry
from lu77U_MobileSec.validation.dedupe import correct_confusable_class, deduplicate
from lu77U_MobileSec.validation.gates import GateResult
from lu77U_MobileSec.validation.validator import (
    _apply, _merge_verify, _verify_view, code_format_note, name_references, polish_titles,
    review_findings, review_floor, sdk_note)

LOCAL_STORAGE_VECTOR = "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class TestFencedAnswers:
    """
    Purpose:
        Model answers wrapped in a markdown fence or written as an object keyed by id.
    """
    def test_a_fenced_list_is_read(self):
        """
        Purpose:
            Pin that a list inside a ```json fence parses to the list.
        """
        text = '```json\n[{"id": 0, "confirmed": true}, {"id": 1, "confirmed": false}]\n```'
        assert coerce_to_vuln_list(text) == [{"id": 0, "confirmed": True}, {"id": 1, "confirmed": False}]

    def test_an_object_keyed_by_id_is_the_list(self):
        """
        Purpose:
            Pin that {"0": {...}, "1": {...}} becomes a list carrying each key as its id.
        """
        text = '```json\n{"0": {"title": "A"}, "1": {"id": 1, "title": "B"}}\n```'
        assert coerce_to_vuln_list(text) == [{"id": 0, "title": "A"}, {"id": 1, "title": "B"}]

    def test_a_wrapped_list_and_garbage_behave_as_before(self):
        """
        Purpose:
            Pin that a wrapper key still unwraps and text that will not parse comes back unchanged.
        """
        assert coerce_to_vuln_list('{"findings": [{"id": 3}]}') == [{"id": 3}]
        assert coerce_to_vuln_list("```json\n[{\"id\": 0}") == "```json\n[{\"id\": 0}"


class TestFieldLength:
    """
    Purpose:
        Model text bounded without cutting it mid-word.
    """
    def test_a_slightly_long_field_is_kept_whole(self):
        """
        Purpose:
            Pin that a description a few words over the schema's limit is kept as written.
        """
        text = "x " * 150 + "end."
        assert fit_field(text, 240) == text.strip()

    def test_a_runaway_field_is_cut_at_a_sentence(self):
        """
        Purpose:
            Pin that a field far past the limit ends at a sentence, or at a word with an ellipsis.
        """
        assert fit_field("First sentence here. " * 10 + "word " * 50, 60).endswith(".")
        cut = fit_field("word " * 100, 60)
        assert cut.endswith("…") and " wo…" not in cut and len(cut) <= 181


class TestReviewFloor:
    """
    Purpose:
        A review's DOWNGRADE stopping where the vector, scored for the strongest local attacker, still stands.
    """
    @pytest.mark.parametrize("vector, floor", [
        (LOCAL_STORAGE_VECTOR, "Medium"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Medium"),
        ("AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Low"),
        ("", "Low"),
    ])
    def test_the_floor(self, vector, floor):
        """
        Purpose:
            Pin the floor for a few vectors.

        Parameters:
            vector: The finding's CVSS vector.
            floor: The expected floor.
        """
        assert review_floor({"cvss_vector": vector}) == floor

    def test_a_blocked_downgrade_keeps_the_verdict_and_says_why(self):
        """
        Purpose:
            Pin that a downgrade the floor stops entirely leaves the severity and verdict alone and records the reason with why it held.
        """
        finding = {"severity": "Medium", "cvss_vector": LOCAL_STORAGE_VECTOR,
                   "gate_result": GateResult(original_severity="Medium", final_severity="Medium").to_dict()}
        _apply(finding, "DOWNGRADE", "Needs root or a backup.", "Low")
        assert finding["severity"] == "Medium" and finding["gate_result"]["verdict"] == "PASS"
        assert finding["gate_result"]["reasons"][0].startswith("Needs root or a backup. Kept at Medium")

    def test_a_downgrade_never_reaches_informational(self):
        """
        Purpose:
            Pin that a DOWNGRADE proposing Informational for a real finding stops at Low.
        """
        finding = {"severity": "Medium", "cvss_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                   "gate_result": GateResult(original_severity="Medium", final_severity="Medium").to_dict()}
        _apply(finding, "DOWNGRADE", "Unproven.", "Informational")
        assert finding["severity"] == "Low" and finding["gate_result"]["verdict"] == "DOWNGRADE"

    def test_unverified_says_nothing_about_an_informational_note(self):
        """
        Purpose:
            Pin that "could not be confirmed" is not added to a note with nothing to confirm or lower.
        """
        finding = {"severity": "Informational",
                   "gate_result": GateResult(original_severity="Informational",
                                             final_severity="Informational").to_dict()}
        _merge_verify(finding, {"verdict": "UNVERIFIED", "reason": "No source code was provided."})
        assert finding["gate_result"]["reasons"] == []


class TestReasonWording:
    """
    Purpose:
        Review reasons that name other findings in words a reader can follow.
    """
    def test_batch_ids_become_titles(self):
        """
        Purpose:
            Pin that "ID 3" is replaced by the title of the batch's fourth finding, and an out-of-range id is left.
        """
        titles = ["a", "b", "c", "SQL injection in NotesProvider"]
        assert (name_references("The real issue is the SQL injection in ID 3, not ID 9.", titles)
                == 'The real issue is the SQL injection in the finding "SQL injection in NotesProvider", not ID 9.')

    def test_a_reason_follows_a_renamed_title(self):
        """
        Purpose:
            Pin that the title pass points a reason naming a finding's old title at its new one.
        """
        renamed = {"title": "The application stores sensitive user notes in an unencrypted SQLite database.",
                   "description": "The application stores sensitive user notes in an unencrypted SQLite database."}
        other = {"title": "Pin in preferences", "gate_result": {"reasons": [
            "Less sensitive than The application stores sensitive user notes in an unencrypted SQLite database."]}}
        polish_titles([renamed, other])
        assert renamed["title"] != "The application stores sensitive user notes in an unencrypted SQLite database."
        assert other["gate_result"]["reasons"] == [f"Less sensitive than {renamed['title']}"]

    def test_disassembly_is_labelled(self):
        """
        Purpose:
            Pin that a finding in Blutter's asm output tells the reviewer its // lines are instructions.
        """
        finding = {"file": "asm/all/chall8.dart", "title": "Pinning", "code_snippet": "// r0 = Pin()"}
        assert "instruction" in code_format_note(finding)
        assert _verify_view(0, finding)["code_format"] == code_format_note(finding)
        assert code_format_note({"file": "sources/a/B.java"}) == ""


class TestChains:
    """
    Purpose:
        Chain findings kept at their own severity and one chain per pattern and entry.
    """
    def test_a_chain_is_never_a_weak_class(self):
        """
        Purpose:
            Pin that a confirmed backup chain, whose wording names the backup finding, is not graded as the backup note.
        """
        chain = {"title": "Backup-enabled app stores credentials in local storage", "severity": "High",
                 "vuln_class": "CHAIN-05", "source": "chain-builder", "confidence": "HIGH",
                 "description": "android:allowBackup is true and credentials sit in SharedPreferences.",
                 "chain": {"id": "chain-001", "pattern": "CHAIN-05", "components": ["a", "b"]}}
        assert classify_weak(chain) is None
        assert apply_gates(chain).verdict != "CHAIN_REQUIRED"

    def test_chains_from_one_entry_fold_into_one(self):
        """
        Purpose:
            Pin that two backup chains over different credential stores become one naming both, and that references to the folded chain are repointed.
        """
        def chain(number, target):
            """
            Purpose:
                Build one chain finding.

            Parameters:
                number: Its sequence number.
                target: The target component's title.

            Returns:
                The chain finding.
            """
            return {"title": "Backup chain", "description": f'Two findings in this app combine into a single exploitable path: "Backup" and "{target}".\n\nAttack path:\n1. step',
                    "chain": {"id": f"chain-00{number}", "pattern": "CHAIN-05", "components": ["Backup", target]}}

        backup = {"title": "Backup", "chained_into": ["chain-001", "chain-002"], "gate_result": {"reasons": [
            "Confirmed as part of chain-001: Backup chain.", "Confirmed as part of chain-002: Backup chain."]}}
        out = _merge_shared_entry([chain(1, "Prefs"), chain(2, "Database")], [backup])
        assert len(out) == 1 and out[0]["chain"]["components"] == ["Backup", "Prefs", "Database"]
        assert out[0]["description"].startswith('3 findings in this app combine into one exploitable path: "Backup", "Prefs" and "Database".')
        assert backup["chained_into"] == ["chain-001"]
        assert backup["gate_result"]["reasons"] == ["Confirmed as part of chain-001: Backup chain."]


def test_one_comparison_filed_under_two_classes_is_one_finding():
    """
    Purpose:
        Pin that the listed AUTH-03 and AUTH-04 pair on the very same line merges even when one pass filed both.
    """
    base = {"file": "sources/a/Notes.java", "line": 17, "line_number": 17, "source": "agent",
            "severity": "Medium", "code_snippet": "if (userpin.equals(pin)) {"}
    findings = [dict(base, title="Client-side authentication bypass", vuln_class="AUTH-03",
                     description="The notes are guarded only by a client-side comparison."),
                dict(base, title="Weak local authentication", vuln_class="AUTH-04",
                     description="The PIN is compared with a value from SharedPreferences.")]
    assert len(deduplicate(findings)) == 1


class TestNumberedEvidence:
    """
    Purpose:
        Device evidence written as a numbered list that names findings inside each item.
    """
    EVIDENCE = ("1. 'dumpsys package' confirms APICreds2Activity is exported without a permission (proving F35). "
                "2. 'am start ... --ez chk_pin false' bypasses the PIN check (proving F6 and F27).")

    @pytest.mark.parametrize("fid, expected", [
        ("F35", "'dumpsys package' confirms APICreds2Activity is exported without a permission."),
        ("F27", "'am start ... --ez chk_pin false' bypasses the PIN check."),
        ("F9", None),
    ])
    def test_each_finding_gets_the_items_that_name_it(self, fid, expected):
        """
        Purpose:
            Pin that each finding gets only the items naming it, cleaned, and a finding no item names gets none.

        Parameters:
            fid: The finding's identifier.
            expected: The evidence it should get.
        """
        assert _evidence_for(fid, self.EVIDENCE) == expected

    def test_list_numbers_left_by_labelled_segments_are_removed(self):
        """
        Purpose:
            Pin that a labelled segment does not end with the next item's number, and that decimals are kept.
        """
        assert _evidence_for("F12", "1. F12: the provider is registered. 2. F18: other. 3.") == "the provider is registered."
        assert _evidence_for("F7", "F7: the database exists. 2. For") == "the database exists."
        assert _clean_ids("Version 1.0 is installed. It runs.") == "Version 1.0 is installed. It runs."


@pytest.mark.parametrize("stated, title, expected", [
    ("BUILD-04", "Missing screenshot protection (FLAG_SECURE)", "PLATFORM-12"),
    ("BUILD-02", "Outdated targetSdkVersion permits cleartext traffic", "NETWORK-02"),
    ("BUILD-04", "Missing network security configuration", "NETWORK-03"),
    ("BUILD-02", "Missing network security configuration", "NETWORK-03"),
    ("BUILD-02", "targetSdkVersion 27 allows implicit component export", "BUILD-02"),
    ("BUILD-04", "No root detection", "BUILD-04"),
    ("PLATFORM-01", "Exported activity shows a screenshot of the card", "PLATFORM-01"),
])
def test_a_misfiled_scanner_fact_is_refiled(stated, title, expected):
    """
    Purpose:
        Pin that FLAG_SECURE filed as a hardening control and cleartext filed as target-SDK behaviour move to the scanners' classes, and nothing else moves.

    Parameters:
        stated: The class the model gave.
        title: The finding's title.
        expected: The class after correction.
    """
    finding = {"vuln_class": stated, "title": title}
    correct_confusable_class(finding)
    assert finding["vuln_class"] == expected


def test_a_surviving_scanner_finding_keeps_the_agents_account():
    """
    Purpose:
        Pin that when the rule engine's finding survives a merge, the agent's impact replaces the scanner's template and its description is appended, while the scanner's class, file and severity stand.
    """
    scanner = {"vuln_class": "PLATFORM-01", "severity": "High", "source": "static-analyzer",
               "file": "AndroidManifest.xml", "line": 24,
               "title": "Exported service BackgroundService has no permission protection",
               "description": 'Service "a.BackgroundService" is reachable by any app and declares no permission.',
               "impact": "Any installed app can invoke this component and whatever it does with the data it is handed."}
    agent = {"vuln_class": "PLATFORM-01", "severity": "Low", "source": "agent",
             "file": "AndroidManifest.xml", "line": 24,
             "title": "Exported BackgroundService without permission protection",
             "description": "Starting it makes the app take a wake lock and open the private DisplayActivity.",
             "impact": "Any app can keep the device awake and put the app's private screen in front of the user."}
    out = deduplicate([dict(scanner), dict(agent)])
    assert len(out) == 1
    kept = out[0]
    assert (kept["source"], kept["file"], kept["severity"]) == ("static-analyzer", "AndroidManifest.xml", "High")
    assert kept["impact"] == agent["impact"]
    assert kept["description"].startswith(scanner["description"]) and agent["description"] in kept["description"]


def test_the_first_pass_merge_leaves_cross_engine_pairs_to_deduplication():
    """
    Purpose:
        Pin that BaseAnalyzer.merge_findings keeps a rule finding and an AI finding at one place both, that deduplication then merges them with the rule's title kept and the AI's account carried, and that two AI findings there still collapse in the first pass.
    """
    from lu77U_MobileSec.analyzers.base import BaseAnalyzer
    rule = {"title": "Permission check reads the app's own identity, not the caller's", "source": "static-analyzer",
            "vuln_class": "PLATFORM-01", "file": "sources/a/MyService.java", "line": 17, "severity": "Medium",
            "description": "enforcePermission() reads Binder.getCallingPid() in onStartCommand()."}
    agent = {"title": "Exported service guarded by weak permission", "source": "agent", "vuln_class": "PLATFORM-01",
             "file": "sources/a/MyService.java", "line": 17, "severity": "Medium",
             "description": "Any app can start MyService and reach SensitiveActivity, which the check was meant to stop."}
    again = dict(agent, title="MyService reachable by any app", line=18)
    first = BaseAnalyzer.merge_findings([dict(agent), dict(again)], [dict(rule)])
    assert sorted(f["source"] for f in first) == ["agent", "static-analyzer"]
    kept = deduplicate(first)
    assert len(kept) == 1 and kept[0]["title"] == rule["title"]
    assert agent["description"] in kept[0]["description"] or again["description"] in kept[0]["description"]


def test_a_permission_check_finding_is_not_folded_into_the_exported_component():
    """
    Purpose:
        Pin that the scanner's in-code permission-check finding and the manifest's exported-without-permission finding for the same service stay two findings, with an agent copy joining the first.

    Implementation notes:
        Both are PLATFORM-01 about MyService, so class-and-subject grouping folded the specific cause into the generic manifest finding on four Ghera benchmarks.
    """
    check = {"title": "Permission check reads the app's own identity, not the caller's", "vuln_class": "PLATFORM-01",
             "source": "static-analyzer", "file": "sources/a/MyService.java", "line": 17, "severity": "Medium",
             "description": "enforcePermission() reads Binder.getCallingPid() in onStartCommand().",
             "fact_key": "permission-check:enforcePermission-calling-pid"}
    exported = {"title": "Exported service MyService has no permission protection", "vuln_class": "PLATFORM-01",
                "source": "static-analyzer", "file": "AndroidManifest.xml", "line": 24, "severity": "High",
                "description": "Service MyService is reachable by any app.", "fact_key": "exported:a.MyService"}
    agent = {"title": "Flawed permission check in MyService", "vuln_class": "PLATFORM-01", "source": "agent",
             "file": "sources/a/MyService.java", "line": 17, "severity": "Medium", "description": "x"}
    kept = deduplicate([check, exported, agent])
    assert sorted(f["title"] for f in kept) == sorted([check["title"], exported["title"]])


def test_findings_naming_different_facts_stay_apart():
    """
    Purpose:
        Pin that two scanner findings with different fact_key values two lines apart are not merged, that an agent copy joins the nearest one, and that findings without a key still merge as before.
    """
    base = {"vuln_class": "PLATFORM-05", "severity": "Medium", "source": "static-analyzer",
            "file": "sources/a/Main.java"}
    content = dict(base, line=19, title="WebView content:// access is enabled",
                   description="setAllowContentAccess(true).", fact_key="webview-setting:content_access")
    universal = dict(base, line=21, severity="High", title="WebView allows universal access from file:// URLs",
                     description="setAllowUniversalAccessFromFileURLs(true).", fact_key="webview-setting:universal")
    agent = dict(base, line=19, source="agent", severity="High", title="WebView allows access to content URLs",
                 description="The WebView can read content:// URIs.")
    out = deduplicate([content, universal, agent])
    assert sorted(f["title"] for f in out) == ["WebView allows universal access from file:// URLs",
                                                "WebView content:// access is enabled"]
    unkeyed = [dict(f) for f in (content, universal, agent)]
    for f in unkeyed:
        f.pop("fact_key", None)
    assert len(deduplicate(unkeyed)) == 1


class TestSharedConstant:
    """
    Purpose:
        A hardcoded constant reported where it is declared and where it is used, in different files.
    """

    DECL = {"vuln_class": "SECRET-01", "severity": "Medium", "source": "agent", "line": 5,
            "file": "sources/a/Util/Constant.java", "title": "Hardcoded administrative password",
            "code_snippet": 'public static java.lang.String PASS = "password";',
            "description": "The app hardcodes the string 'password'."}
    CHECK = {"vuln_class": "AUTH-04", "severity": "Medium", "source": "agent", "line": 21,
             "file": "sources/a/MainActivity.java", "title": "Hardcoded password a.Util.Constant.PASS",
             "code_snippet": "if (pwd.getText().toString().equals(a.Util.Constant.PASS)) {",
             "description": "The gate to 'AddStudent' compares input with the hardcoded constant and is a long enough description to win."}
    KEY = {"vuln_class": "SECRET-01", "severity": "Low", "source": "agent", "line": 8,
           "file": "sources/a/Util/Encrypt.java", "title": "Hardcoded PBKDF2 password in Encrypt",
           "code_snippet": "KeySpec k = new javax.crypto.spec.PBEKeySpec(a.Util.Constant.PASS.toCharArray(), salt, 1, 128);",
           "description": "The constant is the PBKDF2 password."}

    def test_the_declaration_and_its_uses_are_one_finding(self):
        """
        Purpose:
            Pin that the declaration, the comparison and the key derivation reading Constant.PASS merge, and that the declaration survives.
        """
        out = deduplicate([dict(self.CHECK), dict(self.DECL), dict(self.KEY)])
        assert len(out) == 1
        assert out[0]["title"] == "Hardcoded administrative password"

    def test_two_constants_of_one_class_stay_apart(self):
        """
        Purpose:
            Pin that a shared package and class do not join two different fields.
        """
        other = dict(self.KEY, title="Hardcoded API key", line=9, code_snippet="String k = a.Util.Constant.API_KEY;",
                     description="The constant is an API key.")
        assert len(deduplicate([dict(self.DECL), other])) == 2

    def test_a_scanner_finding_naming_its_fact_is_not_joined_by_a_constant_it_reads(self):
        """
        Purpose:
            Pin that a fixed-salt finding whose line also reads Constant.PASS stays apart from the hardcoded-password finding.
        """
        salt = dict(self.KEY, title="Password-based key derivation uses a fixed salt", vuln_class="CRYPTO-02",
                    source="static-analyzer", fact_key="crypto:pbe-fixed-salt",
                    description="The salt comes from a string resource.")
        assert len(deduplicate([dict(self.DECL), salt])) == 2

    def test_a_line_reading_two_constants_is_not_used_to_join(self):
        """
        Purpose:
            Pin that a finding naming two constants is left on its own rather than joined to either.
        """
        both = dict(self.CHECK, code_snippet="if (u.equals(a.Util.Constant.USER) && p.equals(a.Util.Constant.PASS)) {")
        assert len(deduplicate([dict(self.DECL), both])) == 2


def test_a_manifest_citation_is_about_the_component_it_declares():
    """
    Purpose:
        Pin that a finding citing a component's manifest element, with no identifier in its title, groups with the same component reported from its class.
    """
    manifest = {"vuln_class": "PLATFORM-01", "severity": "High", "source": "agent", "file": "AndroidManifest.xml",
                "line": 22, "title": "Unprotected exported activity allows token forgery",
                "code_snippet": '<activity android:name="edu.ksu.cs.benign.NewPasswordActivity">',
                "description": "NewPasswordActivity is exported and unprotected."}
    source = {"vuln_class": "PLATFORM-01", "severity": "Medium", "source": "agent", "line": 13,
              "file": "sources/edu/ksu/cs/benign/NewPasswordActivity.java", "title": "Exported activity NewPasswordActivity",
              "description": "Any app can launch NewPasswordActivity."}
    other = dict(manifest, code_snippet='<activity android:name="edu.ksu.cs.benign.ResetActivity">', line=30,
                 description="ResetActivity is exported and unprotected.")
    assert len(deduplicate([dict(manifest), dict(source)])) == 1
    assert len(deduplicate([dict(manifest), other])) == 2


def test_an_app_wide_fact_reported_twice_is_one_finding():
    """
    Purpose:
        Pin that the agent's and the scanner's notes that FLAG_SECURE is never set, both citing the manifest, merge, that one screen's copy joins the app-wide statement once it exists, and that two screens stay apart without it.
    """
    base = {"vuln_class": "PLATFORM-12", "severity": "Informational", "file": "AndroidManifest.xml", "line": 0}
    agent = dict(base, title="Missing screenshot protection (FLAG_SECURE)", source="agent",
                 description="The app does not set FLAG_SECURE on any window.")
    scanner = dict(base, title="No screenshot protection: FLAG_SECURE is never set", source="static-analyzer",
                   description="Nothing in the app sets WindowManager.LayoutParams.FLAG_SECURE.")
    assert len(deduplicate([agent, scanner])) == 1
    screen = dict(base, title="Login screen shows the password without FLAG_SECURE", source="agent",
                  file="sources/a/LoginActivity.java", line=40,
                  description="LoginActivity shows the password field without FLAG_SECURE.")
    assert len(deduplicate([dict(agent), dict(screen)])) == 1
    other = dict(screen, title="Payment screen shows the card number without FLAG_SECURE",
                 file="sources/a/PayActivity.java", line=12,
                 description="PayActivity shows the card number without FLAG_SECURE.")
    assert len(deduplicate([dict(screen), other])) == 2


class TestAppNote:
    """
    Purpose:
        The app facts both review passes are told before the findings.
    """

    @pytest.mark.parametrize("min_sdk, target_sdk, expected", [
        (16, 27, "The app declares minSdkVersion 16 and targetSdkVersion 27."),
        (None, "33", "The app declares targetSdkVersion 33."),
        ("N/A", "N/A", ""),
    ])
    def test_the_note_states_only_what_is_known(self, min_sdk, target_sdk, expected):
        """
        Purpose:
            Pin the sentence for known, partly known and unknown levels.

        Parameters:
            min_sdk: The declared minimum.
            target_sdk: The declared target.
            expected: The sentence.
        """
        assert sdk_note(min_sdk, target_sdk) == expected

    def test_both_passes_are_told(self):
        """
        Purpose:
            Pin that the note opens the rule-finding batch and the agent-finding batch alike.
        """
        prompts = []

        class _Provider:
            """
            Purpose:
                A provider that records each prompt and returns no verdicts.
            """
            def analyze(self, prompt, **unused_kwargs):
                """
                Purpose:
                    Record the prompt.

                Parameters:
                    prompt: The batch prompt.
                    unused_kwargs: System message, schema and cap, ignored.

                Returns:
                    An empty answer.
                """
                prompts.append(prompt)
                return {"response": "[]"}

        rule = {"title": "Exported service X has no permission protection", "source": "static-analyzer",
                "vuln_class": "PLATFORM-01", "severity": "High", "file": "AndroidManifest.xml", "line": 3}
        agent = {"title": "Private files copied to external storage", "source": "agent",
                 "vuln_class": "STORAGE-02", "severity": "Medium", "file": "sources/a/S.java", "line": 9}
        review_findings([rule, agent], _Provider(), app_note=sdk_note(16, 27))
        assert len(prompts) == 2
        assert all(p.startswith("The app declares minSdkVersion 16 and targetSdkVersion 27.") for p in prompts)
