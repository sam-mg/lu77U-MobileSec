#!/usr/bin/env python3
"""
Module: test_demo_accuracy

Purpose:
    The wording, citations and reasons a reader sees on a finding: per-finding device evidence, report-style titles, gate notes only where a gate changed something, manifest line numbers, and classes and notes that match the code and the declared target.

Responsibilities:
    Pin each correction an audit of the published demo scans called for, so none of them silently comes back.

Dependencies:
    pytest, the verifier helpers, the validator, the gates, dedupe, the chain table and the manifest extractor.

Implementation notes:
    Every case here was a published finding: a missing-FLAG_SECURE note marked verified by evidence about a content provider, titles cut mid-word, "too shallow to support a Critical" under a finding that was only ever High, an SDK inventory note told its claim could not be checked, a @JavascriptInterface finding told it cited an import, DIVA's components at manifest line 0, a strncmp against a literal filed as a crypto key, a backup note claiming adb extraction for an app targeting 36 and citing targetSdkVersion, a scanner's own 80-character title cut to "... where they", and no backup chain over plaintext credentials because the chain table left out their class.
"""

from pathlib import Path

import pytest

from lu77U_MobileSec.dynamic_analysis.verifier import _clean_ids, _evidence_for
from lu77U_MobileSec.validation import apply_gates, find_candidate_chains
from lu77U_MobileSec.validation.dedupe import correct_confusable_class
from lu77U_MobileSec.validation.gates import severity_rank
from lu77U_MobileSec.validation.validator import needs_title, polish_titles, shorten_title


class TestDeviceEvidence:
    """
    Purpose:
        Splitting a batched device verdict so each finding shows only its own proof.
    """
    def test_each_finding_gets_its_own_segment(self):
        """
        Purpose:
            Pin that labelled segments go to their own findings and a finding without one gets none.
        """
        evidence = "F24: dumpsys shows NotesProvider exported. F27: screencap captured the screen."
        assert _evidence_for("F24", evidence) == "dumpsys shows NotesProvider exported."
        assert _evidence_for("F27", evidence) == "screencap captured the screen."
        assert _evidence_for("F26", evidence) is None

    def test_unlabelled_evidence_covers_the_batch_without_internal_ids(self):
        """
        Purpose:
            Pin that evidence without labels is shared by the batch, and that internal identifier lists are removed from what a reader sees.
        """
        assert _evidence_for("F3", "dumpsys shows ALLOW_BACKUP (F13), confirming backup.") == (
            "dumpsys shows ALLOW_BACKUP, confirming backup.")
        assert _clean_ids("Frida was not running, so SQL injections (F1, F8, F9) were not hooked.") == (
            "Frida was not running, so SQL injections were not hooked.")


class _Titler:
    """
    Purpose:
        A provider that answers the title pass with fixed headings.

    Attributes:
        calls: How many requests were made.
    """
    def __init__(self):
        """
        Purpose:
            Start with no calls.
        """
        self.calls = 0

    def analyze(self, unused_prompt, **unused_kwargs):
        """
        Purpose:
            Return a heading for the first finding and an unusable one for the second.

        Parameters:
            unused_prompt: The request, unused here.
            unused_kwargs: The request options, unused here.

        Returns:
            The provider response.
        """
        self.calls += 1
        return {"response": '[{"id": 0, "title": "Premium content gated on a client-side flag"},'
                            ' {"id": 1, "title": "Too..."}]'}


class TestTitles:
    """
    Purpose:
        Report-style headings in place of cut-off sentences.
    """
    @pytest.mark.parametrize("title, expected", [
        ("The decision to display premium content is made on the client side based on t...", True),
        ("SQL injection in the notes search functionality.", True),
        ("Hardcoded Premium API Key", False),
        ("Exported activity APICredsActivity has no permission protection", False),
    ])
    def test_which_titles_need_a_heading(self, title, expected):
        """
        Purpose:
            Pin which titles are treated as sentences.

        Parameters:
            title: The title.
            expected: Whether it needs rewriting.
        """
        assert needs_title({"title": title}) is expected

    def test_the_fallback_keeps_the_opening_clause_from_the_description(self):
        """
        Purpose:
            Pin that a title cut mid-word is rebuilt from the description's sentence, cut at its first clause and with no dangling word.
        """
        description = ('The NotesProvider is exported (android:exported="true") without any permission '
                       'guards, allowing any application to read the notes.')
        title = 'The NotesProvider is exported (android:exported="true") without any permissio...'
        assert shorten_title(title, description) == "The NotesProvider is exported without any permission guards"

    def test_the_model_pass_and_its_fallback(self):
        """
        Purpose:
            Pin that a usable heading from the model replaces the title, and an unusable one falls back to the shortener.
        """
        findings = [
            {"title": "The decision to display premium content is made on the client side based on t...",
             "description": "The decision to display premium content is made on the client side based on the flag."},
            {"title": "The native module exposes a method that reads any file, allowing any script to read data.",
             "description": "x"},
        ]
        provider = _Titler()
        polish_titles(findings, provider)
        assert provider.calls == 1
        assert findings[0]["title"] == "Premium content gated on a client-side flag"
        assert findings[1]["title"] == "The native module exposes a method that reads any file"

    def test_the_fallback_drops_a_dangling_pronoun(self):
        """
        Purpose:
            Pin that a title cut at the length limit does not end on a pronoun or conjunction, as "... without checking where they" once did.
        """
        title = "WebView onMessage handler acts on messages without checking where they came from"
        assert shorten_title(title) == "WebView onMessage handler acts on messages without checking"

    def test_every_scanner_title_is_already_a_heading(self):
        """
        Purpose:
            Pin that no literal title a scanner writes is long enough to be sent through the title pass, whose fallback would cut it.
        """
        import re
        root = Path(__file__).resolve().parents[1] / "lu77U_MobileSec" / "analyzers" / "sast" / "extractors"
        long_titles = [title for path in sorted(root.glob("*.py"))
                       for title in re.findall(r'title="([^"{]+)"', path.read_text(encoding="utf-8"))
                       if needs_title({"title": title})]
        assert long_titles == []


def _finding(**kw):
    """
    Purpose:
        Build a finding that passes the gates unless overridden.

    Parameters:
        kw: Fields replacing the defaults.

    Returns:
        The finding.
    """
    base = {"title": "Exported provider leaks the contacts table", "severity": "High",
            "file": "sources/com/x/Leak.java", "line": "42", "confidence": "HIGH",
            "description": "The provider is exported and returns every row to any caller, with no permission.",
            "code_snippet": "return db.query(table, null, null, null, null, null, null);"}
    base.update(kw)
    return base


class TestGateNotes:
    """
    Purpose:
        What a gate tells the reader.
    """
    def test_a_cap_that_changes_nothing_says_nothing(self):
        """
        Purpose:
            Pin that a ceiling at or above the severity the finding arrived with adds no explanation, while one below it does.
        """
        shallow = dict(agent_origin="agent", region_files_read=2, region_searches=5, cited_file_read=True)
        high = apply_gates(_finding(severity="High", **shallow))
        assert not [r for r in high.reasons if r.find("Critical") >= 0]
        critical = apply_gates(_finding(severity="Critical", **shallow))
        assert [r for r in critical.reasons if r.find("Critical") >= 0]
        assert severity_rank(critical.final_severity) == severity_rank("High")

    def test_an_inventory_note_is_not_told_its_claim_cannot_be_checked(self):
        """
        Purpose:
            Pin that an Informational note with no file is not downgraded for lacking one.
        """
        result = apply_gates({"title": "2 third-party SDKs embedded", "severity": "Informational",
                              "vuln_class": "SUPPLY-01", "file": "", "description": "Detected: OkHttp 4.9.2."})
        assert result.verdict == "PASS" and not result.reasons

    def test_an_annotation_the_finding_is_about_is_a_valid_citation(self):
        """
        Purpose:
            Pin that citing the @JavascriptInterface annotation of a JavaScript-bridge finding is not flagged as citing an import.
        """
        result = apply_gates(_finding(title="Class exposes 1 @JavascriptInterface method to WebView content",
                                      vuln_class="PLATFORM-04", severity="Low",
                                      code_snippet="@android.webkit.JavascriptInterface"))
        assert not result.needs_recitation


def test_a_comparison_against_a_literal_is_not_a_crypto_key():
    """
    Purpose:
        Pin that a crypto-key finding whose code compares input with the literal is re-filed as a hardcoded check.
    """
    finding = {"vuln_class": "CRYPTO-02", "code_snippet": 'iVar1 = strncmp("olsdfgad;lh",__s2,0xb);'}
    correct_confusable_class(finding)
    assert finding["vuln_class"] == "AUTH-04"


def test_backup_pairs_with_plaintext_credentials():
    """
    Purpose:
        Pin that a backup-enabled note and a credential in plain app storage are offered to the chain builder.
    """
    backup = {"title": "Application data is backup-enabled", "vuln_class": "STORAGE-04",
              "severity": "Informational", "file": "AndroidManifest.xml", "line": "19",
              "gate_result": {"chain_eligible": True, "weak_class_rule": "WEAK-02"}}
    creds = {"title": "Plaintext credentials in SharedPreferences", "vuln_class": "STORAGE-01",
             "severity": "Medium", "file": "sources/a/S.java", "line": "16"}
    patterns = {c["pattern"].id if hasattr(c.get("pattern"), "id") else c.get("pattern")
                for c in find_candidate_chains([backup, creds])}
    assert "CHAIN-05" in patterns


def _manifest(tmp_path, target, extra_app="", min_sdk=21):
    """
    Purpose:
        Write a decoded manifest and return its manifest findings.

    Parameters:
        tmp_path: The analysis root.
        target: The targetSdkVersion to declare.
        extra_app: Attributes to add to the application element.
        min_sdk: The minSdkVersion to declare.

    Returns:
        The findings.
    """
    from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
    res = tmp_path / "resources"
    res.mkdir(exist_ok=True)
    (res / "AndroidManifest.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <uses-sdk
        android:minSdkVersion="{min_sdk}"
        android:targetSdkVersion="{target}"/>
    <application
        android:label="App"{extra_app}>
        <activity
            android:name="com.example.app.CredsActivity">
            <intent-filter>
                <action android:name="com.example.app.VIEW_CREDS"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
""")
    return analyze_manifest(tmp_path)


class TestManifestNotes:
    """
    Purpose:
        Manifest findings placed on their lines and worded for the declared target.
    """
    def test_findings_point_at_their_elements(self, tmp_path):
        """
        Purpose:
            Pin that a component finding cites its name, an app-wide note, including the backup note that also names the target SDK, cites the application element, and the minSdkVersion note, whose description names the network security config, cites minSdkVersion.

        Parameters:
            tmp_path: The analysis root.
        """
        found = {f.title: f.line for f in _manifest(tmp_path, 23, min_sdk=15)}
        assert found["Exported activity CredsActivity has no permission protection"] == 10
        assert found["No network security config declared"] == 7
        assert found["Application data is backup-enabled"] == 7
        assert found["minSdkVersion 15 supports Android versions without modern protections"] == 5

    def test_backup_and_network_notes_match_the_target(self, tmp_path):
        """
        Purpose:
            Pin that an app targeting 31 or later is not told adb backup extracts its data, and that the network note states the defaults its target gets.

        Parameters:
            tmp_path: The analysis root.
        """
        old = {f.title: f for f in _manifest(tmp_path, 23)}
        assert "adb backup` copies" in old["Application data is backup-enabled"].description
        assert "still permit cleartext" in old["No network security config declared"].description
        new = {f.title: f for f in _manifest(tmp_path, 36)}
        assert "leave it out of `adb backup`" in new["Application data is backup-enabled"].description
        assert "block cleartext" in new["No network security config declared"].description



class TestDisplay:
    """
    Purpose:
        How a finding reads in a list: its title's case, its labels, and titles that tell two findings apart.
    """
    @pytest.mark.parametrize("title, expected", [
        ("Plaintext Credentials in Temporary File", "Plaintext credentials in temporary file"),
        ("Client-Side Auth Bypass in APICreds2Activity", "Client-side auth bypass in APICreds2Activity"),
        ("Exported ContentProvider without Permission Protection",
         "Exported ContentProvider without permission protection"),
        ("Weak Local Authentication via Plaintext PIN Storage", "Weak local authentication via plaintext PIN storage"),
        ("Hardcoded encryption key in the app's Dart code", "Hardcoded encryption key in the app's Dart code"),
        ("Root detection with RootBeer", "Root detection with RootBeer"),
        ("Google Maps key", "Google Maps key"),
    ])
    def test_title_case_becomes_sentence_case(self, title, expected):
        """
        Purpose:
            Pin that Title Case titles are lowered to sentence case and that sentence-case titles, identifiers, acronyms and proper names are left alone.

        Parameters:
            title: The title.
            expected: The title after the rule.
        """
        from lu77U_MobileSec.validation.validator import sentence_case
        assert sentence_case(title) == expected

    def test_scanner_findings_carry_their_class_labels(self):
        """
        Purpose:
            Pin that a rule finding with no CWE or OWASP category gets its class's, and that one which names its own keeps it.
        """
        from lu77U_MobileSec.analyzers.sast.findings import SastFinding, to_scan_finding
        bare = to_scan_finding(SastFinding(title="Runtime.exec() invocation", severity="Low", description="d",
                                           vuln_class="CODE-02", cwe="CWE-78"))
        assert (bare["cwe"], bare["owasp_mobile"]) == ("CWE-78", "M4: Insufficient Input/Output Validation")
        named = to_scan_finding(SastFinding(title="t", severity="Low", description="d", vuln_class="SECRET-03",
                                            owasp_mobile="M8: Security Misconfiguration"))
        assert named["owasp_mobile"] == "M8: Security Misconfiguration"

    def test_exported_components_are_misconfiguration(self, tmp_path):
        """
        Purpose:
            Pin that an exported component is filed under OWASP M8, as its class is, not M4.

        Parameters:
            tmp_path: The analysis root.
        """
        found = {f.title: f for f in _manifest(tmp_path, 23)}
        assert found["Exported activity CredsActivity has no permission protection"].owasp_mobile == (
            "M8: Security Misconfiguration")

    def test_the_apps_own_framework_is_not_a_third_party_sdk(self, tmp_path):
        """
        Purpose:
            Pin that a Flutter app's inventory leaves Flutter out, and that an ordinary SDK beside it is still listed.

        Parameters:
            tmp_path: The decompiled tree.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.sdk_inventory import analyze_sdks
        for rel in ("io/flutter/embedding/FlutterActivity.java", "okhttp3/OkHttpClient.java"):
            path = tmp_path / "sources" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class X {}")
        notes = [f for f in analyze_sdks(tmp_path) if f.vuln_class == "SUPPLY-01"]
        assert [f.title for f in notes] == ["1 third-party SDK embedded"]
        assert "Flutter" not in notes[0].description

    def test_private_addresses_are_named_in_full(self):
        """
        Purpose:
            Pin that a 10.x address is matched with all four parts, which the title then names.
        """
        import re
        from lu77U_MobileSec.analyzers.agent.patterns import SECRET_PATTERNS
        pattern = next(p for p in SECRET_PATTERNS if p.name == "Private Network Address")
        assert re.search(pattern.regex, 'API_BASE_URL = "http://10.0.2.2:3000"').group(0) == "10.0.2.2"

    def test_repeated_scanner_findings_say_what_differs(self, tmp_path):
        """
        Purpose:
            Pin that two private addresses, and two command executions in different files, get titles that tell them apart.

        Parameters:
            tmp_path: The decompiled tree.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
        (tmp_path / "res").mkdir()
        (tmp_path / "res" / "strings.xml").write_text('<string name="a">http://10.0.2.2:3000</string>\n'
                                                      '<string name="b">192.168.18.141</string>\n')
        titles = sorted(f.title for f in analyze_secrets(tmp_path) if f.vuln_class == "SECRET-03")
        assert titles == ["Private network address 10.0.2.2 shipped in the app",
                          "Private network address 192.168.18.141 shipped in the app"]
        src = tmp_path / "sources" / "com" / "lib"
        src.mkdir(parents=True)
        for name in ("Shell", "Probe"):
            (src / f"{name}.java").write_text(
                "class X { void run(String c) throws Exception { Runtime.getRuntime().exec(c); } }")
        execs = sorted(f.title for f in analyze_injection(tmp_path) if f.vuln_class == "CODE-02")
        assert execs == ["Runtime.exec() invocation in Probe.java", "Runtime.exec() invocation in Shell.java"]

    def test_a_bare_offset_is_named_as_a_hook_point(self):
        """
        Purpose:
            Pin that an exploitation field holding only a libapp.so offset says what the offset is for, and that a sentence is left alone.
        """
        from lu77U_MobileSec.utils.response_parser import hook_point
        assert hook_point("libapp.so offset 0x373a60") == "Frida hook point: libapp.so offset 0x373a60"
        assert hook_point("Hook _checkPin at libapp.so offset 0x39e0f8") == "Hook _checkPin at libapp.so offset 0x39e0f8"


class TestDeviceVerdicts:
    """
    Purpose:
        A device verdict that says "verified" only when something was done on the device.
    """
    @pytest.mark.parametrize("evidence, on_device", [
        ("'adb am start -n app/.Main' launched the activity", True),
        ("dumpsys package shows ALLOW_BACKUP", True),
        ("The screencap command captured the screen", True),
        ("read_source of app_modules/503_PREMIUM_API_KEY.js confirms the hardcoded key", False),
        ("The static analysis confirmed that networkSecurityConfig is absent", False),
    ])
    def test_device_actions(self, evidence, on_device):
        """
        Purpose:
            Pin which evidence describes something done on the device.

        Parameters:
            evidence: The evidence text.
            on_device: Whether it names a device action.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import shown_on_device
        assert shown_on_device(evidence) is on_device

    def test_an_early_stop_quotes_the_tools_error(self):
        """
        Purpose:
            Pin that the reason a stopped session gives is the tool's own error, and that a reason stored in the earlier wording is rewritten to it.
        """
        from lu77U_MobileSec.dynamic_analysis.verifier import abort_reason, reword_abort_reason
        expected = ("Device verification stopped after one device tool failed the same way 3 times in a row: "
                    "frida-server is not running on the device. The findings it had not reached could not be "
                    "checked on the device.")
        assert abort_reason("ERROR: frida-server is not running on the device.", 3) == expected
        old = ("Dynamic verification aborted after a device tool failed identically 3 times in a row "
               "(ERROR: frida-server is not running on the device.). The runtime environment appears broken "
               "(e.g. the Frida Java bridge is unavailable on this Frida version), so further steps could not "
               "make progress.")
        assert reword_abort_reason(old) == expected
        assert reword_abort_reason("Not reached.") == "Not reached."
