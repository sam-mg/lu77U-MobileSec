#!/usr/bin/env python3
"""
Module: test_sast_extractors

Purpose:
    The deterministic scanners, which are the recall floor of a scan.

Responsibilities:
    Pin the manifest, WebView, network configuration, certificate-handling, injection, secret, third-party and rule-engine scanners, along with the runner that aggregates them and the shape of the findings they produce.

Dependencies:
    pytest, the scanner extractors, the scanner runner, the finding helpers and the shared test fixtures.

Implementation notes:
    These must surface the manifest and WebView facts whether or not the agent happened to look at them, which is what makes them a floor rather than an addition. The WebView cases are modelled on a real miss: a bridge class whose exposed methods lived in a different file from the call that bound it.
"""

import re

import pytest

from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
from lu77U_MobileSec.analyzers.sast.extractors.webview import analyze_webviews
from lu77U_MobileSec.analyzers.sast.findings import (
    SastFinding, normalize_severity, to_scan_finding)
from lu77U_MobileSec.analyzers.sast.runner import run_sast, summarize

MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
  <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="27"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <permission android:name="com.demo.MY_PERM" android:protectionLevel="normal"/>
  <application android:debuggable="true" android:usesCleartextTraffic="true">
    <activity android:name="com.demo.Main">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
    <activity android:name="com.demo.DeepLink">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="demoapp"/>
      </intent-filter>
    </activity>
    <provider android:name="com.demo.Leaky" android:exported="true"
              android:grantUriPermissions="true" android:authorities="com.demo.p"/>
    <service android:name="com.demo.Internal" android:exported="false"/>
    <activity android:name="com.demo.Guarded" android:exported="true"
              android:permission="com.demo.SIG"/>
  </application>
</manifest>"""


@pytest.fixture
def tree(tmp_path):
    """
    Purpose:
        Build a decompiled tree holding a manifest exercising every manifest rule.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "resources").mkdir()
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(MANIFEST)
    return tmp_path


def titles(findings):
    """
    Purpose:
        Collect the titles of a list of findings.

    Parameters:
        findings: The findings to read.

    Returns:
        Their titles, in order.
    """
    return [f.title for f in findings]


class TestManifest:
    """
    Purpose:
        The manifest scanner.
    """
    def test_debuggable_is_critical(self, tree):
        """
        Purpose:
            Pin that an application left debuggable is reported at the top severity.

        Parameters:
            tree: The decompiled tree holding the manifest.

        Implementation notes:
            A debuggable build lets any process on the device attach to it and read its memory, which subsumes most of the other findings a scan can make.
        """
        f = next(f for f in analyze_manifest(tree) if "debuggable" in f.title)
        assert f.severity == "Critical"

    def test_allow_backup_defaults_true_when_absent(self, tmp_path):
        """
        Purpose:
            Pin that the backup setting is reported when it is absent, because absent means enabled.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            "<application/></manifest>")
        assert any("backup-enabled" in t for t in titles(analyze_manifest(tmp_path)))

    def test_cleartext_and_sdk_findings(self, tree):
        """
        Purpose:
            Pin that plain-text traffic, the platform version permitting it, and implicitly exported components are all reported.

        Parameters:
            tree: The decompiled tree holding the manifest.
        """
        found = titles(analyze_manifest(tree))
        assert any("Cleartext HTTP" in t for t in found)
        assert any("targetSdkVersion 27 permits cleartext" in t for t in found)
        assert any("implicit component export" in t for t in found)

    def test_exported_provider_with_uri_grants_is_critical(self, tree):
        """
        Purpose:
            Pin that a provider exported with permission grants is reported at the top severity under the right class.

        Parameters:
            tree: The decompiled tree holding the manifest.
        """
        f = next(f for f in analyze_manifest(tree) if "Leaky" in f.title)
        assert f.severity == "Critical"
        assert f.vuln_class == "PLATFORM-01"

    def test_deeplink_activity_is_classified_as_deeplink(self, tree):
        """
        Purpose:
            Pin that an activity reachable by link is classified as such and carries the scheme.

        Parameters:
            tree: The decompiled tree holding the manifest.

        Implementation notes:
            The scheme is what makes the finding actionable: without it the reader cannot construct the link that reaches the component.
        """
        f = next(f for f in analyze_manifest(tree) if "DeepLink" in f.title)
        assert f.vuln_class == "PLATFORM-02"
        assert "demoapp" in f.extra["schemes"]

    def test_non_exported_and_permission_guarded_are_not_reported(self, tree):
        """
        Purpose:
            Pin that a component kept internal or guarded by a permission is not reported.

        Parameters:
            tree: The decompiled tree holding the manifest.

        Implementation notes:
            These are the two correct ways to close the exposure, so reporting them would tell the developer to undo work already done.
        """
        found = titles(analyze_manifest(tree))
        assert not any("Internal" in t for t in found)
        assert not any("Guarded" in t for t in found)

    def test_dangerous_permissions_are_informational_context(self, tree):
        """
        Purpose:
            Pin that a declared sensitive permission is recorded for information rather than as a defect.

        Parameters:
            tree: The decompiled tree holding the manifest.

        Implementation notes:
            Asking for a permission is not a fault; it is context for the findings around it, and grading it any higher is report padding.
        """
        f = next(f for f in analyze_manifest(tree) if "dangerous permission" in f.title)
        assert f.severity == "Informational"

    def test_missing_manifest_returns_empty(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no manifest yields nothing rather than failing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert analyze_manifest(tmp_path) == []

    def test_malformed_manifest_returns_empty(self, tmp_path):
        """
        Purpose:
            Pin that a manifest that cannot be parsed yields nothing rather than failing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        (tmp_path / "AndroidManifest.xml").write_text("<manifest unclosed")
        assert analyze_manifest(tmp_path) == []


@pytest.fixture
def java_tree(tmp_path):
    """
    Purpose:
        Build a decompiled tree whose bridge methods and binding call sit in separate files, alongside framework code that must be ignored.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The tree root.

    Implementation notes:
        The split across two files is the real-world shape that was originally missed, so the fixture reproduces it rather than putting both in one file where a simpler scanner would also pass.
    """
    src = tmp_path / "sources" / "app"
    src.mkdir(parents=True)
    (src / "Bridge.java").write_text(
        "package app;\npublic class Bridge {\n"
        "    @android.webkit.JavascriptInterface\n"
        "    public String getSessionToken() { return t; }\n"
        "    @android.webkit.JavascriptInterface\n"
        "    public void copyTextToClipboard(String s) { }\n}")
    (src / "WebActivity.java").write_text(
        "package app;\nclass WebActivity {\n"
        "  void setup(WebView w) {\n"
        "    w.getSettings().setJavaScriptEnabled(true);\n"
        "    w.getSettings().setAllowUniversalAccessFromFileURLs(true);\n"
        "    w.addJavascriptInterface(new Bridge(), \"AndroidBridge\");\n"
        "    w.loadUrl(getIntent().getStringExtra(\"notifUrl\"));\n"
        "    w.loadUrl(\"https://static.example.com/ok\");\n"
        "  }\n"
        "  public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) {\n"
        "    h.proceed();\n  }\n}")
    noise = tmp_path / "sources" / "androidx"
    noise.mkdir(parents=True)
    (noise / "N.java").write_text(
        "class N { void f(WebView w){ w.getSettings().setJavaScriptEnabled(true); } }")
    return tmp_path


class TestWebView:
    """
    Purpose:
        The WebView scanner.
    """
    def test_bridge_class_found_without_the_binding_call(self, java_tree):
        """
        Purpose:
            Pin that a class exposing methods to page script is found on its own, with those methods named.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.

        Implementation notes:
            Finding it without the binding call is the whole point: the two are routinely in different files, and requiring both in one would miss the case this scanner exists for.
        """
        f = next(f for f in analyze_webviews(java_tree) if f.file.endswith("Bridge.java"))
        assert f.vuln_class == "PLATFORM-04" and f.severity == "High"
        assert set(f.extra["exposed_methods"]) == {"getSessionToken", "copyTextToClipboard"}

    def test_binding_call_reported_with_interface_name(self, java_tree):
        """
        Purpose:
            Pin that the binding call is reported with the name the bridge is exposed under.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.

        Implementation notes:
            That name is what page script calls the object by, so it is what a reviewer needs in order to test the exposure.
        """
        f = next(f for f in analyze_webviews(java_tree) if "AndroidBridge" in f.title)
        assert f.extra["js_interface_name"] == "AndroidBridge"

    def test_universal_file_access_is_critical(self, java_tree):
        """
        Purpose:
            Pin that allowing page script unrestricted file access is reported at the top severity.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.
        """
        f = next(f for f in analyze_webviews(java_tree) if "universal access" in f.title)
        assert f.severity == "Critical"

    def test_intent_tainted_loadurl_is_found_through_nested_call(self, java_tree):
        """
        Purpose:
            Pin that a URL loaded from externally supplied data is found even when the value comes from a nested call.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.

        Implementation notes:
            A pattern that matches an argument without allowing nested parentheses stops at the inner closing bracket and silently finds nothing, which is how this case went unreported.
        """
        loads = [f for f in analyze_webviews(java_tree) if "loads a URL" in f.title]
        assert len(loads) == 1
        assert loads[0].severity == "High"

    def test_static_literal_load_is_not_reported(self, java_tree):
        """
        Purpose:
            Pin that a URL written as a literal is not reported.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.

        Implementation notes:
            Asserted by line number rather than by the reported text, because the evidence snippet carries a couple of lines of context on either side, so the literal load legitimately appears inside the tainted one's snippet without itself being reported.
        """
        source = (java_tree / "sources" / "app" / "WebActivity.java").read_text().splitlines()
        static_line = next(i + 1 for i, l in enumerate(source)
                           if 'loadUrl("https://static.example.com/ok")' in l)
        flagged = {f.line for f in analyze_webviews(java_tree) if "loads a URL" in f.title}
        assert static_line not in flagged

    def test_ssl_error_proceed_is_found(self, java_tree):
        """
        Purpose:
            Pin that continuing past a certificate error is reported under the network class.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.
        """
        f = next(f for f in analyze_webviews(java_tree) if "TLS certificate" in f.title)
        assert f.severity == "High" and f.vuln_class == "NETWORK-01"

    def test_framework_noise_is_skipped(self, java_tree):
        """
        Purpose:
            Pin that the same pattern in framework code is not reported.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.
        """
        assert not any("androidx" in f.file for f in analyze_webviews(java_tree))

    def test_empty_tree(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no source yields nothing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert analyze_webviews(tmp_path) == []


class TestManifestFromApk:
    """
    Purpose:
        Decoding the manifest straight out of the application file when the source tree has none.

    Implementation notes:
        Only a Java decompile leaves a readable manifest in the tree. The source roots the other frameworks produce do not have one at all, so without decoding it from the application file those frameworks would silently get no manifest coverage whatsoever.
    """
    def test_real_apk_manifest_is_decoded_when_source_root_has_none(self, tmp_path):
        """
        Purpose:
            Pin that a real application's manifest is decoded and scanned when the source root has none.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            The temporary directory stands in for an extracted web or bundle root, which genuinely has no manifest in it.
        """
        from fixtures import DVHMA_CORDOVA_APKS, require_fixture
        apk = require_fixture(*DVHMA_CORDOVA_APKS)
        found = analyze_manifest(tmp_path, apk_path=str(apk))
        assert found, "expected manifest findings decoded straight from the APK"
        assert any("debuggable" in f.title for f in found)

    def test_no_apk_and_no_manifest_is_empty_not_an_error(self, tmp_path):
        """
        Purpose:
            Pin that neither a manifest nor an application file yields nothing rather than failing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert analyze_manifest(tmp_path, apk_path=None) == []

    def test_unreadable_apk_is_empty_not_an_error(self, tmp_path):
        """
        Purpose:
            Pin that an application file that cannot be opened yields nothing rather than failing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        bogus = tmp_path / "not.apk"
        bogus.write_bytes(b"not a zip")
        assert analyze_manifest(tmp_path, apk_path=str(bogus)) == []


class TestRunnerAndFindingShape:
    """
    Purpose:
        The runner that aggregates the scanners, and the shape of what they produce.
    """
    def test_runner_aggregates_by_profile(self, tree):
        """
        Purpose:
            Pin that running a known profile produces findings and a summary counting them by severity.

        Parameters:
            tree: The decompiled tree holding the manifest.
        """
        found = run_sast(tree, "java_kotlin")
        assert found and summarize(found)["Critical"] >= 1

    def test_unknown_profile_still_runs_manifest(self, tree):
        """
        Purpose:
            Pin that an unrecognised profile still gets the manifest scanner.

        Parameters:
            tree: The decompiled tree holding the manifest.

        Implementation notes:
            Every framework has a manifest, so an unknown one is better served with partial coverage than with none.
        """
        assert run_sast(tree, "made-up-profile")

    def test_bad_source_root_is_empty_not_an_error(self, tmp_path):
        """
        Purpose:
            Pin that a source root that does not exist yields nothing rather than failing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert run_sast(tmp_path / "nope", "java_kotlin") == []

    def test_one_failing_scanner_does_not_lose_the_others(self, tree, monkeypatch):
        """
        Purpose:
            Pin that a scanner raising does not cost the findings of the scanners beside it.

        Parameters:
            tree: The decompiled tree.
            monkeypatch: Replaces the scanner registry with one failing and one working scanner.

        Implementation notes:
            The scanners share nothing, so one failing is a reason to lose its own results and nothing else.
        """
        def boom(*_, **__):
            """
            Purpose:
                Fail, standing in for a scanner that raised.

            Parameters:
                _: Positional arguments, ignored.
                __: Keyword arguments, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("scanner exploded")

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.sast.runner._SCANNERS",
            {"manifest": boom, "webview": lambda root_unused, **_: [
                SastFinding(title="ok", severity="Low", description="d")]})
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.sast.runner._BY_PROFILE",
            {"java_kotlin": ("manifest", "webview")})
        assert titles(run_sast(tree, "java_kotlin")) == ["ok"]

    def test_severity_normalization(self):
        """
        Purpose:
            Pin how severities of varying case, wording and absence are normalised.
        """
        assert normalize_severity("HIGH") == "High"
        assert normalize_severity("info") == "Informational"
        assert normalize_severity(None) == "Medium"

    def test_converted_finding_carries_source_and_pipeline_keys(self):
        """
        Purpose:
            Pin that a converted finding carries its provenance and both spellings of the fields the rest of the pipeline reads.

        Implementation notes:
            The duplicate spellings exist because the report and the validation layer grew separate conventions, and a finding missing either is dropped further down with nothing reported.
        """
        d = to_scan_finding(SastFinding(
            title="T", severity="High", description="D", file="a.java", line=7,
            vuln_class="PLATFORM-04", detector="webview"))
        assert d["source"] == "static-analyzer"
        assert d["title"] == "T" and d["vulnerability_type"] == "T"
        assert d["line"] == "7" and d["line_number"] == 7
        assert d["vuln_class"] == "PLATFORM-04"


class TestNetworkConfig:
    """
    Purpose:
        The network configuration scanner.
    """
    @pytest.fixture
    def nsc(self, tmp_path):
        """
        Purpose:
            Build a tree holding a network configuration permitting plain-text traffic and trusting user-installed authorities.

        Parameters:
            tmp_path: Directory the tree is written into.

        Returns:
            The tree root.
        """
        xml = tmp_path / "resources" / "res" / "xml"
        xml.mkdir(parents=True)
        (xml / "network_security_config.xml").write_text('''<?xml version="1.0"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="user"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true"><domain>api.legacy.com</domain></domain-config>
  <debug-overrides/>
</network-security-config>''')
        return tmp_path

    def test_app_wide_cleartext_and_user_ca_are_high(self, nsc):
        """
        Purpose:
            Pin that permitting plain-text traffic across the whole application and trusting user-installed authorities are both reported seriously.

        Parameters:
            nsc: The tree holding the network configuration.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_network_config
        found = {f.title: f for f in analyze_network_config(nsc)}
        assert any("cleartext traffic app-wide" in t for t in found)
        assert any("user-installed CA" in t for t in found)
        for title, f in found.items():
            if "app-wide" in title or "user-installed" in title:
                assert f.severity == "High"

    def test_missing_pinning_is_informational_not_a_finding_on_its_own(self, nsc):
        """
        Purpose:
            Pin that the absence of certificate pinning is recorded for information rather than as a defect.

        Parameters:
            nsc: The tree holding the network configuration.

        Implementation notes:
            Most applications do not pin and are not wrong to, so reporting its absence as a fault is the report padding the severity rules exist to prevent.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_network_config
        f = next(f for f in analyze_network_config(nsc) if "pinning" in f.title)
        assert f.severity == "Informational"

    def test_no_config_is_empty(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no network configuration yields nothing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_network_config
        assert analyze_network_config(tmp_path) == []


class TestTlsBypass:
    """
    Purpose:
        The scanner for code that accepts any certificate or any hostname.
    """
    def test_empty_trust_manager_and_verifier_are_found(self, tmp_path):
        """
        Purpose:
            Pin that a certificate check that accepts everything and a hostname check that returns true are both reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Security considerations:
            These two together remove transport security entirely, so they are among the highest-value things a deterministic pass can find.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "T.java").write_text(
            "class T implements X509TrustManager {\n"
            "  public void checkServerTrusted(X509Certificate[] c, String s) throws E { }\n"
            "  public boolean verify(String h, SSLSession s) { return true; }\n}")
        titles_found = [f.title for f in analyze_tls_bypass(tmp_path)]
        assert any("every server certificate" in t for t in titles_found)
        assert any("every hostname" in t for t in titles_found)

    def test_clean_source_is_empty(self, tmp_path):
        """
        Purpose:
            Pin that ordinary source yields nothing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "C.java").write_text("class C { void f(){ int x = 1; } }")
        assert analyze_tls_bypass(tmp_path) == []


class TestInjection:
    """
    Purpose:
        The injection scanner, on queries built by joining strings together.
    """
    @pytest.fixture
    def provider(self, tmp_path):
        """
        Purpose:
            Build a tree holding a component reachable by other applications with two injectable queries and one written safely.

        Parameters:
            tmp_path: Directory the tree is written into.

        Returns:
            The tree root.
        """
        src = tmp_path / "s"
        src.mkdir()
        (src / "P.java").write_text(
            "public class P extends ContentProvider {\n"
            "  Cursor a(String x){ return db.rawQuery(\"SELECT * FROM u WHERE n='\" + x + \"'\", null); }\n"
            "  void b(String x){ db.execSQL(\"DELETE FROM t WHERE id=\" + x); }\n"
            "  Cursor s(String x){ return db.rawQuery(\"SELECT * FROM u WHERE n=?\", new String[]{x}); }\n}")
        return tmp_path

    def test_sql_string_with_apostrophes_is_matched(self, provider):
        """
        Purpose:
            Pin that a query containing quoted values is matched.

        Parameters:
            provider: The tree holding the component.

        Implementation notes:
            A pattern excluding quote characters stops at the apostrophe opening the compared value, which means the most typical injectable query would never match at all.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        assert any("rawQuery" in f.title for f in analyze_injection(provider))

    def test_provider_context_escalates_severity(self, provider):
        """
        Purpose:
            Pin that a query inside a component reachable by other applications is raised to the top severity and says so in its title.

        Parameters:
            provider: The tree holding the component.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        f = next(f for f in analyze_injection(provider) if "rawQuery" in f.title)
        assert f.severity == "Critical" and "ContentProvider" in f.title

    def test_one_finding_per_injectable_query(self, provider):
        """
        Purpose:
            Pin that each injectable query produces exactly one finding.

        Parameters:
            provider: The tree holding the component.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        assert len(analyze_injection(provider)) == 2

    def test_parameterised_query_is_not_flagged(self, provider):
        """
        Purpose:
            Pin that a query using placeholders is not reported.

        Parameters:
            provider: The tree holding the component.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        assert 4 not in {f.line for f in analyze_injection(provider)}


class TestSqlTypingAndPosition:
    """
    Purpose:
        Grading an injectable query by what was concatenated and where it landed.

    Implementation notes:
        On a real application all nine query findings scored the value's origin as unknown and so all came out at the same middle severity, a judgement that fired zero times out of nine and, read by hand, ranked a genuine second-order injection identically to a concatenated timestamp.
    """
    def _findings(self, tmp_path, body, name="Q.java"):
        """
        Purpose:
            Write one source file and return only the findings raised against it.

        Parameters:
            tmp_path: The tree root.
            body: The source to analyse.
            name: The file's name.

        Returns:
            The findings for that file.

        Implementation notes:
            Filtered to this call's own file because several tests write twice into one tree to compare severities, and an unfiltered scan would return both files' findings in whatever order the filesystem lists them, so taking the first could silently pick the wrong one.
        """
        (tmp_path / name).write_text(body)
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        return [f for f in analyze_injection(tmp_path) if f.file == name]

    def test_a_long_operand_is_informational(self, tmp_path):
        """
        Purpose:
            Pin that concatenating a numeric value is recorded for information only.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._findings(tmp_path, '''
public class f {
  void q(SQLiteDatabase db) {
    long j = this.f3937c;
    db.execSQL("DELETE FROM t WHERE ts=" + j);
  }
}''')
        assert len(found) == 1 and found[0].severity == "Informational"

    def test_a_currenttimemillis_operand_is_informational(self, tmp_path):
        """
        Purpose:
            Pin that concatenating a clock reading is recorded for information only.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Nothing can be injected through a value the attacker cannot influence, and these two shapes are most of what a naive pattern match reports.
        """
        found = self._findings(tmp_path, '''
public class i {
  void q(SQLiteDatabase db) {
    db.execSQL("DELETE FROM t WHERE ts=" + System.currentTimeMillis());
  }
}''')
        assert len(found) == 1 and found[0].severity == "Informational"

    def test_a_mixed_numeric_and_string_concat_is_not_suppressed(self, tmp_path):
        """
        Purpose:
            Pin that a query joining both a numeric value and a text value is not written off as informational.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            The numeric part is harmless and the text part is not, so suppressing on the presence of the first would hide the second.
        """
        found = self._findings(tmp_path, '''
public class m {
  void q(SQLiteDatabase db, String name) {
    long j = this.f3937c;
    db.execSQL("DELETE FROM t WHERE ts=" + j + " AND name='" + name + "'");
  }
}''')
        assert found and found[0].severity != "Informational"

    def test_a_table_name_after_from_gets_allowlist_advice(self, tmp_path):
        """
        Purpose:
            Pin that a value concatenated where an identifier belongs is classified as such, scored low, and advised to use an allowed list rather than a placeholder.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            A placeholder cannot stand in for a table name, so the usual advice does not apply and following it would leave the developer stuck.
        """
        found = self._findings(tmp_path, '''
public class m {
  void q(SQLiteDatabase db, String tableName) {
    db.rawQuery("SELECT * FROM " + tableName, null);
  }
}''')
        f = found[0]
        assert f.extra["sql_position"] == "identifier"
        assert "allowlist" in f.recommendation
        assert "placeholder" not in f.recommendation.lower()
        assert f.severity == "Low"

    def test_a_quoted_value_outranks_a_table_name(self, tmp_path):
        """
        Purpose:
            Pin that a value concatenated inside quotes scores above one concatenated as an identifier.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.validation.gates import severity_rank

        table = self._findings(tmp_path, '''
public class m {
  void q(SQLiteDatabase db, String tableName) {
    db.rawQuery("SELECT * FROM " + tableName, null);
  }
}''', name="Table.java")[0]
        value = self._findings(tmp_path, '''
public class n {
  void q(SQLiteDatabase db, String name) {
    db.rawQuery("SELECT * FROM u WHERE n='" + name + "'", null);
  }
}''', name="Value.java")[0]
        assert severity_rank(value.severity) > severity_rank(table.severity)

    def test_a_cursor_getstring_source_is_treated_as_external(self, tmp_path):
        """
        Purpose:
            Pin that a value read back out of the application's own store is treated as externally influenced and scored seriously.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            This is the second-order shape from the real report: whatever was written into that store earlier is what comes back out, so it is no more trustworthy than its original source.
        """
        found = self._findings(tmp_path, '''
public class c {
  void q(SQLiteDatabase db, Cursor cursor) {
    String string = cursor.getString(0);
    String strK = cursor.getString(1);
    db.execSQL("INSERT INTO USER_PROFILES VALUES ('" + string + "', '" + strK + "');");
  }
}''')
        f = found[0]
        assert f.severity == "High"
        assert f.extra["operand_provenance"] == "external"

    def test_no_title_reads_sql_a_query(self, tmp_path):
        """
        Purpose:
            Pin that no title in this family reads ungrammatically, across every sink.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._findings(tmp_path, '''
public class allrules {
  void q(SQLiteDatabase db, String x) {
    Cursor a = db.rawQuery("SELECT * FROM u WHERE n='" + x + "'", null);
    db.execSQL("DELETE FROM t WHERE id=" + x);
    String where = "n='" + x + "'";
    String sel = "SELECT * FROM u WHERE n='" + x + "'";
  }
}''')
        assert found
        for f in found:
            assert not re.search(r"\bSQL (a|an) ", f.title), f.title

    def test_operand_order_is_deterministic(self, tmp_path):
        """
        Purpose:
            Pin that a query joining many values produces the same findings in the same order every run.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            An unstable order would make two scans of the same application differ for no reason, which is indistinguishable from a real change.
        """
        body = '''
public class d {
  void q(SQLiteDatabase db, String a1, String a2, String a3, String a4,
        String a5, String a6, String a7) {
    db.execSQL("DELETE FROM t WHERE x=" + a1 + a2 + a3 + a4 + a5 + a6 + a7);
  }
}'''
        (tmp_path / "D.java").write_text(body)
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        results = [tuple((f.title, f.severity, f.line) for f in analyze_injection(tmp_path))
                  for _ in range(5)]
        assert len(set(results)) == 1

    def test_contentprovider_in_an_unrelated_class_does_not_make_a_query_critical(self, tmp_path):
        """
        Purpose:
            Pin that a component reachable by other applications defined elsewhere in the file does not escalate an unrelated query.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Escalating on the file rather than on the enclosing class made every query in a file merely mentioning that component type come out at the top severity.
        """
        found = self._findings(tmp_path, '''
public class Helper {
  void q(SQLiteDatabase db, String x) {
    db.rawQuery("SELECT * FROM u WHERE n='" + x + "'", null);
  }
}
class SomeOtherThing extends ContentProvider {
  public Cursor query(Uri uri) { return null; }
}''')
        assert found[0].severity != "Critical"

    def test_a_real_contentprovider_query_is_still_critical(self, tmp_path):
        """
        Purpose:
            Pin that a query genuinely inside such a component is still escalated.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._findings(tmp_path, '''
public class P extends ContentProvider {
  Cursor a(SQLiteDatabase db, String x) {
    return db.rawQuery("SELECT * FROM u WHERE n='" + x + "'", null);
  }
}''')
        assert found[0].severity == "Critical"


class TestSecretsAndSdks:
    """
    Purpose:
        The scanners for embedded credentials, plain-text endpoints and third-party components.
    """
    def test_typed_secret_and_cleartext_endpoint(self, tmp_path):
        """
        Purpose:
            Pin that a recognisably shaped credential is reported at the top severity and a plain-text endpoint is reported alongside it.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Security considerations:
            The credential in the fixture is a published placeholder rather than a real one.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
        src = tmp_path / "s"
        src.mkdir()
        (src / "K.java").write_text(
            'class K { static final String A = "AKIAIOSFODNN7EXAMPLE";\n'
            '  static final String U = "http://api.example.com/api/v1/login"; }')
        found = analyze_secrets(tmp_path)
        assert any(f.vuln_class == "SECRET-01" and f.severity == "Critical" for f in found)
        assert any("cleartext HTTP" in f.title for f in found)

    def test_key_in_standard_config_file_is_downgraded(self, tmp_path):
        """
        Purpose:
            Pin that a key in a configuration file that is meant to ship is scored lower.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Those files are generated by the platform's own tooling and are designed to be distributed, so scoring them like a leaked credential buries the ones that really are.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
        (tmp_path / "google-services.json").write_text('{"api_key":"AKIAIOSFODNN7EXAMPLE"}')
        f = next(f for f in analyze_secrets(tmp_path) if f.vuln_class == "SECRET-01")
        assert f.severity == "Medium"

    def test_debug_sdk_is_reported(self, tmp_path):
        """
        Purpose:
            Pin that a debugging component shipped in a build is reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            That component opens an inspection channel into the running application, which is a real exposure in anything a user installs.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.sdk_inventory import analyze_sdks
        p = tmp_path / "sources" / "com" / "facebook" / "stetho"
        p.mkdir(parents=True)
        (p / "S.java").write_text("package com.facebook.stetho; class S {}")
        f = next(f for f in analyze_sdks(tmp_path) if "Stetho" in f.title)
        assert f.severity == "Medium" and f.vuln_class == "SUPPLY-02"

    def test_sdk_inventory_is_informational_with_versions(self, tmp_path):
        """
        Purpose:
            Pin that the third-party inventory is recorded for information, with each component's name and version.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Shipping a library is not a fault, but the version is what lets a reader check it against known issues themselves.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.sdk_inventory import analyze_sdks
        p = tmp_path / "sources" / "okhttp3"
        p.mkdir(parents=True)
        (p / "OkHttpClient.java").write_text(
            'package okhttp3; class OkHttpClient { static final String VERSION = "4.12.0"; }')
        f = next(f for f in analyze_sdks(tmp_path) if "third-party SDK" in f.title)
        assert f.severity == "Informational"
        assert f.extra["sdk_inventory"][0]["name"] == "OkHttp"
        assert f.extra["sdk_inventory"][0]["version"] == "4.12.0"


class TestSignatureDerivedKey:
    """
    Purpose:
        The scanner for an app using its own signing certificate as key material.
    """
    def test_certificate_read_alongside_hmac_is_flagged(self, tmp_path):
        """
        Purpose:
            Pin that reading the signing certificate and referencing an HMAC primitive in the same file is reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Security considerations:
            This is the shape the finding exists for: the certificate, which ships inside the APK, standing in for a secret in a signing routine.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.signature_derived_key import (
            analyze_signature_derived_key)
        src = tmp_path / "s"
        src.mkdir()
        (src / "SignHelper.java").write_text(
            "class SignHelper {\n"
            "  String cert() {\n"
            "    Signature[] sigs = getPackageManager()\n"
            "        .getPackageInfo(pkg, 64).signatures;\n"
            "    return sigs[0].toCharsString();\n"
            "  }\n"
            "  native String hmacSign(String key, String data);\n"
            "}")
        found = analyze_signature_derived_key(tmp_path)
        assert len(found) == 1
        f = found[0]
        assert f.vuln_class == "CRYPTO-02" and f.severity == "High"
        assert "signing certificate" in f.title

    def test_certificate_read_alone_is_not_flagged(self, tmp_path):
        """
        Purpose:
            Pin that reading the signing certificate for an ordinary integrity check, with no cryptographic or native sink nearby, is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Checking the app has not been re-signed is the normal, safe use of this API, and is most of why it appears in an app at all -- flagging every occurrence would bury the genuine cases.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.signature_derived_key import (
            analyze_signature_derived_key)
        src = tmp_path / "s"
        src.mkdir()
        (src / "IntegrityCheck.java").write_text(
            "class IntegrityCheck {\n"
            "  boolean isOfficial() {\n"
            "    Signature[] sigs = getPackageManager()\n"
            "        .getPackageInfo(pkg, 64).signatures;\n"
            "    return sigs[0].toCharsString().equals(KNOWN_GOOD);\n"
            "  }\n"
            "}")
        assert analyze_signature_derived_key(tmp_path) == []

    def test_crypto_sink_alone_is_not_flagged(self, tmp_path):
        """
        Purpose:
            Pin that ordinary cryptographic code with no signature read is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.signature_derived_key import (
            analyze_signature_derived_key)
        src = tmp_path / "s"
        src.mkdir()
        (src / "Crypto.java").write_text(
            "class Crypto { Cipher c = Cipher.getInstance(\"AES\"); }")
        assert analyze_signature_derived_key(tmp_path) == []

    def test_empty_tree(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no source yields nothing.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.signature_derived_key import (
            analyze_signature_derived_key)
        assert analyze_signature_derived_key(tmp_path) == []


class TestSemgrepRunner:
    """
    Purpose:
        The rule engine wrapper.

    Implementation notes:
        The engine is a declared dependency, but a declared dependency can still be absent, of the wrong version, blocked by a sandbox or hung, and none of those may cost the scan its other results.
    """
    def test_missing_semgrep_returns_empty(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an engine that cannot be found yields nothing rather than failing.

        Parameters:
            tmp_path: The source root.
            monkeypatch: Reports the engine as unresolvable.
        """
        from lu77U_MobileSec.analyzers.sast import semgrep_runner
        monkeypatch.setattr(semgrep_runner, "_resolve_semgrep", lambda: None)
        assert semgrep_runner.run_semgrep(tmp_path) == []

    def test_timeout_returns_empty(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a run that exceeded its time limit yields nothing rather than failing.

        Parameters:
            tmp_path: The source root.
            monkeypatch: Resolves the engine and makes the run time out.
        """
        import subprocess
        from lu77U_MobileSec.analyzers.sast import semgrep_runner

        def boom(*_, **__):
            """
            Purpose:
                Report the run as having exceeded its time limit.

            Parameters:
                _: Positional arguments, ignored.
                __: Keyword arguments, ignored.

            Raises:
                subprocess.TimeoutExpired: Always.
            """
            raise subprocess.TimeoutExpired("semgrep", 1)

        monkeypatch.setattr(semgrep_runner, "_resolve_semgrep", lambda: ["semgrep"])
        monkeypatch.setattr(semgrep_runner.subprocess, "run", boom)
        assert semgrep_runner.run_semgrep(tmp_path) == []

    def test_unparseable_output_returns_empty(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that output the wrapper cannot read yields nothing rather than failing.

        Parameters:
            tmp_path: The source root.
            monkeypatch: Resolves the engine and makes it return unreadable output.
        """
        from lu77U_MobileSec.analyzers.sast import semgrep_runner

        class R:
            """
            Purpose:
                A completed process whose output cannot be parsed.

            Attributes:
                stdout: Output that is not in the expected format.
                stderr: The error output.
                returncode: The exit status.
            """
            stdout, stderr, returncode = "not json", "", 0

        monkeypatch.setattr(semgrep_runner, "_resolve_semgrep", lambda: ["semgrep"])
        monkeypatch.setattr(semgrep_runner.subprocess, "run", lambda *_, **__: R())
        assert semgrep_runner.run_semgrep(tmp_path) == []

    def test_results_are_mapped_with_metadata(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a rule result is mapped to a finding carrying its class, its mapped severity, a path relative to the source root, its line, its detector and its chain tag.

        Parameters:
            tmp_path: The source root.
            monkeypatch: Resolves the engine and makes it return one result.

        Implementation notes:
            The path is made relative because the engine reports absolute paths, which would otherwise put the analyst's own directory layout into the published report.
        """
        import json as _json
        from lu77U_MobileSec.analyzers.sast import semgrep_runner

        payload = {"results": [{
            "check_id": "lu77u.android.webview.js-interface-added",
            "path": str(tmp_path / "A.java"),
            "start": {"line": 12}, "end": {"line": 12},
            "extra": {"severity": "WARNING", "message": "bridge exposed",
                      "lines": "w.addJavascriptInterface(o, \"B\");",
                      "metadata": {"vuln_class": "PLATFORM-04", "chain_tag": "js_bridge",
                                   "cwe": "CWE-749"}},
        }]}

        class R:
            """
            Purpose:
                A completed process returning one rule result.

            Attributes:
                stdout: The serialised result.
                stderr: The error output.
                returncode: The exit status.
            """
            stdout, stderr, returncode = _json.dumps(payload), "", 0

        monkeypatch.setattr(semgrep_runner, "_resolve_semgrep", lambda: ["semgrep"])
        monkeypatch.setattr(semgrep_runner.subprocess, "run", lambda *_, **__: R())
        f = semgrep_runner.run_semgrep(tmp_path)[0]
        assert f.vuln_class == "PLATFORM-04"
        assert f.severity == "Medium"
        assert f.file == "A.java"
        assert f.line == 12 and f.detector == "semgrep"
        assert f.extra["chain_tag"] == "js_bridge"

    def test_bundled_rules_directory_exists(self):
        """
        Purpose:
            Pin that the bundled rule directory exists and holds rules.

        Implementation notes:
            An engine with no rules runs cleanly and finds nothing, which is indistinguishable from an application with nothing wrong with it.
        """
        from lu77U_MobileSec.analyzers.sast.semgrep_runner import RULES_DIR
        assert RULES_DIR.is_dir()
        assert list(RULES_DIR.glob("*.yml")), "expected bundled Android rules"


class TestTaskAffinity:
    """
    Purpose:
        The scanner for components that can be opened inside another application's task.

    Implementation notes:
        A component inherits the package name as its task grouping. Any other value is a string another application can also declare, which is what lets the victim's component be opened inside a hostile task.
    """
    def _manifest(self, tmp_path, body):
        """
        Purpose:
            Write a manifest around the given application body and return only the task-grouping findings.

        Parameters:
            tmp_path: The tree root.
            body: The application element's contents.

        Returns:
            The findings of that class.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.x.app">\n'
            '  <uses-sdk android:targetSdkVersion="33" android:minSdkVersion="24"/>\n'
            f'  <application android:label="X">{body}</application>\n'
            '</manifest>')
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        return [f for f in analyze_manifest(tmp_path) if f.vuln_class == "PLATFORM-09"]

    def test_foreign_affinity_is_reported(self, tmp_path):
        """
        Purpose:
            Pin that a component declaring a grouping other than the package name is reported, naming the component.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._manifest(
            tmp_path, '<activity android:name=".Login" '
                      'android:taskAffinity="com.shared.flow"/>')
        assert len(found) == 1
        assert "Login" in found[0].title

    def test_the_package_name_is_the_default_and_not_a_finding(self, tmp_path):
        """
        Purpose:
            Pin that a component declaring the package name explicitly is not reported, since that is the default.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert not self._manifest(
            tmp_path, '<activity android:name=".A" android:taskAffinity="com.x.app"/>')

    def test_an_empty_affinity_is_the_fix_not_the_bug(self, tmp_path):
        """
        Purpose:
            Pin that an empty grouping is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            An empty value isolates the component in a task of its own, which is the hardening, so reporting it would tell the developer to undo it.
        """
        assert not self._manifest(
            tmp_path, '<activity android:name=".A" android:taskAffinity=""/>')

    def test_an_unset_affinity_is_not_a_finding(self, tmp_path):
        """
        Purpose:
            Pin that a component declaring no grouping at all is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert not self._manifest(tmp_path, '<activity android:name=".A"/>')

    def test_an_application_level_affinity_is_reported_once(self, tmp_path):
        """
        Purpose:
            Pin that a grouping declared for the whole application is reported once rather than once per component.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            It is inherited by every component, so repeating it per component would file the same finding as many times as the application has screens.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.x.app">\n'
            '  <application android:taskAffinity="com.shared">\n'
            '    <activity android:name=".A" android:taskAffinity="com.shared"/>\n'
            '    <activity android:name=".B" android:taskAffinity="com.shared"/>\n'
            '  </application>\n</manifest>')
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        found = [f for f in analyze_manifest(tmp_path) if f.vuln_class == "PLATFORM-09"]
        assert len(found) == 1


class TestProviderTraversalAndBiometrics:
    """
    Purpose:
        Two scanners with narrow reachability conditions: file access through a shared component, and an unbound authentication prompt.
    """
    def _run(self, tmp_path, name, body):
        """
        Purpose:
            Write one source file and run the injection scanner over the tree.

        Parameters:
            tmp_path: The tree root.
            name: The file's name.
            body: The source to analyse.

        Returns:
            Every finding the scanner raised.
        """
        (tmp_path / name).write_text(body)
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        return analyze_injection(tmp_path)

    def test_unguarded_openfile_is_reported(self, tmp_path):
        """
        Purpose:
            Pin that a shared component serving a file named by the caller with no containment check is reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Security considerations:
            The path segment comes from whichever application made the request, so without a check it names any file the serving application can read.
        """
        found = self._run(tmp_path, "P.java", '''
public class P extends ContentProvider {
  public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    File f = new File(getContext().getFilesDir(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(f, MODE_READ_ONLY);
  }
}''')
        assert [f.vuln_class for f in found] == ["PLATFORM-11"]

    def test_a_canonical_path_check_clears_it(self, tmp_path):
        """
        Purpose:
            Pin that a containment check on the resolved path clears the finding.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._run(tmp_path, "P.java", '''
public class P extends ContentProvider {
  public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    File f = new File(root, uri.getLastPathSegment());
    if (!f.getCanonicalPath().startsWith(root.getCanonicalPath())) throw new SecurityException();
    return ParcelFileDescriptor.open(f, MODE_READ_ONLY);
  }
}''')
        assert not [f for f in found if f.vuln_class == "PLATFORM-11"]

    def test_openfile_outside_a_provider_is_ignored(self, tmp_path):
        """
        Purpose:
            Pin that the same method on a class other applications cannot reach is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Reachability is what makes it a vulnerability rather than an ordinary file read, and only that component type is reachable from outside.
        """
        found = self._run(tmp_path, "H.java", '''
public class Helper {
  public ParcelFileDescriptor openFile(Uri uri, String mode) {
    return ParcelFileDescriptor.open(new File(uri.getPath()), 0);
  }
}''')
        assert not [f for f in found if f.vuln_class == "PLATFORM-11"]

    def test_unbound_biometric_prompt_is_reported(self, tmp_path):
        """
        Purpose:
            Pin that an authentication prompt bound to nothing is reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Security considerations:
            A prompt that only returns a success flag can be bypassed by changing that flag on a device the attacker controls, which is why the result has to be bound to something cryptographic.
        """
        found = self._run(tmp_path, "B.java", '''
public class Login {
  void auth() {
    BiometricPrompt p = new BiometricPrompt(this, executor, callback);
    p.authenticate(promptInfo);
  }
}''')
        assert [f.vuln_class for f in found] == ["AUTH-02"]

    def test_a_cryptoobject_clears_it(self, tmp_path):
        """
        Purpose:
            Pin that binding the prompt to a cryptographic operation clears the finding.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._run(tmp_path, "B.java", '''
public class Login {
  void auth() {
    BiometricPrompt p = new BiometricPrompt(this, executor, callback);
    p.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
  }
}''')
        assert not [f for f in found if f.vuln_class == "AUTH-02"]

    def test_the_prefilter_lets_the_new_rules_run(self):
        """
        Purpose:
            Pin that the markers each of these rules depends on are present in the file prefilter.

        Implementation notes:
            The prefilter skips a file on its raw bytes before anything decodes it, so a rule whose marker is missing from that list never fires at all and nothing reports that it did not.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import _FILE_MARKERS

        for marker in (b"openFile", b"openAssetFile", b"BiometricPrompt"):
            assert marker in _FILE_MARKERS


class TestBackendEndpoints:
    """
    Purpose:
        Endpoints that are meant to be reachable, filed as what they are.
    """
    def test_a_firebase_url_is_a_backend_finding_not_a_secret(self, tmp_path):
        """
        Purpose:
            Pin that a hosted database URL is reported as a backend finding rather than as a leaked credential.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            The URL is meant to be reachable and the access rules live on the server, so filing it as a leaked credential misstates what the owner actually has to fix.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets

        (tmp_path / "C.java").write_text(
            'class C { String db = "https://my-app-1234.firebaseio.com"; }')
        found = [f for f in analyze_secrets(tmp_path) if "firebase" in f.title.lower()]
        assert found and found[0].vuln_class == "BACKEND-01"
