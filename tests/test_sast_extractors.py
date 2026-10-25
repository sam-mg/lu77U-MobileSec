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
  <permission android:name="com.demo.SIG" android:protectionLevel="signature"/>
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

    @pytest.mark.parametrize("level, severity, wording", [
        ("normal", "Medium", "without the user being asked"),
        ("dangerous", "Low", "once the user accepts"),
        ("signature", None, None),
    ])
    def test_a_custom_permission_is_graded_by_who_can_get_it(self, tmp_path, level, severity, wording):
        """
        Purpose:
            Pin that a custom permission any app is simply granted is Medium, one that needs the user to accept a prompt is Low with wording that says so, and a signature one is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
            level: The declared protectionLevel.
            severity: The expected severity, or None when nothing is reported.
            wording: A phrase the description must contain.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            f'<permission android:name="com.demo.PERM" android:protectionLevel="{level}"/>'
            "<application/></manifest>")
        found = [f for f in analyze_manifest(tmp_path) if "weakly protected" in f.title]
        assert [f.severity for f in found] == ([severity] if severity else [])
        assert all(wording in f.description for f in found)

    @pytest.mark.parametrize("guard, reported", [
        ("com.demo.secure.PERM", True),
        ("com.demo.PERM", False),
        ("android.permission.BIND_JOB_SERVICE", False),
    ])
    def test_a_guard_the_app_never_declares_is_no_guard(self, tmp_path, guard, reported):
        """
        Purpose:
            Pin that an exported component guarded by a permission neither the app nor the platform declares is reported, and one guarded by a declared or platform permission is not.

        Parameters:
            tmp_path: Directory the fixture is written into.
            guard: The permission the receiver requires.
            reported: Whether the guard is reported as no guard.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            '<permission android:name="com.demo.PERM" android:protectionLevel="signature"/>'
            f'<application><receiver android:name="com.demo.R" android:exported="true" android:permission="{guard}"/>'
            "</application></manifest>")
        found = [f for f in analyze_manifest(tmp_path) if "never declares" in f.title]
        assert bool(found) is reported
        assert all(f.severity == "Medium" and f.extra["fact_key"].startswith("undeclared-guard:") for f in found)

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

    @pytest.mark.parametrize("body, reported", [
        ("handler.proceed(username, password);", True),
        ("if (host.equals(\"api.example.com\")) handler.proceed(username, password); else handler.cancel();", False),
        ("if (\"api.example.com\".equals(host)) { handler.proceed(u, p); }", False),
        ("handler.cancel();", False),
    ])
    def test_http_auth_credentials_need_a_host_check(self, tmp_path, body, reported):
        """
        Purpose:
            Pin that answering an HTTP auth challenge with credentials is reported unless the host argument is compared first.

        Parameters:
            tmp_path: Directory the fixture is written into.
            body: The callback's body.
            reported: Whether a finding is expected.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.webview import analyze_webviews
        src = tmp_path / "s"
        src.mkdir()
        (src / "Client.java").write_text(
            "class Client extends WebViewClient {\n"
            "  public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {\n"
            f"    {body}\n  }}\n}}")
        found = [f for f in analyze_webviews(tmp_path) if "HTTP auth" in f.title]
        assert bool(found) is reported

    @pytest.mark.parametrize("hook, reported", [
        ("public boolean shouldOverrideUrlLoading(WebView wv, String url) {\n    Log.d(\"t\", url);\n    return false;\n  }", True),
        ("public WebResourceResponse shouldInterceptRequest(WebView wv, WebResourceRequest r) {\n    return null;\n  }", True),
        ("public boolean shouldOverrideUrlLoading(WebView wv, String url) {\n"
         "    if (!url.startsWith(\"https://app.example.com/\")) return true;\n    return false;\n  }", False),
    ])
    def test_a_hook_that_checks_nothing_is_noted(self, tmp_path, hook, reported):
        """
        Purpose:
            Pin that a navigation or request hook with nothing but logging and the default return is noted, and one that checks the URL is not.

        Parameters:
            tmp_path: Directory the fixture is written into.
            hook: The overriding method.
            reported: Whether a note is expected.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.webview import analyze_webviews
        src = tmp_path / "s"
        src.mkdir()
        (src / "Client.java").write_text(f"class Client extends WebViewClient {{\n  {hook}\n}}")
        found = [f for f in analyze_webviews(tmp_path) if "checks nothing" in f.title]
        assert bool(found) is reported and all(f.severity == "Informational" for f in found)

    @pytest.mark.parametrize("extra, reported", [("", True), ("CookieManager.getInstance().setAcceptCookie(false);", False)])
    def test_a_webview_loading_outside_urls_with_cookies_on(self, tmp_path, extra, reported):
        """
        Purpose:
            Pin that a WebView loading a URL from the Intent is noted as sharing the app's cookies unless cookies are turned off.

        Parameters:
            tmp_path: Directory the fixture is written into.
            extra: Code added before the load.
            reported: Whether the note is expected.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.webview import analyze_webviews
        src = tmp_path / "s"
        src.mkdir()
        (src / "Web.java").write_text(
            "class Web extends Activity {\n  void f(WebView webView) {\n"
            f"    {extra}\n    webView.loadUrl(getIntent().getStringExtra(\"url\"));\n  }}\n}}")
        found = [f for f in analyze_webviews(tmp_path) if "cookies" in f.title]
        assert bool(found) is reported

    def test_settings_are_filed_by_what_they_open(self, java_tree):
        """
        Purpose:
            Pin that JavaScript being enabled is a misconfiguration (PLATFORM-06), as wording inference files it, while file access settings are PLATFORM-05.

        Parameters:
            java_tree: The decompiled tree holding the WebView source.
        """
        found = analyze_webviews(java_tree)
        assert {f.vuln_class for f in found if "JavaScript enabled" in f.title} == {"PLATFORM-06"}
        assert {f.vuln_class for f in found if "universal access" in f.title} == {"PLATFORM-05"}

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

    def test_app_wide_cleartext_is_high_and_user_ca_is_medium(self, nsc):
        """
        Purpose:
            Pin that app-wide plain-text traffic is High, and that trusting user-installed authorities is Medium with the vector that explains why.

        Parameters:
            nsc: The tree holding the network configuration.

        Implementation notes:
            Trusting the user CA store is not a trust-all bypass: the attacker first has to get their CA installed on the victim's device, which the vector records as user interaction (6.8).
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_network_config
        found = {f.title: f for f in analyze_network_config(nsc)}
        assert any("cleartext traffic app-wide" in t for t in found)
        assert any("user-installed CA" in t for t in found)
        for title, f in found.items():
            if "app-wide" in title:
                assert f.severity == "High"
            if "user-installed" in title:
                assert (f.severity, f.cvss_vector) == ("Medium", "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N")
                assert f.vuln_class == "NETWORK-05"

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

    def test_the_lint_flagged_socket_factory_uses_are_found(self, tmp_path):
        """
        Purpose:
            Pin that SSLCertificateSocketFactory.getInsecure() and a socket opened by InetAddress (by variable or factory call) are reported, and one opened by hostname is not.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Shaped like the Ghera benchmarks that plant them, whose scans reported only the other TLS flaws in the same apps.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "S.java").write_text(
            "class S {\n"
            "  void a() { javax.net.ssl.SSLSocketFactory f = android.net.SSLCertificateSocketFactory.getInsecure(-1, null); }\n"
            "  void b() {\n"
            "    android.net.SSLCertificateSocketFactory x = (android.net.SSLCertificateSocketFactory) android.net.SSLCertificateSocketFactory.getDefault(0);\n"
            "    java.net.InetAddress add = java.net.InetAddress.getByAddress(addr);\n"
            "    javax.net.ssl.SSLSocket y = (javax.net.ssl.SSLSocket) x.createSocket(add, 443);\n"
            "    x.createSocket(java.net.InetAddress.getByName(h), 443);\n"
            "    x.createSocket(\"example.com\", 443);\n"
            "  }\n}")
        found = analyze_tls_bypass(tmp_path)
        assert sum("getInsecure()" in f.title for f in found) == 1
        assert sorted(f.line for f in found if "by IP address" in f.title) == [6, 7]

    def test_a_plain_socket_is_reported_unless_tls_is_layered_over_it(self, tmp_path):
        """
        Purpose:
            Pin that new Socket(...) in a file with no TLS wrapping is a cleartext finding, and one wrapped by createSocket(socket, host, port, true), or a ServerSocket, is not.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "Plain.java").write_text(
            "class Plain { void f() throws Exception {\n"
            "  java.net.Socket s = new java.net.Socket();\n"
            "  s.connect(new java.net.InetSocketAddress(host, 8888)); } }")
        (src / "Wrapped.java").write_text(
            "class Wrapped { void f(javax.net.ssl.SSLSocketFactory sf) throws Exception {\n"
            "  java.net.Socket raw = new java.net.Socket(host, 443);\n"
            "  java.net.Socket tls = sf.createSocket(raw, host, 443, true); } }")
        (src / "Server.java").write_text(
            "class Server { void f() throws Exception { java.net.ServerSocket ss = new java.net.ServerSocket(9000); } }")
        found = [(f.file, f.line, f.vuln_class) for f in analyze_tls_bypass(tmp_path) if "Plain TCP" in f.title]
        assert found == [("s/Plain.java", 2, "NETWORK-02")]

    def test_distinct_tls_flaws_survive_deduplication_and_one_trust_manager_stays_one(self, tmp_path):
        """
        Purpose:
            Pin that getInsecure() and an always-true verifier seven lines apart stay two findings, while the two rules flagging one trust-all TrustManager merge.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            A Ghera scan folded getInsecure() into the verifier a few lines below it, and the benchmark about getInsecure() was left with no finding naming it.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        from lu77U_MobileSec.analyzers.sast.findings import to_scan_findings
        from lu77U_MobileSec.validation.dedupe import deduplicate
        src = tmp_path / "s"
        src.mkdir()
        (src / "Svc.java").write_text(
            "class Svc {\n"
            "  void f() {\n"
            "    javax.net.ssl.TrustManager[] trustAllCerts = {new X() {\n"
            "      public void checkServerTrusted(X509Certificate[] c, String s) { }\n"
            "    }};\n"
            "    javax.net.ssl.SSLSocketFactory f = android.net.SSLCertificateSocketFactory.getInsecure(-1, null);\n"
            "    conn.setHostnameVerifier(new HostnameVerifier() {\n"
            "      public boolean verify(String s, SSLSession ss) { return true; }\n"
            "    });\n  }\n}")
        findings = to_scan_findings(analyze_tls_bypass(tmp_path))
        agent = {"title": "TLS validation disabled", "vuln_class": "NETWORK-01", "source": "agent",
                 "file": findings[0]["file"], "line": 6, "severity": "Critical", "description": "x"}
        kept = deduplicate(findings + [agent])
        assert sorted(f["fact_key"] for f in kept) == [
            "tls:hostname-verifier", "tls:insecure-socket-factory", "tls:trust-manager"]

    def test_a_plain_socket_factory_by_address_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that createSocket(InetAddress, ...) in a file that never names SSLCertificateSocketFactory is left alone.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "P.java").write_text(
            "class P { void f(javax.net.ssl.SSLSocketFactory sf) throws Exception {\n"
            "  java.net.InetAddress a = java.net.InetAddress.getByName(\"h\");\n"
            "  sf.createSocket(a, 443); } }")
        assert analyze_tls_bypass(tmp_path) == []

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

    def test_kotlin_compiled_trust_all(self, tmp_path):
        """
        Purpose:
            Pin that a trust-all factory written in Kotlin is found: check methods holding only Intrinsics null checks, and a hostname-verifier lambda compiled to a static method that returns true.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            This is JADX's rendering of a real Kotlin OkHttpClientFactory; the empty-body and verify() patterns missed it entirely.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "platform/sources/com/demo"
        src.mkdir(parents=True)
        (src / "Factory.java").write_text(
            "public final class Factory {\n"
            "    public static final boolean create$lambda$0(java.lang.String str, javax.net.ssl.SSLSession s) {\n"
            "        return true;\n    }\n"
            "    X509TrustManager tm = new X509TrustManager() {\n"
            "        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, java.lang.String authType) {\n"
            "            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(chain, \"chain\");\n"
            "            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(authType, \"authType\");\n"
            "        }\n    };\n}\n")
        titles = {f.title for f in analyze_tls_bypass(tmp_path)}
        assert titles == {"TrustManager accepts every server certificate", "HostnameVerifier accepts every hostname"}

    def test_validating_kotlin_trust_manager_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that a check method doing real work after its null checks is not mistaken for an empty one.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        src = tmp_path / "s"
        src.mkdir()
        (src / "T.java").write_text(
            "class T {\n"
            "    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {\n"
            "        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(chain, \"chain\");\n"
            "        this.delegate.checkServerTrusted(chain, authType);\n"
            "    }\n"
            "    public boolean verify(String host, SSLSession session) {\n"
            "        return host.equals(this.expected);\n    }\n}\n")
        assert analyze_tls_bypass(tmp_path) == []

    @pytest.mark.parametrize("rel", [
        "platform/sources/okhttp3/internal/platform/ConscryptPlatform.java",
        "platform/sources/com/facebook/react/modules/network/Pinning.java",
        "platform/sources/io/flutter/plugin/Tls.java",
    ])
    def test_bundled_library_bypass_is_not_the_apps(self, tmp_path, rel):
        """
        Purpose:
            Pin that a permissive verifier inside a bundled library or a framework embedding is skipped, while the same code in the app is still reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
            rel: Where the library file sits in an analysis root.

        Implementation notes:
            OkHttp's Conscrypt platform carries a hostname verifier that returns true for its own plumbing, and a real React Native scan reported it as the app accepting every hostname.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.network import analyze_tls_bypass
        text = "class V implements HostnameVerifier { public boolean verify(String h, SSLSession s) { return true; } }"
        library = tmp_path / rel
        library.parent.mkdir(parents=True)
        library.write_text(text)
        assert analyze_tls_bypass(tmp_path) == []
        app = tmp_path / "platform/sources/com/demo/V.java"
        app.parent.mkdir(parents=True)
        app.write_text(text)
        assert [f.file for f in analyze_tls_bypass(tmp_path)] == ["platform/sources/com/demo/V.java"]


class TestDartTls:
    """
    Purpose:
        The rule for a Dart HttpClient whose certificate callback always accepts.
    """
    def _release_tree(self, tmp_path, body):
        """
        Purpose:
            Write a Blutter-shaped tree with one app library and one plugin library.

        Parameters:
            tmp_path: Directory to write into.
            body: The app library's disassembly.

        Returns:
            The analysis root.
        """
        app = tmp_path / "asm/demo/net.dart"
        app.parent.mkdir(parents=True)
        app.write_text("// lib: , url: package:demo/net.dart\n" + body)
        main = tmp_path / "asm/demo/main.dart"
        main.write_text("// lib: , url: package:demo/main.dart\n_ main() { }\n")
        plugin = tmp_path / "asm/some_plugin/client.dart"
        plugin.parent.mkdir(parents=True)
        plugin.write_text("// lib: , url: package:some_plugin/client.dart\n" + body)
        return tmp_path

    def test_always_true_closure_on_http_client(self, tmp_path):
        """
        Purpose:
            Pin the release-build shape: Dart's shared always-true closure stored into an _HttpClient the same function built, in the app's code only.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            The setter's name does not survive compilation, which is why a real scan read this function five times without reporting it, and why the title must not name it: the API-claim gate refuted this rule's finding when it did.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.dart_tls import analyze_dart_tls
        root = self._release_tree(tmp_path, (
            "    // 0x361d38: r0 = _HttpClient()\n"
            "    //     0x361d48: bl #0x33ac3c  ; [dart:_http] _HttpClient::_HttpClient\n"
            "    //     0x361d4c: add x1, PP, #0x17  ; [pp+0x17b88] Function: [dart:core] Object::_simpleInstanceOfTrue (0x536910)\n"
            "    // 0x361d58: r0 = AllocateClosure()\n"
            "    // 0x361d60: StoreField: r1->field_33 = r0\n"))
        found = analyze_dart_tls(root)
        assert [(f.file, f.line, f.vuln_class) for f in found] == [("asm/demo/net.dart", 4, "NETWORK-01")]
        from lu77U_MobileSec.validation.claim_terms import api_terms, names_present
        body = (root / "asm/demo/net.dart").read_text()
        names = api_terms(found[0].title)
        missing = set(names) - set(names_present(body, names))
        assert not missing

    def test_always_true_closure_elsewhere_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that the always-true closure on its own, with no HttpClient built nearby, is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.dart_tls import analyze_dart_tls
        root = self._release_tree(tmp_path, (
            "    //     0x10: add x1, PP, #0x17  ; [pp+0x17b88] Function: [dart:core] Object::_simpleInstanceOfTrue (0x536910)\n"
            "    // 0x14: r0 = AllocateClosure()\n"))
        assert analyze_dart_tls(root) == []

    def test_debug_source_assignment(self, tmp_path):
        """
        Purpose:
            Pin the debug-build shape: the assignment in recovered source, arrow or block form.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.dart_tls import analyze_dart_tls
        src = tmp_path / "dart_source/net.dart"
        src.parent.mkdir(parents=True)
        src.write_text("HttpClient a() {\n  final c = HttpClient();\n"
                       "  c.badCertificateCallback = (cert, host, port) => true;\n  return c;\n}\n"
                       "HttpClient b() {\n  final c = HttpClient();\n"
                       "  c.badCertificateCallback = (X509Certificate cert, String host, int port) { return true; };\n"
                       "  return c;\n}\n"
                       "HttpClient ok() {\n  final c = HttpClient();\n"
                       "  c.badCertificateCallback = (cert, host, port) => cert.sha1 == pinned;\n  return c;\n}\n")
        assert [f.line for f in analyze_dart_tls(tmp_path)] == [3, 8]


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


class TestInjectionScope:
    """
    Purpose:
        Which code the injection scanner reads.
    """
    def test_framework_embedding_exec_is_not_the_apps(self, tmp_path):
        """
        Purpose:
            Pin that a Runtime.exec call in the React Native embedding is skipped, while the same call in the app is still reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            React Native's device-info helper runs getprop through Runtime.exec, and a real scan reported it as the app's command execution.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        text = 'class H { void f(String c) throws Exception { Runtime.getRuntime().exec(c); } }'
        framework = tmp_path / "platform/sources/com/facebook/react/modules/systeminfo/H.java"
        framework.parent.mkdir(parents=True)
        framework.write_text(text)
        assert analyze_injection(tmp_path) == []
        app = tmp_path / "platform/sources/com/demo/H.java"
        app.parent.mkdir(parents=True)
        app.write_text(text)
        assert [f.file for f in analyze_injection(tmp_path)] == ["platform/sources/com/demo/H.java"]


def test_a_private_address_is_a_note_not_a_credential(tmp_path):
    """
    Purpose:
        Pin that a private network address is reported as an informational note rather than a hardcoded credential.

    Parameters:
        tmp_path: The analysis root.
    """
    from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
    path = tmp_path / "app_modules/494_API_BASE_URL.js"
    path.parent.mkdir(parents=True)
    path.write_text('export const API_BASE_URL = "http://10.0.2.2:3000";\n')
    notes = [f for f in analyze_secrets(tmp_path) if "rivate network" in f.title]
    assert [(f.severity, f.vuln_class) for f in notes] == [("Informational", "SECRET-03")]


class TestExecGrading:
    """
    Purpose:
        Command execution and class loading graded by what their input can be.

    Implementation notes:
        Root and emulator checks run constant commands ("getprop", "which su") and protection SDKs load their own code; a real Flutter scan listed five of them as Medium command execution.
    """
    def _findings(self, tmp_path, body):
        """
        Purpose:
            Write one app source file and return the injection findings for it.

        Parameters:
            tmp_path: Directory the fixture is written into.
            body: The class body.

        Returns:
            The findings.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import analyze_injection
        path = tmp_path / "platform/sources/com/demo/E.java"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package com.demo;\nclass E {\n" + body + "\n}\n")
        return analyze_injection(tmp_path)

    @pytest.mark.parametrize("call", [
        'Runtime.getRuntime().exec("getprop");',
        'Runtime.getRuntime().exec(new String[]{"which", BINARY_SU});',
        'Runtime.getRuntime().exec(new java.lang.String[]{"which", "su"});',
    ])
    def test_a_constant_command_is_not_reported(self, tmp_path, call):
        """
        Purpose:
            Pin that a command made only of literals and constant names is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
            call: The execution call.
        """
        assert self._findings(tmp_path, f"void f() throws Exception {{ {call} }}") == []

    def test_a_runtime_command_is_a_lead_until_external_input_appears(self, tmp_path):
        """
        Purpose:
            Pin that a runtime-built command is a low-confidence lead on its own and Medium in a file that reads an Intent.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        (lead,) = self._findings(tmp_path, "void f(String c) throws Exception { Runtime.getRuntime().exec(c); }")
        assert (lead.severity, lead.confidence) == ("Low", "LOW")
        (tainted,) = self._findings(tmp_path, (
            'void f() throws Exception { String c = getIntent().getStringExtra("c"); '
            'Runtime.getRuntime().exec("sh -c " + c); }'))
        assert (tainted.severity, tainted.confidence) == ("Medium", "MEDIUM")

    def test_class_loading_is_medium_only_with_an_outside_source(self, tmp_path):
        """
        Purpose:
            Pin that loading code from the app's private directory is a lead, loading it beside external storage is Medium, and the same with a signature check in the file is a lead again.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        (private,) = self._findings(tmp_path, (
            'void f(java.io.File d) { new DexClassLoader(d.getPath(), getDir("x", 0).getPath(), null, null); }'))
        assert (private.severity, private.confidence) == ("Low", "LOW")
        (external,) = self._findings(tmp_path, (
            'void f() { String p = getExternalFilesDir(null) + "/p.dex"; '
            'new DexClassLoader(p, getDir("x", 0).getPath(), null, null); }'))
        assert external.severity == "Medium"
        (verified,) = self._findings(tmp_path, (
            'void f() { java.io.File p = new java.io.File(getExternalFilesDir(null), "p.jar"); '
            'if (!signedBy(p)) return; new PathClassLoader(p.toString(), getClassLoader()); }\n'
            'boolean signedBy(java.io.File f) { return je.getCertificates()[0] != null; }'))
        assert (verified.severity, verified.confidence) == ("Low", "LOW")

    def test_a_biometric_availability_check_is_not_an_unbound_prompt(self, tmp_path):
        """
        Purpose:
            Pin that a file which names the biometric APIs but never shows a prompt is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        found = self._findings(tmp_path, (
            'int g() { if (fm == null) { Log.e("BiometricManager", "FingerprintManager was null."); '
            'return 1; } return 0; }'))
        assert not [f for f in found if f.vuln_class == "AUTH-02"]


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

    def test_text_field_input_weighs_by_statement(self, tmp_path):
        """
        Purpose:
            Pin that the app's own text fields reaching a SELECT stay High while reaching an INSERT drop to Low, and that an Intent extra reaching the INSERT stays High.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            The person typing is the device's own user: through a SELECT they can read rows the screen hides, through an INSERT into their own database they can change nothing the app does not already let them.
        """
        (read,) = self._findings(tmp_path, (
            'class R { void f() { c = db.rawQuery("SELECT * FROM u WHERE n = \'" + t.getText().toString() + "\'", null); } }'),
            name="R.java")
        assert (read.severity, read.extra["operand_provenance"]) == ("High", "ui")
        (write,) = self._findings(tmp_path, (
            'class W { void f() { db.execSQL("INSERT INTO u VALUES (\'" + t.getText().toString() + "\');"); } }'),
            name="W.java")
        assert (write.severity, write.extra["operand_provenance"]) == ("Low", "ui-write")
        (intent,) = self._findings(tmp_path, (
            'class I { void f() { db.execSQL("INSERT INTO u VALUES (\'" + getIntent().getStringExtra("n") + "\');"); } }'),
            name="I.java")
        assert (intent.severity, intent.extra["operand_provenance"]) == ("High", "external")

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

    def test_the_riskiest_operand_decides_the_position(self, tmp_path):
        """
        Purpose:
            Pin that a statement opening with a constant table name is judged by the value it quotes further along, traced through a field to an Intent extra.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            Judged by its first operand, this exact shape was a table-name note at Informational, and the field operand read as "this" and could not be traced.
        """
        found = self._findings(tmp_path, '''
public class MiddleActivity {
  String key; String value;
  void onActivityResult(int reqCode, Intent intent) {
    this.key = intent.getStringExtra("key");
    this.value = intent.getStringExtra("value");
  }
  void query(SQLiteDatabase db) {
    String query = "UPDATE " + MyDatabase.Table1.TABLE_NAME + " SET " + MyDatabase.Table1.COLUMN_NAME_VALUE + " = '" + this.value + "' WHERE " + MyDatabase.Table1.COLUMN_NAME_KEY + " = '" + this.key + "'";
    db.execSQL(query);
  }
}''')
        f = found[0]
        assert f.extra["sql_position"] == "quoted_value"
        assert f.extra["operand_provenance"] == "external"
        assert f.severity == "High"

    def test_a_statement_of_constants_only_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that a statement built only from UPPER_CASE constants is not reported, since nothing a caller sends can reach it, while one variable operand is still enough.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert self._findings(tmp_path, '''
public class c {
  void q(SQLiteDatabase db) {
    db.execSQL("DELETE FROM " + MyDatabase.Table1.TABLE_NAME);
    Cursor k = db.rawQuery("SELECT * FROM " + TABLE + " WHERE " + COL_ID + " = 1", null);
  }
}''', name="Constants.java") == []
        assert self._findings(tmp_path, '''
public class d {
  void q(SQLiteDatabase db, String name) {
    db.execSQL("DELETE FROM " + TABLE + " WHERE n='" + name + "'");
  }
}''', name="Mixed.java")

    def test_a_selection_opening_with_a_column_name_is_read(self, tmp_path):
        """
        Purpose:
            Pin that a selection clause starting with a column name from a constant array is still checked, reported when it splices in an Intent value and not when it uses placeholders.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            The rule used to need the clause to start with a literal, so `projection[0] + " = " + usrname` went unread.
        """
        body = '''
public class Login {
  void a(Intent intent) {
    String usrname = intent.getStringExtra("username");
    String[] projection = {Table.COLUMN_NAME_USER, Table.COLUMN_NAME_PASS};
    String selection = projection[0] + %s;
  }
}'''
        spliced = self._findings(tmp_path, body % "\" = '\" + usrname + \"'\"", name="Spliced.java")
        assert [(f.severity, f.extra["sql_position"]) for f in spliced] == [("High", "quoted_value")]
        assert self._findings(tmp_path, body % '" = ?"', name="Bound.java") == []

    def test_a_parameter_is_traced_to_its_callers(self, tmp_path):
        """
        Purpose:
            Pin that a query built from a method parameter is not reported when every caller in the file passes a placeholder clause of constants, and still is when a caller passes Intent input.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        body = '''
public class Middle {
  void a(Intent intent) {
    String usrname = intent.getStringExtra("username");
    String[] projection = {Table.COL_USER, Table.COL_PASS};
    String selection = %s;
    query(projection, selection, null);
  }
  Cursor query(String[] projection, String selection, String[] args) {
    String query = "SELECT * FROM " + Table.TABLE_NAME + " WHERE " + selection;
    return db.rawQuery(query, args);
  }
}'''
        bound = self._findings(tmp_path, body % 'projection[0] + " = ? AND " + projection[1] + " = ?"', name="Bound.java")
        assert bound == []
        spliced = self._findings(tmp_path, body % "projection[0] + \" = \" + usrname", name="Spliced.java")
        assert spliced

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

    @pytest.mark.parametrize("rel", [
        "platform/sources/io/flutter/embedding/engine/systemchannels/SettingsChannel.java",
        "asm/flutter/src/services/text_input.dart",
    ])
    def test_flutter_framework_is_not_scanned(self, tmp_path, rel):
        """
        Purpose:
            Pin that the Flutter embedding and Blutter's framework disassembly are skipped, while the same text in app code is still reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
            rel: Where the framework file sits in a Flutter analysis root.

        Implementation notes:
            Every Flutter app carries these files, and the embedding names a settings key, BRIEFLY_SHOW_PASSWORD, that the password rule matched on a real scan.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
        text = 'class K { static final String A = "AKIAIOSFODNN7EXAMPLE"; }'
        framework = tmp_path / rel
        framework.parent.mkdir(parents=True)
        framework.write_text(text)
        assert analyze_secrets(tmp_path) == []
        app = tmp_path / "platform/sources/com/demo/K.java"
        app.parent.mkdir(parents=True)
        app.write_text(text)
        assert any(f.file.endswith("com/demo/K.java") for f in analyze_secrets(tmp_path))

    def test_the_tools_own_overviews_are_not_scanned(self, tmp_path):
        """
        Purpose:
            Pin that a scan overview at the analysis root is skipped, while a file of the same name inside the app is still scanned.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            An overview quotes the app's leads, so scanning it reports each one again against a file that is not in the app.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.secrets import analyze_secrets
        text = "Credential-shaped strings: AKIAIOSFODNN7EXAMPLE\n"
        (tmp_path / "rn_scan_overview.txt").write_text(text)
        (tmp_path / "flutter_scan_overview.txt").write_text(text)
        assert analyze_secrets(tmp_path) == []
        asset = tmp_path / "platform/resources/assets/rn_scan_overview.txt"
        asset.parent.mkdir(parents=True)
        asset.write_text(text)
        assert [f.file for f in analyze_secrets(tmp_path)] == ["platform/resources/assets/rn_scan_overview.txt"]

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
        A component inherits the package name as its task grouping. Any other value is a string another application can also declare, which is what lets the victim's component be opened inside a hostile task. The app-wide StrandHogg note is about the default grouping on old Android versions, so the per-component cases leave it out and TestStrandHogg pins it.
    """
    def _manifest(self, tmp_path, body):
        """
        Purpose:
            Write a manifest around the given application body and return only the per-component and application task-grouping findings.

        Parameters:
            tmp_path: The tree root.
            body: The application element's contents.

        Returns:
            The findings of that class, without the StrandHogg note.
        """
        (tmp_path / "AndroidManifest.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.x.app">\n'
            '  <uses-sdk android:targetSdkVersion="33" android:minSdkVersion="24"/>\n'
            f'  <application android:label="X">{body}</application>\n'
            '</manifest>')
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        return [f for f in analyze_manifest(tmp_path)
                if f.vuln_class == "PLATFORM-09" and "StrandHogg" not in f.title]

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
        found = [f for f in analyze_manifest(tmp_path)
                 if f.vuln_class == "PLATFORM-09" and "StrandHogg" not in f.title]
        assert len(found) == 1


class TestStrandHogg:
    """
    Purpose:
        The app-wide note that the default task affinity can be claimed by another app on Android 10 and lower.

    Implementation notes:
        Android 11 (API 30) fixed the attack in the OS; an empty application affinity is the partial mitigation for older versions. Two Ghera benchmarks plant the default.
    """
    def _notes(self, tmp_path, min_sdk, app_attrs=""):
        """
        Purpose:
            Scan a manifest with the given minimum SDK and application attributes and return the StrandHogg notes.

        Parameters:
            tmp_path: The tree root.
            min_sdk: The minSdkVersion to declare, or None to declare none.
            app_attrs: Extra attributes for the application element.

        Returns:
            The notes.
        """
        sdk = f'  <uses-sdk android:targetSdkVersion="27" android:minSdkVersion="{min_sdk}"/>\n' if min_sdk else ""
        (tmp_path / "AndroidManifest.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x.app">\n'
            f'{sdk}  <application {app_attrs}><activity android:name=".Main"/></application>\n</manifest>')
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        return [f for f in analyze_manifest(tmp_path) if "StrandHogg" in f.title]

    def test_the_default_affinity_below_android_11_is_a_note(self, tmp_path):
        """
        Purpose:
            Pin that minSdkVersion 21 with no affinity gives one Informational note naming the package.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        notes = self._notes(tmp_path, 21)
        assert len(notes) == 1
        assert notes[0].severity == "Informational" and '"com.x.app"' in notes[0].description

    def test_an_undeclared_minimum_counts_as_old(self, tmp_path):
        """
        Purpose:
            Pin that a manifest with no minSdkVersion gets the note, since the platform default is the oldest level.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        assert len(self._notes(tmp_path, None)) == 1

    @pytest.mark.parametrize("min_sdk, app_attrs", [
        (30, ""),
        (24, 'android:taskAffinity=""'),
    ])
    def test_android_11_or_an_empty_affinity_needs_no_note(self, tmp_path, min_sdk, app_attrs):
        """
        Purpose:
            Pin that the OS fix and the in-app mitigation each silence the note.

        Parameters:
            tmp_path: Directory the fixture is written into.
            min_sdk: The minSdkVersion.
            app_attrs: The application attributes.
        """
        assert self._notes(tmp_path, min_sdk, app_attrs) == []


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


def _write_java(root, rel, body):
    """
    Purpose:
        Write one decompiled Java file into a tree.

    Parameters:
        root: The analysis root.
        rel: The file's path relative to the root.
        body: The file's text.

    Returns:
        The analysis root.
    """
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return root


class TestCryptoMisuse:
    """
    Purpose:
        Keys and IVs fixed in the code, and weak password-based key derivation.
    """
    def test_literal_and_constant_keys_and_ivs(self, tmp_path):
        """
        Purpose:
            Pin that a key or IV built from a literal, a zero-filled array or a literal constant is reported, and that values the rule cannot resolve are not.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        _write_java(tmp_path, "sources/com/demo/Vault.java", (
            "class Vault {\n"
            '  private static final String KEY = "ThisIsASecretKey";\n'
            "  static final byte[] IV = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};\n"
            "  void a() throws Exception {\n"
            '    SecretKeySpec k1 = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");\n'
            '    SecretKeySpec k2 = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");\n'
            "    IvParameterSpec iv1 = new IvParameterSpec(new byte[16]);\n"
            "    IvParameterSpec iv2 = new IvParameterSpec(IV);\n"
            "    IvParameterSpec ok = new IvParameterSpec(randomIv);\n"
            '    SecretKeySpec ok2 = new SecretKeySpec(derived, "AES");\n'
            "  }\n}\n"))
        found = analyze_crypto_misuse(tmp_path)
        assert sorted((f.line, f.vuln_class) for f in found) == [
            (5, "CRYPTO-02"), (6, "CRYPTO-02"), (7, "CRYPTO-02"), (8, "CRYPTO-02")]
        assert not any("ThisIsASecretKey" in f.description for f in found)

    def test_an_empty_array_filled_at_random_is_not_fixed(self, tmp_path):
        """
        Purpose:
            Pin that a constant declared as an empty array is reported only while nothing writes into it: filled by SecureRandom it is a per-install key, left alone it is all zeros.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        _write_java(tmp_path, "sources/com/demo/Reset.java", (
            "class Reset {\n"
            "  static final byte[] SECRET_KEY = new byte[16];\n"
            "  static {\n    new java.security.SecureRandom().nextBytes(SECRET_KEY);\n  }\n"
            '  void a() { SecretKeySpec k = new SecretKeySpec(Reset.SECRET_KEY, "AES"); }\n}\n'))
        _write_java(tmp_path, "sources/com/demo/Zero.java", (
            "class Zero {\n"
            "  static final byte[] IV = new byte[16];\n"
            "  void a() { IvParameterSpec iv = new IvParameterSpec(IV); }\n}\n"))
        assert [(f.file.rsplit("/", 1)[-1], f.title) for f in analyze_crypto_misuse(tmp_path)] == [
            ("Zero.java", "Cipher uses a fixed IV")]

    def test_literal_hoisted_into_a_local(self, tmp_path):
        """
        Purpose:
            Pin that an IV whose literal bytes were first assigned to a local, as Kotlin and R8 output writes it, is reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            A real app's fixed IV was written exactly this way and missed by a constants-only rule.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        _write_java(tmp_path, "sources/com/demo/Box.java", (
            "class Box {\n  byte[] seal(byte[] data) throws Exception {\n"
            '    byte[] bytes2 = "__fixed_iv_16b__".getBytes(UTF_8);\n'
            "    cipher.init(1, key, new javax.crypto.spec.IvParameterSpec(bytes2));\n"
            "    return cipher.doFinal(data);\n  }\n}\n"))
        assert [(f.line, f.title) for f in analyze_crypto_misuse(tmp_path)] == [(4, "Cipher uses a fixed IV")]

    def test_pbkdf2_iteration_floor(self, tmp_path):
        """
        Purpose:
            Pin that a low iteration count is reported and an adequate one is not.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        _write_java(tmp_path, "sources/com/demo/Kdf.java", (
            "class Kdf {\n  void a() {\n"
            "    PBEKeySpec weak = new PBEKeySpec(pw.toCharArray(), salt, 1000, 256);\n"
            "    PBEKeySpec strong = new PBEKeySpec(pw.toCharArray(), salt, 600000, 256);\n"
            "  }\n}\n"))
        found = analyze_crypto_misuse(tmp_path)
        assert [(f.line, f.vuln_class) for f in found] == [(3, "CRYPTO-01")]

    @pytest.mark.parametrize("provider_attrs, reported", [
        ('android:writePermission="a.w"', True),
        ('android:readPermission="a.r"', True),
        ('android:permission="a.p" android:writePermission="a.w"', False),
        ('android:writePermission="a.w" android:exported="false"', False),
    ])
    def test_a_provider_call_that_writes_past_its_write_permission(self, tmp_path, provider_attrs, reported):
        """
        Purpose:
            Pin that call() writing in a provider with separate read or write permissions is reported, and an overall permission or an unexported provider is not.

        Parameters:
            tmp_path: Directory the fixture is written into.
            provider_attrs: The provider element's permission attributes.
            reported: Whether a finding is expected.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.platform_misuse import analyze_platform_misuse
        (tmp_path / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a">'
            f'<application><provider android:name=".Files" {provider_attrs} android:authorities="a.files"/>'
            "</application></manifest>")
        _write_java(tmp_path, "sources/a/Files.java",
                    "public class Files extends ContentProvider {\n"
                    "  public Bundle call(String method, String arg, Bundle extras) {\n"
                    "    new FileOutputStream(new File(getContext().getFilesDir(), arg)).write(data);\n"
                    "    return null;\n  }\n}\n")
        found = [f for f in analyze_platform_misuse(tmp_path) if "call()" in f.title]
        assert bool(found) is reported

    @pytest.mark.parametrize("component, uses, expected", [
        ('<receiver android:name=".Sms" android:exported="true"/>', "SEND_SMS", ["Exported receiver Sms uses SEND_SMS for any app"]),
        ('<receiver android:name=".Sms" android:exported="true" android:permission="a.p"/>', "SEND_SMS", []),
        ('<receiver android:name=".Sms" android:exported="true"/>', "", []),
        ('<activity android:name=".Sms"><intent-filter><action android:name="android.intent.action.MAIN"/>'
         '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>', "SEND_SMS", []),
    ])
    def test_an_exported_component_using_the_apps_permission(self, tmp_path, component, uses, expected):
        """
        Purpose:
            Pin permission re-delegation: an unguarded exported component using an API a requested permission guards is reported, and a guarded one, one whose permission the app does not request, and the launcher entry are not.

        Parameters:
            tmp_path: Directory the fixture is written into.
            component: The component element.
            uses: The permission the app requests, or empty.
            expected: The finding titles.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.platform_misuse import analyze_platform_misuse
        requested = f'<uses-permission android:name="android.permission.{uses}"/>' if uses else ""
        (tmp_path / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a">'
            f"{requested}<application>{component}</application></manifest>")
        _write_java(tmp_path, "sources/a/Sms.java",
                    "public class Sms extends BroadcastReceiver {\n"
                    "  public void onReceive(Context c, Intent i) {\n"
                    "    SmsManager.getDefault().sendTextMessage(i.getStringExtra(\"n\"), null, \"x\", null, null);\n"
                    "  }\n}\n")
        assert [f.title for f in analyze_platform_misuse(tmp_path) if "for any app" in f.title] == expected

    def test_library_code_is_not_the_apps(self, tmp_path):
        """
        Purpose:
            Pin that a bundled library's fixed key is not reported as the app's.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        _write_java(tmp_path, "sources/org/bouncycastle/Test.java",
                    'class T { Object k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES"); }\n')
        assert analyze_crypto_misuse(tmp_path) == []


class TestPbeSalt:
    """
    Purpose:
        The fixed-salt rule for password-based key derivation.
    """
    @pytest.mark.parametrize("files, expected", [
        ({"Enc.java": 'class Enc { byte[] k(char[] p) { return new PBEKeySpec(p, "NaCl".getBytes(), 600000, 256); } }'},
         "a literal"),
        ({"Enc.java": "class Enc { static final String SALT = \"s4lt\";\n"
                      "  void k(char[] p) { new PBEKeySpec(p, SALT.getBytes(), 600000, 256); } }"},
         "the constant SALT"),
        ({"Enc.java": "class Enc {\n  public static String enc(String salt, String v) {\n"
                      "    KeySpec s = new PBEKeySpec(PASS.toCharArray(), salt.getBytes(), 600000, 256);\n    return v;\n  }\n}",
          "Provider.java": "class Provider { void f() { String e = Enc.enc(getContext().getString(R.string.salt), v); } }"},
         "a string resource, passed in at"),
        ({"Enc.java": "class Enc {\n  public static String enc(String salt, String v) {\n"
                      "    KeySpec s = new PBEKeySpec(PASS.toCharArray(), salt.getBytes(), 600000, 256);\n    return v;\n  }\n}",
          "Provider.java": "class Provider { void f() { byte[] r = random(); String e = Enc.enc(fresh, v); } }"},
         ""),
    ])
    def test_a_salt_fixed_here_or_one_call_up_is_reported(self, tmp_path, files, expected):
        """
        Purpose:
            Pin a literal, a constant and a string resource passed into a helper as fixed salts, and a salt a caller computes as not.

        Parameters:
            tmp_path: Directory the fixture is written into.
            files: File name to source.
            expected: Text the description must contain, or empty when nothing is reported.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse import analyze_crypto_misuse
        for name, body in files.items():
            _write_java(tmp_path, f"sources/com/demo/{name}", body)
        found = [f for f in analyze_crypto_misuse(tmp_path) if "fixed salt" in f.title]
        if expected:
            assert len(found) == 1 and expected in found[0].description
        else:
            assert found == []


class TestPlatformMisuse:
    """
    Purpose:
        Android API misuse with the guard each one needs.
    """
    @pytest.mark.parametrize("body, expected", [
        ("ZipEntry e = zis.getNextEntry();\nFile out = new File(dir, e.getName());\n", ["CODE-04"]),
        ("ZipEntry e = zis.getNextEntry();\nFile out = new File(dir, e.getName());\n"
         "if (!out.getCanonicalPath().startsWith(dir.getCanonicalPath())) throw new IOException();\n", []),
        ("ZipEntry e = zis.getNextEntry();\nString name = e.getName();\nlog(name);\n"
         "FileOutputStream os = new FileOutputStream(new File(dir, name));\n", ["CODE-04"]),
        ("ZipFile z = new ZipFile(new File(path));\nEnumeration<? extends ZipEntry> en = z.entries();\n"
         "Matcher m = pattern.matcher(en.nextElement().getName());\n", []),
        ("ObjectInputStream in = new ObjectInputStream(socket.getInputStream());\nObject o = in.readObject();\n",
         ["CODE-03"]),
        ("ObjectOutputStream out = new ObjectOutputStream(bos);\nout.writeObject(obj);\n"
         "ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));\n"
         "Object copy = in.readObject();\n", []),
        ("protected boolean isValidFragment(String name) {\n    return true;\n}\n", ["PLATFORM-02"]),
        ("protected boolean isValidFragment(String name) {\n    return Allowed.class.getName().equals(name);\n}\n", []),
        ("Intent i = Intent.parseUri(url, Intent.URI_INTENT_SCHEME);\nstartActivity(i);\n", ["PLATFORM-03"]),
        ("Intent i = Intent.parseUri(url, 1);\ni.setComponent(null);\ni.setSelector(null);\nstartActivity(i);\n", []),
        ("WebView.setWebContentsDebuggingEnabled(true);\n", ["PLATFORM-06"]),
        ("if (BuildConfig.DEBUG) {\n    WebView.setWebContentsDebuggingEnabled(true);\n}\n", []),
        ('String otpCode = view.getText();\nClipData c = ClipData.newPlainText("otp", otpCode);\n', ["STORAGE-02"]),
        ('ClipData c = ClipData.newPlainText("address", shippingAddress);\n', []),
        ("public int onStartCommand(Intent i, int f, int id) {\n"
         "    if (checkCallingOrSelfPermission(\"a.perm\") == 0) { start(); }\n    return 1;\n}\n", ["PLATFORM-01"]),
        ("public int onStartCommand(Intent i, int f, int id) {\n"
         "    enforcePermission(\"a.perm\", Binder.getCallingPid(), Binder.getCallingUid(), \"no\");\n"
         "    return 1;\n}\n", ["PLATFORM-01"]),
        ("public String getSecret() throws RemoteException {\n"
         "    enforcePermission(\"a.perm\", Binder.getCallingPid(), Binder.getCallingUid(), \"no\");\n"
         "    return s;\n}\n", []),
        ("void ask() {\n    if (checkPermission(\"a.perm\", Process.myPid(), Process.myUid()) != 0) { request(); }\n}\n",
         []),
        ("public void onReceive(Context c, Intent i) {\n    String n = getResultData();\n    setResultData(\"+1\" + n);\n}\n",
         ["PLATFORM-02"]),
        ("void send() {\n    Object r = receiver.getResultData();\n}\n", []),
        ("void a() { File f = new File(getExternalFilesDir(null), \"b.txt\"); show(f); }\n"
         "void show(File f) { Scanner sc = new Scanner(f); }\n", ["STORAGE-02"]),
        ("void a() { File f = new File(getExternalFilesDir(null), \"b.txt\"); write(f); }\n", []),
        ("void a() { File f = new File(getFilesDir(), \"b.txt\"); Scanner sc = new Scanner(f); }\n", []),
        ("void a() {\n    Intent intent = new Intent();\n    intent.setAction(\"com.demo.EDIT\");\n"
         "    intent.putExtra(\"image\", data);\n    startActivity(intent);\n}\n", ["PLATFORM-07"]),
        ("void a() {\n    Intent intent = new Intent(\"com.demo.EDIT\");\n    intent.setPackage(getPackageName());\n"
         "    intent.putExtra(\"image\", data);\n    startActivity(intent);\n}\n", []),
        ("void a() {\n    Intent intent = new Intent(\"android.intent.action.SEND\");\n"
         "    intent.putExtra(\"text\", data);\n    startActivity(intent);\n}\n", []),
        ("void a() { PendingIntent pi = PendingIntent.getService(ctx, 0, new Intent(), PendingIntent.FLAG_UPDATE_CURRENT); }\n",
         ["PLATFORM-08"]),
        ("void a() {\n    Intent i = new Intent();\n    i.setAction(\"com.demo.SERV\");\n"
         "    PendingIntent pi = PendingIntent.getService(ctx, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);\n}\n", ["PLATFORM-08"]),
        ("void a() {\n    Intent i = new Intent();\n    i.setComponent(new ComponentName(pkg, \"a.S\"));\n"
         "    PendingIntent pi = PendingIntent.getService(ctx, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);\n}\n", []),
        ("void a() { PendingIntent pi = PendingIntent.getActivity(ctx, 0, new Intent(ctx, Main.class), 0); }\n", []),
        ("void a() { PendingIntent pi = PendingIntent.getService(ctx, 0, new Intent(), PendingIntent.FLAG_IMMUTABLE); }\n", []),
    ])
    def test_rule_and_guard(self, tmp_path, body, expected):
        """
        Purpose:
            Pin each rule firing on the risky shape and staying quiet when the guard it needs is present.

        Parameters:
            tmp_path: Directory the fixture is written into.
            body: The method body under test.
            expected: The classes that must be reported.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.platform_misuse import analyze_platform_misuse
        _write_java(tmp_path, "sources/com/demo/Thing.java", "class Thing {\n" + body + "}\n")
        assert [f.vuln_class for f in analyze_platform_misuse(tmp_path)] == expected

    def test_library_code_is_not_the_apps(self, tmp_path):
        """
        Purpose:
            Pin that the same shapes inside a bundled library are ignored.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.platform_misuse import analyze_platform_misuse
        _write_java(tmp_path, "platform/sources/io/flutter/Web.java",
                    "class Web { void a() { WebView.setWebContentsDebuggingEnabled(true); } }\n")
        assert analyze_platform_misuse(tmp_path) == []


class TestOAuthFlows:
    """
    Purpose:
        OAuth flows a native app should not use, found in its own code.
    """
    def test_flows_in_java_and_js(self, tmp_path):
        """
        Purpose:
            Pin the implicit grant, the password grant and plain PKCE in both the query-string and the key-value forms, and that the code grant with S256 is not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.oauth import analyze_oauth
        _write_java(tmp_path, "sources/com/demo/Auth.java", (
            "class Auth {\n"
            '  String a = "https://idp.example/authorize?response_type=token&client_id=x";\n'
            '  void b(Uri.Builder u) { u.appendQueryParameter("code_challenge_method", "plain"); }\n'
            '  String ok = "https://idp.example/authorize?response_type=code&code_challenge_method=S256";\n'
            "}\n"))
        module = tmp_path / "app_modules/12_login.js"
        module.parent.mkdir(parents=True)
        module.write_text("const body = {grant_type: 'password', username: u, password: p};\n")
        found = sorted((f.file, f.line, f.title.split(" (")[0]) for f in analyze_oauth(tmp_path))
        assert found == [
            ("app_modules/12_login.js", 1, "OAuth password grant is used"),
            ("sources/com/demo/Auth.java", 2, "OAuth implicit grant is used"),
            ("sources/com/demo/Auth.java", 3, "PKCE uses the plain method"),
        ]

    def test_oauth_library_is_not_the_apps(self, tmp_path):
        """
        Purpose:
            Pin that an OAuth library's own constants are not reported.

        Parameters:
            tmp_path: Directory the fixture is written into.

        Implementation notes:
            AppAuth carries the string for the plain PKCE method for completeness; reporting it would flag every app that uses the library correctly.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.oauth import analyze_oauth
        _write_java(tmp_path, "sources/net/openid/appauth/CodeVerifierUtil.java",
                    'class C { String m = "code_challenge_method=plain"; }\n')
        assert analyze_oauth(tmp_path) == []


class TestManifestBuildAndProviders:
    """
    Purpose:
        Test-only builds and FileProvider path files.
    """
    def _tree(self, tmp_path, app_attrs, paths_xml):
        """
        Purpose:
            Write a manifest with a FileProvider and its paths file.

        Parameters:
            tmp_path: Directory to write into.
            app_attrs: Extra attributes for the application element.
            paths_xml: The paths file's body.

        Returns:
            The analysis root.
        """
        res = tmp_path / "resources"
        (res / "res/xml").mkdir(parents=True)
        (res / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">'
            f"<application {app_attrs}>"
            '<provider android:name="androidx.core.content.FileProvider" android:authorities="com.demo.files"'
            ' android:exported="false" android:grantUriPermissions="true">'
            '<meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths"/>'
            "</provider></application></manifest>")
        (res / "res/xml/file_paths.xml").write_text(f"<paths>{paths_xml}</paths>")
        return tmp_path

    def test_test_only_and_root_path(self, tmp_path):
        """
        Purpose:
            Pin the test-only build note and the root-path and whole-directory provider findings.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        root = self._tree(tmp_path, 'android:testOnly="true"',
                          '<root-path name="r" path=""/><files-path name="f" path="."/>'
                          '<cache-path name="c" path="shared/"/>')
        found = {f.title: (f.vuln_class, f.file) for f in analyze_manifest(root)}
        assert found["Application is marked as a test-only build (android:testOnly)"][0] == "BUILD-01"
        assert found["FileProvider shares the entire filesystem (root-path)"] == (
            "PLATFORM-11", "resources/res/xml/file_paths.xml")
        assert found["FileProvider shares the whole files directory"][0] == "PLATFORM-11"
        assert not any("cache directory" in title for title in found)

    def test_narrow_provider_and_release_build_are_quiet(self, tmp_path):
        """
        Purpose:
            Pin that a provider sharing a dedicated subdirectory, in a build without testOnly, raises neither finding.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import analyze_manifest
        root = self._tree(tmp_path, 'android:allowBackup="false"', '<files-path name="f" path="exports/"/>')
        titles = [f.title for f in analyze_manifest(root)]
        assert not any("test-only" in t or "FileProvider" in t for t in titles)


def test_new_rules_run_for_every_android_code_profile():
    """
    Purpose:
        Pin that the crypto, platform and OAuth rules run wherever the app's Java is analysed: Java/Kotlin, and the Flutter and React Native platform layers.
    """
    from lu77U_MobileSec.analyzers.sast.runner import _BY_PROFILE
    for profile in ("java_kotlin", "flutter", "react_native"):
        assert {"crypto-misuse", "platform-misuse", "oauth"} <= set(_BY_PROFILE[profile])


VAULT_ASM = '''// lib: , url: package:vault/main.dart

// class id: 1, size: 0x8
class :: {

  static void main() {
    // ** addr: 0x1000, size: 0x30
    // 0x1000: r0 = runApp()
    //     0x1000: bl              #0x9000  ; [package:flutter/src/widgets/binding.dart] ::runApp
  }
}

// class id: 2, size: 0x10
class _LoginState extends State<dynamic> {

  _ _login(/* No info */) async {
    // ** addr: 0x2000, size: 0x100
    // 0x2004: r16 = "Logging in with PIN: "
    // 0x2008: r0 = _interpolate()
    //     0x2008: bl              #0x7000  ; [dart:core] _StringBase::_interpolate
    // 0x200c: r0 = print()
    //     0x200c: bl              #0x7100  ; [dart:core] ::print
    // 0x2010: r2 = "pin"
    // 0x2014: r0 = _setValue()
    //     0x2014: bl              #0x7200  ; [package:shared_preferences/src/shared_preferences_legacy.dart] SharedPreferences::_setValue
    // 0x2018: r2 = "spinner_style"
    // 0x201c: r0 = _setValue()
    //     0x201c: bl              #0x7200  ; [package:shared_preferences/src/shared_preferences_legacy.dart] SharedPreferences::_setValue
  }

  _ _search(/* No info */) async {
    // ** addr: 0x3000, size: 0x100
    // 0x3004: r16 = "SELECT * FROM notes WHERE title LIKE '%"
    // 0x300c: r0 = _interpolate()
    //     0x300c: bl              #0x7000  ; [dart:core] _StringBase::_interpolate
    // 0x3010: r0 = rawQuery()
    //     0x3010: bl              #0x7300  ; [package:sqflite_common/src/database_mixin.dart] _MixinApplication1&Object&SqfliteDatabaseExecutorMixin::rawQuery
    // 0x3014: r0 = Key()
    //     0x3014: bl              #0x7400  ; AllocateKeyStub -> Key (size=0xc)
    // 0x3018: r2 = "STATIC_DEMO_KEY_0123456789abcdef"
    // 0x301c: r0 = Encrypted.fromUtf8()
    //     0x301c: bl              #0x7500  ; [package:encrypt/encrypt.dart] Encrypted::Encrypted.fromUtf8
    // 0x3020: r2 = "http://api.vault-demo.net/v1/balance"
    // 0x3024: r0 = parse()
    //     0x3024: bl              #0x7600  ; [dart:core] Uri::parse
    // 0x3028: r2 = "http://help.vault-demo.net/faq"
  }

  _ _checkPin(/* No info */) {
    // ** addr: 0x4000, size: 0x40
    // 0x4004: r0 = convert()
    //     0x4004: bl              #0x7700  ; [package:crypto/src/hash.dart] Hash::convert
    // 0x4008: r0 = toString()
    //     0x4008: bl              #0x7800  ; [package:crypto/src/digest.dart] Digest::toString
    // 0x400c: r16 = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
  }
}
'''

RN_MODULE = '''// Module ID: 12
async function _save(token, user) {
  yield _default.setItem("authToken", token);
  yield _default.setItem("themeMode", "dark");
  console.log("login attempt", user.password);
  const fn = new Function("app", remote.script);
  const str = AES.encrypt(card, closure_7, obj);
}
let closure_7 = Utf8.parse("WalletCardKey123");
export const API = "http://api.vault-demo.net/v1";
export const DEV = "http://10.0.2.2:3000";
export default function Help() {
  return <WebView source={src} originWhitelist={["*"]} allowUniversalAccessFromFileURLs mixedContentMode="always" onMessage={function onMessage(nativeEvent) {
    const parsed = JSON.parse(nativeEvent.nativeEvent.data);
    run(parsed.action);
  }} />;
}
'''

RN_SAFE_MODULE = '''// Module ID: 13
import EncryptedStorage from "EncryptedStorage";
async function _save(token) {
  yield EncryptedStorage.setItem("authToken", token);
  console.log("screen opened", route.name);
  const fixed = new Function("return 1");
}
export default function Page() {
  return <WebView source={src} onMessage={function onMessage(event) {
    if (event.nativeEvent.url !== TRUSTED) { return; }
    run(JSON.parse(event.nativeEvent.data));
  }} />;
}
'''


class TestScriptRules:
    """
    Purpose:
        The rules over a cross-platform app's recovered JavaScript and Dart.
    """

    @pytest.mark.parametrize("text,expected", [
        ("authToken", ["auth", "token"]),
        ("session_token", ["session", "token"]),
        ("Enter your PIN", ["pin"]),
        ("spinner_style", []),
        ("shipping mapping", []),
    ])
    def test_sensitive_words_match_whole_words(self, text, expected):
        """
        Purpose:
            Pin that names are split on punctuation and camel case before matching.

        Parameters:
            text: The name or literal.
            expected: The sensitive words it holds.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.script_rules import sensitive_words
        assert sensitive_words(text) == expected

    def test_dart_rules(self, tmp_path):
        """
        Purpose:
            Pin the print, SharedPreferences, interpolated SQL, literal key and cleartext rules on Blutter output, each at the line that shows it - the key at its literal, not at the conversion call after it.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.script_rules import analyze_script_rules
        _write_java(tmp_path, "asm/vault/main.dart", VAULT_ASM)
        lines = VAULT_ASM.splitlines()

        def line_of(marker):
            """
            Purpose:
                Find a fixture line.

            Parameters:
                marker: Text on the line.

            Returns:
                Its 1-based number.
            """
            return next(i for i, line in enumerate(lines, 1) if marker in line)

        found = {(f.vuln_class, f.line): f for f in analyze_script_rules(tmp_path)}
        assert set(found) == {
            ("SECRET-02", line_of("r0 = print()")),
            ("STORAGE-01", line_of("r0 = _setValue()")),
            ("CODE-01", line_of("r0 = rawQuery()")),
            ("CRYPTO-02", line_of('r2 = "STATIC_DEMO_KEY_0123456789abcdef"')),
            ("NETWORK-02", line_of('"http://api.vault-demo.net')),
            ("AUTH-04", line_of('"03ac6742')),
        }
        assert found[("STORAGE-01", line_of("r0 = _setValue()"))].title.endswith("'pin' stored in plain SharedPreferences")
        assert found[("CRYPTO-02", line_of('r2 = "STATIC_DEMO_KEY_0123456789abcdef"'))].severity == "High"

    def test_javascript_rules(self, tmp_path):
        """
        Purpose:
            Pin the storage, logging, dynamic code, literal key, onMessage, WebView setting and cleartext rules on a recovered module, with a private development host left out.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.script_rules import analyze_script_rules
        _write_java(tmp_path, "app_modules/12_Wallet.js", RN_MODULE)
        found = analyze_script_rules(tmp_path)
        by_class = {}
        for f in found:
            by_class.setdefault(f.vuln_class, []).append(f.title)
        assert by_class["STORAGE-01"] == ["Sensitive value 'authToken' stored with setItem in unencrypted storage"]
        assert by_class["SECRET-02"] and by_class["CODE-02"] and by_class["CRYPTO-02"]
        assert by_class["PLATFORM-04"] and by_class["PLATFORM-05"]
        assert len(by_class["PLATFORM-06"]) == 2
        assert by_class["NETWORK-02"] == ["App code uses a plain-HTTP endpoint (api.vault-demo.net)"]

    def test_javascript_mitigations_keep_it_quiet(self, tmp_path):
        """
        Purpose:
            Pin that an encrypting store, a log without credentials, a literal-only Function and an origin-checking handler raise nothing.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.script_rules import analyze_script_rules
        _write_java(tmp_path, "app_modules/13_Page.js", RN_SAFE_MODULE)
        assert analyze_script_rules(tmp_path) == []

    def test_runs_for_both_cross_platform_profiles(self):
        """
        Purpose:
            Pin that the script rules are wired into the Flutter and React Native rule sets.
        """
        from lu77U_MobileSec.analyzers.sast.runner import _BY_PROFILE
        assert "script-rules" in _BY_PROFILE["flutter"] and "script-rules" in _BY_PROFILE["react_native"]
        assert "script-rules" not in _BY_PROFILE["java_kotlin"]


LAUNCHER_MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.labs.app">
  <application>
    <activity android:name="com.labs.ui.MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".LinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="labs"/>
      </intent-filter>
    </activity>
    <activity android:name=".WebLinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="labsweb"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


class TestLauncherAndPluginCode:
    """
    Purpose:
        The launcher entry is not an exported-component finding, and rule hits in a cross-platform app's plugin code are dependency notes.
    """

    def test_launcher_only_activity_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that a MAIN/LAUNCHER-only activity is skipped, a launcher that is also a non-browsable link target keeps the ordinary finding, and a browsable deep-link entry is listed as an Informational entry point.

        Parameters:
            tmp_path: Directory the manifest is written into.
        """
        (tmp_path / "AndroidManifest.xml").write_text(LAUNCHER_MANIFEST)
        found = {f.title: f for f in analyze_manifest(tmp_path)}
        assert not any("MainActivity" in t for t in found)
        assert any("LinkActivity has no permission protection" in t for t in found)
        entry = found["Activity WebLinkActivity receives deep links (labsweb)"]
        assert (entry.severity, entry.vuln_class) == ("Informational", "PLATFORM-02")
        assert not any("WebLinkActivity has no permission" in t for t in found)

    def test_app_code_packages(self, tmp_path):
        """
        Purpose:
            Pin that the app's own packages are the manifest package plus each launcher activity's package.

        Parameters:
            tmp_path: Directory the manifest is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import app_code_packages
        (tmp_path / "AndroidManifest.xml").write_text(LAUNCHER_MANIFEST)
        assert app_code_packages(tmp_path) == ["com.labs.app", "com.labs.ui"]
        assert app_code_packages(tmp_path / "missing") == []

    def test_plugin_findings_are_capped_at_low(self, tmp_path):
        """
        Purpose:
            Pin that a finding in a readable third-party package is capped at Low with its vector cleared and says which plugin it is in, even when it was already Low, while the app's own code, obfuscated paths and Java/Kotlin apps are untouched.

        Parameters:
            tmp_path: The analysis root.
        """
        from lu77U_MobileSec.analyzers.sast.runner import demote_plugin_findings
        (tmp_path / "platform/resources").mkdir(parents=True)
        (tmp_path / "platform/resources/AndroidManifest.xml").write_text(LAUNCHER_MANIFEST)

        def make(rel):
            """
            Purpose:
                Build a Medium finding at a path.

            Parameters:
                rel: The finding's file.

            Returns:
                The finding.
            """
            return SastFinding(title="Runtime.exec() invocation", severity="Medium", description="exec.",
                               file=rel, cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")

        plugin = make("platform/sources/com/scottyab/rootbeer/RootBeer.java")
        own = make("platform/sources/com/labs/ui/Shell.java")
        hidden = make("platform/sources/G0/C0025b.java")
        demote_plugin_findings([plugin, own, hidden], tmp_path, "flutter")
        assert (plugin.severity, plugin.cvss_vector) == ("Low", "")
        assert "com.scottyab.rootbeer" in plugin.description
        assert own.severity == "Medium" and hidden.severity == "Medium"
        native = make("platform/sources/com/scottyab/rootbeer/RootBeer.java")
        demote_plugin_findings([native], tmp_path, "java_kotlin")
        assert native.severity == "Medium"
        low = make("platform/sources/com/emrys/rjsniffer/shellEx.java")
        low.severity = "Low"
        demote_plugin_findings([low], tmp_path, "flutter")
        assert low.severity == "Low" and "com.emrys.rjsniffer, a third-party plugin" in low.description


CREDENTIAL_WRITES = '''package com.demo.app;
class Store {
    void save(String usr, String pwd) throws Exception {
        SharedPreferences.Editor editor = prefs.edit(); editor.putString("password", pwd);
        editor.putString("theme", "dark");
        mDB.execSQL("CREATE TABLE IF NOT EXISTS users(user VARCHAR, password VARCHAR);");
        mDB.execSQL("INSERT INTO users VALUES ('admin', 'seed-pass');");
        mDB.execSQL("INSERT INTO users VALUES ('" + usr + "', '" + pwd + "');");
        File tmp = File.createTempFile("uinfo", "tmp", dir);
        FileWriter fw = new FileWriter(tmp);
        fw.write(usr + ":" + pwd + "\\n");
    }
    void export(String pwd) throws Exception {
        File sdir = Environment.getExternalStorageDirectory();
        FileWriter out = new FileWriter(new File(sdir, ".uinfo.txt"));
        out.write("Password: " + pwd);
    }
    void note(String body) throws Exception {
        File sdir = Environment.getExternalStorageDirectory();
        FileWriter out = new FileWriter(new File(sdir, "note.txt"));
        out.write("Password reminder disabled " + body);
    }
}
'''


class TestCredentialStorage:
    """
    Purpose:
        Credentials the app's Java writes to preferences, SQLite, a temp file or external storage.
    """

    def test_each_sink_is_reported_once_with_its_destination(self, tmp_path):
        """
        Purpose:
            Pin one finding per sink, at the write, with literal seed rows, schema statements and literal labels left out.

        Parameters:
            tmp_path: The analysis root.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.credential_storage import analyze_credential_storage
        _write_java(tmp_path, "sources/com/demo/app/Store.java", CREDENTIAL_WRITES)
        found = {(f.vuln_class, f.line, f.title) for f in analyze_credential_storage(tmp_path)}
        assert found == {
            ("STORAGE-01", 4, "Credential stored in SharedPreferences in plain text (putString)"),
            ("STORAGE-01", 8, "Credential stored in a SQLite database in plain text (execSQL)"),
            ("STORAGE-01", 11, "Credential written to a temporary file (createTempFile)"),
            ("STORAGE-02", 16, "Credential written to external storage"),
        }

    def test_a_bundle_is_not_shared_preferences(self, tmp_path):
        """
        Purpose:
            Pin that putString on a Bundle, in a file that never touches SharedPreferences, is not a stored credential, and that a null value stores nothing either.

        Parameters:
            tmp_path: The analysis root.

        Implementation notes:
            A real scan reported Google Sign-In's option bundle - a "forceCodeForRefreshToken" key set to null - as a credential stored in SharedPreferences.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.credential_storage import analyze_credential_storage
        _write_java(tmp_path, "sources/com/demo/app/Opts.java", '''package com.demo.app;
class Opts {
    Bundle build(String token) {
        bundle.putString("signin.internal.forceCodeForRefreshToken", token);
        return bundle;
    }
}
''')
        _write_java(tmp_path, "sources/com/demo/app/Prefs.java", '''package com.demo.app;
class Prefs {
    void clear(SharedPreferences prefs) {
        prefs.edit().putString("session_token", null).apply();
    }
}
''')
        assert analyze_credential_storage(tmp_path) == []

    def test_library_code_is_not_the_apps(self, tmp_path):
        """
        Purpose:
            Pin that the same writes inside a bundled library are not reported.

        Parameters:
            tmp_path: The analysis root.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.credential_storage import analyze_credential_storage
        _write_java(tmp_path, "sources/androidx/demo/Store.java", CREDENTIAL_WRITES)
        assert analyze_credential_storage(tmp_path) == []

    def test_call_arguments_skip_strings(self):
        """
        Purpose:
            Pin that parentheses and semicolons inside string literals do not end an argument list.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.credential_storage import call_arguments
        text = "db.execSQL(\"INSERT INTO t VALUES ('a;b)');\" + x);"
        assert call_arguments(text, text.index("(") + 1) == "\"INSERT INTO t VALUES ('a;b)');\" + x"
        assert call_arguments("f(unclosed", 2) == ""

    def test_runs_wherever_app_java_is_read(self):
        """
        Purpose:
            Pin that the rule is wired into the Java/Kotlin, Flutter and React Native rule sets.
        """
        from lu77U_MobileSec.analyzers.sast.runner import _BY_PROFILE
        for profile in ("java_kotlin", "flutter", "react_native"):
            assert "credential-storage" in _BY_PROFILE[profile]


class TestHardcodedChecks:
    """
    Purpose:
        User input compared against a value written into the app.
    """

    @pytest.mark.parametrize("body,reported", [
        ('if (key.getText().toString().equals("vendorsecretkey")) { ok(); }', True),
        ('if ("S3cretPass".equals(pwd.getText().toString().trim())) { ok(); }', True),
        ('if (answer.getText().toString().equals("Yes")) { ok(); }', False),
        ('if (name.getText().toString().equals("John Smith")) { ok(); }', False),
        ('if (key.getText().toString().equals(expected)) { ok(); }', False),
    ])
    def test_input_compared_with_a_literal(self, tmp_path, body, reported):
        """
        Purpose:
            Pin that a field's text compared with a secret-shaped literal is reported, and labels, phrases and variables are not.

        Parameters:
            tmp_path: The analysis root.
            body: The comparison.
            reported: Whether it should be reported.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.hardcoded_check import analyze_hardcoded_checks
        _write_java(tmp_path, "sources/com/demo/app/Gate.java",
                    "package com.demo.app;\nclass Gate {\n  void check() {\n    " + body + "\n  }\n}\n")
        found = analyze_hardcoded_checks(tmp_path)
        assert [(f.vuln_class, f.line) for f in found] == ([("AUTH-04", 4)] if reported else [])

    def test_runs_wherever_app_java_is_read(self):
        """
        Purpose:
            Pin that the rule is wired into every rule set that reads the app's Java.
        """
        from lu77U_MobileSec.analyzers.sast.runner import _BY_PROFILE
        for profile in ("java_kotlin", "flutter", "react_native"):
            assert "hardcoded-check" in _BY_PROFILE[profile]


class TestScreenCapture:
    """
    Purpose:
        The app-wide note for an app that never sets FLAG_SECURE.
    """

    @pytest.mark.parametrize("rel,body,noted", [
        ("sources/com/demo/app/Main.java", "class Main { void a() { show(); } }", True),
        ("sources/com/demo/app/Main.java", "class Main { void a() { getWindow().addFlags(8192); } }", False),
        ("sources/com/demo/app/Main.java", "class Main { int f = WindowManager.LayoutParams.FLAG_SECURE; }", False),
        ("app_modules/12_Vault.js", "FlutterWindowManager; secure_application;", False),
        ("sources/com/facebook/react/views/modal/Host.java", "class Host { void a() { w.setFlags(8192, 8192); } }", True),
    ])
    def test_flag_secure_anywhere_in_app_code(self, tmp_path, rel, body, noted):
        """
        Purpose:
            Pin that any app or plugin code setting the flag silences the note, and that the React Native modal passing it along does not.

        Parameters:
            tmp_path: The analysis root.
            rel: Where the code is.
            body: The code.
            noted: Whether the note is expected.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.screen_capture import analyze_screen_capture
        _write_java(tmp_path, rel, body)
        found = analyze_screen_capture(tmp_path)
        assert [(f.vuln_class, f.severity) for f in found] == ([("PLATFORM-12", "Informational")] if noted else [])

    def test_runs_for_every_android_code_profile(self):
        """
        Purpose:
            Pin that the note is wired into the Java/Kotlin, Flutter and React Native rule sets.
        """
        from lu77U_MobileSec.analyzers.sast.runner import _BY_PROFILE
        for profile in ("java_kotlin", "flutter", "react_native"):
            assert "screen-capture" in _BY_PROFILE[profile]


class TestTypedUrl:
    """
    Purpose:
        A WebView loading the text of an input field.
    """

    @pytest.mark.parametrize("body,reported", [
        ("wv.loadUrl(urlText.getText().toString());", True),
        ("String u = urlText.getText().toString();\n"
         "    if (u.startsWith(\"https://\")) { wv.loadUrl(urlText.getText().toString()); }", False),
        ("wv.loadUrl(\"https://example.org/help\");", False),
    ])
    def test_typed_url_without_a_scheme_check(self, tmp_path, body, reported):
        """
        Purpose:
            Pin that a typed URL is reported unless the file checks its scheme.

        Parameters:
            tmp_path: The analysis root.
            body: The load call.
            reported: Whether it should be reported.
        """
        _write_java(tmp_path, "sources/com/demo/app/Browse.java",
                    "package com.demo.app;\nimport android.webkit.WebView;\nclass Browse {\n  void go(WebView wv) {\n    "
                    + body + "\n  }\n}\n")
        found = [f for f in analyze_webviews(tmp_path) if f.title.startswith("WebView loads a URL typed")]
        assert [(f.vuln_class, f.line) for f in found] == ([("PLATFORM-06", 5)] if reported else [])


PINNED_ASM = '''// lib: , url: package:vault/main.dart

// class id: 1, size: 0x8
class :: {

  static void main() {
    // ** addr: 0x1000, size: 0x30
    // 0x1000: r0 = runApp()
    //     0x1000: bl              #0x9000  ; [package:flutter/src/widgets/binding.dart] ::runApp
  }
}

class _StatementsState extends State<dynamic> {

  _ _pinnedClient(/* No info */) {
    // ** addr: 0x2000, size: 0x80
    // 0x2004: r0 = SecurityContext()
    //     0x2004: bl              #0x7000  ; [dart:io] SecurityContext::SecurityContext
    // 0x2008: r0 = setTrustedCertificatesBytes()
    //     0x2008: bl              #0x7100  ; [dart:io] _SecurityContext::setTrustedCertificatesBytes
    // 0x200c: r0 = _HttpClient()
    //     0x200c: bl              #0x7200  ; [dart:_http] _HttpClient::_HttpClient
    // 0x2010: ret
    //     0x2010: ret
    // 0x2014: sub             SP, fp, #0x60
    // 0x2018: r0 = _HttpClient()
    //     0x2018: bl              #0x7200  ; [dart:_http] _HttpClient::_HttpClient
    // 0x201c: ret
    //     0x201c: ret
  }

  _ _strictClient(/* No info */) {
    // ** addr: 0x3000, size: 0x80
    // 0x3004: r0 = SecurityContext()
    //     0x3004: bl              #0x7000  ; [dart:io] SecurityContext::SecurityContext
    // 0x3008: r0 = setTrustedCertificatesBytes()
    //     0x3008: bl              #0x7100  ; [dart:io] _SecurityContext::setTrustedCertificatesBytes
    // 0x300c: r0 = _HttpClient()
    //     0x300c: bl              #0x7200  ; [dart:_http] _HttpClient::_HttpClient
    // 0x3010: ret
    //     0x3010: ret
  }
}
'''


def test_pinning_that_falls_back_in_a_catch_is_reported(tmp_path):
    """
    Purpose:
        Pin that a pinned SecurityContext whose exception handler builds a plain HttpClient is reported once, at the handler, and a pinned client without such a handler is not.

    Parameters:
        tmp_path: The analysis root.
    """
    from lu77U_MobileSec.analyzers.sast.extractors.script_rules import analyze_script_rules
    _write_java(tmp_path, "asm/vault/main.dart", PINNED_ASM)
    handler = next(i for i, l in enumerate(PINNED_ASM.splitlines(), 1) if "sub             SP" in l)
    found = [(f.vuln_class, f.line) for f in analyze_script_rules(tmp_path) if f.vuln_class == "NETWORK-03"]
    assert found == [("NETWORK-03", handler)]


def test_pinning_in_app_code_is_noted_once(tmp_path):
    """
    Purpose:
        Pin that a pinned client in the app's Dart is noted once per file at Informational, at the first pinning call.

    Parameters:
        tmp_path: The analysis root.
    """
    from lu77U_MobileSec.analyzers.sast.extractors.script_rules import analyze_script_rules
    _write_java(tmp_path, "asm/vault/main.dart", PINNED_ASM)
    first = next(i for i, l in enumerate(PINNED_ASM.splitlines(), 1) if "r0 = setTrustedCertificatesBytes()" in l)
    found = [(f.severity, f.line) for f in analyze_script_rules(tmp_path) if f.vuln_class == "BUILD-04"]
    assert found == [("Informational", first)]
