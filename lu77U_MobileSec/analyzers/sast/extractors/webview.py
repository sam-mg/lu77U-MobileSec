#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.webview

Purpose:
    Find WebView issues: dangerous settings, native bridges exposed to web content, attacker-influenced URLs reaching a load call, and SSL errors being ignored.

Responsibilities:
    Match the constructs, apply per-rule budgets, and emit findings with the surrounding code.

Dependencies:
    re only.

Implementation notes:
    WebViews are where most serious Android chains end, because a native bridge in a WebView loading attacker-chosen content is remote code execution in the app's context. The four rule groups here correspond to the links in that chain, which is what lets the chaining stage connect them.

Security considerations:
    A permissive setting on a WebView that only ever loads bundled content is not a finding, and this extractor cannot tell the difference. That judgement is left to the verification pass and the gates, which have the mitigating context this layer does not.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MAX_FILES = 60000
_MAX_FINDINGS_PER_RULE = 40

_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/", "/okhttp3/", "/retrofit2/")

_SETTINGS_RULES: Tuple[Tuple[str, str, str, str, str], ...] = (
    ("universal_file_access",
     r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", "Critical",
     "WebView allows universal access from file:// URLs",
     "setAllowUniversalAccessFromFileURLs(true) lets content loaded from a file:// URL "
     "read any origin, defeating the same-origin policy."),
    ("file_access_from_file_urls",
     r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)", "High",
     "WebView allows file access from file:// URLs",
     "setAllowFileAccessFromFileURLs(true) lets a loaded local page read other local files."),
    ("file_access",
     r"setAllowFileAccess\s*\(\s*true\s*\)", "Medium",
     "WebView file access is enabled",
     "setAllowFileAccess(true) permits file:// loads; combined with attacker-controlled "
     "URLs this reads app-private storage."),
    ("content_access",
     r"setAllowContentAccess\s*\(\s*true\s*\)", "Medium",
     "WebView content:// access is enabled",
     "setAllowContentAccess(true) lets the WebView reach content providers."),
    ("javascript_enabled",
     r"setJavaScriptEnabled\s*\(\s*true\s*\)", "Low",
     "WebView has JavaScript enabled",
     "JavaScript is enabled. On its own this is normal; it is what makes every other "
     "WebView weakness on this page exploitable."),
)

_TAINT_RULES: Tuple[Tuple[str, str, str, str], ...] = (
    ("loadurl_intent_data",
     r"load(?:Url|DataWithBaseURL)\s*\([^;]*?getIntent\s*\(\s*\)\s*\.\s*getData\s*\(",
     "High",
     "WebView loads a URL taken from the launching Intent"),
    ("loadurl_string_extra",
     r"load(?:Url|DataWithBaseURL)\s*\([^;]*?getStringExtra\s*\(",
     "High",
     "WebView loads a URL taken from an Intent extra"),
    ("loadurl_query_param",
     r"load(?:Url|DataWithBaseURL)\s*\([^;]*?getQueryParameter\s*\(",
     "High",
     "WebView loads a URL built from a deep-link query parameter"),
    ("loadurl_intent_variable",
     r"load(?:Url|DataWithBaseURL)\s*\([^;]*?\b(?:intent|getIntent\s*\(\s*\))\s*\.",
     "Medium",
     "WebView loads a URL derived from the launching Intent"),
)

_JS_INTERFACE_CALL_RE = re.compile(r"addJavascriptInterface\s*\(\s*([^,]+),\s*[\"']([^\"']+)[\"']")
_JS_INTERFACE_ANNOTATION_RE = re.compile(
    r"@(?:android\.webkit\.)?JavascriptInterface\b[^{;]*?\b([A-Za-z_$][\w$]*)\s*\(", re.DOTALL)
_SSL_ERROR_RE = re.compile(
    r"onReceivedSslError\s*\([^)]*\)\s*\{[^}]*?\.proceed\s*\(\s*\)", re.DOTALL)


def _is_noise(rel: str) -> bool:
    """
    Purpose:
        Recognise files that are framework or generated code rather than the app's own.

    Parameters:
        rel: The file's path relative to the source root.

    Returns:
        True when the file should be skipped.

    Implementation notes:
        Bundled web libraries configure WebViews for their own purposes, and reporting their settings as the app's would be both wrong and voluminous.
    """
    probe = "/" + rel.replace("\\", "/")
    return any(fragment in probe for fragment in _NOISE)


def _line_of(text: str, index: int) -> int:
    """
    Purpose:
        Convert a match offset to a line number.

    Parameters:
        text: The file's source.
        index: The match offset.

    Returns:
        The one-based line number.

    Implementation notes:
        Matching is done over the whole file rather than line by line, because these constructs span lines; the offset is converted back afterwards so the finding cites a real line.
    """
    return text[:index].count("\n") + 1


def _snippet(text: str, index: int, span: int = 2) -> str:
    """
    Purpose:
        Extract the lines around a match for the finding's evidence.

    Parameters:
        text: The file's source.
        index: The match offset.
        span: How many lines either side to include.

    Returns:
        The snippet.

    Implementation notes:
        Context on both sides, because a WebView setting alone rarely shows whether it is dangerous -- what the WebView loads is usually on a nearby line.
    """
    lines = text.splitlines()
    n = _line_of(text, index) - 1
    return "\n".join(lines[max(0, n - span):n + span + 1])


def analyze_webviews(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Scan a decompiled tree for WebView issues.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads source files.

    Implementation notes:
        The four rule groups run over each candidate file, and each is separately budgeted so one noisy group cannot crowd out the others.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    out: List[SastFinding] = []
    counts: Dict[str, int] = {}
    scanned = 0

    for path in root.rglob("*.java"):
        scanned += 1
        if scanned > _MAX_FILES:
            verbose_print(f"SAST webview: stopped after {_MAX_FILES} files", verbose)
            break
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        if _is_noise(rel):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"WebView" not in data and b"JavascriptInterface" not in data \
                and b"onReceivedSslError" not in data:
            continue
        text = data.decode("utf-8", errors="ignore")

        out += _settings_findings(text, rel, counts)
        out += _bridge_findings(text, rel, counts)
        out += _taint_findings(text, rel, counts)
        out += _ssl_findings(text, rel, counts)

    verbose_print(f"SAST webview: {plural(len(out), 'finding')} across {plural(scanned, 'file')}", verbose)
    return out


def _budget(counts: Dict[str, int], rule: str) -> bool:
    """
    Purpose:
        Limit how many findings one rule may contribute.

    Parameters:
        counts: Running counts per rule.
        rule: The rule being counted.

    Returns:
        True while the rule is within budget.

    Side effects:
        Increments the rule's count.

    Implementation notes:
        Budgeted per rule rather than overall, so a file configuring many WebViews does not exhaust the budget for the bridge and SSL rules, which are the more serious ones.
    """
    counts[rule] = counts.get(rule, 0) + 1
    return counts[rule] <= _MAX_FINDINGS_PER_RULE


def _settings_findings(text: str, rel: str, counts) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for dangerous WebView settings.

    Parameters:
        text: The file's source.
        rel: The file's path.
        counts: Running rule counts.

    Returns:
        The findings.

    Implementation notes:
        Covers JavaScript being enabled, file access from web content, and universal access from file URLs. The last is the most serious: it lets a local page read any file the app can, which turns a downloaded HTML file into a data exfiltration primitive. None of these is exploitable on its own, which is why they carry moderate severities and matter mainly as chain components.
    """
    out = []
    for rule_id, pattern, severity, title, description in _SETTINGS_RULES:
        for match in re.finditer(pattern, text):
            if not _budget(counts, rule_id):
                break
            out.append(SastFinding(
                title=title, severity=severity, vuln_class="PLATFORM-05",
                file=rel, line=_line_of(text, match.start()),
                detector="webview", confidence="MEDIUM",
                description=description,
                evidence=_snippet(text, match.start()),
                recommendation="Disable this setting unless the WebView only ever loads "
                               "trusted, app-bundled content.",
                cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration"))
    return out


def _bridge_findings(text: str, rel: str, counts) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for native bridges exposed to web content.

    Parameters:
        text: The file's source.
        rel: The file's path.
        counts: Running rule counts.

    Returns:
        The findings.

    Implementation notes:
        A bridge binds an application object into the page's JavaScript context, so any page the WebView loads can call its annotated methods with the app's permissions. This is the highest-value target in a WebView, and it is what the deep-link chains are ultimately reaching for. The bridge name is recorded, since a reader needs to know which object is exposed to judge what it grants.
    """
    out = []
    exposed = [m.group(1) for m in _JS_INTERFACE_ANNOTATION_RE.finditer(text)]
    for match in _JS_INTERFACE_CALL_RE.finditer(text):
        if not _budget(counts, "js_bridge"):
            break
        name = match.group(2)
        methods = ", ".join(sorted(set(exposed))[:8]) or "(none found in this file)"
        out.append(SastFinding(
            title=f"WebView exposes a JavaScript bridge as \"{name}\"",
            severity="High", vuln_class="PLATFORM-04",
            file=rel, line=_line_of(text, match.start()),
            detector="webview", confidence="MEDIUM",
            description=(
                f'addJavascriptInterface binds a Java object to the JavaScript name "{name}". '
                f"Any page loaded in this WebView can call its @JavascriptInterface methods: {methods}."),
            impact="If attacker-controlled content ever loads in this WebView, it can invoke "
                   "these native methods directly.",
            recommendation="Restrict the WebView to trusted origins, and keep the bridge surface "
                           "minimal - no methods returning secrets or performing privileged actions.",
            evidence=_snippet(text, match.start()),
            cwe="CWE-749", owasp_mobile="M4: Insufficient Input/Output Validation",
            extra={"js_interface_name": name, "exposed_methods": sorted(set(exposed))[:12]}))

    if exposed and not _JS_INTERFACE_CALL_RE.search(text):
        first = _JS_INTERFACE_ANNOTATION_RE.search(text)
        if first and _budget(counts, "js_bridge_class"):
            out.append(SastFinding(
                title=f"Class exposes {plural(len(set(exposed)), '@JavascriptInterface method')} to WebView content",
                severity="High", vuln_class="PLATFORM-04",
                file=rel, line=_line_of(text, first.start()),
                detector="webview", confidence="MEDIUM",
                description=("This class annotates methods with @JavascriptInterface, so once it is "
                             "bound to a WebView any loaded page can call them: "
                             + ", ".join(sorted(set(exposed))[:10]) + "."),
                impact="Determines what JavaScript in the WebView can reach in native code.",
                recommendation="Audit each exposed method for what it returns and what it performs; "
                               "bind the object only to WebViews restricted to trusted origins.",
                evidence=_snippet(text, first.start()),
                cwe="CWE-749", owasp_mobile="M4: Insufficient Input/Output Validation",
                extra={"exposed_methods": sorted(set(exposed))[:12]}))
    return out


def _taint_findings(text: str, rel: str, counts) -> List[SastFinding]:
    """
    Purpose:
        Emit findings where an attacker-influenced value reaches a WebView load call.

    Parameters:
        text: The file's source.
        rel: The file's path.
        counts: Running rule counts.

    Returns:
        The findings.

    Implementation notes:
        This is the link that turns WebView settings from configuration into exposure: it establishes that the WebView can be made to load something the attacker chose, which is what every other WebView finding depends on. Matched by proximity between a taint source and a load call rather than by real dataflow, so it can miss a path through a helper method and can over-report one where the value is validated in between.
    """
    out = []
    claimed: set = set()
    for rule_id, pattern, severity, title in _TAINT_RULES:
        for match in re.finditer(pattern, text, re.DOTALL):
            line = _line_of(text, match.start())
            if line in claimed:
                continue
            if not _budget(counts, rule_id):
                break
            claimed.add(line)
            out.append(SastFinding(
                title=title, severity=severity, vuln_class="PLATFORM-02",
                file=rel, line=_line_of(text, match.start()),
                detector="webview", confidence="MEDIUM",
                description="A WebView load call is fed data that originates from an Intent, so "
                            "whoever can send that Intent controls what the WebView loads.",
                impact="With a JavaScript bridge or file access enabled on the same WebView, this "
                       "is the deep-link to WebView chain: attacker content running with the app's "
                       "bridge privileges.",
                recommendation="Validate the URL against an allowlist of exact hosts before "
                               "loading. Reject javascript:, file: and data: schemes.",
                evidence=_snippet(text, match.start()),
                cwe="CWE-939", owasp_mobile="M4: Insufficient Input/Output Validation"))
    return out


def _ssl_findings(text: str, rel: str, counts) -> List[SastFinding]:
    """
    Purpose:
        Emit findings where a WebView proceeds past an SSL error.

    Parameters:
        text: The file's source.
        rel: The file's path.
        counts: Running rule counts.

    Returns:
        The findings.

    Implementation notes:
        An error handler that proceeds regardless disables transport security for everything that WebView loads. Unlike the settings findings this is reported seriously on its own, because it is an active decision in the app's code rather than a configuration that might never matter.
    """
    out = []
    for match in _SSL_ERROR_RE.finditer(text):
        if not _budget(counts, "ssl_proceed"):
            break
        out.append(SastFinding(
            title="WebView ignores TLS certificate errors",
            severity="High", vuln_class="NETWORK-01",
            file=rel, line=_line_of(text, match.start()),
            detector="webview", confidence="MEDIUM",
            description="onReceivedSslError() calls handler.proceed(), which accepts invalid or "
                        "untrusted certificates instead of failing the load.",
            impact="Any attacker on the network path can present their own certificate and read "
                   "or modify the traffic in this WebView.",
            recommendation="Call handler.cancel() and surface the error. Never proceed on an SSL "
                           "error in a production build.",
            evidence=_snippet(text, match.start()),
            cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))
    return out
