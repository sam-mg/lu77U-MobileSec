#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.runner

Purpose:
    Run the deterministic analysis over decompiled source: the built-in extractors and, where available, Semgrep.

Responsibilities:
    Select the extractors for the framework, run them, and collect their findings.

Dependencies:
    The extractor modules and the Semgrep runner.

Implementation notes:
    This pass exists so that a scan produces rule-backed findings independently of any model. Flutter and React Native run the Java rules too, because their analysis roots carry the JADX-decompiled platform layer under platform/, where WebView, TLS and injection issues are written in Java like any app; network-config is left out of Flutter because Dart networking does not honour network_security_config, and dart-tls covers what the Java TLS rules cannot see: a certificate callback installed in Dart. script-rules does the same for the rest of the logic those apps keep outside Java - storage, logging, SQL, keys and endpoints in the recovered JavaScript and Dart. It is what makes cross-engine agreement a meaningful confidence signal, and what keeps a scan useful when the AI phase fails or is unconfigured.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List

from .extractors.credential_storage import analyze_credential_storage
from .extractors.crypto_misuse import analyze_crypto_misuse
from .extractors.dart_tls import analyze_dart_tls
from .extractors.flutter_build import analyze_flutter_build
from .extractors.hardcoded_check import analyze_hardcoded_checks
from .extractors.injection import analyze_injection
from .extractors.manifest import analyze_manifest, app_code_packages
from .extractors.network import analyze_network_config, analyze_tls_bypass
from .extractors.oauth import analyze_oauth
from .extractors.platform_misuse import analyze_platform_misuse
from .extractors.sdk_inventory import analyze_sdks
from .extractors.screen_capture import analyze_screen_capture
from .extractors.script_rules import analyze_script_rules
from .extractors.secrets import analyze_secrets
from .extractors.signature_derived_key import analyze_signature_derived_key
from .extractors.webview import analyze_webviews
from .findings import SastFinding, to_scan_findings
from ..layout import PLATFORM_DIR
from ...validation.gates import severity_rank
from .semgrep_runner import run_semgrep
from ...utils.cancellation import ScanCancelled
from ...utils.verbose import plural, verbose_print

_SCANNERS: Dict[str, Callable[..., List[SastFinding]]] = {
    "manifest": analyze_manifest,
    "webview": analyze_webviews,
    "network-config": analyze_network_config,
    "tls": analyze_tls_bypass,
    "injection": analyze_injection,
    "secrets": analyze_secrets,
    "sdk-inventory": analyze_sdks,
    "signature-derived-key": analyze_signature_derived_key,
    "flutter-build": analyze_flutter_build,
    "dart-tls": analyze_dart_tls,
    "crypto-misuse": analyze_crypto_misuse,
    "platform-misuse": analyze_platform_misuse,
    "oauth": analyze_oauth,
    "script-rules": analyze_script_rules,
    "credential-storage": analyze_credential_storage,
    "hardcoded-check": analyze_hardcoded_checks,
    "screen-capture": analyze_screen_capture,
    "semgrep": run_semgrep,
}

_BY_PROFILE: Dict[str, tuple] = {
    "java_kotlin": ("manifest", "webview", "network-config", "tls", "injection",
                    "secrets", "sdk-inventory", "signature-derived-key", "crypto-misuse",
                    "platform-misuse", "oauth", "credential-storage", "hardcoded-check", "screen-capture",
                    "semgrep"),
    "flutter": ("manifest", "secrets", "flutter-build", "dart-tls", "webview", "tls", "injection",
                "crypto-misuse", "platform-misuse", "oauth", "credential-storage", "hardcoded-check",
                "script-rules", "screen-capture", "sdk-inventory"),
    "react_native": ("manifest", "secrets", "webview", "tls", "injection", "crypto-misuse",
                     "platform-misuse", "oauth", "credential-storage", "hardcoded-check", "script-rules",
                     "screen-capture", "sdk-inventory"),
    "cordova": ("manifest", "secrets"),
    "xamarin": ("manifest", "secrets"),
}

_DEFAULT_SCANNERS = ("manifest", "secrets")

_CROSS_PLATFORM = ("flutter", "react_native")
_PLATFORM_SOURCES = f"{PLATFORM_DIR}/sources/"
_PACKAGE_ROOTS = frozenset((
    "com", "org", "net", "io", "dev", "me", "de", "fr", "uk", "co", "app", "in", "info", "eu",
    "ru", "cn", "jp", "br", "nl", "us", "ca", "au", "tech", "xyz",
))


def _named_package(rel: str) -> str:
    """
    Purpose:
        Read a readable Java package out of a platform-layer path.

    Parameters:
        rel: The file's path, relative to the analysis root.

    Returns:
        The dotted package when the path is a readable reverse-domain one, otherwise "".

    Implementation notes:
        R8 renames packages to one or two characters ("G0", "p045z0"), and an obfuscated path says nothing about who wrote the code, so only a path that starts with a domain root and carries a real name under it counts. An unreadable path returns "" and its finding is left untouched.
    """
    segments = rel[len(_PLATFORM_SOURCES):].split("/")[:-1]
    if len(segments) < 2 or segments[0] not in _PACKAGE_ROOTS or len(segments[1]) < 3:
        return ""
    return ".".join(segments)


def demote_plugin_findings(findings: List[SastFinding], root: Path, profile_key: str) -> List[SastFinding]:
    """
    Purpose:
        Report rule hits in a Flutter or React Native app's third-party plugin code as dependency notes rather than as app flaws.

    Parameters:
        findings: The rule findings, updated in place.
        root: The analysis root.
        profile_key: The framework profile.

    Returns:
        The same findings.

    Implementation notes:
        A cross-platform app's platform layer carries every plugin's Java alongside the app's own few classes, and the generic Java rules fire on plugin internals: a root-detection library running "which su" is a Runtime.exec hit, and benchmark reports listed three of them at Medium as if the app ran shell commands. A finding in a readable package outside the app's own packages says where it is and is capped at Low, so it stays visible as a dependency note without being scored as the app's flaw; one already at Low or below still says where it is, since a published Runtime.exec hit inside a root-detection plugin read as the app's own code. Its CVSS vector is cleared, because severity is recomputed from a vector downstream and would otherwise undo the cap. Obfuscated paths are left alone, since R8 hides the app's own classes the same way.
    """
    if profile_key not in _CROSS_PLATFORM:
        return findings
    app_dirs = tuple(_PLATFORM_SOURCES + package.replace(".", "/") + "/" for package in app_code_packages(root))
    if not app_dirs:
        return findings
    for finding in findings:
        rel = (finding.file or "").replace("\\", "/")
        if not rel.startswith(_PLATFORM_SOURCES) or rel.startswith(app_dirs):
            continue
        package = _named_package(rel)
        if not package:
            continue
        if severity_rank(finding.severity) > severity_rank("Low"):
            finding.severity = "Low"
            finding.cvss_vector = ""
        finding.description = (
            f"{finding.description} This code is in {package}, a third-party plugin bundled with the "
            "app rather than the app's own code, so it is reported as a dependency note.").strip()
    return findings


def run_sast(source_root, profile_key: str = "java_kotlin", verbose: bool = False,
             is_cancelled=None, apk_path=None) -> List[SastFinding]:
    """
    Purpose:
        Run the rule engine over a decompiled tree.

    Parameters:
        source_root: Root of the decompiled source.
        profile_key: Framework profile, selecting which extractors apply.
        verbose: Traces progress.
        is_cancelled: Polled between extractors.
        apk_path: Path to the APK, for extractors that read the archive directly.

    Returns:
        The rule findings.

    Raises:
        ScanCancelled: When the user stopped the scan.

    Implementation notes:
        A missing or invalid source root returns nothing rather than raising, since a framework whose decompilation failed should still complete its scan with whatever else was gathered. Each extractor is run under its own guard, so one failing costs its rules rather than the whole pass. Cancellation is checked between extractors, which is granular enough to stop promptly without interrupting one partway.
    """
    is_cancelled = is_cancelled or (lambda: False)
    root = Path(source_root) if source_root else None
    if root is None or not root.is_dir():
        verbose_print(f"SAST: source root {source_root!r} is not a directory; skipping", verbose)
        return []

    names = _BY_PROFILE.get(profile_key, _DEFAULT_SCANNERS)
    out: List[SastFinding] = []
    for name in names:
        if is_cancelled():
            raise ScanCancelled()
        scanner = _SCANNERS.get(name)
        if scanner is None:
            continue
        try:
            kwargs = {"verbose": verbose}
            if name == "manifest":
                kwargs["apk_path"] = apk_path
            found = scanner(root, **kwargs) or []
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"SAST scanner {name!r} failed ({exc}); continuing", verbose)
            continue
        verbose_print(f"SAST {name}: {plural(len(found), 'finding')}", verbose)
        out += found

    verbose_print(f"SAST: {plural(len(out), 'deterministic finding')} total", verbose)
    return demote_plugin_findings(out, root, profile_key)


def run_sast_findings(source_root, profile_key: str = "java_kotlin", verbose: bool = False,
                      is_cancelled=None, apk_path=None) -> List[Dict[str, Any]]:
    """
    Purpose:
        Run the rule engine and return its findings in the pipeline's dict shape.

    Parameters:
        source_root: Root of the decompiled source.
        profile_key: Framework profile.
        verbose: Traces progress.
        is_cancelled: Polled between extractors.
        apk_path: Path to the APK.

    Returns:
        The findings as dicts.
    """
    return to_scan_findings(
        run_sast(source_root, profile_key, verbose, is_cancelled, apk_path))


def summarize(findings: List[SastFinding]) -> Dict[str, int]:
    """
    Purpose:
        Count rule findings by severity, for progress reporting.

    Parameters:
        findings: The rule findings.

    Returns:
        Counts keyed by severity.
    """
    out: Dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
