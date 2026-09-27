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
    This pass exists so that a scan produces rule-backed findings independently of any model. It is what makes cross-engine agreement a meaningful confidence signal, and what keeps a scan useful when the AI phase fails or is unconfigured.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List

from .extractors.injection import analyze_injection
from .extractors.manifest import analyze_manifest
from .extractors.network import analyze_network_config, analyze_tls_bypass
from .extractors.sdk_inventory import analyze_sdks
from .extractors.secrets import analyze_secrets
from .extractors.webview import analyze_webviews
from .findings import SastFinding, to_scan_findings
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
    "semgrep": run_semgrep,
}

_BY_PROFILE: Dict[str, tuple] = {
    "java_kotlin": ("manifest", "webview", "network-config", "tls", "injection",
                    "secrets", "sdk-inventory", "semgrep"),
    "flutter": ("manifest", "secrets"),
    "react_native": ("manifest", "secrets"),
    "cordova": ("manifest", "secrets"),
    "xamarin": ("manifest", "secrets"),
}

_DEFAULT_SCANNERS = ("manifest", "secrets")


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
    return out


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
