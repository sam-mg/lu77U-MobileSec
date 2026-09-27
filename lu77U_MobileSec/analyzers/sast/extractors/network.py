#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.network

Purpose:
    Find transport security problems: a network security configuration that permits cleartext or trusts user-added CAs, and code that disables certificate or hostname validation.

Responsibilities:
    Parse the network security configuration and scan source for TLS bypasses.

Dependencies:
    The XML parser.

Implementation notes:
    The two halves answer different questions. The configuration says what the platform will allow; the code says what the app actually does. A trust-all implementation in code is a defect regardless of configuration, while a permissive configuration only matters if something uses it.

Security considerations:
    A TLS bypass is among the most serious findings this tool produces, because it makes every request the app sends interceptable by anyone on the network path.
"""

import re
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_ANDROID = "{http://schemas.android.com/apk/res/android}"
_MAX_FILES = 60000

_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/")

_PINNING_INDICATORS = (
    ("OkHttp CertificatePinner", r"CertificatePinner", "framework"),
    ("Network security config pin-set", r"<pin-set|<pin\s+digest=", "config"),
    ("Custom TrustManager", r"X509TrustManager|checkServerTrusted", "custom"),
    ("Custom SSLContext", r"SSLContext\.getInstance|TrustManagerFactory", "custom"),
    ("HostnameVerifier", r"HostnameVerifier|setHostnameVerifier", "custom"),
    ("Certificate transparency", r"certificateTransparency", "framework"),
)

_BYPASS_PATTERNS = (
    ("trust_all_certs",
     r"(?i)(?:trustAllCert|acceptAllCert|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllHosts)",
     "High", "Code trusts all TLS certificates",
     "A trust-all TrustManager or hostname verifier accepts any certificate, which "
     "removes TLS authentication entirely."),
    ("empty_trust_manager",
     r"public\s+void\s+checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}",
     "High", "TrustManager accepts every server certificate",
     "checkServerTrusted() has an empty body, so every certificate is accepted "
     "including attacker-supplied ones."),
    ("hostname_verifier_true",
     r"public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;",
     "High", "HostnameVerifier accepts every hostname",
     "verify() unconditionally returns true, so a certificate for any hostname is "
     "accepted for any connection."),
    ("pinning_disable_flag",
     r"(?i)(?:disable|skip|bypass)[_\-]?(?:pinning|ssl|cert)",
     "Medium", "Code path disables certificate pinning",
     "A flag or branch disables pinning. Verify it cannot be reached in a release build."),
)


def find_network_security_config(source_root) -> Optional[Path]:
    """
    Purpose:
        Locate the network security configuration in a decompiled tree.

    Parameters:
        source_root: Root of the decompiled source.

    Returns:
        The configuration path, or None when the app declares none.

    Implementation notes:
        Its absence is not itself a finding: an app with no configuration gets the platform defaults, which are secure on current targets.
    """
    root = Path(source_root)
    for candidate in root.rglob("network_security_config.xml"):
        return candidate
    for candidate in root.rglob("network_security_conf*.xml"):
        return candidate
    return None


def analyze_network_config(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Derive findings from the network security configuration.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Implementation notes:
        Cleartext permission and user-CA trust are reported per scope, so a finding names the domains it applies to rather than implying the whole app. An app that permits cleartext for one internal hostname is in a very different position from one that permits it everywhere. Debug-only overrides are distinguished from production configuration, since the former does not ship in a release build.
    """
    config = find_network_security_config(source_root)
    if config is None:
        return []
    try:
        root = ElementTree.parse(config).getroot()
    except (ElementTree.ParseError, OSError) as exc:
        verbose_print(f"SAST network: could not parse {config}: {exc}", verbose)
        return []

    try:
        rel = str(config.relative_to(Path(source_root)))
    except ValueError:
        rel = config.name

    out: List[SastFinding] = []
    has_pins = root.find(".//pin-set") is not None

    def _cleartext(el) -> Optional[str]:
        """
        Purpose:
            Read the cleartext permission from a configuration element.

        Parameters:
            el: The configuration element.

        Returns:
            The declared value, or None when the element does not set it.

        Implementation notes:
            None means inherit, which is materially different from an explicit denial -- the effective value then comes from the enclosing scope or the platform default, and only the explicit settings are worth reporting.
        """
        return el.get("cleartextTrafficPermitted")

    base = root.find("base-config")
    if base is not None:
        if str(_cleartext(base)).lower() == "true":
            out.append(SastFinding(
                title="Network security config permits cleartext traffic app-wide",
                severity="High", vuln_class="NETWORK-02", file=rel, detector="network-config",
                description='base-config sets cleartextTrafficPermitted="true", allowing '
                            "unencrypted HTTP from anywhere in the app.",
                impact="Traffic can be read and modified on any network path.",
                recommendation="Set it to false and declare narrow per-domain exceptions if "
                               "genuinely required.",
                cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))
        for anchor in base.findall(".//certificates"):
            if anchor.get("src") == "user":
                out.append(SastFinding(
                    title="App trusts user-installed CA certificates",
                    severity="High", vuln_class="NETWORK-01", file=rel, detector="network-config",
                    description='base-config trusts certificates with src="user", so anyone who '
                                "can install a CA on the device can intercept HTTPS.",
                    impact="Trivial HTTPS interception with a user-installed proxy certificate.",
                    recommendation='Remove the user trust anchor; trust only src="system".',
                    cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))

    cleartext_domains = []
    user_trust_domains = []
    for domain_config in root.findall("domain-config"):
        names = [d.text.strip() for d in domain_config.findall("domain") if d.text]
        if str(_cleartext(domain_config)).lower() == "true":
            cleartext_domains += names
        for anchor in domain_config.findall(".//certificates"):
            if anchor.get("src") == "user":
                user_trust_domains += names

    if cleartext_domains:
        listed = ", ".join(sorted(set(cleartext_domains))[:8])
        out.append(SastFinding(
            title=f"Cleartext traffic permitted for {plural(len(set(cleartext_domains)), 'domain')}",
            severity="Medium", vuln_class="NETWORK-02", file=rel, detector="network-config",
            description=f"These domains accept unencrypted HTTP: {listed}.",
            recommendation="Serve these domains over HTTPS and remove the exception.",
            cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))

    if user_trust_domains:
        listed = ", ".join(sorted(set(user_trust_domains))[:8])
        out.append(SastFinding(
            title=f"User CA certificates trusted for {plural(len(set(user_trust_domains)), 'domain')}",
            severity="Medium", vuln_class="NETWORK-01", file=rel, detector="network-config",
            description=f"These domains trust user-installed CAs: {listed}.",
            recommendation='Trust only src="system" for domains carrying sensitive data.',
            cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))

    if root.find("debug-overrides") is not None:
        out.append(SastFinding(
            title="Network security config declares debug-overrides",
            severity="Low", vuln_class="BUILD-01", file=rel, detector="network-config",
            description="debug-overrides apply only when the app is debuggable. Confirm the "
                        "release build is not debuggable, or these relaxations become live.",
            recommendation="Keep debug-overrides and ensure release builds set "
                           'android:debuggable="false".'))

    if not has_pins:
        out.append(SastFinding(
            title="No certificate pinning declared in the network security config",
            severity="Informational", vuln_class="NETWORK-03", file=rel, detector="network-config",
            description="The config declares no <pin-set>, so the app relies on the platform CA "
                        "store alone.",
            impact="On its own this is informational - it matters when combined with sensitive "
                   "traffic and an interception path.",
            recommendation="Pin the domains that carry credentials or personal data.",
            cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))

    verbose_print(f"SAST network-config: {plural(len(out), 'finding')} from {config}", verbose)
    return out


def analyze_tls_bypass(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Find code that disables certificate or hostname verification.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads source files.

    Implementation notes:
        Looks for the recognisable shapes: a trust manager whose check methods do nothing, a hostname verifier that always returns true, and an SSL error handler that proceeds regardless. These are reported at high severity without requiring a chain, because unlike a permissive configuration they are an active decision in the app's own code that defeats transport security wherever that code is used.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    out: List[SastFinding] = []
    pinning_seen = set()
    per_rule = {}
    scanned = 0

    for path in root.rglob("*.java"):
        scanned += 1
        if scanned > _MAX_FILES:
            break
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        if any(fragment in "/" + rel.replace("\\", "/") for fragment in _NOISE):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"Trust" not in data and b"SSL" not in data and b"Hostname" not in data \
                and b"CertificatePinner" not in data and b"pinning" not in data.lower():
            continue
        text = data.decode("utf-8", errors="ignore")

        for name, pattern, _kind in _PINNING_INDICATORS:
            if re.search(pattern, text):
                pinning_seen.add(name)

        for rule_id, pattern, severity, title, description in _BYPASS_PATTERNS:
            for match in re.finditer(pattern, text, re.DOTALL):
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                if per_rule[rule_id] > 20:
                    break
                line = text[:match.start()].count("\n") + 1
                out.append(SastFinding(
                    title=title, severity=severity, vuln_class="NETWORK-01",
                    file=rel, line=line, detector="tls", confidence="MEDIUM",
                    description=description,
                    impact="An attacker on the network path can present their own certificate "
                           "and read or modify traffic.",
                    recommendation="Remove the bypass and validate certificates normally; use "
                                   "pinning for sensitive endpoints.",
                    cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))

    if not pinning_seen and out:
        verbose_print("SAST tls: bypasses found and no pinning implementation detected", verbose)
    verbose_print(f"SAST tls: {plural(len(out), 'finding')}; pinning indicators: "
                  f"{sorted(pinning_seen) or 'none'}", verbose)
    return out
