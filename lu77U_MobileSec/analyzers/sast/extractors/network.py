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

_MAX_FILES = 60000

_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/", "/okhttp3/", "/okio/", "/retrofit2/",
          "/com/facebook/react/", "/io/flutter/")

_PINNING_INDICATORS = (
    ("OkHttp CertificatePinner", r"CertificatePinner", "framework"),
    ("Network security config pin-set", r"<pin-set|<pin\s+digest=", "config"),
    ("Custom TrustManager", r"X509TrustManager|checkServerTrusted", "custom"),
    ("Custom SSLContext", r"SSLContext\.getInstance|TrustManagerFactory", "custom"),
    ("HostnameVerifier", r"HostnameVerifier|setHostnameVerifier", "custom"),
    ("Certificate transparency", r"certificateTransparency", "framework"),
)

_FACT_KEYS = {
    "trust_all_certs": "tls:trust-manager", "empty_trust_manager": "tls:trust-manager",
    "hostname_verifier_true": "tls:hostname-verifier", "insecure_socket_factory": "tls:insecure-socket-factory",
}
_KOTLIN_NULL_CHECKS = r"(?:\s*(?:kotlin\.jvm\.internal\.)?Intrinsics\.check\w*\([^;]*\);)*"

_BYPASS_PATTERNS = (
    ("trust_all_certs",
     r"(?i)(?:trustAllCert|acceptAllCert|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllHosts)",
     "High", "Code trusts all TLS certificates",
     "A trust-all TrustManager or hostname verifier accepts any certificate, which "
     "removes TLS authentication entirely."),
    ("empty_trust_manager",
     r"public\s+void\s+checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{" + _KOTLIN_NULL_CHECKS + r"\s*\}",
     "High", "TrustManager accepts every server certificate",
     "checkServerTrusted() has an empty body, so every certificate is accepted "
     "including attacker-supplied ones."),
    ("hostname_verifier_true",
     r"boolean\s+[\w$]+\s*\([^)]*SSLSession[^)]*\)\s*\{" + _KOTLIN_NULL_CHECKS + r"\s*return\s+true\s*;",
     "High", "HostnameVerifier accepts every hostname",
     "A hostname check (verify(), or the lambda a Kotlin HostnameVerifier compiles to) "
     "unconditionally returns true, so a certificate for any hostname is accepted for any "
     "connection."),
    ("insecure_socket_factory",
     r"SSLCertificateSocketFactory\.getInsecure\s*\(",
     "High", "SSLCertificateSocketFactory.getInsecure() disables certificate checks",
     "getInsecure() returns a socket factory with every certificate and hostname check "
     "turned off; Android Lint flags it as SSLCertificateSocketFactoryGetInsecure."),
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
                    severity="Medium", vuln_class="NETWORK-05", file=rel, detector="network-config",
                    description='base-config trusts certificates with src="user", so anyone who '
                                "can install a CA on the device can intercept HTTPS. Getting a CA "
                                "installed is the attacker's first step, which is why this is not "
                                "graded as a trust-all TLS bypass.",
                    cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
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
            severity="Medium", vuln_class="NETWORK-05", file=rel, detector="network-config",
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


_INET_VAR_RE = re.compile(r"(?:java\.net\.)?InetAddress\s+([A-Za-z_$][\w$]*)\s*=")
_INET_EXPR = r"(?:java\.net\.)?InetAddress\.\w+\s*\([^)]*\)"


_PLAIN_SOCKET_RE = re.compile(r"new\s+(?:java\.net\.)?Socket\s*\(")


def _plain_sockets(text: str) -> List[int]:
    """
    Purpose:
        Find plain TCP sockets the app opens itself, in a file that never layers TLS over them.

    Parameters:
        text: The file's source.

    Returns:
        The 1-based lines of each new Socket(...).

    Implementation notes:
        A java.net.Socket carries whatever is written to it in the clear. Wrapping it in TLS is done with SSLSocketFactory.createSocket(socket, host, port, autoClose) or an SSLEngine, so a file that calls createSocket or names SSLEngine or SSLSocket is left alone rather than guessed at; ServerSocket and SSLSocket are not matched. A Ghera app reading its server's reply over a plain socket was reported only through the generic target-SDK cleartext note, and its agent read the file without remarking on it.
    """
    if "createSocket" in text or "SSLEngine" in text or "SSLSocket" in text:
        return []
    return [text[:m.start()].count("\n") + 1 for m in _PLAIN_SOCKET_RE.finditer(text)]


def _socket_by_address(text: str) -> List[int]:
    """
    Purpose:
        Find createSocket calls whose first argument is an InetAddress, in a file using SSLCertificateSocketFactory.

    Parameters:
        text: The file's source.

    Returns:
        The 1-based lines of those calls.

    Implementation notes:
        SSLCertificateSocketFactory checks the hostname only when it is given one; called with an InetAddress it has no name to check, so a certificate for any host is accepted (Android Lint: SSLCertificateSocketFactoryCreateSocket). The first argument counts when it is a variable declared as an InetAddress in the file or an InetAddress factory call. The file must name SSLCertificateSocketFactory, since a plain javax SSLSocketFactory takes an InetAddress too and the platform does not promise it a hostname check either way.
    """
    if "SSLCertificateSocketFactory" not in text:
        return []
    names = set(_INET_VAR_RE.findall(text))
    first = "|".join([re.escape(n) for n in sorted(names)] + [_INET_EXPR])
    call = re.compile(rf"\.createSocket\s*\(\s*(?:{first})\s*,")
    return [text[:m.start()].count("\n") + 1 for m in call.finditer(text)]


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
        Looks for the recognisable shapes: a trust manager whose check methods do nothing, a hostname verifier that always returns true, an SSL error handler that proceeds regardless, a plain TCP socket no TLS is layered over (_plain_sockets), and the two SSLCertificateSocketFactory uses Android Lint flags - getInsecure(), and a socket opened by InetAddress, which skips the hostname check. Ghera benchmarks plant both, and the scans reported only the other flaws in the same apps. Each rule names its fact in fact_key so deduplication keeps distinct flaws apart even a few lines from each other: getInsecure() on line 31 was folded into an always-true hostname verifier on line 38. The trust-all and empty-checkServerTrusted rules share one key, since they describe one TrustManager. Kotlin compiles both differently from Java, and a real trust-all factory written in Kotlin was missed for it: an empty check method still carries Intrinsics null checks on its parameters, and a hostname-verifier lambda becomes a static method with another name taking (String, SSLSession), which verify() merely delegates to. So a body of nothing but null checks counts as empty, and any boolean method taking an SSLSession that returns true counts as the verifier. These are reported at high severity without requiring a chain, because unlike a permissive configuration they are an active decision in the app's own code that defeats transport security wherever that code is used. Bundled libraries are skipped because the claim is about the app's own code: OkHttp ships a hostname verifier that returns true for its internal platform plumbing, which a real React Native scan reported as the app accepting every hostname, and the React Native and Flutter embeddings are framework code in every such app.
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
                and b"CertificatePinner" not in data and b"pinning" not in data.lower() \
                and b"Socket(" not in data:
            continue
        text = data.decode("utf-8", errors="ignore")

        for line in _plain_sockets(text)[:20]:
            out.append(SastFinding(
                title="Plain TCP socket carries data without TLS",
                severity="Medium", vuln_class="NETWORK-02", file=rel, line=line, detector="tls",
                confidence="MEDIUM",
                description="The app opens a java.net.Socket and nothing in this file wraps it in TLS, "
                            "so everything sent and received on it travels in the clear.",
                impact="Anyone on the network path can read the traffic and, with nothing "
                       "authenticating the server, answer in its place.",
                recommendation="Use an SSLSocket from SSLSocketFactory (or HTTPS) and verify the "
                               "server's certificate and hostname.",
                cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))

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
                    extra={"fact_key": _FACT_KEYS[rule_id]} if rule_id in _FACT_KEYS else {},
                    description=description,
                    impact="An attacker on the network path can present their own certificate "
                           "and read or modify traffic.",
                    recommendation="Remove the bypass and validate certificates normally; use "
                                   "pinning for sensitive endpoints.",
                    cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))

        for line in _socket_by_address(text)[:20]:
            out.append(SastFinding(
                title="TLS socket opened by IP address skips hostname check",
                severity="High", vuln_class="NETWORK-01", file=rel, line=line, detector="tls",
                confidence="MEDIUM", extra={"fact_key": "tls:socket-by-address"},
                description="createSocket() is given an InetAddress, so SSLCertificateSocketFactory has no "
                            "hostname to check the certificate against and accepts a valid certificate "
                            "for any host.",
                impact="An attacker on the network path with a certificate for any domain can "
                       "impersonate the server and read or modify the traffic.",
                recommendation="Open the socket by hostname, or verify the session's peer with "
                               "HttpsURLConnection.getDefaultHostnameVerifier() before use.",
                cwe="CWE-297", owasp_mobile="M5: Insecure Communication"))

    if not pinning_seen and out:
        verbose_print("SAST tls: bypasses found and no pinning implementation detected", verbose)
    verbose_print(f"SAST tls: {plural(len(out), 'finding')}; pinning indicators: "
                  f"{sorted(pinning_seen) or 'none'}", verbose)
    return out
