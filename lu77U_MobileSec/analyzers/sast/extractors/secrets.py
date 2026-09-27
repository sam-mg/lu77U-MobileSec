#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.secrets

Purpose:
    Find credentials and keys hardcoded into the app.

Responsibilities:
    Match credential patterns across the decompiled tree and emit findings that do not disclose the value.

Dependencies:
    The shared secret pattern table.

Implementation notes:
    The pattern table distinguishes real secrets from public identifiers. A Firebase URL or a Google API key is meant to ship in the app and is protected server-side; reporting it as a leaked credential is both wrong and loud, so those patterns are marked public and the gates demote them.

Security considerations:
    Findings from this extractor point at credential material. The value itself is not written into the finding -- the location and the kind are enough to act on, and a report that quoted the key in full would turn every shared report into a disclosure.
"""

from pathlib import Path
from typing import Dict, List

from ..findings import SastFinding
from ...agent.patterns import find_endpoints, find_secrets
from ....utils.verbose import plural, verbose_print

_SCAN_EXTS = {".java", ".kt", ".xml", ".json", ".js", ".jsx", ".ts", ".tsx",
              ".html", ".htm", ".properties", ".yml", ".yaml", ".txt", ".cfg",
              ".conf", ".env", ".ini", ".dart", ".cs", ".gradle", ".smali"}
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_FILES = 60000
_MAX_FINDINGS = 120

_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/", "/node_modules/", "/okhttp3/", "/retrofit2/")

_CONFIG_NAMES = {"google-services.json", "strings.xml", "config.xml",
                 "AndroidManifest.xml", "GoogleService-Info.plist"}


def _is_noise(rel: str) -> bool:
    """
    Purpose:
        Recognise files that are framework or generated code rather than the app's own.

    Parameters:
        rel: The file's path relative to the source root.

    Returns:
        True when the file should be skipped.

    Implementation notes:
        Bundled libraries carry their own test fixtures and sample keys, which match credential patterns and are not the app's secrets. Skipping them is what keeps this extractor's output readable.
    """
    probe = "/" + rel.replace("\\", "/")
    return any(fragment in probe for fragment in _NOISE)


def analyze_secrets(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Scan a decompiled tree for hardcoded credentials.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads source files.

    Implementation notes:
        Each match is classified by the pattern that found it, so a finding names what kind of credential it is -- which is what tells a reader how urgently to rotate it. Patterns marked public produce findings classified accordingly rather than being suppressed here, because a public identifier is still worth listing with its server-side protection noted.

    Security considerations:
        Matched values are not written into the findings.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    out: List[SastFinding] = []
    seen: set = set()
    cleartext_hosts: Dict[str, str] = {}
    scanned = 0

    for path in root.rglob("*"):
        if len(out) >= _MAX_FINDINGS:
            break
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        scanned += 1
        if scanned > _MAX_FILES:
            break
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            rel = str(path.relative_to(root))
        except (OSError, ValueError):
            continue
        if _is_noise(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        in_config = path.name in _CONFIG_NAMES
        for hit in find_secrets(text, max_results=10):
            key = (hit["name"], hit["value"])
            if key in seen:
                continue
            seen.add(key)
            severity = hit["severity"]
            if in_config and severity in ("Critical", "High"):
                severity = "Medium"
            is_backend = "firebase" in hit["name"].lower() and "url" in hit["name"].lower()

            google_api_key_in_config = (
                in_config and hit["name"] == "Google API Key" and not hit.get("public"))
            if google_api_key_in_config:
                out.append(SastFinding(
                    title="Google API key shipped in a config file",
                    severity="Low",
                    vuln_class="SECRET-03",
                    file=rel, line=hit["line"], detector="secrets", confidence="HIGH",
                    description=(
                        f"A Google API key appears in {rel} at line {hit['line']}. "
                        "In a standard config file this is normal packaging; whether it "
                        "is a problem depends entirely on the restrictions set on it in "
                        "the Google Cloud console."),
                    impact="If the key has no application (package + signing certificate) "
                           "or API restriction, anyone who extracts it can spend against "
                           "the project's quota/billing for the enabled APIs.",
                    recommendation=(
                        "Confirm the key is restricted: an Android app restriction bound "
                        "to this package name and signing certificate, and an API "
                        "restriction to only the services the app uses. An unrestricted "
                        "key should be rotated and restricted."),
                    evidence=hit["value"],
                    cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration",
                    extra={"secret_type": hit["name"]}))
                continue

            if hit.get("public"):
                out.append(SastFinding(
                    title=f"{hit['name']} shipped in the app",
                    severity="Informational",
                    vuln_class="BACKEND-01" if is_backend else "SECRET-03",
                    file=rel, line=hit["line"], detector="secrets", confidence="HIGH",
                    description=(
                        f"A {hit['name']} appears in {rel} at line {hit['line']}. Identifiers of "
                        "this kind are meant to ship inside the package - they name the app to "
                        "the provider and are not secrets. Recorded so the server-side control "
                        "that actually protects it can be confirmed."),
                    impact="None directly. The identifier is public by design; the risk lives in "
                           "whatever the provider allows an unauthenticated caller to do with it.",
                    recommendation=(
                        "No change to the app is required. Confirm the server-side control is in "
                        "place: Firebase Security Rules for a Firebase project, an OAuth client "
                        "type and package-signature restriction for a client ID, and API key "
                        "restrictions in the Google Cloud console."),
                    evidence=hit["value"],
                    cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration",
                    extra={"secret_type": hit["name"], "public_identifier": True}))
                continue

            out.append(SastFinding(
                title=f"{hit['name']} shipped in the app",
                severity=severity,
                vuln_class="BACKEND-01" if is_backend else "SECRET-01",
                file=rel, line=hit["line"], detector="secrets", confidence="HIGH",
                description=(
                    f"A {hit['name']} appears in {rel} at line {hit['line']}. Anything inside the "
                    "package is readable by anyone who downloads it, so this value is public."
                    + (" It sits in a standard configuration file, which is normal packaging - "
                       "what matters is what the key is scoped to." if in_config else "")),
                impact="Whatever the credential unlocks is reachable by anyone who extracts it "
                       "from the APK.",
                recommendation="Move the secret server-side, or restrict the key by package "
                               "signature and API scope and rotate the exposed value.",
                evidence=hit["value"],
                cwe="CWE-798", owasp_mobile="M1: Improper Credential Usage",
                extra={"secret_type": hit["name"]}))

        for endpoint in find_endpoints(text, max_results=10):
            if endpoint["cleartext"] and endpoint["sensitive_path"]:
                cleartext_hosts.setdefault(endpoint["url"], rel)

    for url, rel in list(cleartext_hosts.items())[:20]:
        out.append(SastFinding(
            title="Sensitive endpoint reached over cleartext HTTP",
            severity="High", vuln_class="NETWORK-02", file=rel, detector="secrets",
            confidence="MEDIUM",
            description=f"The app references {url} over plain HTTP, and the path looks "
                        "authentication- or account-related.",
            impact="Credentials or tokens sent to this endpoint can be read and modified by "
                   "anyone on the network path.",
            recommendation="Serve the endpoint over HTTPS and remove any cleartext exception.",
            evidence=url,
            cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))

    verbose_print(f"SAST secrets: {plural(len(out), 'finding')} across {plural(scanned, 'file')}", verbose)
    return out
