#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.signature_derived_key

Purpose:
    Find an app using its own APK signing certificate as key material for request signing or payload encryption, rather than as an integrity check.

Responsibilities:
    Recognise the API shape that reads the signing certificate at runtime, and flag it when the value also reaches a cryptographic or native call in the same file.

Dependencies:
    re only.

Implementation notes:
    Reading `signatures[0]` to *verify* the app has not been re-signed is normal and not a finding on its own -- most apps do this. What makes it a finding is the value also flowing into an HMAC, a cipher, a native method, or a request-signing helper: at that point the certificate, which anyone holding the APK can extract, is standing in for a secret. An attacker never needs to break the algorithm, only to read the same bytes an installer can already read. This class of bug is invisible to a normal security review because the code that uses the value and the code that reads it are often in different files, and each one looks unremarkable alone.

Security considerations:
    The value itself is never a secret -- it is a certificate shipped inside the APK -- so this finding is about a design mistake (using public material as if it were private), not about a leaked credential. The remediation is a server-issued secret or a properly provisioned key, not a way to keep this value hidden.
"""

import re
from pathlib import Path
from typing import List

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MAX_FILES = 60000

_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/")

_SIGNATURE_READ_RE = re.compile(
    r"getPackageInfo\([^)]*,\s*(?:64|PackageManager\.GET_SIGNATURES|GET_SIGNATURES)\)"
    r"|signatures\s*\[\s*0\s*\]"
    r"|toCharsString\s*\(\s*\)")

_CRYPTO_SINK_RE = re.compile(
    r"(?i)\bhmac|\bmac\.getinstance|\bcipher\.getinstance|\bmessagedigest\.getinstance|"
    r"\bsecretkeyspec\b|\bnative\s+[\w.\[\]<>]+\s+\w+\s*\(|\bmd5\b|\bsha[_-]?1\b|"
    r"\bsha[_-]?256\b|\bdes\b|\baes\b")


def analyze_signature_derived_key(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Find files that read the app's own signing certificate and also feed a value into a cryptographic or native routine.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads source files.

    Complexity:
        O(files) with two regex searches per candidate file.

    Implementation notes:
        Both patterns must appear in the *same file* to fire, which is a coarse proxy for "the same helper class" -- the one shape actually seen in the wild, where an app wraps a signing/encryption helper in one class that both reads the certificate and calls into HMAC/AES or a native method. This will miss a version split across two files and will not confirm the two values are actually the same variable; it is a lead for the agent to verify, not a proof, which is why confidence is MEDIUM rather than HIGH.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    out: List[SastFinding] = []
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
        if b"signatures" not in data and b"toCharsString" not in data \
                and b"GET_SIGNATURES" not in data:
            continue
        text = data.decode("utf-8", errors="ignore")

        sig_match = _SIGNATURE_READ_RE.search(text)
        if not sig_match:
            continue
        if not _CRYPTO_SINK_RE.search(text):
            continue

        line = text[:sig_match.start()].count("\n") + 1
        out.append(SastFinding(
            title="App's own signing certificate used as cryptographic key material",
            severity="High", vuln_class="CRYPTO-02", file=rel, line=line,
            detector="signature-derived-key", confidence="MEDIUM",
            description="This file reads the app's own signing certificate at runtime "
                        "(getPackageInfo(..., GET_SIGNATURES), signatures[0] or "
                        "toCharsString()) and also references a cryptographic primitive "
                        "or a native method in the same class, which is the shape of a "
                        "helper that feeds the certificate into request signing or "
                        "payload encryption as if it were a secret.",
            impact="The signing certificate ships inside the APK, so anyone who has the "
                   "app already has this value. If it is used as an HMAC or cipher key, "
                   "the resulting signature or ciphertext offers no protection an "
                   "attacker who extracted the app cannot reproduce.",
            recommendation="Verify whether the certificate feeds a keying operation "
                           "rather than only an integrity check (compare against a known "
                           "value). If it does, replace it with a server-issued secret "
                           "or a properly provisioned key that is not derivable from the "
                           "installed package.",
            cwe="CWE-321", owasp_mobile="M10: Insufficient Cryptography"))

    verbose_print(
        f"SAST signature-derived-key: {plural(len(out), 'finding')}", verbose)
    return out
