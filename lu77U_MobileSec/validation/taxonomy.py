#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.taxonomy

Purpose:
    The catalogue of vulnerability classes: one code per kind of finding, carrying the label shown in reports, the CWE and OWASP Mobile identifiers, whether the class can stand alone as a finding, and what proof it requires.

Responsibilities:
    Declare the classes and provide lookup by code, the standalone predicate, the proof requirement and the prose hint embedded in the AI schema.

Dependencies:
    dataclasses only.

Implementation notes:
    A single code drives three separate things: the CWE and OWASP identifiers that appear in the report, whether the finding survives gating on its own, and what evidence the AI is told to produce. Asking the model for one code rather than three related identifiers is both easier to get right and impossible to make self-contradictory. The standalone flag is the substantive judgement encoded here. Several classes -- missing pinning, cleartext capability, an unencrypted database, backup extractability -- describe a weakness that is only a finding when something else makes it reachable. Marking them non-standalone is what stops a report padding itself with configuration observations presented as vulnerabilities. The proof strings are written as instructions to the model and are deliberately specific about what would distinguish a real finding from a theoretical one.

Security considerations:
    This table decides what gets reported and how severe it looks. Marking a class standalone that should not be inflates reports with noise; the reverse silently suppresses real findings.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class VulnClass:
    """
    Purpose:
        One vulnerability class in the catalogue.

    Attributes:
        code: Stable identifier, used by the AI, by gating and in reports.
        label: Human-readable name shown in reports.
        group: MASVS control group this class belongs to, used for grouping.
        standalone: Whether a finding of this class is reportable on its own, or needs a chain partner to matter.
        proof: What evidence a finding of this class must carry, phrased as guidance to the model.
        cwe: CWE identifier, filled into findings automatically.
        owasp_mobile: OWASP Mobile Top 10 category, filled in automatically.

    Invariants:
        Frozen, and codes are unique across the catalogue.

    Thread-safety:
        Immutable and safe to share.
    """
    code: str
    label: str
    group: str
    standalone: bool = True
    proof: str = ""
    cwe: str = ""
    owasp_mobile: str = ""


def _c(code, label, group, standalone=True, proof="", cwe="", owasp_mobile=""):
    """
    Purpose:
        Shorthand constructor so the catalogue reads as a table rather than as pages of keyword arguments.

    Parameters:
        code: Class code.
        label: Human-readable name.
        group: MASVS control group.
        standalone: Whether the class is reportable on its own.
        proof: Required evidence, as guidance to the model.
        cwe: CWE identifier.
        owasp_mobile: OWASP Mobile category.

    Returns:
        The constructed class entry.

    Implementation notes:
        Exists purely for legibility of the catalogue below. The defaults mean an entry only states what is unusual about it.
    """
    return VulnClass(code=code, label=label, group=group, standalone=standalone,
                     proof=proof, cwe=cwe, owasp_mobile=owasp_mobile)


VULN_CLASSES: Tuple[VulnClass, ...] = (
    _c("PLATFORM-01", "Exported component without a permission guard", "PLATFORM",
       proof="The specific action or data an unprivileged caller obtains.",
       cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-02", "Deep link or Intent input reaching a sink", "PLATFORM",
       proof="The parameter name, and the sink the value reaches.",
       cwe="CWE-20", owasp_mobile="M4: Insufficient Input/Output Validation"),
    _c("PLATFORM-03", "Intent redirection", "PLATFORM",
       proof="The component the redirected Intent reaches, and what it holds.",
       cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-04", "WebView native bridge exposed to web content", "PLATFORM",
       proof="The bridge name and what its methods expose.",
       cwe="CWE-749", owasp_mobile="M4: Insufficient Input/Output Validation"),
    _c("PLATFORM-05", "WebView file access from web content", "PLATFORM",
       proof="Which local files become readable, and by what content.",
       cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-06", "WebView misconfiguration", "PLATFORM",
       proof="What the WebView actually loads.",
       cwe="CWE-16", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-07", "Unprotected broadcast", "PLATFORM",
       proof="The extra that is sensitive, named.",
       cwe="CWE-925", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-08", "Mutable PendingIntent with an implicit base Intent", "PLATFORM",
       proof="The app's targetSdkVersion, since the default flipped at 31.",
       cwe="CWE-927", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-09", "Task hijacking through taskAffinity", "PLATFORM",
       proof="The activity, its affinity value, and what it displays - a login "
             "screen matters, a settings page does not.",
       cwe="CWE-668", owasp_mobile="M8: Security Misconfiguration"),
    _c("PLATFORM-10", "Screen overlay and tapjacking exposure", "PLATFORM",
       standalone=False,
       proof="A sensitive action reachable by touch that has no "
             "filterTouchesWhenObscured or FLAG_SECURE.",
       cwe="CWE-1021", owasp_mobile="M4: Insufficient Input/Output Validation"),
    _c("PLATFORM-11", "FileProvider path traversal", "PLATFORM",
       proof="The unvalidated path segment, and what it reaches outside the "
             "declared root.",
       cwe="CWE-22", owasp_mobile="M4: Insufficient Input/Output Validation"),

    _c("STORAGE-01", "Credential in plain app storage", "STORAGE",
       proof="The specific value stored, and where.",
       cwe="CWE-312", owasp_mobile="M9: Insecure Data Storage"),
    _c("STORAGE-02", "Sensitive data on shared or external storage", "STORAGE",
       proof="The value, and that the path is world-readable.",
       cwe="CWE-922", owasp_mobile="M9: Insecure Data Storage"),
    _c("STORAGE-03", "Unencrypted local database", "STORAGE", standalone=False,
       proof="A route off the device - backup, external storage, an exported provider.",
       cwe="CWE-311", owasp_mobile="M9: Insecure Data Storage"),
    _c("STORAGE-04", "App data extractable by backup", "STORAGE", standalone=False,
       proof="A named credential inside the storage the backup would copy.",
       cwe="CWE-530", owasp_mobile="M9: Insecure Data Storage"),

    _c("NETWORK-01", "TLS certificate or hostname validation disabled", "NETWORK",
       proof="The trust-all implementation, and what the channel carries.",
       cwe="CWE-295", owasp_mobile="M5: Insecure Communication"),
    _c("NETWORK-02", "Cleartext traffic", "NETWORK", standalone=False,
       proof="A request that actually goes out over HTTP, and what is in it.",
       cwe="CWE-319", owasp_mobile="M5: Insecure Communication"),
    _c("NETWORK-03", "No certificate pinning", "NETWORK", standalone=False,
       proof="A demonstrated interception path plus the data on that channel.",
       cwe="CWE-300", owasp_mobile="M5: Insecure Communication"),
    _c("NETWORK-04", "Sensitive data in a URL", "NETWORK",
       proof="The parameter, and where the URL is logged or sent.",
       cwe="CWE-598", owasp_mobile="M5: Insecure Communication"),

    _c("CRYPTO-01", "Broken or deprecated cryptographic primitive", "CRYPTO",
       proof="The data it protects - a checksum use is not a finding.",
       cwe="CWE-327", owasp_mobile="M10: Insufficient Cryptography"),
    _c("CRYPTO-02", "Hardcoded key or IV", "CRYPTO",
       proof="The value, and what it decrypts.",
       cwe="CWE-321", owasp_mobile="M10: Insufficient Cryptography"),
    _c("CRYPTO-03", "Predictable randomness in a security context", "CRYPTO",
       proof="What the random value is used for.",
       cwe="CWE-330", owasp_mobile="M10: Insufficient Cryptography"),

    _c("SECRET-01", "Hardcoded credential or API key", "SECRET",
       proof="The service it authenticates to and the access that key type grants.",
       cwe="CWE-798", owasp_mobile="M1: Improper Credential Usage"),
    _c("SECRET-02", "Sensitive value written to the log", "SECRET",
       proof="The value, and that the call is reachable in a release build.",
       cwe="CWE-532", owasp_mobile="M9: Insecure Data Storage"),
    _c("SECRET-03", "Public identifier shipped in the app", "SECRET",
       standalone=False,
       proof="Which project or client the identifier names, and whether the "
             "provider-side restriction on it is in place.",
       cwe="CWE-200", owasp_mobile="M1: Improper Credential Usage"),

    _c("CODE-01", "SQL injection", "CODE",
       proof="The concatenation, and whether the query is reachable from outside.",
       cwe="CWE-89", owasp_mobile="M4: Insufficient Input/Output Validation"),
    _c("CODE-02", "Command execution or unsafe reflection", "CODE",
       proof="That the executed value can be influenced from outside the app.",
       cwe="CWE-78", owasp_mobile="M4: Insufficient Input/Output Validation"),
    _c("CODE-03", "Unsafe deserialization", "CODE",
       proof="That deserialized data crosses a trust boundary.",
       cwe="CWE-502", owasp_mobile="M4: Insufficient Input/Output Validation"),

    _c("SUPPLY-01", "Third-party SDK with a known vulnerability", "SUPPLY",
       proof="The exact version, and whether this app reaches the vulnerable path.",
       cwe="CWE-1104", owasp_mobile="M2: Inadequate Supply Chain Security"),
    _c("SUPPLY-02", "Debug or instrumentation SDK in a release build", "SUPPLY",
       proof="The SDK, and the surface it opens.",
       cwe="CWE-489", owasp_mobile="M2: Inadequate Supply Chain Security"),

    _c("AUTH-01", "Token or session handling flaw", "AUTH",
       proof="Where the token ends up and who can read it there.",
       cwe="CWE-287", owasp_mobile="M3: Insecure Authentication/Authorization"),
    _c("AUTH-02", "Biometric check not bound to a cryptographic operation", "AUTH",
       proof="That the protected work runs on the callback rather than behind a "
             "CryptoObject-wrapped Keystore key.",
       cwe="CWE-287", owasp_mobile="M3: Insecure Authentication/Authorization"),

    _c("BACKEND-01", "Misconfigured backend service", "BACKEND",
       proof="The service and endpoint. Access rules live on the server, so a "
             "static finding names what to check rather than asserting it is open.",
       cwe="CWE-200", owasp_mobile="M8: Security Misconfiguration"),

    _c("BUILD-01", "Debuggable release build", "BUILD", standalone=False,
       proof="Nothing rescues this - it is a release-process note.",
       cwe="CWE-489", owasp_mobile="M8: Security Misconfiguration"),
    _c("BUILD-02", "SDK level enables legacy platform behaviour", "BUILD",
       standalone=False,
       proof="The behaviour it re-enables, and a finding that depends on it.",
       cwe="CWE-1188", owasp_mobile="M8: Security Misconfiguration"),
    _c("BUILD-03", "Excessive or dangerous permissions", "BUILD", standalone=False,
       proof="A finding whose impact the permission widens.",
       cwe="CWE-250", owasp_mobile="M8: Security Misconfiguration"),
    _c("BUILD-04", "Missing hardening control", "BUILD", standalone=False,
       proof="Nothing rescues this - controls raise cost, they are not boundaries.",
       cwe="CWE-693", owasp_mobile="M7: Insufficient Binary Protections"),
)

BY_CODE: Dict[str, VulnClass] = {c.code: c for c in VULN_CLASSES}

ALL_CODES: Tuple[str, ...] = tuple(c.code for c in VULN_CLASSES)

BY_GROUP: Dict[str, Tuple[str, ...]] = {}
for _cls in VULN_CLASSES:
    BY_GROUP.setdefault(_cls.group, ())
    BY_GROUP[_cls.group] += (_cls.code,)


def describe(code: str) -> Optional[VulnClass]:
    """
    Purpose:
        Look up a vulnerability class by code.

    Parameters:
        code: A class code, in any case, with any surrounding whitespace.

    Returns:
        The class entry, or None when the code is unknown.

    Complexity:
        O(1).

    Implementation notes:
        The code is normalised before lookup because it arrives from model output, where case and stray whitespace are common. Normalising here means no caller has to.
    """
    return BY_CODE.get(str(code or "").strip().upper())


def is_standalone(code: str) -> bool:
    """
    Purpose:
        Report whether a finding of this class can be reported on its own.

    Parameters:
        code: A class code.

    Returns:
        The class's standalone flag, or True when the code is unknown.

    Implementation notes:
        An unknown code defaults to standalone -- the permissive direction. A model inventing or mistyping a code would otherwise have its finding silently suppressed by gating, which turns a classification slip into a missed vulnerability.
    """
    entry = describe(code)
    return True if entry is None else entry.standalone


def required_proof(code: str) -> str:
    """
    Purpose:
        Return the evidence requirement for a class, for embedding in prompts and gate messages.

    Parameters:
        code: A class code.

    Returns:
        The proof requirement, or an empty string when the code is unknown.
    """
    entry = describe(code)
    return entry.proof if entry else ""


def schema_hint() -> str:
    """
    Purpose:
        Render the whole catalogue as one line of prose, for embedding in the AI schema description when an enum cannot be used.

    Returns:
        Codes and labels grouped by MASVS control group.

    Complexity:
        O(n) in the number of classes.

    Implementation notes:
        Grouped rather than listed flat so the model can see the structure of the catalogue, which helps it pick a neighbouring code correctly rather than defaulting to the first plausible one. Labels are lowercased so the line reads as prose inside a schema description rather than as a list of headings.
    """
    groups = []
    for group, codes in BY_GROUP.items():
        listed = ", ".join(f"{code} {BY_CODE[code].label.lower()}" for code in codes)
        groups.append(f"{group}: {listed}")
    return "; ".join(groups)
