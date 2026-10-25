#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.crypto_misuse

Purpose:
    Find cryptography in the app's own Java that uses a key or IV fixed in the code, or derives a key from a password with too few iterations or a fixed salt.

Responsibilities:
    Match SecretKeySpec and IvParameterSpec built from a literal or a constant, and PBEKeySpec with a literal iteration count below the floor or a salt fixed in the app (a literal, a constant or a string resource, followed one call up when it is a parameter), and emit one finding per site.

Dependencies:
    re, the app-code walker.

Implementation notes:
    A key or IV is fixed when it is built from a string literal's bytes, an array literal, a zero-filled array, or a static final field initialised from one of those; following the constant matters because decompiled code usually names the key once and uses it everywhere. The weak-algorithm case (DES, ECB) is left to the Semgrep rule that already covers it. A key handed in from a variable the rule cannot resolve is not reported: the agent and the Frida hooks are how a derived key is judged, not a regular expression.

Security considerations:
    The value of a hardcoded key is not copied into the finding; the location is enough to act on and keeps a shared report from disclosing it.
"""

import hmac
import re
from typing import Dict, List

from .app_java import call_args, excerpt, iter_app_java, line_of
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

MIN_PBKDF2_ITERATIONS = 10000

_STRING_BYTES = r"\"[^\"\n]{1,200}\"\s*\.\s*getBytes\s*\([^)]{0,40}\)"
_NEW_ARRAY = r"new\s+byte\s*\[\s*\d+\s*\]|new\s+byte\s*\[\s*\]\s*\{[^}]{0,400}\}"
_SPEC = r"new\s+(?:javax\.crypto\.spec\.)?(SecretKeySpec|IvParameterSpec)\s*\(\s*"
_SPEC_LITERAL_RE = re.compile(_SPEC + "(?:" + _STRING_BYTES + "|" + _NEW_ARRAY + ")")
_SPEC_NAME_RE = re.compile(
    _SPEC + r"(?:[\w.]+\.)?([A-Za-z_]\w*)(?:\s*\.\s*getBytes\s*\([^)]{0,40}\))?\s*[,)]")
_LOCAL_LITERAL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*" + _STRING_BYTES)
_CONSTANT_RE = re.compile(
    r"\bstatic\s+(?:final\s+)?(?:byte\s*\[\s*\]|String)\s+([A-Za-z_]\w*)\s*=\s*"
    r"(?:\"[^\"\n]{1,200}\"|" + _NEW_ARRAY + r"|\{[^}]{0,400}\})")
_SIZED_ARRAY_RE = re.compile(r"=\s*new\s+byte\s*\[\s*\d+\s*\]\s*;")
_PBE_RE = re.compile(r"new\s+(?:javax\.crypto\.spec\.)?PBEKeySpec\s*\([^;]{0,300}?,\s*(\d{1,7})\s*(?:,\s*\d+\s*)?\)")

_PBE_OPEN_RE = re.compile(r"new\s+(?:javax\.crypto\.spec\.)?PBEKeySpec\s*\(")
_SIGNATURE_RE = re.compile(r"^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)*"
                           r"[\w.$<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$")
_RESOURCE_STRING_RE = re.compile(r"\bR\s*\.\s*string\s*\.|\bgetString\s*\(")

_TITLES = {
    "SecretKeySpec": ("Encryption key is hardcoded in the app", "High"),
    "IvParameterSpec": ("Cipher uses a fixed IV", "Medium"),
}


def _fixed_constants(text: str) -> Dict[str, int]:
    """
    Purpose:
        Find the names in a file whose value is a literal: static constants, and locals assigned a literal's bytes.

    Parameters:
        text: The file's text.

    Returns:
        Name to the line it is assigned on.

    Implementation notes:
        Locals count because Kotlin and R8 output usually hoists the literal into a local first -- `byte[] bytes2 = "...".getBytes(UTF_8)` and then `new IvParameterSpec(bytes2)` -- and a real app's fixed IV was missed until they did. A name reused in another method of the same file can be mistaken for the literal one; the agent reads the site before relying on it.
    """
    found = {match.group(1): line_of(text, match.start()) for match in _LOCAL_LITERAL_RE.finditer(text)}
    found.update({match.group(1): line_of(text, match.start()) for match in _CONSTANT_RE.finditer(text)
                  if not (_SIZED_ARRAY_RE.search(match.group(0) + ";") and _filled(text, match.group(1)))})
    return found


def _filled(text: str, name: str) -> bool:
    """
    Purpose:
        Tell whether a file writes into an array it declared empty.

    Parameters:
        text: The file's text.
        name: The array's name.

    Returns:
        True when the file fills it from a random source or a stream, copies into it, or assigns its elements.

    Implementation notes:
        `static final byte[] KEY = new byte[16]` is all zeros only until something writes into it, and the usual next line is `new SecureRandom().nextBytes(KEY)` in a static block: a per-install random key, not a fixed one. Ghera's fixed constant-key app does exactly that and was reported as having a hardcoded key. Only the declaring file is checked, which is where such an initialiser lives.
    """
    ref = r"(?:[\w$]+\.)*" + re.escape(name)
    writes = (r"\.\s*(?:nextBytes|read|readFully|get)\s*\(\s*" + ref + r"\s*[,)]",
              r"\barraycopy\s*\([^;]*?,[^;]*?,\s*" + ref + r"\s*,",
              r"(?<![\w$.])" + ref + r"\s*\[[^\]]+\]\s*=[^=]")
    return any(re.search(pattern, text) for pattern in writes)


def _spec_finding(rel: str, text: str, line: int, spec: str, via: str) -> SastFinding:
    """
    Purpose:
        Build the finding for a key or IV fixed in the code.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.
        line: The line of the construction.
        spec: SecretKeySpec or IvParameterSpec.
        via: How the value was found to be fixed, for the description.

    Returns:
        The finding.
    """
    title, severity = _TITLES[spec]
    if spec == "SecretKeySpec":
        description = (f"A SecretKeySpec is built from a value fixed in the code ({via}), so every "
                       "install shares one key that anyone with the APK can read out.")
        impact = "Anything the app encrypts with it can be decrypted, and forged, by anyone holding the APK."
        recommendation = ("Generate the key in the Android Keystore (KeyGenParameterSpec) so it never "
                          "exists outside secure hardware, or wrap a per-install key with one.")
        cwe = "CWE-321"
    else:
        description = (f"An IvParameterSpec is built from a value fixed in the code ({via}), so every "
                       "message encrypted under the same key uses the same IV.")
        impact = ("Equal plaintexts produce equal ciphertexts, and in CTR or GCM mode a reused IV "
                  "exposes the XOR of messages and lets an attacker forge them.")
        recommendation = "Generate a fresh random IV with SecureRandom for every encryption and store it beside the ciphertext."
        cwe = "CWE-329"
    return SastFinding(
        title=title, severity=severity, vuln_class="CRYPTO-02", file=rel, line=line,
        detector="crypto-misuse", confidence="MEDIUM", description=description, impact=impact,
        recommendation=recommendation, evidence=excerpt(text, line), cwe=cwe,
        owasp_mobile="M10: Insufficient Cryptography")


def _fixed_value(expr: str, constants: Dict[str, int]) -> str:
    """
    Purpose:
        Say how an expression's value is fixed in the app, if it is.

    Parameters:
        expr: The expression.
        constants: Names in the same file whose value is a literal.

    Returns:
        "a literal", "a string resource" or "the constant NAME"; empty when the value is not visibly fixed.
    """
    core = re.sub(r"\s*\.\s*(?:getBytes|toCharArray)\s*\([^)]*\)\s*$", "", expr.strip())
    if re.fullmatch(r"\"[^\"\n]*\"", core) or re.match(_NEW_ARRAY, core):
        return "a literal"
    if _RESOURCE_STRING_RE.search(core):
        return "a string resource"
    name = core.rsplit(".", 1)[-1]
    if name in constants:
        return f"the constant {name}"
    return ""


def _enclosing_signature(lines: List[str], line: int):
    """
    Purpose:
        Find the method a line sits in, with its parameter names.

    Parameters:
        lines: The file's lines.
        line: The 1-based line.

    Returns:
        (method name, parameter names), or None.
    """
    for index in range(min(line, len(lines)) - 1, -1, -1):
        match = _SIGNATURE_RE.match(lines[index])
        if match:
            params = [p.strip().split()[-1] for p in match.group(2).split(",") if p.strip()]
            return match.group(1), params
    return None


def _fixed_salt(source_root, text: str, match) -> str:
    """
    Purpose:
        Say where a PBEKeySpec's salt is fixed, looking one call up when it arrives as a parameter.

    Parameters:
        source_root: The analysis root, for finding call sites in other files.
        text: The file's text.
        match: The PBEKeySpec construction.

    Returns:
        A description of the fixed source, or an empty string.

    Implementation notes:
        Names are compared with hmac.compare_digest and every app file is read for call sites rather than filtered by the method name, because both come from the decompiled text and the project's CodeQL gate treats a short-circuiting comparison of such values as a timing risk. A salt is fixed when it is a literal, a constant or a string resource - the same for every install, so one precomputed dictionary serves every user. Helpers usually take the salt as a parameter, so a parameter is followed to the calls of its method in the app's own code, and the salt counts as fixed when any caller passes a fixed value; a Ghera app passing getString(R.string.salt) into its encrypt helper was found by one run's agent and missed by the next.
    """
    args = call_args(text, match.end())
    if len(args) < 2:
        return ""
    found = _fixed_value(args[1], _fixed_constants(text))
    if found:
        return found
    argument = re.sub(r"\s*\.\s*getBytes\s*\([^)]*\)\s*$", "", args[1].strip())
    signature = _enclosing_signature(text.splitlines(), line_of(text, match.start()))
    if not signature:
        return ""
    method, params = signature
    position = next((i for i, p in enumerate(params) if hmac.compare_digest(p, argument)), None)
    if position is None:
        return ""
    call_re = re.compile(rf"\b{re.escape(method)}\s*\(")
    for other_rel, other in iter_app_java(source_root, ()):
        lines = other.splitlines()
        for call in call_re.finditer(other):
            if _SIGNATURE_RE.match(lines[line_of(other, call.start()) - 1]):
                continue
            passed = call_args(other, call.end())
            if len(passed) > position:
                via = _fixed_value(passed[position], _fixed_constants(other))
                if via:
                    return f"{via}, passed in at {other_rel}:{line_of(other, call.start())}"
    return ""


def analyze_crypto_misuse(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report keys and IVs fixed in the app's code and weak password-based key derivation.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the outcome.

    Returns:
        The findings.

    Side effects:
        Reads the app's Java files.

    Implementation notes:
        One finding per construction site; a literal and a constant reference on the same line are reported once.
    """
    out: List[SastFinding] = []
    for rel, text in iter_app_java(source_root, (b"SecretKeySpec", b"IvParameterSpec", b"PBEKeySpec")):
        seen = set()
        for match in _SPEC_LITERAL_RE.finditer(text):
            line = line_of(text, match.start())
            seen.add((match.group(1), line))
            out.append(_spec_finding(rel, text, line, match.group(1), "a literal"))
        constants = _fixed_constants(text)
        for match in _SPEC_NAME_RE.finditer(text):
            spec, name = match.group(1), match.group(2)
            line = line_of(text, match.start())
            if (spec, line) in seen or name not in constants:
                continue
            seen.add((spec, line))
            out.append(_spec_finding(rel, text, line, spec,
                                     f"the constant {name}, declared on line {constants[name]}"))
        for match in _PBE_OPEN_RE.finditer(text):
            via = _fixed_salt(source_root, text, match)
            if not via:
                continue
            line = line_of(text, match.start())
            out.append(SastFinding(
                title="Password-based key derivation uses a fixed salt",
                severity="Medium", vuln_class="CRYPTO-02", file=rel, line=line,
                detector="crypto-misuse", confidence="MEDIUM", extra={"fact_key": "crypto:pbe-fixed-salt"},
                description=(f"A PBEKeySpec takes its salt from {via}, so every install derives keys with the "
                             "same salt."),
                impact=("One precomputed dictionary of password guesses serves every user, and equal passwords "
                        "give equal keys."),
                recommendation="Generate a random salt with SecureRandom for each password and store it beside the derived data.",
                evidence=excerpt(text, line), cwe="CWE-760", owasp_mobile="M10: Insufficient Cryptography"))
        for match in _PBE_RE.finditer(text):
            iterations = int(match.group(1))
            if iterations >= MIN_PBKDF2_ITERATIONS:
                continue
            line = line_of(text, match.start())
            out.append(SastFinding(
                title=f"Password-based key derivation uses only {iterations} iterations",
                severity="Medium", vuln_class="CRYPTO-01", file=rel, line=line,
                detector="crypto-misuse", confidence="MEDIUM", extra={"fact_key": "crypto:pbe-iterations"},
                description=(f"A PBEKeySpec derives a key with {iterations} iterations, far below what "
                             "makes guessing the password expensive."),
                impact="An attacker holding the ciphertext or the derived key tests password guesses quickly offline.",
                recommendation=("Use at least 600,000 iterations of PBKDF2-HMAC-SHA256, or a memory-hard "
                                "function such as Argon2 or scrypt, with a random per-user salt."),
                evidence=excerpt(text, line), cwe="CWE-916", owasp_mobile="M10: Insufficient Cryptography"))
    verbose_print(f"SAST crypto-misuse: {plural(len(out), 'finding')}", verbose)
    return out
