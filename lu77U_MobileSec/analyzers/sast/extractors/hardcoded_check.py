#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.hardcoded_check

Purpose:
    Find app Java that checks what the user typed against a value written into the code - a password, key or PIN that unlocks something locally.

Responsibilities:
    Read the app's own Java, find equals comparisons between a text field's contents and a string literal, and report each one at the comparison.

Dependencies:
    re, the app-Java helpers.

Implementation notes:
    The secret here is not a credential for a server, so the secret scanners - which look for key-shaped values - pass over a plain word such as a vendor key, and the agent tends to read past a one-line if. Matching the shape of the check instead is reliable: a field's getText().toString() compared with equals against a literal is the app deciding locally that this exact value is the secret. Literals shorter than six characters or containing spaces are left out, since those are labels and choices ("Yes", "Male") rather than secrets.

Security considerations:
    Reads untrusted decompiled text with bounded expressions; nothing is executed.
"""

import re
from typing import List

from .app_java import excerpt, iter_app_java, line_of
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MARKERS = (b"getText()",)
_INPUT = r"[\w.]*getText\(\)\s*\.\s*toString\(\)(?:\s*\.\s*trim\(\))?"
_LITERAL = r"\"([^\"\s\\]{6,64})\""
_CHECK_RES = (
    re.compile(_INPUT + r"\s*\.\s*equals\(\s*" + _LITERAL + r"\s*\)"),
    re.compile(_LITERAL + r"\s*\.\s*equals\(\s*" + _INPUT + r"\s*\)"),
)


def analyze_hardcoded_checks(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report user input compared against a value hardcoded in the app.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the result.

    Returns:
        The findings, one per file.

    Implementation notes:
        The literal itself is not repeated in the title, since a report is often shared further than the code; the description carries it so the owner can find the check.
    """
    out: List[SastFinding] = []
    for rel, text in iter_app_java(source_root, _MARKERS):
        for pattern in _CHECK_RES:
            match = pattern.search(text)
            if not match:
                continue
            line = line_of(text, match.start())
            out.append(SastFinding(
                title="User input checked against a hardcoded secret",
                severity="Medium", vuln_class="AUTH-04", file=rel, line=line, detector="hardcoded-check",
                confidence="MEDIUM", evidence=excerpt(text, line),
                description=(f"The app compares what the user typed with the literal \"{match.group(1)}\", so the "
                             "value that unlocks this screen ships inside the app."),
                impact="Anyone who decompiles the app reads the value and passes the check.",
                recommendation="Verify the value on a server, or derive a key from it, instead of comparing it to a constant.",
                cwe="CWE-798", owasp_mobile="M1: Improper Credential Usage"))
            break
    verbose_print(f"SAST hardcoded checks: {plural(len(out), 'finding')}", verbose)
    return out
