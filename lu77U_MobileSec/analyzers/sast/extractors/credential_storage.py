#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.credential_storage

Purpose:
    Find app Java that writes a credential to storage in plain text: SharedPreferences, a SQLite statement, a temporary file or external storage.

Responsibilities:
    Read the app's own Java, find the four write sinks, decide from the values written whether they carry a credential, and emit one finding per file and sink naming where the value ends up.

Dependencies:
    re, the app-Java helpers, the script rules' sensitive-word matcher.

Implementation notes:
    A Java benchmark app stores the same username and password four ways - preferences, SQLite, a temp file, external storage - and scans found the first and missed the rest: the SQLite insert was reported as SQL injection, which it also is, and the two file writes were never reported at all. Each sink is a separate exposure with a different reader, so each gets its own finding. Sensitivity is read from the expression being written - identifiers such as pwd, password, pin, token, secret, split on camel case so getText is not a token - and, for preferences, from the key as well. A file write is attributed to its destination by the file creation in the lines just above it: createTempFile is a temporary file in the app's cache, the external-storage getters are storage other apps can read.

Security considerations:
    Reads untrusted decompiled text with bounded expressions; nothing is executed.
"""

import re
from typing import List, Tuple

from .app_java import excerpt, iter_app_java, line_of
from .script_rules import sensitive_words
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MARKERS = (b"putString", b"execSQL", b".write(")
_PUT_RE = re.compile(r"\.putString\(\s*\"([^\"\n]{1,80})\"\s*,")
_PREFS_CONTEXT_RE = re.compile(r"\bSharedPreferences\b|\.edit\(\s*\)")
_SQL_RE = re.compile(r"\.execSQL\(")
_SQL_WRITE_RE = re.compile(r"^\s*\"\s*(?:INSERT|UPDATE|REPLACE)\b", re.IGNORECASE)
_WRITE_RE = re.compile(r"\b[A-Za-z_]\w*\.write\(")
_MAX_ARGS_CHARS = 800
_TEMP_RE = re.compile(r"\bcreateTempFile\(")
_EXTERNAL_RE = re.compile(
    r"\bgetExternal(?:StorageDirectory|FilesDir|CacheDir|StoragePublicDirectory)\(|\"/sdcard/|\"/storage/emulated/")
_LOOKBACK_LINES = 15
_STRING_LITERAL_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"")


def call_arguments(text: str, start: int) -> str:
    """
    Purpose:
        Read a call's argument text, from just after its opening parenthesis to the matching close.

    Parameters:
        text: The file's text.
        start: The offset just after the opening parenthesis.

    Returns:
        The argument text, or "" when no matching parenthesis is found within a bounded distance.

    Implementation notes:
        String literals are skipped while counting parentheses, because an SQL statement routinely holds both parentheses and the semicolon that a simpler pattern would stop at.
    """
    depth = 1
    quote = ""
    index = start
    end = min(len(text), start + _MAX_ARGS_CHARS)
    while index < end:
        char = text[index]
        if quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
        index += 1
    return ""


def _written_words(expression: str) -> List[str]:
    """
    Purpose:
        Name the credential-like identifiers in an expression being written.

    Parameters:
        expression: The argument text.

    Returns:
        The sensitive words among its identifiers.

    Implementation notes:
        String literals are removed first, so a label such as "Password:" written beside a harmless value does not make the value a credential; the identifiers carry the meaning.
    """
    return sensitive_words(_STRING_LITERAL_RE.sub(" ", expression))


def _finding(rel: str, text: str, line: int, sink: Tuple[str, str, str, str, str], words: List[str]) -> SastFinding:
    """
    Purpose:
        Build the finding for one write.

    Parameters:
        rel: The file's path.
        text: The file's text, for the excerpt.
        line: The write's line.
        sink: (title, vuln_class, cwe, where it ends up, who can read it).
        words: The sensitive words that marked the value.

    Returns:
        The finding.
    """
    title, vuln_class, cwe, where, readers = sink
    return SastFinding(
        title=title, severity="Medium", vuln_class=vuln_class, file=rel, line=line,
        detector="credential-storage", confidence="MEDIUM", evidence=excerpt(text, line),
        description=(f"The app writes a value built from {', '.join(words)} to {where} without encrypting it."),
        impact=f"{readers} read the credential in plain text.",
        recommendation=("Do not store the credential; keep a server-issued token instead, encrypted with a "
                        "key held in the Android Keystore."),
        cwe=cwe, owasp_mobile="M9: Insecure Data Storage")


_PREFS = ("Credential stored in SharedPreferences in plain text (putString)", "STORAGE-01", "CWE-312",
          "the app's SharedPreferences XML file",
          "Anyone with a backup of the app data, root on the device or a debuggable build")
_SQLITE = ("Credential stored in a SQLite database in plain text (execSQL)", "STORAGE-01", "CWE-312",
           "a SQLite database in the app's data directory",
           "Anyone with a backup of the app data, root on the device or a debuggable build")
_TEMP = ("Credential written to a temporary file (createTempFile)", "STORAGE-01", "CWE-377",
         "a temporary file that is left on disk",
         "Anyone with a backup of the app data, root on the device or a debuggable build")
_EXTERNAL = ("Credential written to external storage", "STORAGE-02", "CWE-922",
             "a file on external storage",
             "Other apps holding the storage permission and anyone who connects the device to a computer")


def analyze_credential_storage(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report credentials the app's Java writes to storage in plain text.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the result.

    Returns:
        The findings, at most one per file and sink.

    Implementation notes:
        A putString counts only in a file that uses SharedPreferences, and only when it writes a value: Bundle and Intent extras share the method name, and a real scan reported Google Sign-In's option bundle (a "forceCodeForRefreshToken" key set to null) as a stored credential. An SQL statement counts only when it writes rows (INSERT, UPDATE, REPLACE) and the values come from identifiers - a CREATE TABLE naming a password column stores nothing, and a literal seed row is the developer's own data rather than a user's credential. A file write whose destination cannot be seen in the lines above it is left alone rather than guessed at.
    """
    out: List[SastFinding] = []
    for rel, text in iter_app_java(source_root, _MARKERS):
        lines = text.splitlines()
        seen = set()
        uses_prefs = bool(_PREFS_CONTEXT_RE.search(text))
        for match in _PUT_RE.finditer(text):
            value = call_arguments(text, match.end()).strip()
            if not uses_prefs or value in ("", "null"):
                continue
            words = sensitive_words(match.group(1)) or _written_words(value)
            if words and "prefs" not in seen:
                seen.add("prefs")
                out.append(_finding(rel, text, line_of(text, match.start()), _PREFS, words))
        for match in _SQL_RE.finditer(text):
            statement = call_arguments(text, match.end())
            words = _written_words(statement)
            if words and _SQL_WRITE_RE.match(statement) and "sqlite" not in seen:
                seen.add("sqlite")
                out.append(_finding(rel, text, line_of(text, match.start()), _SQLITE, words))
        for match in _WRITE_RE.finditer(text):
            words = _written_words(call_arguments(text, match.end()))
            if not words:
                continue
            line = line_of(text, match.start())
            window = "\n".join(lines[max(0, line - 1 - _LOOKBACK_LINES):line])
            if _EXTERNAL_RE.search(window) and "external" not in seen:
                seen.add("external")
                out.append(_finding(rel, text, line, _EXTERNAL, words))
            elif _TEMP_RE.search(window) and "temp" not in seen:
                seen.add("temp")
                out.append(_finding(rel, text, line, _TEMP, words))
    verbose_print(f"SAST credential storage: {plural(len(out), 'finding')}", verbose)
    return out
