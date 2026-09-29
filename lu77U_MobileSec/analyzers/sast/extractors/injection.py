#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.injection

Purpose:
    Find injection and traversal issues in decompiled source: SQL built by concatenation, command execution and unsafe class loading, and content providers serving caller-supplied paths.

Responsibilities:
    Match the risky constructs, work out where the concatenated values come from, and grade the result accordingly.

Dependencies:
    re only.

Implementation notes:
    Provenance analysis is what separates this from a grep. String-built SQL is common and usually harmless -- the operand is a constant or a column name the app read from its own schema. Reporting every occurrence at a serious severity would bury the ones that matter, so the operand is traced back to its assignment and the severity follows what it found. Findings are budgeted per rule, because one bad pattern in a large app can match hundreds of times and a report cannot absorb that.

Security considerations:
    This is text analysis over decompiled code, not dataflow. It can miss a taint path that crosses a method boundary and can misjudge one it cannot trace, which is why an untraceable operand keeps a middling severity rather than being dismissed.
"""

import contextlib
import re
from pathlib import Path
from typing import List, Tuple

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MAX_FILES = 60000
_MAX_PER_RULE = 30
_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/", "/okhttp3/", "/retrofit2/", "/io/reactivex/")

_SQL_RULES = (
    ("raw_query_concat",
     r'\.rawQuery\s*\(\s*(?:"[^"]*"|[A-Za-z_$][\w$.]*)\s*\+',
     "a rawQuery() call", "HIGH"),
    ("exec_sql_concat",
     r'\.execSQL\s*\(\s*(?:"[^"]*"|[A-Za-z_$][\w$.]*)\s*\+',
     "an execSQL() call", "HIGH"),
    ("query_selection_concat",
     r'(?i)\b(?:selection|where)\s*=\s*"[^"]*"\s*\+',
     "a selection clause", "MEDIUM"),
    ("sql_keyword_concat",
     r'"[^"]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^"]*"\s*\+',
     "a SQL statement", "MEDIUM"),
)

_TAINT_SOURCE_RE = re.compile(
    r"getIntent\s*\(|getStringExtra|getIntExtra|getExtras|getSerializableExtra"
    r"|getParcelableExtra|getData\s*\(|getQueryParameter|getPathSegments"
    r"|\.getText\s*\(|@JavascriptInterface|shouldOverrideUrlLoading"
    r"|getInputStream|\.body\s*\(|response\."
    r"|cursor\.getString|\.getString\s*\(\s*\w*[Cc]olumn|getColumnIndex")

_CONSTANT_RHS_RE = re.compile(r'=\s*("(?:[^"\\]|\\.)*"|\d+)\s*;')

_CATALOGUE_RE = re.compile(
    r"\bfrom\s+sqlite_master\b|\bfrom\s+sqlite_temp_master\b|PRAGMA\s+table_info",
    re.IGNORECASE)

_OPERAND_RE = re.compile(
    r"\+\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*\s*(?:\([^()]*\))?)*)")

_NUMERIC_CALL_RE = re.compile(
    r"\.(?:currentTimeMillis|nanoTime|getTime|length|size|hashCode|ordinal)"
    r"\s*\(\s*\)\s*$")

_NUMERIC_TYPE_KEYWORDS = ("long", "int", "short", "byte", "char", "boolean",
                          "float", "double")

_TRAILING_LITERAL_RE = re.compile(r'"([^"]*)"\s*\+\s*$')


def _operand_bare_name(expr: str) -> str:
    """
    Purpose:
        Reduce an operand expression to the identifier it ultimately names.

    Parameters:
        expr: The operand expression.

    Returns:
        The bare identifier.

    Implementation notes:
        Qualifiers and member access are stripped so the name can be searched for as an assignment target, which is how provenance is traced.
    """
    match = re.match(r"[A-Za-z_$][\w$]*", expr)
    return match.group(0) if match else expr


def _operand_is_numeric(text: str, expr: str) -> bool:
    """
    Purpose:
        Decide whether an operand is a number rather than text.

    Parameters:
        text: The file's source.
        expr: The operand expression.

    Returns:
        True when the operand appears to be numeric.

    Implementation notes:
        A numeric operand cannot carry SQL syntax, so concatenating one is a code-quality issue rather than an injection. Recognising that is what keeps identifier-by-number queries out of the serious findings.
    """
    if _NUMERIC_CALL_RE.search(expr):
        return True
    name = _operand_bare_name(expr)
    type_re = re.compile(
        r"\b(?:" + "|".join(_NUMERIC_TYPE_KEYWORDS) + r")\s+"
        + re.escape(name) + r"\s*[=;)]")
    return bool(type_re.search(text))


def _operand_provenance(text: str, line: int) -> str:
    """
    Purpose:
        Work out where a concatenated operand came from: outside the app, the app's own schema, or a constant.

    Parameters:
        text: The file's source.
        line: The line of the concatenation.

    Returns:
        The provenance verdict.

    Complexity:
        O(n) in file length for each operand traced.

    Implementation notes:
        A taint source anywhere in the immediate window returns external immediately, since that is the decisive case and further tracing cannot make it safer. Otherwise each operand is traced to its assignments across the whole file, and the weakest safe verdict wins -- a value assigned from the schema catalogue outranks one that merely looks constant, because the catalogue evidence is stronger. The number of operands traced is capped, since a long concatenation would otherwise scan the file once per operand.
    """
    lines = text.splitlines()
    window = "\n".join(lines[max(0, line - 1):line + 2])
    exprs = list(dict.fromkeys(_OPERAND_RE.findall(window)))
    if not exprs:
        return "unknown"

    if _TAINT_SOURCE_RE.search(window):
        return "external"

    verdict = "unknown"
    for expr in exprs[:6]:
        name = _operand_bare_name(expr)
        for assign in re.finditer(
                r"\b" + re.escape(name) + r"\s*=(?!=)([^;\n]*)[;\n]", text):
            rhs = assign.group(1)
            if _TAINT_SOURCE_RE.search(rhs):
                return "external"
            if _CATALOGUE_RE.search(rhs):
                verdict = "catalogue"
            elif _CONSTANT_RHS_RE.search(assign.group(0)) and verdict == "unknown":
                verdict = "constant"
    return verdict


def resolve_sql_provenance(text: str, line: int, enum_lookup=None) -> str:
    """
    Purpose:
        Determine the provenance of a SQL operand, with a wider search and an enum check for the cases the immediate window cannot settle.

    Parameters:
        text: The file's source.
        line: The line of the concatenation.
        enum_lookup: Resolves whether a named type is an enum.

    Returns:
        The provenance verdict.

    Implementation notes:
        Runs the narrow analysis first and accepts a decisive answer. Only an unknown verdict triggers the more expensive work. A wider window is then searched for schema-catalogue evidence, because the assignment that establishes a column name is frequently further from the query than the immediate window reaches. Finally, an operand read from an enum accessor is treated as constant. Enum-backed column names are a common idiom, and without this check they read as untraceable and get reported at a middling severity -- which is a false positive with a plausible-looking justification. The lookup is caller-supplied and searches the decompiled tree, so any exception it raises is suppressed and counts as no evidence that the type is an enum: the operand keeps its earlier verdict and the remaining operands are still checked.
    """
    base = _operand_provenance(text, line)
    if base in ("external", "catalogue", "constant"):
        return base

    lines = text.splitlines()
    window = "\n".join(lines[max(0, line - 1):line + 2])

    wide = "\n".join(lines[max(0, line - 41):line + 40])
    if _CATALOGUE_RE.search(wide):
        return "catalogue"

    if enum_lookup is None:
        return base

    exprs = list(dict.fromkeys(_OPERAND_RE.findall(window)))
    for expr in exprs[:6]:
        name = _operand_bare_name(expr)
        for assign in re.finditer(
                r"\b" + re.escape(name) + r"\s*=(?!=)([^;\n]*)[;\n]", text):
            rhs = assign.group(1)
            m = re.search(r"\(?\s*\(?\s*([A-Za-z_$][\w$.]*)\s*\)?[^.;]*\.\s*get[A-Za-z0-9_]*\s*\(",
                          rhs)
            if not m:
                continue
            type_name = m.group(1).split(".")[-1]
            with contextlib.suppress(Exception):
                if enum_lookup(type_name):
                    return "constant"
    return base


def _all_operands_numeric(text: str, line: int) -> bool:
    """
    Purpose:
        Decide whether every operand in a concatenation is numeric.

    Parameters:
        text: The file's source.
        line: The line of the concatenation.

    Returns:
        True when all operands are numeric.

    Implementation notes:
        Requires all of them, since one text operand is enough to carry injected syntax. An empty operand list returns False rather than vacuously true, so a concatenation this code could not parse is not dismissed as safe.
    """
    lines = text.splitlines()
    window = "\n".join(lines[max(0, line - 1):line + 2])
    exprs = list(dict.fromkeys(_OPERAND_RE.findall(window)))
    if not exprs:
        return False
    return all(_operand_is_numeric(text, expr) for expr in exprs)


def _operand_position(matched_text: str) -> str:
    """
    Purpose:
        Work out where in the statement the concatenated value lands, which decides what an attacker could do with it.

    Parameters:
        matched_text: The matched construct.

    Returns:
        The classification.

    Implementation notes:
        Position matters more than presence. A value concatenated inside a quoted literal is a classic injection; one used as an identifier is far more constrained, because most engines will not accept arbitrary syntax there. The severity table reads this.
    """
    literal = _TRAILING_LITERAL_RE.search(matched_text)
    if literal is None:
        return "unknown"
    tail = literal.group(1).rstrip()
    if re.search(r"(?i)\b(?:FROM|INTO|UPDATE|JOIN)\s*$", tail):
        return "identifier"
    if tail.endswith("'") or re.search(r"[=<>]\s*$", tail):
        return "quoted_value"
    return "unknown"


_SQL_TEMPLATES = {
    "identifier": "Table or column name built from a variable in {sink}",
    "numeric": "Numeric value concatenated into {sink}",
    "quoted_value": "{sink_cap} built by string concatenation",
    "unknown": "{sink_cap} built by string concatenation",
}
_SQL_RECOMMENDATIONS = {
    "identifier": "A SQL identifier cannot be parameterised - `FROM ?` is not "
                 "valid SQL. Validate the name against a fixed allowlist of "
                 "the tables and columns this code is allowed to touch, and "
                 "reject anything else.",
    "numeric": "A numeric or boolean operand cannot carry SQL syntax, so this "
              "is a code-quality note rather than an injection risk. Bind it "
              "as a parameter anyway if the field could ever widen to a "
              "String.",
    "quoted_value": "Use parameter binding (selectionArgs / ? placeholders) "
                    "and never concatenate caller-supplied values into SQL.",
    "unknown": "Use parameter binding (selectionArgs / ? placeholders) and "
              "never concatenate caller-supplied values into SQL.",
}


def _cap(text: str) -> str:
    """
    Purpose:
        Bound a matched snippet before it goes into a finding.

    Parameters:
        text: The matched text.

    Returns:
        The bounded text.

    Implementation notes:
        A match can span a long statement, and an unbounded snippet would dominate the report entry it is meant to illustrate.
    """
    return text[0].upper() + text[1:] if text else text


def _sql_severity(is_provider: bool, provenance: str, classification: str) -> str:
    """
    Purpose:
        Grade a SQL concatenation from its reachability, its operand provenance and where the value lands.

    Parameters:
        is_provider: Whether the query is inside a content provider.
        provenance: Where the operand came from.
        classification: Where the value lands in the statement.

    Returns:
        The severity.

    Implementation notes:
        The three inputs are ordered by how much they matter. A query inside an exported content provider is reachable by any app on the device, which makes it critical almost regardless of the rest. Externally-sourced operands come next. An identifier position caps the result, because the injection surface there is narrow. Numeric operands are informational -- the pattern is worth noting, the risk is not real. An untraceable operand lands in the middle rather than at either extreme, which is the honest answer: the analysis could not establish that it is safe or that it is not.
    """
    if classification == "numeric":
        return "Informational"
    if is_provider and classification != "identifier":
        return "Critical"
    if provenance == "external" and classification != "identifier":
        return "High"
    if provenance == "external" and classification == "identifier":
        return "Medium"
    if classification == "identifier":
        return "Low"
    if provenance in ("constant", "catalogue"):
        return "Low"
    return "Medium"

_TRAVERSAL_RULES = (
    ("provider_open_file",
     r"public\s+ParcelFileDescriptor\s+openFile\s*\([^)]*\)[^{]*\{",
     "High", "ContentProvider.openFile() serves a caller-supplied path"),
    ("provider_open_asset",
     r"public\s+AssetFileDescriptor\s+openAssetFile\s*\([^)]*\)[^{]*\{",
     "High", "ContentProvider.openAssetFile() serves a caller-supplied path"),
)

_TRAVERSAL_GUARDS = ("getCanonicalPath", "getCanonicalFile", "toRealPath",
                     "normalize()", "startsWith(")

_BIOMETRIC_RE = r"\b(?:BiometricPrompt|FingerprintManager)\b"
_CRYPTO_OBJECT_RE = r"\bCryptoObject\b"

_EXEC_RULES = (
    ("runtime_exec",
     r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
     "Medium", "Runtime.exec() invocation"),
    ("dexclassloader",
     r"\b(?:DexClassLoader|PathClassLoader)\s*\(",
     "Medium", "Dynamic class loading"),
)

_PROVIDER_CLASS_RE = re.compile(
    r"\bclass\s+\w+[^{;]*\bextends\s+[\w.]*ContentProvider\b[^{;]*\{")


def _provider_class_spans(text: str) -> List[Tuple[int, int]]:
    """
    Purpose:
        Find the source ranges occupied by content provider classes.

    Parameters:
        text: The file's source.

    Returns:
        The start and end offsets of each provider class.

    Complexity:
        O(n) in file length.

    Implementation notes:
        Class bodies are found by matching braces from the declaration, because a file can contain several classes and only the provider's own queries are reachable by other apps. An unbalanced file yields a span running to the end rather than failing, so truncated decompiler output still produces a usable, if over-broad, answer.
    """
    spans: List[Tuple[int, int]] = []
    for match in _PROVIDER_CLASS_RE.finditer(text):
        brace_start = match.end() - 1
        depth = 0
        i = brace_start
        n = len(text)
        end = n
        while i < n:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        spans.append((match.start(), end))
    return spans


def _in_provider_class(spans: List[Tuple[int, int]], offset: int) -> bool:
    """
    Purpose:
        Decide whether a match sits inside a content provider class.

    Parameters:
        spans: The provider class ranges.
        offset: The match's offset.

    Returns:
        True when the match is inside one.

    Implementation notes:
        This is the reachability signal the severity table weighs most heavily: the same concatenation is a serious issue inside an exported provider and a minor one in a private helper.
    """
    return any(start <= offset <= end for start, end in spans)


_FILE_MARKERS = (
    b"rawQuery", b"execSQL", b"selection",
    b"Runtime", b"ClassLoader",
    b"openFile", b"openAssetFile",
    b"BiometricPrompt", b"FingerprintManager",
)


def _is_noise(rel: str) -> bool:
    """
    Purpose:
        Recognise files that are framework or generated code rather than the app's own.

    Parameters:
        rel: The file's path relative to the source root.

    Returns:
        True when the file should be skipped.

    Implementation notes:
        Matched against a normalised path with a leading separator, so a fragment matches a whole path component rather than part of a name.

    Security considerations:
        Skipping suppresses findings, so the fragments are library paths an application would not use. A vulnerability inside a bundled library is real but is not the app owner's to fix, and reporting it at the same weight as their own code misdirects them.
    """
    probe = "/" + rel.replace("\\", "/")
    return any(fragment in probe for fragment in _NOISE)


def _budget_ok(per_rule: dict, rule_id: str) -> bool:
    """
    Purpose:
        Limit how many findings one rule may contribute.

    Parameters:
        per_rule: Running counts per rule.
        rule_id: The rule being counted.

    Returns:
        True while the rule is within budget.

    Side effects:
        Increments the rule's count.

    Implementation notes:
        A single pattern in a large app can match hundreds of times, and the hundredth instance tells a reader nothing the first did not. The budget keeps the report readable at the cost of completeness for the noisiest rules.
    """
    per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
    return per_rule[rule_id] <= _MAX_PER_RULE


def analyze_injection(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Scan a decompiled tree for injection and traversal issues.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads source files.

    Implementation notes:
        Files are pre-filtered by a byte-level marker scan before being decoded and analysed, which skips the great majority of a decompiled tree cheaply -- most files contain none of the constructs this extractor looks for. Noise paths are excluded, and each rule is budgeted. Provenance is resolved per finding, and the resulting verdict is attached so the gates can act on it later rather than re-deriving it.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    out: List[SastFinding] = []
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
        if _is_noise(rel):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not any(marker in data for marker in _FILE_MARKERS):
            continue
        text = data.decode("utf-8", errors="ignore")
        provider_spans = _provider_class_spans(text)
        urimatcher_hint = "UriMatcher" in text and not provider_spans

        claimed: set = set()
        for rule_id, pattern, sink, base_confidence in _SQL_RULES:
            for match in re.finditer(pattern, text):
                line = text[:match.start()].count("\n") + 1
                if line in claimed:
                    continue
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                if per_rule[rule_id] > _MAX_PER_RULE:
                    break
                claimed.add(line)

                is_provider = _in_provider_class(provider_spans, match.start())
                provenance = _operand_provenance(text, line)
                classification = ("numeric" if _all_operands_numeric(text, line)
                                  else _operand_position(match.group(0)))
                severity = _sql_severity(is_provider, provenance, classification)
                confidence = "LOW" if provenance == "unknown" else base_confidence

                origin = {
                    "external": " The concatenated value is traceable to input from "
                                "outside the app.",
                    "constant": " The concatenated value appears to be fixed at compile "
                                "time, which limits it to a code-quality issue unless a "
                                "caller can reach it another way.",
                    "catalogue": " The concatenated value is a table/column name the app "
                                 "read out of its own SQLite schema (sqlite_master), so "
                                 "it is not attacker-controlled.",
                }.get(provenance, " The provenance of the concatenated value could not be "
                                  "determined from this file alone.")
                title = _SQL_TEMPLATES[classification].format(
                    sink=sink, sink_cap=_cap(sink))
                if is_provider:
                    title += " in a ContentProvider"
                description = (
                    "A SQL string is assembled by concatenation rather than passed as a "
                    "parameterised argument." + origin +
                    (" This class implements a ContentProvider, so the query may be "
                     "reachable from any app on the device." if is_provider else "") +
                    (" This file references UriMatcher, which is commonly used for "
                     "ContentProvider URI routing - confirm whether this class is "
                     "reachable from one." if urimatcher_hint else ""))
                out.append(SastFinding(
                    title=title,
                    severity=severity, vuln_class="CODE-01",
                    file=rel, line=line, detector="injection", confidence=confidence,
                    description=description,
                    impact="An attacker who controls the concatenated value can alter the query "
                           "and read or modify data beyond what the caller should see.",
                    recommendation=_SQL_RECOMMENDATIONS[classification],
                    evidence="\n".join(text.splitlines()[max(0, line - 2):line + 2]),
                    cwe="CWE-89", owasp_mobile="M4: Insufficient Input/Output Validation",
                    extra={"operand_provenance": provenance, "sql_sink": sink,
                          "sql_position": classification}))

        for rule_id, pattern, severity, title in _TRAVERSAL_RULES:
            for match in re.finditer(pattern, text):
                if not _in_provider_class(provider_spans, match.start()):
                    continue
                if not _budget_ok(per_rule, rule_id):
                    break
                body = text[match.end():match.end() + 1600]
                if any(guard in body for guard in _TRAVERSAL_GUARDS):
                    continue
                line = text[:match.start()].count("\n") + 1
                out.append(SastFinding(
                    title=title, severity=severity, vuln_class="PLATFORM-11",
                    file=rel, line=line, detector="injection", confidence="MEDIUM",
                    description="The method opens a file derived from the caller's URI "
                                "and no canonical-path check appears in its body.",
                    impact="A caller that walks the path with ../ reads any file the app "
                           "can read, including its databases and shared preferences.",
                    recommendation="Resolve the requested file, call getCanonicalPath(), "
                                   "and reject anything that does not start with the "
                                   "directory you intended to share.",
                    evidence="\n".join(text.splitlines()[max(0, line - 2):line + 3]),
                    cwe="CWE-22", owasp_mobile="M4: Insufficient Input/Output Validation"))

        if re.search(_BIOMETRIC_RE, text) and not re.search(_CRYPTO_OBJECT_RE, text):
            match = re.search(_BIOMETRIC_RE, text)
            line = text[:match.start()].count("\n") + 1
            out.append(SastFinding(
                title="Biometric prompt is not bound to a Keystore key",
                severity="Medium", vuln_class="AUTH-02",
                file=rel, line=line, detector="injection", confidence="MEDIUM",
                description="A biometric prompt is shown, but no CryptoObject appears in this "
                            "file, so the result is a boolean the app trusts rather than a key "
                            "it needs.",
                impact="Anyone who can hook the process - or patch the APK - returns success "
                       "from the callback and reaches the protected functionality without "
                       "authenticating.",
                recommendation="Generate a Keystore key with setUserAuthenticationRequired(true), "
                               "wrap its Cipher in a BiometricPrompt.CryptoObject, and do the "
                               "protected work with the Cipher the callback hands back.",
                evidence="\n".join(text.splitlines()[max(0, line - 2):line + 3]),
                cwe="CWE-287", owasp_mobile="M3: Insecure Authentication/Authorization"))

        for rule_id, pattern, severity, title in _EXEC_RULES:
            for match in re.finditer(pattern, text):
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                if per_rule[rule_id] > _MAX_PER_RULE:
                    break
                line = text[:match.start()].count("\n") + 1
                out.append(SastFinding(
                    title=title, severity=severity, vuln_class="CODE-02",
                    file=rel, line=line, detector="injection", confidence="MEDIUM",
                    description="Dynamic execution or class loading. Confirm the input cannot be "
                                "influenced by another app or by remote content.",
                    recommendation="Avoid dynamic execution; if unavoidable, validate the input "
                                   "against a strict allowlist.",
                    evidence="\n".join(text.splitlines()[max(0, line - 2):line + 2]),
                    cwe="CWE-78"))

    verbose_print(f"SAST injection: {plural(len(out), 'finding')} across {plural(scanned, 'file')}", verbose)
    return out
