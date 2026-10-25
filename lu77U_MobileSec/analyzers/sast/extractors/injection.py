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
from typing import List, Optional, Tuple

from .credential_storage import call_arguments
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MAX_FILES = 60000
_MAX_PER_RULE = 30
_NOISE = ("/androidx/", "/android/support/", "/com/google/android/gms/",
          "/kotlin/", "/kotlinx/", "/okhttp3/", "/retrofit2/", "/io/reactivex/",
          "/com/facebook/react/", "/io/flutter/")

_SQL_RULES = (
    ("raw_query_concat",
     r'\.rawQuery\s*\(\s*(?:"[^"]*"|[A-Za-z_$][\w$.]*)\s*\+',
     "a rawQuery() call", "HIGH"),
    ("exec_sql_concat",
     r'\.execSQL\s*\(\s*(?:"[^"]*"|[A-Za-z_$][\w$.]*)\s*\+',
     "an execSQL() call", "HIGH"),
    ("query_selection_concat",
     r'(?i)\b(?:selection|where)\s*=\s*(?:"[^"]*"|[A-Za-z_$][\w$.]*(?:\s*\[[^\]]*\])?)\s*\+',
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

_CONSTANT_ITEM = r'(?:"(?:[^"\\]|\\.)*"|(?:[\w$]+\s*\.\s*)*[A-Z][A-Z0-9_]*)'
_CONSTANT_RHS_RE = re.compile(
    r'=\s*(?:"(?:[^"\\]|\\.)*"|\d+'
    r'|\{\s*(?:' + _CONSTANT_ITEM + r'(?:\s*,\s*' + _CONSTANT_ITEM + r')*(?:\s*,)?)?\s*\})\s*;')

_UI_INPUT_PREFIX = ".getText"
_SQL_WRITE_RE = re.compile(r"(?i)\bexecSQL\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b")
_SQL_READ_RE = re.compile(r"(?i)\brawQuery\s*\(|\bSELECT\b|\.query\s*\(")


def _taint_kind(fragment: str) -> str:
    """
    Purpose:
        Tell whether the input sources in a piece of code are only the app's own text fields.

    Parameters:
        fragment: The code to inspect.

    Returns:
        "ui" when every taint source is a text field's getText, "external" when any other source is present, "" when there is none.
    """
    sources = [m.group() for m in _TAINT_SOURCE_RE.finditer(fragment)]
    if not sources:
        return ""
    return "ui" if all(src.startswith(_UI_INPUT_PREFIX) for src in sources) else "external"

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
        Qualifiers and member access are stripped so the name can be searched for as an assignment target, which is how provenance is traced. A leading `this.` is skipped rather than kept: `this.value` is the field `value`, assigned from an Intent extra two methods away, and reducing it to `this` made every field operand untraceable.
    """
    match = re.match(r"(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)", expr)
    return match.group(1) if match else expr


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
        A taint source anywhere in the immediate window returns external immediately, since that is the decisive case and further tracing cannot make it safer. Operands fixed at compile time (_is_constant_operand) are set aside first: a constant column name beside an untraced parameter once made the whole statement "constant". Otherwise each remaining operand is traced to its assignments across the whole file, and the weakest safe verdict wins -- a value assigned from the schema catalogue outranks one that merely looks constant, because the catalogue evidence is stronger. The number of operands traced is capped, since a long concatenation would otherwise scan the file once per operand.
    """
    lines = text.splitlines()
    window = "\n".join(lines[max(0, line - 1):line + 2])
    exprs = list(dict.fromkeys(_OPERAND_RE.findall(window)))
    if not exprs:
        return "unknown"

    kind = _taint_kind(window)
    if kind:
        return _with_statement(kind, window)

    exprs = [expr for expr in exprs if not _is_constant_operand(text, expr)]
    if not exprs:
        return "constant"
    verdict = "unknown"
    for expr in exprs[:6]:
        name = _operand_bare_name(expr)
        for assign in re.finditer(
                r"\b" + re.escape(name) + r"\s*=(?!=)([^;\n]*)[;\n]", text):
            rhs = assign.group(1)
            kind = _taint_kind(rhs)
            if kind:
                return _with_statement(kind, window)
            if _CATALOGUE_RE.search(rhs):
                verdict = "catalogue"
            elif _CONSTANT_RHS_RE.search(assign.group(0)) and verdict == "unknown":
                verdict = "constant"
    return verdict


def _with_statement(kind: str, window: str) -> str:
    """
    Purpose:
        Refine a taint verdict by the statement it reaches.

    Parameters:
        kind: "ui" or "external".
        window: The lines around the statement.

    Returns:
        "ui-write" for the app's own text input reaching a statement that only writes, otherwise the kind unchanged.

    Implementation notes:
        Text typed into the app's own fields comes from the device's own user. Written into the app's own database, it lets them change only what they could change by using the app, so the injection grants no one anything; read back through a SELECT, it can still show rows the screen hides, so that case keeps its weight.
    """
    if kind == "ui" and _SQL_WRITE_RE.search(window) and not _SQL_READ_RE.search(window):
        return "ui-write"
    return kind


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
    if base in ("external", "ui", "ui-write", "catalogue", "constant"):
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


_TERM_RE = re.compile(
    r'"(?:[^"\\\n]|\\.)*"'
    r"|[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*(?:\s*\((?:[^()]|\([^()]*\))*\))?(?:\s*\[[^\]]*\])*"
    r"|\d+|\S")
_CONSTANT_NAME_RE = re.compile(r"(?:[\w$]+\s*\.\s*)*[A-Z][A-Z0-9_]*")
_POSITION_RANK = {"quoted_value": 2, "unknown": 1, "identifier": 0}


def _concat_operands(text: str, start: int) -> List[Tuple[str, str]]:
    """
    Purpose:
        List the operands of the string concatenation that begins at an offset, each with the literal just before it.

    Parameters:
        text: The file's source.
        start: Where the concatenation's first term begins.

    Returns:
        (preceding literal's text, operand) pairs, the literal empty when the operand does not follow one; empty when nothing could be read.

    Implementation notes:
        Reading stops at the end of the expression: a semicolon, a comma or closing parenthesis outside the terms, or two terms with no plus between them. Only 800 characters are read, which covers any real statement.
    """
    out: List[Tuple[str, str]] = []
    literal = ""
    expect = True
    for match in _TERM_RE.finditer(text, start, min(len(text), start + 800)):
        term = match.group(0)
        if term == "+":
            expect = True
            continue
        if not expect or term in (";", ",", ")"):
            break
        expect = False
        if term.startswith('"'):
            literal = term[1:-1]
        else:
            out.append((literal, term))
            literal = ""
    return out


def _is_constant_operand(text: str, expr: str, depth: int = 0) -> bool:
    """
    Purpose:
        Tell whether an operand is fixed at compile time.

    Parameters:
        text: The file's source.
        expr: The operand expression.
        depth: How many parameter hops have been followed to get here.

    Returns:
        True for an UPPER_CASE name, bare or qualified; for a local or field every assignment in the file gives a literal, an array of literals and constants, or a concatenation of those; and for a method parameter every call in the file passes such a value for.

    Implementation notes:
        `MyDatabase.Table1.TABLE_NAME` is declared in another class, so no assignment in this file says it is constant; Java's naming convention is the evidence there is. `projection[0]` from `projection = {Table.COL_USER, Table.COL_PASS}` is a column name the app chose. A parameter is followed to its callers in the same file, two hops at most: Ghera's fixed raw-query app builds its query from a `selection` parameter that the one caller fills with `projection[0] + " = ? AND " + projection[1] + " = ?"`, and the statement was reported. A constant cannot carry anything a caller sends, so it neither decides where an injected value lands nor makes a statement injectable.
    """
    if _CONSTANT_NAME_RE.fullmatch(expr.strip()):
        return True
    if "(" in expr:
        return False
    name = _operand_bare_name(expr)
    assignments = list(re.finditer(r"\b" + re.escape(name) + r"\s*=(?!=)([^;\n]*);", text))
    if assignments:
        return all(_constant_value(text, a.group(1), depth) for a in assignments)
    if depth >= 2:
        return False
    passed = _parameter_arguments(text, name)
    return bool(passed) and all(
        _constant_value(text, arg, depth + 1) for arg in passed)


def _constant_value(text: str, rhs: str, depth: int) -> bool:
    """
    Purpose:
        Tell whether an assigned or passed expression is fixed at compile time.

    Parameters:
        text: The file's source.
        rhs: The expression.
        depth: Parameter hops followed so far.

    Returns:
        True for a literal, an array of literals and constants, a constant name, or a concatenation of only those.
    """
    rhs = rhs.strip()
    if _CONSTANT_RHS_RE.search(f"= {rhs};"):
        return True
    if not rhs or "(" in rhs:
        return False
    if "+" not in rhs:
        return _is_constant_operand(text, rhs, depth)
    terms = _concat_operands(rhs, 0)
    return bool(terms) and all(_is_constant_operand(text, expr, depth) for _, expr in terms)


_CONTROL_WORDS = frozenset(("if", "for", "while", "switch", "catch", "synchronized", "return", "new"))


def _parameter_arguments(text: str, name: str) -> List[str]:
    """
    Purpose:
        Collect what the calls in a file pass for a method parameter.

    Parameters:
        text: The file's source.
        name: The parameter's name.

    Returns:
        One argument expression per call found; empty when the name is no parameter here or nothing calls the method.
    """
    for decl in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws[^{;]*)?\{", text):
        method = decl.group(1)
        if method in _CONTROL_WORDS:
            continue
        params = [p.strip() for p in decl.group(2).split(",") if p.strip()]
        index = next((i for i, p in enumerate(params)
                      if re.search(r"\s" + re.escape(name) + r"$", p)), None)
        if index is None:
            continue
        passed = []
        for call in re.finditer(r"(?<![\w$.])" + re.escape(method) + r"\s*\(", text):
            if call.start() == decl.start():
                continue
            args = _split_args(text[call.end():call.end() + 600])
            if len(args) > index:
                passed.append(args[index])
        return passed
    return []


def _split_args(text: str) -> List[str]:
    """
    Purpose:
        Split a call's argument text at its top-level commas.

    Parameters:
        text: The text after the opening parenthesis.

    Returns:
        The arguments, stripped, up to the call's closing parenthesis.
    """
    args, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                args.append(text[start:index].strip())
                return args
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:index].strip())
            start = index + 1
    return args


def _statement_position(text: str, start: int, matched_text: str) -> Optional[str]:
    """
    Purpose:
        Work out where the concatenation's variable values land, judged by the riskiest of them.

    Parameters:
        text: The file's source.
        start: Where the concatenation's first term begins.
        matched_text: The matched construct, the fallback when the terms cannot be read.

    Returns:
        "quoted_value", "unknown" or "identifier"; None when every operand is a constant, so nothing can be injected.

    Implementation notes:
        Judging by the first operand only read `"UPDATE " + Table.TABLE_NAME + " SET " + Table.COLUMN + " = '" + this.value + "'"` as a table name built from a variable, the least dangerous position, while the value an Intent supplied sat in quotes further along; one Ghera benchmark's injection was reported as an Informational note that way.
    """
    operands = _concat_operands(text, start)
    if not operands:
        return _operand_position(matched_text)
    live = [(literal, expr) for literal, expr in operands if not _is_constant_operand(text, expr)]
    if not live:
        return None
    return max((_literal_position(literal) for literal, _ in live), key=_POSITION_RANK.__getitem__)


def _literal_position(tail: str) -> str:
    """
    Purpose:
        Classify where a value lands from the literal text just before it.

    Parameters:
        tail: The literal's text.

    Returns:
        "identifier", "quoted_value" or "unknown".
    """
    tail = tail.rstrip()
    if re.search(r"(?i)\b(?:FROM|INTO|UPDATE|JOIN)\s*$", tail):
        return "identifier"
    if tail.endswith("'") or re.search(r"[=<>]\s*$", tail):
        return "quoted_value"
    return "unknown"


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
    return _literal_position(literal.group(1))


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
        The three inputs are ordered by how much they matter. A query inside an exported content provider is reachable by any app on the device, which makes it critical almost regardless of the rest. Externally-sourced operands come next; the app's own text fields count as external for a read, since the device's user can pull rows the screen hides, but a write fed only by them is Low, because its user can change nothing they could not change through the app. An identifier position caps the result, because the injection surface there is narrow. Numeric operands are informational -- the pattern is worth noting, the risk is not real. An untraceable operand lands in the middle rather than at either extreme, which is the honest answer: the analysis could not establish that it is safe or that it is not.
    """
    if classification == "numeric":
        return "Informational"
    if is_provider and classification != "identifier":
        return "Critical"
    if provenance == "ui-write":
        return "Low"
    if provenance in ("external", "ui") and classification != "identifier":
        return "High"
    if provenance in ("external", "ui") and classification == "identifier":
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
_PROMPT_SHOWN_RE = r"\bnew\s+(?:[\w.]+\.)?BiometricPrompt\s*\(|\.authenticate\s*\("

_CONSTANT_ITEM = r'(?:"(?:[^"\\]|\\.)*"|[A-Z][A-Z0-9_]*)'
_CONSTANT_ARGS_RE = re.compile(
    r"^\s*(?:" + _CONSTANT_ITEM + r"|new\s+(?:java\.lang\.)?String\s*\[\s*\]\s*\{\s*(?:"
    + _CONSTANT_ITEM + r"(?:\s*,\s*" + _CONSTANT_ITEM + r")*)?\s*,?\s*\})\s*$")
_EXEC_INPUT_RE = re.compile(
    r"getIntent\s*\(|getStringExtra|getExtras|getData\s*\(|getQueryParameter|getPathSegments"
    r"|@JavascriptInterface|shouldOverrideUrlLoading|onReceive\s*\(")
_EXTERNAL_CODE_RE = re.compile(
    r"getExternal(?:Storage|Files|Cache)\w*\(|\"/sdcard|openConnection\s*\(|HttpURLConnection"
    r"|\bURL\s*\(|DownloadManager")

_INTEGRITY_RE = re.compile(
    r"\.getCertificates\s*\(|\bSignature\s*\.\s*getInstance\s*\(|\bMessageDigest\s*\.\s*getInstance\s*\("
    r"|\.verify\s*\(\s*[A-Za-z_$][\w$]*\s*\)")

_EXEC_RULES = (
    ("runtime_exec",
     r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
     "Runtime.exec() invocation"),
    ("dexclassloader",
     r"\b(?:DexClassLoader|PathClassLoader)\s*\(",
     "Dynamic class loading"),
)


def _exec_grade(rule_id: str, text: str, arguments: str) -> Optional[Tuple[str, str, str]]:
    """
    Purpose:
        Grade one command-execution or class-loading call by what its input can be.

    Parameters:
        rule_id: Which rule matched.
        text: The file's text.
        arguments: The call's argument text.

    Returns:
        The severity, confidence and description to report, or None when the call cannot be influenced at all.

    Implementation notes:
        A command made only of string literals and constant names cannot be injected into, so it is not reported: root and emulator checks run "getprop" and "which su" this way, and a real scan listed them as command execution. A command built at runtime is Medium only when the file reads input another app or a web page controls (an Intent, a deep link, a JavaScript bridge, a broadcast); the SQL rule's wider source list is not used, because it counts getInputStream and a root check reads its own command's output that way. Otherwise it is a low-confidence lead, which the confidence gate turns into a note, because nothing shows where its input comes from. Class loading is Medium only when the file also touches external storage or a download, the two ways an attacker gets code into the loaded path, and nothing in the file checks a signature or digest; with such a check it is a low-confidence lead, since the check is there to verify, though not proven to run on the loaded file. Ghera's fixed dynamic-loading app verifies the JAR's signer before loading it and was reported at Medium. A loader reading the app's private directory is a lead.
    """
    if rule_id == "runtime_exec":
        if _CONSTANT_ARGS_RE.match(arguments):
            return None
        if _EXEC_INPUT_RE.search(text):
            return ("Medium", "MEDIUM",
                    "A command built at runtime is executed, in a file that reads input from "
                    "outside the app. Confirm the input cannot reach the command.")
        return ("Low", "LOW",
                "A command built at runtime is executed. Nothing in this file shows its input "
                "coming from outside the app; confirm where the command comes from.")
    if _EXTERNAL_CODE_RE.search(text) and _INTEGRITY_RE.search(text):
        return ("Low", "LOW",
                "Code is loaded at runtime in a file that also touches external storage or a "
                "download, and the same file checks a signature or digest. Confirm that check runs "
                "on the loaded file, and refuses it on failure, before it loads.")
    if _EXTERNAL_CODE_RE.search(text):
        return ("Medium", "MEDIUM",
                "Code is loaded at runtime in a file that also touches external storage or a "
                "download. Confirm the loaded file cannot be replaced by another app or the network.")
    return ("Low", "LOW",
            "Code is loaded at runtime. Nothing in this file shows the loaded file coming from "
            "external storage or the network; confirm it is the app's own private file.")

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
        Skipping suppresses findings, so the fragments are library paths an application would not use. A vulnerability inside a bundled library is real but is not the app owner's to fix, and reporting it at the same weight as their own code misdirects them. The React Native and Flutter embeddings are framework code present in every such app; React Native's own device-info helper runs getprop through Runtime.exec, which a real scan reported as the app's command execution.
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
        Files are pre-filtered by a byte-level marker scan before being decoded and analysed, which skips the great majority of a decompiled tree cheaply -- most files contain none of the constructs this extractor looks for. Noise paths are excluded, and each rule is budgeted. Provenance is resolved per finding, and the resulting verdict is attached so the gates can act on it later rather than re-deriving it. The biometric rule needs the file to show a prompt (construct one, or call authenticate) as well as name the API: an obfuscated copy of androidx's BiometricManager names it and checks availability, and was reported as the app trusting an unbound prompt.
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
                matched = match.group(0)
                opener = matched.find("(") if rule_id in ("raw_query_concat", "exec_sql_concat") else (
                    matched.find("=") if rule_id == "query_selection_concat" else -1)
                position = _statement_position(text, match.start() + opener + 1, matched)
                if position is None:
                    claimed.add(line)
                    continue
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                if per_rule[rule_id] > _MAX_PER_RULE:
                    break
                claimed.add(line)

                is_provider = _in_provider_class(provider_spans, match.start())
                provenance = _operand_provenance(text, line)
                classification = "numeric" if _all_operands_numeric(text, line) else position
                severity = _sql_severity(is_provider, provenance, classification)
                confidence = "LOW" if provenance == "unknown" else base_confidence

                origin = {
                    "external": " The concatenated value is traceable to input from "
                                "outside the app.",
                    "ui": " The concatenated value comes from the app's own text fields, so "
                          "the device's user can use it to read rows the screen does not show.",
                    "ui-write": " The concatenated value comes from the app's own text fields "
                                "and only reaches a statement that writes, so the device's user "
                                "can change nothing they could not change by using the app.",
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

        if (re.search(_BIOMETRIC_RE, text) and re.search(_PROMPT_SHOWN_RE, text)
                and not re.search(_CRYPTO_OBJECT_RE, text)):
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

        for rule_id, pattern, title in _EXEC_RULES:
            for match in re.finditer(pattern, text):
                grade = _exec_grade(rule_id, text, call_arguments(text, match.end()))
                if grade is None:
                    continue
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                if per_rule[rule_id] > _MAX_PER_RULE:
                    break
                severity, confidence, description = grade
                line = text[:match.start()].count("\n") + 1
                out.append(SastFinding(
                    title=f"{title} in {Path(rel).name}", severity=severity, vuln_class="CODE-02",
                    file=rel, line=line, detector="injection", confidence=confidence,
                    description=description,
                    recommendation="Avoid dynamic execution; if unavoidable, validate the input "
                                   "against a strict allowlist.",
                    evidence="\n".join(text.splitlines()[max(0, line - 2):line + 2]),
                    cwe="CWE-78"))

    verbose_print(f"SAST injection: {plural(len(out), 'finding')} across {plural(scanned, 'file')}", verbose)
    return out
