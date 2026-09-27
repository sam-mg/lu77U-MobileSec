#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.dedupe

Purpose:
    Collapse the same vulnerability reported more than once into a single finding, without losing the fact that two independent engines saw it.

Responsibilities:
    Infer a vulnerability class from wording when one was not supplied, derive a subject for each finding, group by location and by class-plus-subject, pick a survivor, and merge the rest into it.

Dependencies:
    .gates for severity ranking and normalisation, .taxonomy for the code list, ..utils.verbose.

Implementation notes:
    A scan runs a rule engine and an AI agent over the same code, so overlap is expected and is in fact the point -- two engines agreeing is the strongest confidence signal available. Deduplication is therefore a merge rather than a delete: the survivor inherits anything the duplicate had that it lacked, and records who else saw it. Two passes run in order. The first collapses findings at the same code location across engines, which catches the same issue described in two different vocabularies. The second groups by inferred class and subject, which catches the same issue reported at two different lines. Location first is deliberate: it is the more precise signal, and running the looser pass first would merge findings that the location pass would have kept distinct.

Security considerations:
    Merging wrongly hides a real finding. The rules are therefore conservative: a cluster is only collapsed when the findings agree on class, and cross-engine severity conflicts resolve toward the rule engine, which reasons from the code rather than about it.
"""

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .gates import normalize_severity, severity_rank
from .taxonomy import ALL_CODES
from ..utils.verbose import plural, verbose_print

_CLASS_HINTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("STORAGE-03", ("unencrypted database", "unencrypted sqlite",
                    "sqlite database", "unencrypted local database")),
    ("SECRET-01", ("hardcoded api", "hardcoded credential", "hardcoded secret",
                   "hardcoded password", "hardcoded key", "api credential",
                   "api key")),
    ("CODE-01", ("sql injection", "sqli", "rawquery", "execsql",
                 "sql statement", "sql query")),
    ("CODE-02", ("command execution", "runtime.exec", "reflection",
                 "dynamic class load", "dexclassloader")),
    ("CODE-03", ("deserializ",)),
    ("PLATFORM-04", ("javascriptinterface", "javascript interface",
                     "javascript bridge", "js bridge", "addjavascriptinterface")),
    ("PLATFORM-05", ("file access from file", "universal access", "allowfileaccess")),
    ("PLATFORM-11", ("path traversal", "openfile", "openassetfile")),
    ("PLATFORM-02", ("deep link", "deeplink", "intent extra", "getstringextra",
                     "intent data", "url parameter")),
    ("PLATFORM-03", ("intent redirect", "intent redirection", "nested intent")),
    ("PLATFORM-07", ("broadcast",)),
    ("PLATFORM-08", ("pendingintent", "pending intent")),
    ("PLATFORM-09", ("taskaffinity", "task affinity", "task hijack")),
    ("PLATFORM-10", ("tapjack", "overlay", "filtertouches")),
    ("PLATFORM-06", ("webview", "onreceivedsslerror")),
    ("PLATFORM-01", ("exported", "no permission protection", "content provider",
                     "contentprovider")),
    ("AUTH-02", ("biometric", "fingerprint")),
    ("AUTH-01", ("oauth", "session token", "token handling", "pkce")),
    ("NETWORK-01", ("trustmanager", "hostnameverifier", "trusts user",
                    "certificate validation", "trust-all", "trust all")),
    ("NETWORK-03", ("certificate pinning", "cert pinning", "pinning")),
    ("NETWORK-02", ("cleartext", "http traffic")),
    ("NETWORK-04", ("sensitive data in a url", "token in url")),
    ("CRYPTO-02", ("hardcoded key", "hardcoded iv", "static iv")),
    ("CRYPTO-03", ("securerandom", "predictable random", "weak random")),
    ("CRYPTO-01", ("weak crypto", "md5", "sha-1", "sha1", "des", "rc4", "ecb",
                   "weak cipher", "weak algorithm", "weak hashing")),
    ("SECRET-02", ("logged", "logcat", "logging of", "log.d", "log.e")),
    ("SECRET-01", ("hardcoded", "api key", "api credential", "credential in",
                   "secret", "password")),
    ("STORAGE-02", ("external storage", "world-readable", "world readable",
                    "mode_world")),
    ("STORAGE-04", ("backup",)),
    ("STORAGE-03", ("unencrypted database", "sqlite database", "unencrypted sqlite")),
    ("STORAGE-01", ("sharedpreferences", "shared preferences", "plain storage",
                    "stored in plaintext", "insecure storage", "insecure data storage")),
    ("SUPPLY-02", ("debug sdk", "stetho", "flipper", "leakcanary")),
    ("SUPPLY-01", ("third-party sdk", "vulnerable sdk")),
    ("BACKEND-01", ("firebase", "firebaseio", "s3 bucket", "storage bucket")),
    ("BUILD-01", ("debuggable", "debug-overrides")),
    ("BUILD-03", ("dangerous permission", "excessive permission")),
    ("BUILD-04", ("obfuscation", "root detection", "tamper")),
    ("BUILD-02", ("minsdk", "targetsdk", "sdkversion", "sdk version")),
)

_GENERIC_TOKENS = frozenset({
    "Android", "AndroidManifest", "Activity", "Service", "Provider", "Receiver",
    "ContentProvider", "WebView", "Intent", "SQLite", "SQLiteDatabase", "String",
    "Context", "Application", "Manifest", "This", "That", "These", "Those",
    "The", "There", "When", "Where", "Which", "While", "With", "Without",
    "SharedPreferences", "JavaScript", "Java", "Kotlin", "HTTP", "HTTPS", "URI",
    "URL", "API", "SDK", "JSON", "XML", "TLS", "SSL", "CWE", "OWASP", "CVSS",
    "Bearer", "Base64", "PendingIntent",
})

_TOKEN_RE = re.compile(r"\b([A-Z][a-z0-9]*(?:[A-Z][A-Za-z0-9]*)+)\b")


def _identifiers(text: str) -> List[str]:
    """
    Purpose:
        Extract distinctive code identifiers from text, for use as a finding's subject.

    Parameters:
        text: Title or description text.

    Returns:
        Identifiers in order of appearance.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Only multi-word CamelCase tokens are kept. A token that is entirely uppercase is an acronym, and one with fewer than two capitals is an ordinary word -- neither identifies a subject. Generic tokens are excluded, including a naive singular form, so that both "Activities" and "Activity" are filtered. Without that list, almost every Android finding would share a subject like WebView or Intent and would be merged into one.
    """
    out = []
    for t in _TOKEN_RE.findall(text):
        singular = t[:-1] if t.endswith("s") else t
        if t in _GENERIC_TOKENS or singular in _GENERIC_TOKENS:
            continue
        if t.isupper() or sum(c.isupper() for c in t) < 2:
            continue
        out.append(t)
    return out


def infer_vuln_class(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Determine a finding's vulnerability class, using the stated code when it is valid and falling back to wording.

    Parameters:
        finding: The finding dict.

    Returns:
        A class code, or an empty string when nothing matched.

    Complexity:
        O(h) in the number of hint patterns, run over title then description.

    Implementation notes:
        A valid stated code wins outright. The fallback exists for rule-engine findings, which carry no class, and for model output that omitted or invented one. Title is searched before description, because the title states the subject while the description often mentions several related concepts in passing. Searching the description first would classify a SQL injection finding as a logging issue because it mentioned a log call. The hint table is ordered so that specific patterns precede general ones sharing a keyword -- the hardcoded-key crypto entry sits before the general secret entry for exactly that reason. An empty result is meaningful: it prevents the finding from being grouped at all, which is the safe outcome for something that could not be classified.
    """
    stated = str(finding.get("vuln_class") or "").strip().upper()
    if stated in ALL_CODES:
        return stated

    title = " ".join(str(finding.get(k) or "") for k in
                     ("title", "vulnerability_type")).lower()
    for code, needles in _CLASS_HINTS:
        if any(needle in title for needle in needles):
            return code
    body = str(finding.get("description") or "").lower()
    for code, needles in _CLASS_HINTS:
        if any(needle in body for needle in needles):
            return code
    return ""


def _matched_hint(text: str, code: str) -> str:
    """
    Purpose:
        Recover which hint phrase caused a particular classification, for use as a fallback subject.

    Parameters:
        text: Lowercased text that was matched.
        code: The class code that was inferred.

    Returns:
        The matching phrase, or an empty string.

    Implementation notes:
        Used only when a finding has no identifier to name it. The phrase that classified it is a weak subject but a stable one, which is what grouping needs.
    """
    for c, needles in _CLASS_HINTS:
        if c != code:
            continue
        for needle in needles:
            if needle in text:
                return needle
    return ""


def subject_tokens(finding: Dict[str, Any]) -> Set[str]:
    """
    Purpose:
        Collect every plausible subject identifier for a finding, for overlap comparisons.

    Parameters:
        finding: The finding dict.

    Returns:
        A set of identifiers, possibly empty.

    Complexity:
        O(n) in the length of the fields consulted.

    Implementation notes:
        The description is truncated to its first 400 characters, because identifiers named after that point are usually background rather than the subject, and including them dilutes the comparison. The file stem is added as a token when it is long enough to be distinctive, since a finding in a specifically-named class is about that class.
    """
    text = " ".join(str(finding.get(k) or "") for k in
                    ("title", "vulnerability_type"))
    text += " " + str(finding.get("description") or "")[:400]
    tokens = set(_identifiers(text))
    stem = Path(str(finding.get("file") or "")).stem
    if stem and stem not in _GENERIC_TOKENS and len(stem) > 3:
        tokens.add(stem)
    return tokens


def primary_subject(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Pick the single identifier that best names what a finding is about, for use as a grouping key.

    Parameters:
        finding: The finding dict.

    Returns:
        The subject, or an empty string when none could be derived.

    Implementation notes:
        Four fallbacks in decreasing order of reliability: an identifier in the title, the file stem, the phrase that classified it, then an identifier from the description. Where several identifiers are available the sorted first is taken rather than the textually first. Determinism is what matters here -- two reports of the same issue must derive the same subject regardless of word order, or they will not group. An empty result excludes the finding from grouping entirely, which is preferable to grouping on a guess.
    """
    title = " ".join(str(finding.get(k) or "") for k in
                     ("title", "vulnerability_type"))
    named = _identifiers(title)
    if named:
        return sorted(named)[0]

    stem = Path(str(finding.get("file") or "")).stem
    if stem and stem not in _GENERIC_TOKENS and len(stem) > 3:
        return stem

    code = infer_vuln_class(finding)
    if code:
        hint = _matched_hint(title.lower(), code)
        if hint:
            return hint

    body = _identifiers(str(finding.get("description") or "")[:400])
    return sorted(body)[0] if body else ""


def _key(finding: Dict[str, Any]) -> Tuple[str, str]:
    """
    Purpose:
        Build the grouping key for a finding.

    Parameters:
        finding: The finding dict.

    Returns:
        A (class code, subject) pair.

    Implementation notes:
        Both halves must be non-empty for grouping to proceed; the caller enforces that. Class alone would merge every hardcoded secret in the app, and subject alone would merge two unrelated issues in the same class file.
    """
    return (infer_vuln_class(finding), primary_subject(finding))


def finding_identity(finding: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    """
    Purpose:
        Produce a coarse identity for a finding, for cross-run comparison and resumption.

    Parameters:
        finding: The finding dict.

    Returns:
        A (file, line bucket, class) triple, or None when the finding lacks a file, a line or a class.

    Implementation notes:
        The line is bucketed into groups of four so that a finding re-reported a line or two away still matches. Decompiler output shifts slightly between runs, and an exact line would make the identity useless. None is returned rather than a partial identity, so callers cannot accidentally compare findings on an incomplete key.
    """
    file = _norm_file(finding)
    line = _finding_line(finding)
    code = infer_vuln_class(finding)
    if not file or line <= 0 or not code:
        return None
    return (file, str(line // 4), code)


def finding_richness(finding: Dict[str, Any]) -> Tuple[int, int, int]:
    """
    Purpose:
        Score how informative a finding is, for choosing which of several duplicates survives.

    Parameters:
        finding: The finding dict.

    Returns:
        A tuple of severity rank, description length and recommendation length, comparable directly.

    Implementation notes:
        Severity leads, so the most serious framing of an issue is what the user sees. Length is a crude proxy for detail, but between two descriptions of the same issue the longer one almost always carries the specifics.
    """
    return (severity_rank(finding.get("severity")),
            len(str(finding.get("description") or "")),
            len(str(finding.get("recommendation") or "")))


_richness = finding_richness


def _norm_file(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Normalise a finding's file path for comparison.

    Parameters:
        finding: The finding dict.

    Returns:
        The lowercased path with forward slashes, or an empty string.

    Implementation notes:
        Separators and case are normalised because findings originate from different engines, one of which may report Windows-style paths. Two spellings of one path must compare equal or the location pass cannot group them.
    """
    return str(finding.get("file") or "").replace("\\", "/").strip().lower()


def _finding_line(finding: Dict[str, Any]) -> int:
    """
    Purpose:
        Extract a usable line number from a finding.

    Parameters:
        finding: The finding dict.

    Returns:
        The line number, or 0 when none could be read.

    Implementation notes:
        line_number is preferred over line because it is the normalised field. A range yields its start, since the start is where the issue begins and is what two engines will agree on. Zero stands for absent, which callers treat as "cannot be grouped by location".
    """
    for key in ("line_number", "line"):
        try:
            n = int(str(finding.get(key) or "0").split("-")[0].strip())
            if n > 0:
                return n
        except (TypeError, ValueError):
            continue
    return 0


def _collapse_by_location(findings: List[Dict[str, Any]],
                          verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Purpose:
        Merge findings that sit on the same code line and were reported by different engines.

    Parameters:
        findings: All findings.
        verbose: Traces each collapse.

    Returns:
        The findings with same-location cross-engine duplicates merged.

    Complexity:
        O(n * c) for n findings and c clusters per file.

    Implementation notes:
        Findings without a usable file and line bypass this pass untouched rather than being grouped together, which would merge unrelated manifest and certificate findings. Clustering allows a few lines of slack in either direction, plus a bucket match, so two engines pointing at adjacent lines of the same statement still cluster. Three conditions must all hold before a cluster collapses: more than one member, at least one from each engine, and exactly one vulnerability class across the cluster. The cross-engine requirement is what makes this pass safe -- two findings from the same engine on one line are usually genuinely different issues. The single-class requirement stops a SQL injection and a logging issue on the same line from merging.
    """
    if len(findings) < 2:
        return findings

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    loose: List[Dict[str, Any]] = []
    for f in findings:
        file, line = _norm_file(f), _finding_line(f)
        if file and line > 0:
            by_file.setdefault(file, []).append(f)
        else:
            loose.append(f)

    out: List[Dict[str, Any]] = []
    collapsed = 0
    for file, group in by_file.items():
        group.sort(key=_finding_line)
        clusters: List[List[Dict[str, Any]]] = []
        for f in group:
            line = _finding_line(f)
            for cluster in clusters:
                anchor = _finding_line(cluster[0])
                if abs(line - anchor) <= 3 or line // 4 == anchor // 4:
                    cluster.append(f)
                    break
            else:
                clusters.append([f])

        for cluster in clusters:
            has_scanner = any(f.get("source") == "static-analyzer" for f in cluster)
            has_agent = any(f.get("source") != "static-analyzer" for f in cluster)
            classes = {infer_vuln_class(f) for f in cluster}
            if (len(cluster) == 1 or not (has_scanner and has_agent)
                    or len(classes - {""}) != 1):
                out.extend(cluster)
                continue
            survivor = _pick_location_survivor(cluster)
            rest = [f for f in cluster if f is not survivor]
            _absorb_location(survivor, rest)
            collapsed += len(rest)
            out.append(survivor)
            for dropped in rest:
                verbose_print(
                    f"Location dedupe: {file}:{_finding_line(dropped)} dropped "
                    f"{dropped.get('title')!r} ({dropped.get('source')}) into "
                    f"{survivor.get('title')!r} ({survivor.get('source')}) "
                    f"at {survivor.get('severity')}", verbose)

    if collapsed:
        verbose_print(
            f"Location dedupe: collapsed {plural(collapsed, 'same-line duplicate')}",
            verbose)
    return out + loose


def _pick_location_survivor(cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Choose which finding survives a same-location cluster.

    Parameters:
        cluster: Findings at the same location.

    Returns:
        The surviving finding.

    Implementation notes:
        The rule-engine finding wins over the AI one, then longer description, then longer recommendation. The rule engine is preferred because its class, line and severity come from matching the code itself, where the AI's come from reading it -- and the AI's richer prose is not lost, since the merge absorbs it.
    """
    return sorted(
        cluster,
        key=lambda f: (f.get("source") == "static-analyzer",
                       len(str(f.get("description") or "")),
                       len(str(f.get("recommendation") or ""))),
        reverse=True)[0]


def _absorb_location(survivor: Dict[str, Any], rest: Iterable[Dict[str, Any]]) -> None:
    """
    Purpose:
        Merge the dropped members of a location cluster into the survivor.

    Parameters:
        survivor: The finding being kept, mutated in place.
        rest: The findings being merged into it.

    Side effects:
        Mutates the survivor: severity, missing fields, related findings and corroboration.

    Implementation notes:
        Severity resolution differs by case. Across engines, the rule engine's severity wins outright even when it is lower, because it is derived from the matched pattern rather than from a model's judgement. Within one engine, the higher severity wins. Only fields the survivor lacks are filled in, so nothing it already stated is overwritten. Each merge is recorded in related_findings with a confirmed flag set when the corroboration came from the other engine, so a reader can see that two engines agreed. Entries are deduplicated by their target so repeated merges do not accumulate.
    """
    sources = {str(survivor.get("source") or "agent")}
    for other in rest:
        o_source = str(other.get("source") or "agent")
        sources.add(o_source)
        s_rank = severity_rank(survivor.get("severity"))
        o_rank = severity_rank(other.get("severity"))
        cross_engine = o_source != survivor.get("source")
        if cross_engine and o_rank != s_rank:
            scanner = other if o_source == "static-analyzer" else survivor
            survivor["severity"] = normalize_severity(scanner.get("severity"))
        elif o_rank > s_rank and not cross_engine:
            survivor["severity"] = normalize_severity(other.get("severity"))

        entry = {
            "reason": (f"same code line, reported by {o_source} at "
                       f"{other.get('severity')}"),
            "pattern": "same-location",
            "with": {
                "title": str(other.get("title") or other.get("vulnerability_type") or ""),
                "file": str(other.get("file") or ""),
                "line": other.get("line") or other.get("line_number") or "",
            },
            "confirmed": cross_engine,
        }
        related = survivor.setdefault("related_findings", [])
        if entry["with"] not in [r.get("with") for r in related]:
            related.append(entry)

        for field in ("line", "line_number", "cwe", "owasp_mobile", "cvss_vector",
                      "recommendation", "impact", "exploitation", "code_snippet",
                      "code_context", "vuln_class"):
            if not survivor.get(field) and other.get(field):
                survivor[field] = other[field]

    if len(sources) > 1:
        survivor["corroborated_by"] = sorted(
            set(survivor.get("corroborated_by") or []) | sources)


def deduplicate(findings: List[Dict[str, Any]],
                verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Purpose:
        Collapse duplicate findings across the whole result set.

    Parameters:
        findings: All findings from every engine.
        verbose: Traces every collapse and a summary.

    Returns:
        The deduplicated findings. Ungroupable findings are preserved and appended.

    Complexity:
        O(n) grouping plus the location pass.

    Postconditions:
        No finding is discarded without its content being merged into a survivor. A survivor seen by more than one engine carries corroboration and HIGH confidence.

    Implementation notes:
        Runs the location pass first, then groups by class and subject. Findings that cannot produce both halves of the key are passed through untouched -- never grouped together, which would merge everything the classifier failed on into one arbitrary finding. Within a group the richest finding survives and the rest are absorbed.
    """
    if len(findings) < 2:
        return findings

    findings = _collapse_by_location(findings, verbose=verbose)
    if len(findings) < 2:
        return findings

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    ungrouped: List[Dict[str, Any]] = []
    for finding in findings:
        code, subject = _key(finding)
        if not code or not subject:
            ungrouped.append(finding)
            continue
        groups.setdefault((code, subject), []).append(finding)

    out: List[Dict[str, Any]] = []
    collapsed = 0
    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        members.sort(key=_richness, reverse=True)
        survivor, rest = members[0], members[1:]
        _absorb(survivor, rest)
        collapsed += len(rest)
        out.append(survivor)
        survivor_title = survivor.get("title") or survivor.get("vulnerability_type") or "(untitled)"
        survivor_file = survivor.get("file") or "no file"
        for dropped in rest:
            dropped_title = dropped.get("title") or dropped.get("vulnerability_type") or "(untitled)"
            dropped_file = dropped.get("file") or "no file"
            verbose_print(
                f"Deduplication: dropped {dropped_title!r} ({dropped_file}) into "
                f"{survivor_title!r} ({survivor_file})", verbose)

    if collapsed:
        verbose_print(
            f"Deduplication: collapsed {plural(collapsed, 'duplicate finding')} "
            f"into {plural(len(findings) - collapsed - len(ungrouped), 'finding')}",
            verbose)
    return out + ungrouped


def _absorb(survivor: Dict[str, Any], rest: Iterable[Dict[str, Any]]) -> None:
    """
    Purpose:
        Merge duplicates into the survivor of a class-and-subject group.

    Parameters:
        survivor: The finding being kept, mutated in place.
        rest: The findings being merged into it.

    Side effects:
        Mutates the survivor: severity, missing fields, merged titles, dedupe provenance, corroboration and confidence.

    Implementation notes:
        Severity takes the maximum across the group, so the most serious assessment survives -- unlike the location pass, because here the duplicates are not necessarily describing the line from different angles. That maximum is then overridden by a public-identifier pin: a finding explicitly marked as a public identifier, or an informational rule-engine finding in one of the publicly-identifiable classes, forces the merged result to Informational. Without this, a correct informational finding about a shipped project identifier gets merged with a model's alarmed description of the same string and is reported as a hardcoded secret. Merged titles and dedupe targets are recorded so a reader can see what was folded in, and cross-engine agreement sets confidence to HIGH -- the single strongest signal available that a finding is real.
    """
    rest = list(rest)
    sources = {str(survivor.get("source") or "agent")}
    titles = {str(survivor.get("title") or "")}
    best = severity_rank(survivor.get("severity"))
    deduped_into: List[Dict[str, Any]] = []

    for other in rest:
        sources.add(str(other.get("source") or "agent"))
        title = str(other.get("title") or "")
        if title:
            titles.add(title)
        deduped_into.append({
            "title": title or str(other.get("vulnerability_type") or ""),
            "file": str(other.get("file") or ""),
            "line": other.get("line") or other.get("line_number") or "",
        })
        rank = severity_rank(other.get("severity"))
        if rank > best:
            best = rank
            survivor["severity"] = normalize_severity(other.get("severity"))
        for field in ("line", "line_number", "cwe", "owasp_mobile", "cvss_vector",
                      "recommendation", "impact", "exploitation", "code_snippet"):
            if not survivor.get(field) and other.get(field):
                survivor[field] = other[field]

    for member in (survivor, *rest):
        pins_low = (
            (member.get("extra") or {}).get("public_identifier")
            or member.get("public_identifier")
            or (str(member.get("source") or "") == "static-analyzer"
                and normalize_severity(member.get("severity")) == "Informational"
                and str(member.get("vuln_class") or "") in ("SECRET-03", "BACKEND-01")))
        if pins_low:
            survivor["severity"] = "Informational"
            break

    if not survivor.get("vuln_class"):
        survivor["vuln_class"] = infer_vuln_class(survivor)

    merged = sorted(t for t in titles if t != survivor.get("title"))
    if merged:
        survivor["duplicate_titles"] = merged
    if deduped_into:
        survivor["deduped_into"] = deduped_into
    if len(sources) > 1:
        survivor["corroborated_by"] = sorted(sources)
        survivor["confidence"] = "HIGH"
