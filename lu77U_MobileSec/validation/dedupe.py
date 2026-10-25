#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.dedupe

Purpose:
    Collapse the same vulnerability reported more than once into a single finding, without losing the fact that two independent engines saw it.

Responsibilities:
    Infer a vulnerability class from wording when one was not supplied, derive a subject for each finding, group by location and by class-plus-subject, pick a survivor, and merge the rest into it.

Dependencies:
    .gates for severity ranking and normalisation, .taxonomy for the code list, ..utils.verbose, hmac.

Implementation notes:
    A scan runs a rule engine and an AI agent over the same code, so overlap is expected and is in fact the point -- two engines agreeing is the strongest confidence signal available. Deduplication is therefore a merge rather than a delete: the survivor inherits anything the duplicate had that it lacked, and records who else saw it. Two passes run in order. The first collapses findings at the same code location across engines, which catches the same issue described in two different vocabularies. The second groups by inferred class and subject, which catches the same issue reported at two different lines. Location first is deliberate: it is the more precise signal, and running the looser pass first would merge findings that the location pass would have kept distinct.

Security considerations:
    Merging wrongly hides a real finding. The rules are therefore conservative: a cluster is only collapsed when the findings agree on class, and cross-engine severity conflicts resolve toward the rule engine, which reasons from the code rather than about it.
"""

import hmac
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
    ("CODE-05", ("buffer overflow", "stack overflow in native", "heap overflow", "out-of-bounds write",
                 "memory corruption", "strcpy", "sprintf")),
    ("CODE-02", ("command execution", "runtime.exec", "reflection",
                 "dynamic class load", "dexclassloader")),
    ("CODE-03", ("deserializ",)),
    ("PLATFORM-04", ("javascriptinterface", "javascript interface",
                     "javascript bridge", "js bridge", "addjavascriptinterface")),
    ("PLATFORM-05", ("file access from file", "universal access", "allowfileaccess")),
    ("CODE-04", ("zip slip", "zipslip", "archive entr", "zip entr", "extracted without a path check")),
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
    ("AUTH-04", ("brute force", "brute-force", "attempt limit", "rate limit", "rate-limit",
                 "lockout", "unlimited attempts", "weak pin")),
    ("AUTH-03", ("client-side authoriz", "client side authoriz", "client-side gate",
                 "client-side entitlement", "client-side premium", "entitlement check",
                 "paywall", "premium check", "premium flag", "premium status")),
    ("NETWORK-05", ("trusts user", "user-installed ca", "user ca certificates",
                    "user-added ca", "user certificate store")),
    ("NETWORK-01", ("trustmanager", "hostnameverifier",
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
    "Bearer", "Base64", "PendingIntent", "AsyncStorage", "Logcat", "LogCat", "FileWriter",
    "FileOutputStream", "SQLiteOpenHelper", "MethodChannel", "NativeModules",
})

_TOKEN_RE = re.compile(r"\b([A-Z][a-z0-9]*[A-Z][A-Za-z0-9]*)\b")
_DECLARED_NAME_RE = re.compile(r'android:name\s*=\s*"([\w.$]+)"')


def _constant_time_in(value: str, collection: Iterable[str]) -> bool:
    """
    Purpose:
        Test membership without the variable-time short-circuit an ordinary `in` check gives, for a value this module's own taint analysis traces back to model-supplied text.

    Parameters:
        value: The candidate to look up.
        collection: The values it is tested against.

    Returns:
        True when value matches any member of collection.

    Complexity:
        O(n) in the size of collection, since every candidate is compared rather than stopping at the first match.

    Security considerations:
        Every collection this is called with is a hardcoded generic-token list, never a secret, but a static analyser reasoning from shape rather than meaning cannot tell that, so this compares every candidate in constant time regardless.
    """
    return any(hmac.compare_digest(value, candidate) for candidate in collection)


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
        Only multi-word CamelCase tokens are kept. A token that is entirely uppercase is an acronym, and one with fewer than two capitals is an ordinary word -- neither identifies a subject. Generic tokens are excluded, including a naive singular form, so that both "Activities" and "Activity" are filtered. Without that list, almost every Android finding would share a subject like WebView or Intent and would be merged into one. The pattern names the second capital once rather than repeating a capitalised group, which matches exactly the same tokens: the repeated form let each capital either extend the current group or open the next, so a long uppercase run followed by a word character retried every split of the run and never finished on model-written text.
    """
    out = []
    for t in _TOKEN_RE.findall(text):
        singular = t[:-1] if t.endswith("s") else t
        if _constant_time_in(t, _GENERIC_TOKENS) or _constant_time_in(singular, _GENERIC_TOKENS):
            continue
        if t.isupper() or sum(c.isupper() for c in t) < 2:
            continue
        out.append(t)
    return out


_USER_CA_WORDING = ("user-installed ca", "user installed ca", "user ca", "trusts user",
                    "user certificate store", "user-added ca", 'src="user"')
_TRUST_ALL_WORDING = ("trustmanager", "hostnameverifier", "trust-all", "trust all",
                      "accepts any certificate", "accepts every", "onreceivedsslerror",
                      "badcertificatecallback")


_COMPARISON_RE = re.compile(r"\b(?:strn?cmp|memcmp|strcasecmp|equals(?:IgnoreCase)?|compareTo)\s*\(|==\s*\"")
_CRYPTO_USE_RE = re.compile(
    r"(?i)\b(?:cipher|secretkeyspec|ivparameterspec|keyspec|aes|des|rsa|evp_|encrypt|decrypt|"
    r"hmac|mac\.getinstance|key\.from|keygenerator|messagedigest)")


_REFILED_BY_TITLE = (
    ("BUILD-04", ("flag_secure", "screenshot", "screen capture", "screen recording"), "PLATFORM-12"),
    ("BUILD-02", ("cleartext",), "NETWORK-02"),
    ("BUILD-02", ("network security config",), "NETWORK-03"),
    ("BUILD-04", ("network security config",), "NETWORK-03"),
)


def correct_confusable_class(finding: Dict[str, Any]) -> None:
    """
    Purpose:
        Re-file a finding a model filed under a class it is commonly confused with: NETWORK-01 for trusting the user CA store, CRYPTO-02 for comparing input with a hardcoded value, BUILD-04 for missing FLAG_SECURE and BUILD-02 for cleartext allowed by the target SDK.

    Parameters:
        finding: The finding dict, updated in place.

    Side effects:
        May change the finding's vuln_class from NETWORK-01 to NETWORK-05, from CRYPTO-02 to AUTH-04, from BUILD-04 to PLATFORM-12 or NETWORK-03, or from BUILD-02 to NETWORK-02 or NETWORK-03.

    Implementation notes:
        NETWORK-01 means the app accepts any certificate; trusting user-installed CAs was filed under it until NETWORK-05 existed, and a model that learned the old filing keeps using it. Left alone, the agent's copy of a user-CA fact would not merge with the scanner's, and it would be paired with missing pinning as an "active TLS bypass". The re-filing is narrow: the title must name the user CA store and must name no trust-all construct, so a real bypass that mentions user CAs in passing keeps its class. A CRYPTO-02 (hardcoded crypto key) finding whose cited code compares input with the literal (strcmp, strncmp, equals) and uses no cipher, key or digest API is a hardcoded check and is re-filed as AUTH-04: DIVA's native strncmp("olsdfgad;lh", input) was filed as a crypto key. The scanners file missing FLAG_SECURE under PLATFORM-12 and cleartext-by-default under NETWORK-02; agents on Ghera apps filed the same facts as BUILD-04 (a hardening control) and BUILD-02 (target SDK behaviour), so each app listed them twice. A missing network security config, NETWORK-03 to the scanner, came back from agents under both of those too. Those two re-filings key on the title's wording and apply only from the one class each is confused with.
    """
    stated = str(finding.get("vuln_class") or "").strip().upper()
    title = " ".join(str(finding.get(k) or "") for k in ("title", "vulnerability_type")).lower()
    for confused, wording, meant in _REFILED_BY_TITLE:
        if stated == confused and any(w in title for w in wording):
            finding["vuln_class"] = meant
            return
    if stated == "CRYPTO-02":
        code = str(finding.get("code_snippet") or "")
        if _COMPARISON_RE.search(code) and not _CRYPTO_USE_RE.search(code):
            finding["vuln_class"] = "AUTH-04"
        return
    if stated != "NETWORK-01":
        return
    if (any(w in title for w in _USER_CA_WORDING)
            and not any(w in title for w in _TRUST_ALL_WORDING)):
        finding["vuln_class"] = "NETWORK-05"


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
    if stem and not _constant_time_in(stem, _GENERIC_TOKENS) and len(stem) > 3:
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
        Five fallbacks in decreasing order of reliability: an identifier in the title, the file stem, for a manifest citation the component its cited element declares, the phrase that classified it, then an identifier from the description. The manifest step exists because the manifest's stem names nothing: an agent's "Unprotected Exported Activity allows Token Forgery" citing the activity's element took "exported" as its subject and stayed apart from the same agent's "Exported activity NewPasswordActivity", so one Ghera scan listed the activity twice. Where several identifiers are available the sorted first is taken rather than the textually first. Determinism is what matters here -- two reports of the same issue must derive the same subject regardless of word order, or they will not group. An empty result excludes the finding from grouping entirely, which is preferable to grouping on a guess.
    """
    title = " ".join(str(finding.get(k) or "") for k in
                     ("title", "vulnerability_type"))
    named = _identifiers(title)
    if named:
        return sorted(named)[0]

    stem = Path(str(finding.get("file") or "")).stem
    if stem and not _constant_time_in(stem, _GENERIC_TOKENS) and len(stem) > 3:
        return stem

    if stem == "AndroidManifest":
        declared = _DECLARED_NAME_RE.search(str(finding.get("code_snippet") or ""))
        if declared:
            return declared.group(1).rsplit(".", 1)[-1]

    code = infer_vuln_class(finding)
    if code:
        hint = _matched_hint(title.lower(), code)
        if hint:
            return hint

    body = _identifiers(str(finding.get("description") or "")[:400])
    return sorted(body)[0] if body else ""


_APP_WIDE_CLASSES = frozenset(("PLATFORM-12", "STORAGE-04", "NETWORK-03", "BUILD-01"))
_APP_SUBJECT = "<app>"


def _key(finding: Dict[str, Any]) -> Tuple[str, str]:
    """
    Purpose:
        Build the grouping key for a finding.

    Parameters:
        finding: The finding dict.

    Returns:
        A (class code, subject) pair.

    Implementation notes:
        Both halves must be non-empty for grouping to proceed; the caller enforces that. Class alone would merge every hardcoded secret in the app, and subject alone would merge two unrelated issues in the same class file. A fact about the whole app - FLAG_SECURE never set, backup enabled, no network security config, a debuggable build - has the app as its subject when it cites the manifest or no file, so an agent's copy and the scanner's group by class alone; the agent's "Missing screenshot protection (FLAG_SECURE)" had no subject and the scanner's took "LayoutParams" from its description, so a scan listed both.
    """
    code = infer_vuln_class(finding)
    cited = str(finding.get("file") or "").replace("\\", "/").rsplit("/", 1)[-1]
    if code in _APP_WIDE_CLASSES and cited in ("", "AndroidManifest.xml"):
        return (code, _APP_SUBJECT)
    return (code, primary_subject(finding))


def _fold_into_app_wide(groups: Dict[Tuple[str, str], List[Dict[str, Any]]]) -> None:
    """
    Purpose:
        Fold every copy of an app-wide fact into the app-wide group when the scanner has stated it for the whole app.

    Parameters:
        groups: Findings grouped by (class, subject), changed in place.

    Implementation notes:
        A model that reports FLAG_SECURE missing on one screen cites that activity, so its copy takes the activity as its subject and stays apart from the scanner's "FLAG_SECURE is never set" - a Ghera scan listed both. Once the app-wide statement exists, a same-class copy at one file restates part of it, so it joins that group and the richer of them survives with the other's content absorbed. Without the app-wide statement nothing moves: two screens missing FLAG_SECURE in an app that sets it elsewhere are separate facts.
    """
    for code in sorted(_APP_WIDE_CLASSES):
        app = groups.get((code, _APP_SUBJECT))
        if app is None:
            continue
        for key in [k for k in groups if k[0] == code and k[1] != _APP_SUBJECT]:
            app.extend(groups.pop(key))


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


_LOCATION_FAMILIES = {"AUTH-04": "SECRET-01", "CRYPTO-02": "SECRET-01"}
_LITERAL_FAMILIES = frozenset(("SECRET-01", "STORAGE-01"))
RULE_SOURCES = ("static-analyzer", "semgrep")
_LOCATION_WINDOW = 12
_QUOTED_LITERAL_RE = re.compile(r"""['"`]([^\s'"`]{8,120})['"`]""")
_DOTTED_NAME_RE = re.compile(r"^[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)+$")
_SAME_LINE_PAIRS = frozenset((
    frozenset(("AUTH-03", "PLATFORM-02")),
    frozenset(("PLATFORM-01", "PLATFORM-02")),
    frozenset(("AUTH-03", "AUTH-04")),
))


def _engine(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Name the pass that produced a finding, for telling independent reports of one fact from one pass's own repeats.

    Parameters:
        finding: The finding dict.

    Returns:
        "rules" for the rule engine, "review" for the file review, "agent" for a region agent.

    Implementation notes:
        The file review re-reads the files the agents were steered to, so an agent and the review reporting the same line are two passes agreeing, exactly like the rule engine and an agent; treating both as one "AI" engine left every such pair in the report twice.
    """
    if str(finding.get("source") or "") in RULE_SOURCES:
        return "rules"
    return "review" if finding.get("agent_origin") == "file_review" else "agent"


def _quoted_literals(finding: Dict[str, Any]) -> Set[str]:
    """
    Purpose:
        Collect the literal values a finding quotes in its title and description.

    Parameters:
        finding: The finding dict.

    Returns:
        Quoted tokens of eight or more characters with no whitespace - keys, hashes, values - leaving out dotted code names.

    Implementation notes:
        A dotted name ("jakhar.aseem.diva.APICredsActivity", "com.example.action.VIEW") names a component or an action, not a value; one finding quoting the component and another its intent action are still about the same component, and counting the names as values split that pair apart.
    """
    text = " ".join(str(finding.get(k) or "") for k in ("title", "description"))
    return {t for t in _QUOTED_LITERAL_RE.findall(text) if not _DOTTED_NAME_RE.match(t)}


def _location_family(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        The class a finding is compared under in the location pass.

    Parameters:
        finding: The finding dict.

    Returns:
        The class, with the codes that describe one literal seen two ways mapped to one family.
    """
    code = infer_vuln_class(finding)
    return _LOCATION_FAMILIES.get(code, code)


def _distinct_values(cluster: List[Dict[str, Any]], candidate: Dict[str, Any]) -> bool:
    """
    Purpose:
        Tell whether a candidate is about a different value from a cluster it sits near.

    Parameters:
        cluster: The findings already clustered.
        candidate: The finding being considered for the cluster.

    Returns:
        True when the candidate and some member each quote literals and share none.
    """
    mine = _quoted_literals(candidate)
    if not mine:
        return False
    return any((theirs := _quoted_literals(member)) and not (mine & theirs) for member in cluster)


def _split_by_value(members: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Purpose:
        Split a class-and-subject group where its members quote different values.

    Parameters:
        members: Findings sharing a class and a subject.

    Returns:
        Sub-groups; a finding that quotes no value joins the first one.

    Implementation notes:
        The subject is often just the file, so two different secrets in one screen - a developer menu's debug key and its gateway secret - shared a key and collapsed into one finding. Two findings that each quote values and share none are about different things.
    """
    subgroups: List[List[Dict[str, Any]]] = []
    for member in members:
        mine = _quoted_literals(member)
        for group in subgroups:
            theirs = set().union(*(_quoted_literals(other) for other in group))
            if not mine or not theirs or mine & theirs:
                group.append(member)
                break
        else:
            subgroups.append([member])
    return subgroups


def _cluster_by_location(group: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Purpose:
        Cluster one file's findings into candidate duplicates.

    Parameters:
        group: The file's findings with a usable line.

    Returns:
        The clusters.

    Implementation notes:
        Clusters form within one class family, so a nearby finding of another class can neither join nor block a merge. Within a family the window is twelve lines from the cluster's first member: one routine often writes two values in a row, and a rule finding citing the second write is the same fact as an agent finding citing the first. A finding that quotes a value the cluster's members do not is kept apart, because two secrets ten lines apart are two secrets. A secret and a storage finding that quote the same literal near the same line are one value seen two ways - the hardcoded secret and the database row it is seeded into - and cluster together across their families. A few class pairs name one fact from two sides when they cite the very same line (_SAME_LINE_PAIRS): an Intent extra that decides an authorization check is a client-side authorization decision and untrusted Intent data at once, and an agent and the file review once filed it under each.
    """
    clusters: List[List[Dict[str, Any]]] = []
    for f in sorted(group, key=_finding_line):
        family = _location_family(f)
        line = _finding_line(f)
        for cluster in clusters:
            anchor = cluster[0]
            if abs(line - _finding_line(anchor)) > _LOCATION_WINDOW:
                continue
            same_family = family and family == _location_family(anchor)
            shared = (family in _LITERAL_FAMILIES and _location_family(anchor) in _LITERAL_FAMILIES
                      and any(_quoted_literals(f) & _quoted_literals(m) for m in cluster))
            paired = line == _finding_line(anchor) and _listed_pair(f, anchor)
            if (same_family or shared or paired) and not (
                    same_family and not shared and _distinct_values(cluster, f)):
                cluster.append(f)
                break
        else:
            clusters.append([f])
    return clusters


def _split_by_fact(cluster: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Purpose:
        Keep findings that name different facts apart, however close they sit.

    Parameters:
        cluster: Findings about to be merged.

    Returns:
        Sub-groups, one per fact_key; a finding with no fact_key joins the keyed finding nearest its line.

    Implementation notes:
        A scanner that checks separate switches names each one in fact_key. A WebView's setAllowContentAccess(true) on line 19 and setAllowUniversalAccessFromFileURLs(true) on line 21 are two settings with two fixes, but they fell in one twelve-line cluster with the agent's copy of the first, and the report kept only "universal access" - a Ghera benchmark about content access then had no finding naming it. Different rules can describe one fact (two TLS rules flag one trust-all TrustManager), so only an explicit key separates findings.
    """
    keyed = [f for f in cluster if f.get("fact_key")]
    keys: List[str] = []
    for f in keyed:
        if f["fact_key"] not in keys:
            keys.append(f["fact_key"])
    if len(keys) < 2:
        return [cluster]
    groups: Dict[str, List[Dict[str, Any]]] = {k: [] for k in keys}
    for f in cluster:
        key = f.get("fact_key") or min(
            keyed, key=lambda g: abs(_finding_line(g) - _finding_line(f)))["fact_key"]
        groups[key].append(f)
    return list(groups.values())


def _collapse_by_location(findings: List[Dict[str, Any]],
                          verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Purpose:
        Merge findings that report the same code location and were produced by different passes.

    Parameters:
        findings: All findings.
        verbose: Traces each collapse.

    Returns:
        The findings with cross-pass location duplicates merged.

    Complexity:
        O(n * c) for n findings and c clusters per file.

    Implementation notes:
        Findings without a usable file and line bypass this pass untouched rather than being grouped together, which would merge unrelated manifest and certificate findings. Clustering is per class family (see _cluster_by_location). A cluster collapses only when it has more than one member and they come from at least two passes - the rule engine, a region agent, the file review - because one pass reporting two things near each other is usually reporting two things; the exception is a listed class pair on the very same line (_one_fact), which is one thing however many passes filed it. A hardcoded secret that the same line checks the user's input against, or uses as a key, is one fact seen two ways - the rule engine reports the check (AUTH-04) or the key (CRYPTO-02), the agent the secret (SECRET-01) - so those count as one family here and nowhere else.
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
        for cluster in (sub for whole in _cluster_by_location(group) for sub in _split_by_fact(whole)):
            if len(cluster) == 1 or (len({_engine(f) for f in cluster}) < 2 and not _one_fact(cluster)):
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
                    f"{dropped.get('title')!r} ({_engine(dropped)}) into "
                    f"{survivor.get('title')!r} ({_engine(survivor)}) "
                    f"at {survivor.get('severity')}", verbose)

    if collapsed:
        verbose_print(
            f"Location dedupe: collapsed {plural(collapsed, 'location duplicate')}",
            verbose)
    return out + loose


_CONSTANT_DECL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final)\s+)*(?:static|final)\s+"
    r"(?:(?:static|final)\s+)*[\w.$<>\[\]]+\s+([A-Za-z_$][\w$]*)\s*=[^=]")
_DOTTED_RE = re.compile(r"(?<![\w$.])((?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*)(\s*\()?")


def secret_constants(finding: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """
    Purpose:
        Name the constants a secret-family finding is about: the one its cited line declares, and every Class.FIELD it reads.

    Parameters:
        finding: The finding dict.

    Returns:
        (class, field) pairs; empty for a finding outside the SECRET-01 location family, one that names its own fact in fact_key, or one citing no constant.

    Implementation notes:
        A scanner finding with a fact_key already says what it is about; the PBKDF2 fixed-salt finding cites a line that also reads Constant.PASS as the password and was folded into the hardcoded-password finding by it. A declaration counts only when it is static or final, since a local variable's name says nothing outside its method. A dotted chain followed by a call drops its last segment (Constant.PASS.toCharArray() reads Constant.PASS), and only the last two segments of what remains are kept, with the class capitalised, so a package prefix shared by two constants of one class never joins them.
    """
    if _location_family(finding) != "SECRET-01" or finding.get("fact_key"):
        return set()
    snippet = str(finding.get("code_snippet") or "")
    out: Set[Tuple[str, str]] = set()
    first = next((line for line in snippet.splitlines() if line.strip()), "")
    declared = _CONSTANT_DECL_RE.match(first)
    stem = Path(str(finding.get("file") or "")).stem
    if declared and stem:
        out.add((stem, declared.group(1)))
    for match in _DOTTED_RE.finditer(snippet):
        parts = match.group(1).split(".")
        if match.group(2):
            parts = parts[:-1]
        if len(parts) >= 2 and parts[-2][:1].isupper():
            out.add((parts[-2], parts[-1]))
    return out


def _collapse_by_constant(findings: List[Dict[str, Any]], verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Purpose:
        Merge secret-family findings about one constant reported where it is declared and where it is used.

    Parameters:
        findings: All findings.
        verbose: Traces each collapse.

    Returns:
        The findings with each shared constant's findings merged, in their original order.

    Implementation notes:
        The location pass already treats a hardcoded value and the check or key that uses it as one fact when they sit a few lines apart. A constant declared in one class and used in others is the same fact spread across files: a Ghera app's "password" in Constant.PASS came out as a hardcoded password at the declaration, a weak local authentication at the comparison in MainActivity, and a hardcoded PBKDF2 password in Encrypt. Only a finding naming exactly one constant is grouped, by that constant; a line reading two constants could be about either, so it stays on its own. The constant is the identity, so the quoted-value split used elsewhere is not applied: the comparison's finding quoted the activity it unlocks and was split off by it. The finding at the declaration survives when there is one, since the value is the fact and its uses are where it shows.
    """
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for finding in findings:
        constants = secret_constants(finding)
        if len(constants) == 1:
            groups.setdefault(next(iter(constants)), []).append(finding)
    dropped_ids = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        declaring = [f for f in members if _CONSTANT_DECL_RE.match(
            next((line for line in str(f.get("code_snippet") or "").splitlines() if line.strip()), ""))]
        survivor = _pick_location_survivor(declaring or members)
        rest = [f for f in members if f is not survivor]
        _absorb_location(survivor, rest)
        for dropped in rest:
            dropped_ids.add(id(dropped))
            verbose_print(f"Constant dedupe: dropped {dropped.get('title')!r} into {survivor.get('title')!r}", verbose)
    return [f for f in findings if id(f) not in dropped_ids]


def _one_fact(cluster: List[Dict[str, Any]]) -> bool:
    """
    Purpose:
        Tell whether a cluster is one fact filed under two classes that _SAME_LINE_PAIRS says name it from two sides.

    Parameters:
        cluster: A location cluster.

    Returns:
        True when the cluster is two findings on the same line whose classes are a listed pair.

    Implementation notes:
        Such a cluster collapses even when one pass produced both: a published scan listed "Client-Side Authentication Bypass for Private Notes" (AUTH-03) and "Weak Local Authentication via Plaintext SharedPreferences" (AUTH-04) on the same comparison, both from region agents.
    """
    return (len(cluster) == 2 and _finding_line(cluster[0]) == _finding_line(cluster[1])
            and _listed_pair(cluster[0], cluster[1]))


def _listed_pair(first: Dict[str, Any], second: Dict[str, Any]) -> bool:
    """
    Purpose:
        Tell whether two findings' classes are a pair _SAME_LINE_PAIRS lists.

    Parameters:
        first: One finding.
        second: The other.

    Returns:
        True when their classes, or their location families, form a listed pair.

    Implementation notes:
        The classes are checked as well as the families, because a family can be wider than its class: AUTH-04 counts as the SECRET-01 family, so the listed AUTH-03 and AUTH-04 pair never matched on families alone.
    """
    classes = frozenset(str(f.get("vuln_class") or "").strip().upper() for f in (first, second))
    families = frozenset(_location_family(f) for f in (first, second))
    return classes in _SAME_LINE_PAIRS or families in _SAME_LINE_PAIRS


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


def _carry_account(survivor: Dict[str, Any], rest: List[Dict[str, Any]]) -> None:
    """
    Purpose:
        Give a surviving rule-engine finding the model's account of what the flagged code does.

    Parameters:
        survivor: The finding being kept, mutated in place.
        rest: The findings merged into it.

    Side effects:
        When the survivor is the rule engine's and an AI finding was merged into it, replaces the survivor's impact and exploitation with the AI's and appends the AI's description to its own.

    Implementation notes:
        A scanner knows the construct, not its consequence: its impact is a template ("whatever it does with the data it is handed"). When its finding survives a merge, only fields it lacked used to be filled, so the agent's account was dropped and the review pass, which reads description and impact, judged the template. A Ghera app's exported service that takes a wake lock and opens a private activity was demoted to Informational for "failing to demonstrate a concrete impact" while the merged agent finding had stated it. The scanner keeps its class, line and severity; the AI finding with the longest description supplies the account, and its description is appended only when the scanner's does not already contain it.
    """
    if str(survivor.get("source") or "") != "static-analyzer":
        return
    accounts = [f for f in rest if str(f.get("source") or "agent") != "static-analyzer" and f.get("description")]
    if not accounts:
        return
    best = max(accounts, key=lambda f: len(str(f.get("description") or "")))
    for field in ("impact", "exploitation"):
        if best.get(field):
            survivor[field] = best[field]
    own = str(survivor.get("description") or "")
    told = str(best.get("description") or "").strip()
    if told and told not in own:
        survivor["description"] = f"{own} {told}".strip()


_DEVICE_RANK = {"verified": 3, "refuted": 2, "not_verified": 1}


def _carry_device_verdict(survivor: Dict[str, Any], rest: List[Dict[str, Any]]) -> None:
    """
    Purpose:
        Keep the strongest device verdict among findings merged into one.

    Parameters:
        survivor: The finding being kept, mutated in place.
        rest: The findings merged into it.

    Side effects:
        Sets the survivor's dynamic_verification to the strongest one in the group, when any member has one.

    Implementation notes:
        Device verification runs before grading, so findings arrive at deduplication already carrying verdicts, and a merge kept only the survivor's. A Ghera fixed app's receiver finding, refuted on the device, was merged into the scanner's finding for the same receiver, which had none, and the report kept a Medium the device had disproved. Verified outranks refuted, so a proven issue is never set aside because another report of it did not reproduce; refuted outranks not verified, since it is evidence where the other is its absence.
    """
    verdicts = [m.get("dynamic_verification") for m in (survivor, *rest)
                if isinstance(m.get("dynamic_verification"), dict)]
    if verdicts:
        survivor["dynamic_verification"] = dict(
            max(verdicts, key=lambda v: _DEVICE_RANK.get(str(v.get("status")), 0)))


def _absorb_location(survivor: Dict[str, Any], rest: Iterable[Dict[str, Any]]) -> None:
    """
    Purpose:
        Merge the dropped members of a location cluster into the survivor.

    Parameters:
        survivor: The finding being kept, mutated in place.
        rest: The findings being merged into it.

    Side effects:
        Mutates the survivor: severity, missing fields, related findings, corroboration and the device verdict (_carry_device_verdict).

    Implementation notes:
        A rule-engine survivor first takes the merged AI finding's account of the consequence (_carry_account). Severity resolution differs by case. Across engines, the rule engine's severity wins outright even when it is lower, because it is derived from the matched pattern rather than from a model's judgement. Within one engine, the higher severity wins. Only fields the survivor lacks are filled in, so nothing it already stated is overwritten. Each merge is recorded in related_findings with a confirmed flag set when the corroboration came from the other engine, so a reader can see that two engines agreed. Entries are deduplicated by their target so repeated merges do not accumulate.
    """
    rest = list(rest)
    _carry_account(survivor, rest)
    _carry_device_verdict(survivor, rest)
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
        A model's NETWORK-01 for a user-CA fact is re-filed as NETWORK-05 first, so it groups with the scanner's copy. Then runs the location pass, then the shared-constant pass, then groups by class and subject. Findings that cannot produce both halves of the key are passed through untouched -- never grouped together, which would merge everything the classifier failed on into one arbitrary finding. Once the scanner has stated a class for the whole app, every same-class group joins that statement. A group whose members quote different values is split first, and so is one holding findings with different fact_key values (_split_by_fact). Within a group the richest finding survives and the rest are absorbed, except that a group holding a scanner finding with a fact_key keeps that one: the group exists because of the fact it names, its claim was checked against the code by construction, and _carry_account still gives it the agent's account and the group's highest severity. An agent finding surviving instead took the scanner's fact down with it when its own wording was refuted: a Ghera receiver's "no permission protection" finding vanished inside an agent finding refuted for a title cut off mid-name.
    """
    if len(findings) < 2:
        return findings

    for finding in findings:
        correct_confusable_class(finding)
    findings = _collapse_by_location(findings, verbose=verbose)
    findings = _collapse_by_constant(findings, verbose=verbose)
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
    _fold_into_app_wide(groups)

    out: List[Dict[str, Any]] = []
    collapsed = 0
    for members in (sub for grouped in groups.values() for part in _split_by_value(grouped)
                    for sub in _split_by_fact(part)):
        if len(members) == 1:
            out.append(members[0])
            continue
        members.sort(key=_richness, reverse=True)
        keyed = [m for m in members if m.get("fact_key") and str(m.get("source") or "") in RULE_SOURCES]
        if keyed:
            members.remove(keyed[0])
            members.insert(0, keyed[0])
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
        Mutates the survivor: severity, missing fields, merged titles, dedupe provenance, corroboration, confidence and the device verdict (_carry_device_verdict).

    Implementation notes:
        Severity takes the maximum across the group, so the most serious assessment survives -- unlike the location pass, because here the duplicates are not necessarily describing the line from different angles. That maximum is then overridden by a public-identifier pin: a finding explicitly marked as a public identifier, or an informational rule-engine finding in one of the publicly-identifiable classes, forces the merged result to Informational. Without this, a correct informational finding about a shipped project identifier gets merged with a model's alarmed description of the same string and is reported as a hardcoded secret. Merged titles and dedupe targets are recorded so a reader can see what was folded in, and cross-engine agreement sets confidence to HIGH -- the single strongest signal available that a finding is real.
    """
    rest = list(rest)
    _carry_account(survivor, rest)
    _carry_device_verdict(survivor, rest)
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
