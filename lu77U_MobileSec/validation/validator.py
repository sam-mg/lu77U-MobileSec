#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.validator

Purpose:
    The final review stage: deduplicate, run the mechanical gates, then have an AI review what survives -- rule findings checked against their source, agent findings judged on exploitability -- and produce the sorted list that reaches the report.

Responsibilities:
    Orchestrate the passes, hold the two review system prompts and their schemas, batch findings to the provider, merge verdicts back, cache verdicts across runs, and sort.

Dependencies:
    .gates, .dedupe, .taxonomy, ..ai.schema for response coercion, ..utils.cvss, ..utils.cancellation.

Implementation notes:
    Rule findings and agent findings get different reviews, which is the central design decision here. A rule matched a line and cannot see what reaches it, so its review supplies the surrounding source and asks a factual question: does this code do what the rule claims. An agent finding already reasoned about the code, so re-checking the facts adds little; what it needs is a judgement about exploitability and severity. One combined prompt would do both badly. Neither review may discard a finding. The verdicts downgrade, demote or mark as needing a chain, and even a false positive stays in the report at Informational with its reason. The report goes to the app's owner, for whom a true statement about their build is useful even when it is not exploitable. Mechanically refuted findings skip the AI review entirely. Their contradiction was established from the evidence itself and spending tokens re-litigating it is waste.

Security considerations:
    This stage decides what the user is told is real. It is deliberately asymmetric: the prompts state that wrongly softening a genuine finding is the more expensive mistake, and every verdict must carry a reason the reader can check.
"""

import hashlib
import hmac
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .gates import (GateResult, VERDICT_ORDER, apply_gates, lower_severity,
                    normalize_severity, severity_rank)
from .dedupe import deduplicate, infer_vuln_class
from .taxonomy import describe, required_proof
from ..utils.cancellation import ScanCancelled
from ..utils.cvss import parse_vector, severity_from_vector
from ..utils.verbose import plural, verbose_print

JUDGMENT_BATCH_SIZE = 25
VERIFY_BATCH_SIZE = 10

RULE_SOURCES = ("static-analyzer", "semgrep")

PATTERN_DETECTORS = frozenset({
    "webview", "injection", "tls", "secrets", "semgrep",
})

VALUE_DETECTORS = frozenset({
    "manifest", "network-config", "sdk-inventory",
})

VERIFY_CONTEXT_LINES = 12


_JUDGMENT_SYSTEM = """You are reviewing the findings of a mobile app security scan \
before they reach the app owner's report. You are not looking for new issues. You are \
deciding whether each finding, as written, is worth the severity attached to it.

Ask of every finding:

1. Exploitability - can an attacker trigger this on a real, unmodified device? Anything \
needing root, ADB, developer mode or physical access to an unlocked device is not \
something an attacker does to a victim. Code that is never called is not exploitable. \
Name the weakest attacker who reaches it: remote (a web page, a link, a QR code, a \
network position), another app on the device, physical access, a rooted device. An \
exported component is reached by another app, not remotely; a deep link is remote only \
when a web page can fire it. A finding that claims a stronger attacker than its path \
supports is overstated.
2. Reachability - is the affected code reachable from an entry point: an exported \
component, a deep link, a network response, WebView content? An unreachable sink is a \
code-quality note.
3. Build relevance - does this describe the shipped release build, or a debug-only path?
4. Novelty - is this documented platform behaviour rather than a defect? Implicit intent \
resolution, backup copying app data, and WebViews loading HTTP on old targets are all \
working as designed. The finding must show impact beyond the documented behaviour.
5. Concrete gain - what does an attacker get that they could not get by using the app \
normally? "Access to data" is not an answer. "The session token, from any installed app, \
with no permission" is.
6. Proof - does the finding show what it claims? Each finding below carries a \
`proof_expected` line naming what its class has to establish. A finding that asserts the \
class without establishing that is a note.
7. Standalone value - is this a vulnerability alone, or one step of a chain? Absent \
pinning, cleartext configuration and enabled backup are steps. A credential in plain \
storage, a hardcoded key or a client-side gate is not a step, and is never CHAIN_REQUIRED. \
Its CVSS vector already scores the attacker it needs - local access, root as high \
privileges - so needing root or a backup is not by itself a reason to DOWNGRADE it again. \
Downgrade it when the vector claims a stronger attacker than the path supports, or when \
what is stored is not sensitive.
8. Mitigations - only real ones count. Obfuscation, native code and string encryption \
slow a reader down but recover nothing: a key or rule in the app is still the \
attacker's. A check the client makes and trusts - a root-detection result, a biometric \
callback with no key behind it, an entitlement flag in local storage - is one hook away \
and mitigates nothing unless a server verifies it. A newer-Android default closes a path \
only for apps that target that level (cleartext off from 28, explicit export and \
immutable PendingIntents from 31): check the app's targetSdkVersion. A mutable \
PendingIntent whose base Intent names its component cannot be redirected by whoever \
holds it, who can only fill in fields the base left empty, such as extras: it matters \
only when that component acts on them. A protection the OS \
version gives whatever the target - scoped storage keeping other apps out of \
Android/data from Android 11, the task-hijacking fix in 11 - covers only devices running \
it: an app whose minSdkVersion is lower installs on older devices, where the path is open. \
Android/data/<package> (getExternalFilesDir, getExternalCacheDir) was never private before \
scoped storage: Android 4.4 only stopped requiring a permission for the app's own access, \
and any app holding READ_EXTERNAL_STORAGE reads it on Android 10 and lower. Any app can \
send an exported receiver an explicit Intent, with any action or none, whatever its intent \
filter lists. Registering for a protected system broadcast (BOOT_COMPLETED, \
DEVICE_STORAGE_LOW, NEW_OUTGOING_CALL and the like) does not change that; only a receiver \
that checks getAction() for the protected action before acting is out of other apps' \
reach, because they cannot send that action itself. A component \
guarded by a signature-level permission the app declares is reachable only by apps signed \
with the same key, so no other developer's app is the attacker there; a guard naming a \
permission the app never declares guards nothing, since another app can declare it first. \
Java's new File(dir, name) keeps dir even when name is absolute (unlike Path.resolve), so \
a ".." check on name does guard that path. The declared levels are stated above the \
findings when known.

Downgrade on a specific fact: a guard on the path, a platform default this app actually \
gets, a precondition the finding skipped. General doubt is not a reason - a finding that \
names a concrete path keeps its severity.

Then: could it be demonstrated today; is the gain specific; is it distinct from the \
other findings in this batch; is it documented well enough to act on.

Return one verdict per finding:

PASS            - valid as written, severity is right
DOWNGRADE       - real, but overstated; give the severity it deserves, Low at the least
CHAIN_REQUIRED  - real, but only matters combined with another finding
INFORMATIONAL   - worth telling the owner, not a vulnerability

You are reporting to the owner of the app, not to a bug bounty triager. Never discard a \
finding: a true statement about their build is useful to them even when it is not \
exploitable. Downgrade it and say why. Equally, do not inflate - a finding that names a \
real exploitable path keeps its severity, and softening those is the more expensive \
mistake.

Reasons are read by the app's owner. Say what is missing or why it does not hold, in ONE \
concrete sentence, and name another finding by its title, never by its id. "Does not meet the bar" tells them nothing. Omit "reason" entirely on a \
PASS - it is discarded for PASS and there is nothing to explain."""


_VERIFY_SYSTEM = """You are reviewing findings that were produced by pattern-matching \
rules - a regex or a Semgrep pattern matched a line of code. Your job is to decide which \
of them are real, using the source that is included with each one.

A rule can only see the line it matched. It cannot see what reaches that line, what \
guards it, or whether the value involved is attacker-influenced. That is what you are \
adding. Read the code shown and answer: **does this code actually do what the finding \
claims?**

Reject a finding when the code shows the claim does not hold. The recurring cases:

- The WebView only ever loads bundled local content, so its settings do not expose it to \
attacker-controlled pages.
- The concatenated SQL is built from constants or from values the app itself produced, \
not from anything a caller supplies.
- The "secret" is a public value - a certificate, a public key, a client identifier, an \
API key documented as safe to ship, a test or placeholder credential.
- The code path is guarded by BuildConfig.DEBUG or an equivalent, so it is not in the \
release build.
- The match is inside library or generated code the app merely bundles, not the app's own \
logic.
- The pattern matched a comment, a string literal, or a name that resembles the API \
without being it.
- The unsafe call is dead: nothing reaches it.

Confirm a finding when the code supports it, even if the code shown does not prove full \
exploitability - the rule's claim is what you are checking, not the whole attack path.

When the excerpt is too small to decide, say so and mark it unverified rather than \
guessing either way. An unverified finding stays in the report as a lead; a wrongly \
confirmed one wastes the reader's time, and a wrongly rejected one hides a real bug.

Return one verdict per finding:

CONFIRMED     - the code supports the claim
UNVERIFIED    - cannot tell from what is shown; keep it as a lead
FALSE_POSITIVE - the code shows the claim does not hold

For CONFIRMED you may also give `severity` if the code shows the finding is materially \
weaker than reported; it is never used to raise severity. Give `reason` for UNVERIFIED and \
FALSE_POSITIVE - naming what in the code decided it, "the URL is a string constant on line \
41", not "looks fine"; that sentence is shown to the app's owner and is the only way they \
can check your work. Omit `reason` on a plain CONFIRMED with nothing to add."""


_REASON_MAX = 240

_JUDGMENT_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "id": {"type": "integer",
                   "description": "The finding's id from the input list."},
            "verdict": {"type": "string",
                        "enum": ["PASS", "DOWNGRADE", "CHAIN_REQUIRED", "INFORMATIONAL"]},
            "severity": {"type": "string",
                         "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                         "description": "Required for DOWNGRADE: the severity it should be."},
            "reason": {"type": "string", "maxLength": _REASON_MAX,
                       "description": (
                           "One concrete sentence the app owner can act on. Omit entirely "
                           "on a PASS that needs no explanation - it is not shown for PASS.")},
        },
        "required": ["id", "verdict"],
    },
}

_VERIFY_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "id": {"type": "integer",
                   "description": "The finding's id from the input list."},
            "verdict": {"type": "string",
                        "enum": ["CONFIRMED", "UNVERIFIED", "FALSE_POSITIVE"]},
            "severity": {"type": "string",
                         "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                         "description": "Optional, CONFIRMED only: a lower severity the code supports."},
            "reason": {"type": "string", "maxLength": _REASON_MAX,
                       "description": (
                           "What in the shown code decided it. Name the line or value. Omit "
                           "on a plain CONFIRMED that needs no comment.")},
        },
        "required": ["id", "verdict"],
    },
}


_TITLE_MAX_CHARS = 72
_TITLE_TRAILING_WORDS = frozenset(("of", "and", "or", "to", "the", "a", "an", "with", "in", "for", "by",
                                   "from", "on", "at", "that", "which", "via", "using", "is", "are",
                                   "without", "where", "when", "who", "whose", "they", "it", "its", "their",
                                   "this", "as", "into", "can", "be", "was", "were", "has", "have"))
_TITLE_CLAUSE_MARKERS = (", allowing", ", which", " because", ", making", ", enabling", "; ",
                         ", so ", " that allows", " so that", " - ", ", leading", ", exposing")

_TITLE_SYSTEM = """You write the titles of security findings for a report read by the app's \
owner. Rewrite each title as a short noun phrase of at most 70 characters that names the \
weakness and where it is, the way a heading in a security report does: "SQL injection in the \
notes search", "Hardcoded TVEETER API credentials in APICreds2Activity", "Session token stored \
unencrypted in AsyncStorage". Keep class, file, method and identifier names exactly as written. \
Add nothing the description does not say, and leave out severity words. No trailing period. \
Return one object per finding: its id and the new title."""

_TITLE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "description": "The finding's id from the input list."},
            "title": {"type": "string", "maxLength": 90},
        },
        "required": ["id", "title"],
    },
}


def needs_title(finding: Dict[str, Any]) -> bool:
    """
    Purpose:
        Tell whether a finding's title reads as a cut-off sentence rather than a heading.

    Parameters:
        finding: The finding dict.

    Returns:
        True for a title that ends in an ellipsis, runs past _TITLE_MAX_CHARS, or is a whole sentence.

    Implementation notes:
        A model that leaves the title out gets the first sentence of its description, cut at 77 characters with "...", which published titles such as "The decision to display premium content is made on the client side based on t...".
    """
    title = str(finding.get("title") or "").strip()
    if not title:
        return False
    return (title.endswith(("...", "\u2026")) or len(title) > _TITLE_MAX_CHARS
            or (title.endswith(".") and len(title.split()) >= 6))


def shorten_title(title: str, description: str = "") -> str:
    """
    Purpose:
        Turn a sentence-shaped title into a heading without a model.

    Parameters:
        title: The title.
        description: The finding's description, whose first sentence replaces a title that was itself cut short.

    Returns:
        The title without its ellipsis, final period and parentheticals, cut at its first clause boundary past the subject, and at a word boundary within _TITLE_MAX_CHARS with no dangling connective or pronoun.

    Implementation notes:
        The fallback when the title pass cannot run. It keeps the opening clause, which in a model's finding sentence is nearly always the weakness and where it is, and drops what follows ("..., allowing an attacker to ..."). A title that already ends in "..." was cut mid-word from the description, so the description's own sentence is used instead of the fragment.
    """
    text = str(title or "").strip()
    stem = text.rstrip(".\u2026 ")
    if text.endswith(("...", "\u2026")) and str(description or "").startswith(stem[:40]):
        text = re.split(r"(?<=[.!?])\s", str(description).strip(), maxsplit=1)[0]
    text = re.sub(r"\s*\([^)]*\)", "", text).rstrip(".\u2026 ").strip()
    for marker in _TITLE_CLAUSE_MARKERS:
        cut = text.find(marker)
        if cut >= 25:
            text = text[:cut]
            break
    if len(text) > _TITLE_MAX_CHARS:
        text = text[:_TITLE_MAX_CHARS].rsplit(" ", 1)[0]
    words = text.rstrip(",;:- ").split()
    while len(words) > 3 and words[-1].lower() in _TITLE_TRAILING_WORDS:
        words.pop()
    text = " ".join(words)
    return (text[0].upper() + text[1:]) if text else str(title or "")


_TITLE_FUNCTION_WORDS = frozenset((
    "a", "an", "the", "and", "or", "of", "in", "on", "at", "to", "for", "by", "via", "with",
    "without", "from", "into", "over", "under", "as", "per", "vs"))
_TITLE_PROPER_WORDS = frozenset((
    "Android", "Google", "Firebase", "Flutter", "Dart", "Java", "Kotlin", "React", "Native",
    "Cordova", "Xamarin", "Hermes", "Blutter", "Ghidra", "Frida", "Logcat", "Keystore", "Intent",
    "Chrome", "Edge", "Windows", "Linux", "Gradle", "Play", "Stripe", "Slack", "Base64"))
_TITLE_CASED_WORD_RE = re.compile(r"[A-Z][a-z]+(?:'s)?")


def sentence_case(title: str) -> str:
    """
    Purpose:
        Turn a title written in Title Case into the sentence case every other title uses.

    Parameters:
        title: The title.

    Returns:
        The title with its capitalised ordinary words lowered, or the title unchanged when it is not in Title Case.

    Implementation notes:
        A title counts as Title Case when, after its first word, at least one ordinary capitalised word appears and no ordinary lower-case word other than a short function word does; "Hardcoded encryption key in the app's Dart code" has lower-case words and is left alone, while "Plaintext Credentials in Temporary File" becomes "Plaintext credentials in temporary file". Only plain capitalised words are lowered: identifiers (ContentProvider, APICreds2Activity), acronyms (PIN, SQL), quoted or punctuated tokens and a short list of proper names keep their case. Each part of a hyphenated word is treated as a word, so "Client-Side" becomes "Client-side". Published scans mixed both styles in one list, because the model writes either.
    """
    words = str(title or "").split(" ")
    if len(words) < 2:
        return str(title or "")
    parts = [(i, j, part) for i, word in enumerate(words) for j, part in enumerate(word.split("-"))
             if (i, j) != (0, 0)]
    capitalised = [(i, j) for i, j, part in parts
                   if _TITLE_CASED_WORD_RE.fullmatch(part) and part not in _TITLE_PROPER_WORDS]
    lowered = [part for _, _, part in parts if part[:1].islower() and part.isalpha()
               and part not in _TITLE_FUNCTION_WORDS]
    if not capitalised or lowered:
        return str(title)
    marked = set(capitalised)
    rebuilt = []
    for i, word in enumerate(words):
        pieces = word.split("-")
        rebuilt.append("-".join(piece.lower() if (i, j) in marked else piece
                                for j, piece in enumerate(pieces)))
    return " ".join(rebuilt)


def _title_view(index: int, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Build the compact view the title pass reads.

    Parameters:
        index: Its position in the batch.
        finding: The finding.

    Returns:
        The view dict.
    """
    return {
        "id": index,
        "title": _text(finding.get("title")),
        "description": _text(finding.get("description"))[:400],
        "file": finding.get("file") or "",
        "vuln_class": finding.get("vuln_class") or "",
    }


def _merge_title(finding: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """
    Purpose:
        Apply one rewritten title.

    Parameters:
        finding: The finding dict, mutated in place.
        entry: The model's answer for it.

    Side effects:
        Replaces the title when the answer is a usable heading.
    """
    title = str(entry.get("title") or "").strip().rstrip(". ")
    if 8 <= len(title) <= 90 and not title.endswith(("...", "\u2026")):
        finding["title"] = title


def polish_titles(findings: List[Dict[str, Any]], provider=None, verbose: bool = False,
                  is_cancelled: Optional[Callable[[], bool]] = None,
                  progress: Optional[Callable[..., None]] = None, fallback: bool = True) -> None:
    """
    Purpose:
        Give sentence-shaped titles a heading's shape before the report is written.

    Parameters:
        findings: All findings, mutated in place.
        provider: The model provider, or None to use only the deterministic shortener.
        verbose: Traces the pass.
        is_cancelled: Polled between batches.
        progress: Receives progress updates.
        fallback: Whether titles the model left unusable are then reshaped by shorten_title; off when a caller applies its own titles first.

    Side effects:
        Rewrites the titles that need it; makes provider requests when a provider is given.

    Implementation notes:
        Runs after grading, so the gates and the reviewer judged the claim as the agent wrote it; only its wording changes, and a review reason that named a finding by its old title is pointed at the new one. One batch covers many titles, because each answer is a few words. A mechanically refuted finding never reaches the model, here as in the review passes; it and any title the model leaves unusable, or every title when there is no provider or the request fails, fall back to shorten_title. Every title then goes through sentence_case, so a list does not mix "Plaintext Credentials in Temporary File" with "Hardcoded encryption key in the app's Dart code".
    """
    before = {id(f): f.get("title") for f in findings}
    pending = [f for f in findings if needs_title(f)]
    graded = [f for f in pending if not (f.get("gate_result") or {}).get("mechanically_refuted")]
    if provider is not None and graded:
        _run_pass(graded, provider, verbose, is_cancelled or (lambda: False),
                  progress or (lambda *unused_a, **unused_kw: None),
                  system=_TITLE_SYSTEM, schema=_TITLE_SCHEMA, batch_size=JUDGMENT_BATCH_SIZE,
                  summarize=_title_view, merge=_merge_title, label="Titling findings",
                  intro="Rewrite each title. Return one object per finding, keyed by its id.")
    for finding in pending if fallback else []:
        if needs_title(finding):
            finding["title"] = shorten_title(finding.get("title"), finding.get("description") or "")
    for finding in findings if fallback else []:
        if finding.get("title"):
            finding["title"] = sentence_case(finding["title"])
    rename_references(findings, {before[id(f)]: f.get("title") for f in findings})


def rename_references(findings: List[Dict[str, Any]], renames: Dict[str, str]) -> None:
    """
    Purpose:
        Rewrite review reasons that name a finding by a title it no longer has.

    Parameters:
        findings: The findings whose reasons are rewritten, updated in place.
        renames: Old title to new title.

    Side effects:
        Replaces each old title in the findings' gate reasons with the new one.

    Implementation notes:
        The review pass runs before the title pass and is asked to name other findings by title, so a published reason pointed at "Sensitive Credentials Stored in Plaintext SQLite Database", a title the report no longer contained once the title pass had rewritten it. Titles shorter than twelve characters are left alone, since a short one could match ordinary words.
    """
    pairs = [(old, new) for old, new in renames.items() if old and new and old != new and len(old) >= 12]
    if not pairs:
        return
    for finding in findings:
        gate = finding.get("gate_result")
        if not isinstance(gate, dict) or not gate.get("reasons"):
            continue
        reasons = []
        for reason in gate["reasons"]:
            for old, new in pairs:
                reason = reason.replace(old, new)
            reasons.append(reason)
        gate["reasons"] = reasons


def is_rule_finding(finding: Dict[str, Any]) -> bool:
    """
    Purpose:
        Decide whether a finding came from a pattern-matching rule and should therefore go through source verification rather than exploitability judgement.

    Parameters:
        finding: The finding dict.

    Returns:
        True when the finding should be verified against source.

    Implementation notes:
        Source alone is not enough. Some detectors in the rule engine read values rather than match patterns -- the manifest parser, the network-config reader, the SDK inventory -- and their findings are statements of fact about configuration, not pattern hits. Sending those to a verifier that asks "does the code do this" would produce meaningless verdicts, so they are routed to the judgement pass instead.
    """
    if str(finding.get("source") or "").strip().lower() not in RULE_SOURCES:
        return False
    detector = str(finding.get("detector") or "").strip().lower()
    if detector in VALUE_DETECTORS:
        return False
    return True


_VERDICT_CACHE: Dict[Tuple[str, ...], List[Tuple[str, Dict[str, Any]]]] = {}


def _verdict_key(finding: Dict[str, Any], scope: str = "") -> Optional[Tuple[str, ...]]:
    """
    Purpose:
        Build a cache key identifying one exact claim about one app, so an identical finding in a later run of the same app reuses its verdict instead of being re-reviewed.

    Parameters:
        finding: The finding dict.
        scope: Identifies the app the finding is about; empty when unknown.

    Returns:
        A key tuple, or None when there is no scope or the finding lacks the file or snippet needed to identify it.

    Implementation notes:
        The key covers the app, class, file, line, as-filed severity and a hash of the snippet. The app is part of it because the rest does not identify one: two apps can share a package path, a file name and a one-line snippet such as a method signature, and the verdict on one app's claim was being applied to the other's. In a run of the Ghera benchmark more than half of the fixed apps' findings took the vulnerable app's verdict, including a receiver judged spoofable whose fixed version checks the action before acting. Without a scope nothing is cached, since nothing says two findings are about the same app. The snippet is hashed rather than stored so the cache does not retain application source. The severity used is the one before gating, so that a cached verdict is keyed to what was originally claimed rather than to the outcome of applying it -- otherwise the cache would never hit twice. None is returned rather than a partial key, so a finding that cannot be identified precisely is always re-reviewed.
    """
    snippet = str(finding.get("code_snippet") or "").strip()
    file = str(finding.get("file") or "").strip()
    if not scope or not snippet or not file:
        return None
    filed = (finding.get("gate_result") or {}).get("original_severity") \
        or finding.get("severity")
    return (
        scope,
        str(finding.get("vuln_class") or "").strip(),
        file,
        str(finding.get("line") or finding.get("line_number") or "").strip(),
        normalize_severity(filed),
        hashlib.sha1(snippet.encode("utf-8", "ignore")).hexdigest(),
    )


def _cache_lookup(key: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Look up a prior verdict for a cache key, comparing the embedded snippet hash in constant time so a lookup cannot leak the stored digest through timing.

    Parameters:
        key: The cache key tuple returned by _verdict_key, whose last element is the snippet's sha1 hexdigest.

    Returns:
        The cached gate result for an exact match, or None when no cached entry shares the key's prefix and digest.

    Implementation notes:
        The dict is keyed on everything but the digest so an ordinary dict lookup narrows to the (usually single) candidate sharing app, class, file, line and severity, then hmac.compare_digest checks the digest itself; the loop never breaks early on a match, so its runtime depends only on how many candidates share the prefix, never on which byte of the digest matched.
    """
    prefix, digest = key[:-1], key[-1]
    match = None
    for candidate_digest, result in _VERDICT_CACHE.get(prefix, []):
        if hmac.compare_digest(candidate_digest, digest):
            match = result
    return match


def _cache_store(key: Tuple[str, ...], result: Dict[str, Any]) -> None:
    """
    Purpose:
        Remember a verdict under its cache key, replacing any earlier entry for the same snippet hash.

    Parameters:
        key: The cache key tuple returned by _verdict_key, whose last element is the snippet's sha1 hexdigest.
        result: The gate result to remember.

    Side effects:
        Mutates the module-global verdict cache.

    Implementation notes:
        Digest comparisons use hmac.compare_digest for the same constant-time reason _cache_lookup does, so replacing a stale entry does not reintroduce a variable-time comparison on the way in.
    """
    prefix, digest = key[:-1], key[-1]
    entries = _VERDICT_CACHE.setdefault(prefix, [])
    entries[:] = [(d, r) for d, r in entries if not hmac.compare_digest(d, digest)]
    entries.append((digest, result))


def clear_verdict_cache() -> None:
    """
    Purpose:
        Empty the verdict cache.

    Side effects:
        Discards every cached verdict for the process.

    Implementation notes:
        Needed between unrelated scans and in tests, since the cache is module-global and would otherwise carry verdicts from one APK to another. The key includes the file path and snippet hash, so a genuine collision is unlikely, but the cache is still process-wide state that should not silently persist.
    """
    _VERDICT_CACHE.clear()


def sdk_note(min_sdk: Any = None, target_sdk: Any = None) -> str:
    """
    Purpose:
        State the app's declared SDK levels for the review passes.

    Parameters:
        min_sdk: The declared minSdkVersion, or None when unknown.
        target_sdk: The declared targetSdkVersion, or None when unknown.

    Returns:
        One sentence, or an empty string when neither level is known.

    Implementation notes:
        The review prompt tells the model to check the target SDK before calling a path closed, and to weigh what older devices leave open, but it was never given either level. A Ghera app copying private files into its external files directory was rated Informational because those are "not world-readable by design on modern Android" - true from Android 11, while the app installs on far older versions.
    """
    parts = [f"{name} {value}" for name, value in (("minSdkVersion", min_sdk), ("targetSdkVersion", target_sdk))
             if value not in (None, "", "N/A")]
    return f"The app declares {' and '.join(parts)}." if parts else ""


def validate_findings(
    findings: List[Dict[str, Any]],
    provider=None,
    verbose: bool = False,
    is_cancelled: Optional[Callable[[], bool]] = None,
    progress: Optional[Callable[..., None]] = None,
    app_note: str = "",
    scope: str = "",
) -> List[Dict[str, Any]]:
    """
    Purpose:
        Run the full validation pipeline over a scan's findings and return them ordered for the report.

    Parameters:
        findings: All findings from every engine. Mutated in place as well as returned.
        provider: AI provider for the review passes; None runs only the mechanical gates.
        verbose: Traces each stage.
        is_cancelled: Polled between batches so a user stop takes effect promptly.
        progress: Reports progress to the dashboard.
        app_note: Facts about the app both review passes are told first, such as its declared SDK levels (see sdk_note); empty for none.
        scope: Identifies the app, such as its APK's digest, so a verdict is reused only for the same app; empty disables reuse.

    Returns:
        The validated findings, sorted by severity then title.

    Raises:
        ScanCancelled: When the user stopped the scan between batches.

    Side effects:
        Mutates each finding's severity and gate result, and populates the verdict cache.

    Implementation notes:
        Order matters throughout. Deduplication runs first so the review passes are not asked about the same issue twice. Class inference and CVSS scoring fill gaps before gating, because gates read both. Gates run before the AI so that mechanical conclusions are available to the prompt as context. Cached verdicts are applied before batching, and those findings are excluded from the batches, so a re-scan of an unchanged app is substantially cheaper; they are reused only within one scope, the same app. Running without a provider is a supported mode: the mechanical gates alone still produce a usable, if more conservative, result. The cache is written after the passes and only for findings that did not come from it, so a cached verdict is not rewritten over itself.
    """
    if not findings:
        return findings
    is_cancelled = is_cancelled or (lambda: False)
    progress = progress or (lambda *unused_a, **unused_kw: None)

    findings[:] = deduplicate(findings, verbose=verbose)

    for finding in findings:
        if not finding.get("vuln_class"):
            inferred = infer_vuln_class(finding)
            if inferred:
                finding["vuln_class"] = inferred
        if finding.get("cvss_vector") and finding.get("cvss_score") is None:
            _, score = severity_from_vector(finding["cvss_vector"])
            if score is not None:
                finding["cvss_score"] = score
        _attach(finding, apply_gates(finding))

    adjusted = sum(1 for f in findings if f["gate_result"]["verdict"] != "PASS")
    verbose_print(
        f"Gates: {adjusted}/{len(findings)} findings adjusted by the mechanical checks",
        verbose)

    if provider is not None:
        cached: List[Dict[str, Any]] = []
        for finding in findings:
            key = _verdict_key(finding, scope)
            prior = _cache_lookup(key) if key is not None else None
            if prior is not None:
                _apply(finding, prior.get("verdict", "PASS"),
                       "Reusing the verdict this exact claim received earlier.",
                       prior.get("final_severity"))
                finding["gate_result"]["from_cache"] = True
                cached.append(finding)

        cached_ids = {id(f) for f in cached}
        review_findings([f for f in findings if id(f) not in cached_ids], provider, verbose,
                        is_cancelled, progress, app_note=app_note)

        for finding in findings:
            key = _verdict_key(finding, scope)
            if key is not None and not finding.get("gate_result", {}).get("from_cache"):
                _cache_store(key, dict(finding.get("gate_result") or {}))

    polish_titles(findings, provider, verbose, is_cancelled, progress)
    return sort_findings(findings)


def review_findings(findings: List[Dict[str, Any]], provider, verbose: bool = False,
                    is_cancelled: Optional[Callable[[], bool]] = None,
                    progress: Optional[Callable[..., None]] = None, app_note: str = "") -> None:
    """
    Purpose:
        Run the model's two review passes over gated findings: rule findings checked against their code, and everything else judged for its severity.

    Parameters:
        findings: The findings to review, already gated. Mutated in place.
        provider: The model provider.
        verbose: Traces each batch.
        is_cancelled: Polled between batches.
        progress: Receives progress updates.
        app_note: Facts about the app stated ahead of each batch, such as its declared SDK levels; empty for none.

    Raises:
        ScanCancelled: When the user stopped the scan between batches.

    Side effects:
        Makes provider requests and may change each finding's verdict, reasons and severity.

    Implementation notes:
        A mechanically refuted finding never reaches the model. Separate from validate_findings so the two passes can be driven directly on findings already gated, as the review tests do, through the same code a scan runs.
    """
    is_cancelled = is_cancelled or (lambda: False)
    progress = progress or (lambda *unused_a, **unused_kw: None)
    graded = [f for f in findings if not (f.get("gate_result") or {}).get("mechanically_refuted")]
    _run_pass([f for f in graded if is_rule_finding(f)], provider, verbose, is_cancelled, progress,
              system=_VERIFY_SYSTEM, schema=_VERIFY_SCHEMA,
              batch_size=VERIFY_BATCH_SIZE, summarize=_verify_view,
              merge=_merge_verify, label="Verifying rule findings",
              intro=(f"{app_note} " if app_note else "") + "Review each pattern-rule finding against the code shown. "
                    "Return one object per finding.")
    _run_pass([f for f in graded if not is_rule_finding(f)], provider, verbose, is_cancelled, progress,
              system=_JUDGMENT_SYSTEM, schema=_JUDGMENT_SCHEMA,
              batch_size=JUDGMENT_BATCH_SIZE, summarize=_judgment_view,
              merge=_merge_judgment, label="Reviewing findings",
              intro=(f"{app_note} " if app_note else "") + "Review these findings. Return one object per finding, "
                    "keyed by its id.")


def _attach(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Write a gate result onto its finding.

    Parameters:
        finding: The finding dict, mutated in place.
        result: The gate result.

    Side effects:
        Replaces the finding's severity with the gated one and attaches the serialised result.
    """
    finding["severity"] = result.final_severity
    finding["gate_result"] = result.to_dict()


def _run_pass(findings, provider, verbose, is_cancelled, progress, *,
              system, schema, batch_size, summarize, merge, label, intro) -> None:
    """
    Purpose:
        Run one review pass over a set of findings, in batches, merging verdicts back as they arrive.

    Parameters:
        findings: Findings for this pass.
        provider: AI provider.
        verbose: Traces batch progress.
        is_cancelled: Polled before each batch.
        progress: Reports progress to the dashboard.
        system: System prompt for this pass.
        schema: Response schema for this pass.
        batch_size: Findings per request.
        summarize: Builds the per-finding view sent to the model.
        merge: Applies one verdict back onto its finding.
        label: Name of the pass, used in progress messages.
        intro: Instruction line prefixed to the batch payload.

    Side effects:
        Makes provider requests and mutates findings.

    Raises:
        ScanCancelled: When cancellation is observed before a batch.

    Implementation notes:
        Batching exists because one request per finding would be prohibitively slow and expensive, while one request for all of them would exceed the context window and degrade the model's attention. The two passes use different batch sizes: verification carries source excerpts and so needs smaller batches than judgement, which carries only summaries. A failed batch is logged and skipped rather than aborting the pass. The findings in it keep their mechanical verdicts, which is a safe fallback -- conservative, and still reviewed. Verdicts are matched back by the index assigned in the batch view, and an entry whose id will not parse or falls outside the batch is dropped. A model returning a wrong id must not be allowed to apply a verdict to an unrelated finding. Cancellation is checked between batches rather than inside them, so a stop is honoured within one request rather than mid-flight.
    """
    if not findings:
        return
    batches = [findings[i:i + batch_size] for i in range(0, len(findings), batch_size)]
    for index, batch in enumerate(batches, start=1):
        if is_cancelled():
            raise ScanCancelled()
        verbose_print(f"{label}: batch {index}/{len(batches)} "
                      f"({plural(len(batch), 'finding')})", verbose)
        progress("validating", 0, f"{label} ({index}/{len(batches)})")
        try:
            verdicts = _ask(provider, batch, system, schema, summarize, intro, verbose)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"{label}: batch {index} failed ({exc}); keeping the "
                          "mechanical verdicts for it", verbose)
            continue
        titles = [str(f.get("title") or f.get("vulnerability_type") or "") for f in batch]
        for entry in verdicts:
            try:
                position = int(entry.get("id"))
            except (TypeError, ValueError):
                continue
            if 0 <= position < len(batch):
                if entry.get("reason"):
                    entry = dict(entry, reason=name_references(str(entry["reason"]), titles))
                merge(batch[position], entry)


_ID_REFERENCE_RE = re.compile(r"\b(?:ID|id|Id|finding|Finding)\s?#?(\d{1,3})\b")


def name_references(text: str, titles: List[str]) -> str:
    """
    Purpose:
        Replace a model's references to other findings by batch id with their titles.

    Parameters:
        text: A reason the model wrote.
        titles: The titles of the batch's findings, by id.

    Returns:
        The text with each in-range id reference replaced by "the finding" and the quoted title.

    Implementation notes:
        The ids exist only inside one request; a published reason read "the actual vulnerability is the SQL injection in ID 3", which no reader can follow.
    """
    def named(match) -> str:
        """
        Purpose:
            Name one reference.

        Parameters:
            match: The id reference.

        Returns:
            The quoted title, or the reference unchanged when the id is out of range.
        """
        index = int(match.group(1))
        return f'the finding "{titles[index]}"' if 0 <= index < len(titles) and titles[index] else match.group(0)

    return _ID_REFERENCE_RE.sub(named, text)


_PER_VERDICT_TOKENS = 100
_MIN_VERDICT_BATCH_TOKENS = 500


def _ask(provider, batch, system, schema, summarize, intro, verbose
         ) -> List[Dict[str, Any]]:
    """
    Purpose:
        Send one batch to the provider and return the verdict objects it produced.

    Parameters:
        provider: AI provider.
        batch: Findings in this batch.
        system: System prompt.
        schema: Response schema.
        summarize: Builds the per-finding view.
        intro: Instruction line.
        verbose: Traces a failed request.

    Returns:
        The verdict dicts, or an empty list on any failure.

    Implementation notes:
        The token cap scales with batch size, with a floor, because the response is one small object per finding. Sizing it this way keeps a large batch from being truncated mid-list while not over-allocating for a small one. Non-dict entries are filtered out, so a model returning a stray string among its objects does not break the merge. A failed request returns an empty list rather than raising, which leaves the batch on its mechanical verdicts.
    """
    payload = [summarize(i, f) for i, f in enumerate(batch)]
    prompt = f"{intro}\n\n" + json.dumps(payload, indent=2)
    from ..ai.schema import coerce_to_vuln_list

    max_tokens = max(_MIN_VERDICT_BATCH_TOKENS, len(batch) * _PER_VERDICT_TOKENS)
    response = provider.analyze(prompt, system_message=system, schema=schema,
                                max_tokens=max_tokens)
    if not isinstance(response, dict) or response.get("error"):
        verbose_print(f"Validation request failed: {(response or {}).get('error')}",
                      verbose)
        return []
    parsed = coerce_to_vuln_list(response.get("response"))
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _judgment_view(index: int, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Build the compact view of an agent finding sent to the judgement pass.

    Parameters:
        index: Position in the batch, used as the id the model must echo back.
        finding: The finding dict.

    Returns:
        The view dict.

    Implementation notes:
        Fields are clipped to bounded lengths so one verbose finding cannot crowd out the rest of the batch. The class's proof requirement is attached, which is what lets the prompt ask whether the finding establishes what its class demands rather than merely asserts it. Mechanical verdicts are included only when they are not PASS, so the model sees what the gates already concluded and can agree or disagree, without being primed on findings the gates had no opinion about. Code in an unusual format carries a note saying how to read it (code_format_note).
    """
    gate = finding.get("gate_result") or {}
    view = {
        "id": index,
        "title": _text(finding.get("title") or finding.get("vulnerability_type")),
        "severity": finding.get("severity") or "",
        "vuln_class": finding.get("vuln_class") or "",
        "file": finding.get("file") or "",
        "line": finding.get("line") or finding.get("line_number") or "",
        "description": _clip(finding.get("description"), 700),
        "impact": _clip(finding.get("impact"), 400),
        "evidence": _clip(finding.get("code_snippet") or finding.get("evidence"), 400),
    }
    if code_format_note(finding):
        view["code_format"] = code_format_note(finding)
    proof = required_proof(finding.get("vuln_class") or "")
    if proof:
        view["proof_expected"] = proof
    if gate.get("verdict") and gate["verdict"] != "PASS":
        view["mechanical_verdict"] = gate["verdict"]
        view["mechanical_reasons"] = gate.get("reasons", [])
    return view


def _verify_view(index: int, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Build the view of a rule finding sent to the verification pass, centred on the source.

    Parameters:
        index: Position in the batch, used as the id.
        finding: The finding dict.

    Returns:
        The view dict.

    Implementation notes:
        Framed as a claim plus the code, because the question being asked is factual rather than evaluative. The detector name is included so the model knows what kind of pattern fired. The description is relabelled as why the rule fired, which is what it actually is for a rule finding, and stops the model treating a generic rule message as an assertion of fact. Code in an unusual format carries a note saying how to read it (code_format_note).
    """
    view = {
        "id": index,
        "claim": _text(finding.get("title") or finding.get("vulnerability_type")),
        "vuln_class": finding.get("vuln_class") or "",
        "severity": finding.get("severity") or "",
        "detector": finding.get("detector") or finding.get("source") or "rule",
        "file": finding.get("file") or "",
        "line": finding.get("line") or finding.get("line_number") or "",
        "why_the_rule_fired": _clip(finding.get("description"), 500),
        "code": _code_window(finding),
    }
    if code_format_note(finding):
        view["code_format"] = code_format_note(finding)
    proof = required_proof(finding.get("vuln_class") or "")
    if proof:
        view["proof_expected"] = proof
    return view


_DISASSEMBLY_NOTE = ("Blutter disassembly of the app's compiled Dart code: every line is written as a // "
                     "comment, and each one is an instruction the app executes, not a source comment.")


def code_format_note(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Say how to read a finding's code excerpt when its format is not ordinary source.

    Parameters:
        finding: The finding dict.

    Returns:
        A note for Blutter disassembly of a Flutter app, or "" for anything else.

    Implementation notes:
        Blutter writes each disassembled instruction as a "//" line under asm/, and a review pass reading one refuted a real pinning call because "the pattern matched comments, not executable code".
    """
    return _DISASSEMBLY_NOTE if str(finding.get("file") or "").replace("\\", "/").startswith("asm/") else ""


def _code_window(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Render the source around a finding with line numbers and a marker on the cited lines.

    Parameters:
        finding: The finding dict.

    Returns:
        The rendered window, the raw snippet, or an explicit note that no source was recovered.

    Implementation notes:
        Line numbers and a marker are included so the model can refer to a specific line in its reason, which is what makes a verdict checkable by the reader. An over-long context is trimmed around the highlighted line rather than from the start, keeping the relevant code centred. When no source exists at all, the placeholder tells the model to mark the finding unverified rather than guess. Without that instruction, a model presented with an empty code field tends to confirm from the claim alone -- exactly the failure this pass exists to prevent.
    """
    context = finding.get("code_context")
    if isinstance(context, dict) and context.get("lines"):
        start = int(context.get("start_line") or 1)
        lines = list(context["lines"])
        highlight_start = int(context.get("highlight_start") or start)
        highlight_end = int(context.get("highlight_end") or highlight_start)
        if len(lines) > VERIFY_CONTEXT_LINES * 2:
            centre = max(0, highlight_start - start)
            lo = max(0, centre - VERIFY_CONTEXT_LINES)
            hi = min(len(lines), centre + VERIFY_CONTEXT_LINES)
            lines, start = lines[lo:hi], start + lo
        out = []
        for offset, text in enumerate(lines):
            number = start + offset
            marker = ">" if highlight_start <= number <= highlight_end else " "
            out.append(f"{marker}{number:>5}| {text}")
        return "\n".join(out)

    snippet = _text(finding.get("evidence") or finding.get("code_snippet"))
    if snippet:
        return snippet[:1200]
    return "(no source was recovered for this finding - judge it UNVERIFIED " \
           "unless the claim is decidable without code)"


def _text(value) -> str:
    """
    Purpose:
        Coerce a value to a stripped string.

    Parameters:
        value: Any value, including None.

    Returns:
        The stripped text, or an empty string.
    """
    return str(value or "").strip()


def _clip(value, limit: int) -> str:
    """
    Purpose:
        Collapse whitespace and truncate text to a bounded length.

    Parameters:
        value: Any value.
        limit: Maximum length before truncation.

    Returns:
        The normalised text, with an ellipsis when truncated.

    Implementation notes:
        Whitespace is collapsed as well as truncated, so a multi-line description does not consume the budget on indentation before it reaches the limit.
    """
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


def _merge_judgment(finding: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """
    Purpose:
        Apply one judgement verdict back onto its finding.

    Parameters:
        finding: The finding dict, mutated in place.
        entry: The verdict object.

    Side effects:
        May change the finding's verdict, reason and severity.

    Implementation notes:
        A verdict outside the known ladder is ignored entirely rather than treated as a default, so a malformed response cannot alter a finding.
    """
    verdict = str(entry.get("verdict") or "").strip().upper()
    if verdict not in VERDICT_ORDER:
        return
    _apply(finding, verdict, entry.get("reason"), entry.get("severity"))


def _merge_verify(finding: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """
    Purpose:
        Apply one verification verdict back onto its rule finding.

    Parameters:
        finding: The finding dict, mutated in place.
        entry: The verdict object.

    Side effects:
        May change the finding's verdict, reason and severity, or mark it as source-verified.

    Implementation notes:
        The three verdicts map deliberately onto different outcomes. A false positive becomes Informational with the model's reason attached, not a deletion. Unverified becomes a downgrade rather than a rejection, because "could not tell" is not evidence against the finding. Confirmed records a verification flag and leaves the severity alone. A confirmed finding may carry a lower severity, and it is applied only when it is genuinely lower. This pass can never raise a severity: the model is looking at one excerpt, which is enough to weaken a claim but not enough to establish a stronger one. Each reason is prefixed with what the verdict means, so the report says how the conclusion was reached rather than presenting the model's sentence bare.
    """
    verdict = str(entry.get("verdict") or "").strip().upper()
    reason = _clip(entry.get("reason"), 400)

    if verdict == "FALSE_POSITIVE":
        _apply(finding, "FALSE_POSITIVE",
               f"Reviewed against the source and not confirmed: {reason}"
               if reason else "Reviewed against the source and not confirmed.",
               None)
        return

    if verdict == "UNVERIFIED":
        if normalize_severity(finding.get("severity")) == "Informational":
            return
        _apply(finding, "DOWNGRADE",
               f"Could not be confirmed from the available source: {reason}"
               if reason else "Could not be confirmed from the available source.",
               None)
        return

    if verdict == "CONFIRMED":
        gate = finding.setdefault("gate_result", GateResult().to_dict())
        gate["rule_verified"] = True
        if reason and reason not in gate.setdefault("reasons", []):
            gate["reasons"].append(f"Confirmed against the source: {reason}")
        proposed = entry.get("severity")
        if proposed and severity_rank(proposed) < severity_rank(finding.get("severity")):
            _apply(finding, "DOWNGRADE",
                   f"The source supports a lower severity: {reason}" if reason
                   else "The source supports a lower severity.", proposed)


def review_floor(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Find the lowest severity a review's DOWNGRADE may give a finding.

    Parameters:
        finding: The finding dict.

    Returns:
        The severity of the finding's CVSS vector re-scored for the strongest local attacker - local access with high privileges - or Low when that is lower or there is no vector.

    Implementation notes:
        A reviewer that downgrades because the attacker needs root, a backup or adb is restating what the vector's attack vector and privileges already score. Re-scoring the vector with that attacker gives the severity the claim is still worth: plaintext credentials an attacker with root reads (AV:L/PR:H/C:H) are 4.4, Medium. Once the review pass's answers were actually read, it moved every local-storage finding of a benchmark app to Low for "requires root or a backup", including credentials its own vector scored Medium for exactly that attacker. A finding that is not a vulnerability at all is still INFORMATIONAL, which this floor does not touch, and the impact metrics are kept, so a vector that overstates what is exposed still lowers it.
    """
    metrics = parse_vector(str(finding.get("cvss_vector") or ""))
    if metrics is None:
        return "Low"
    if metrics.get("AV") in ("N", "A"):
        metrics["AV"] = "L"
    metrics["PR"] = "H"
    floor = severity_from_vector("/".join(f"{key}:{value}" for key, value in metrics.items()))[0] or "Low"
    return floor if severity_rank(floor) > severity_rank("Low") else "Low"


def _apply(finding: Dict[str, Any], verdict: str, reason: Optional[str],
           proposed_severity: Optional[str]) -> None:
    """
    Purpose:
        Apply a verdict, its reason and any proposed severity to a finding, respecting the verdict ladder and any existing cap.

    Parameters:
        finding: The finding dict, mutated in place.
        verdict: The new verdict.
        reason: The explanation.
        proposed_severity: A severity the reviewer suggested, honoured only when lower.

    Side effects:
        Mutates the finding's severity and gate result.

    Implementation notes:
        A CHAIN_REQUIRED verdict on a class the catalogue marks standalone is applied as a DOWNGRADE: whether a class needs a partner is the catalogue's decision, and a reviewer that thinks the attacker's position is weak is saying the severity is lower, which the vector and a one-step downgrade express without collapsing the finding to Informational. A benchmark scan lost a PIN stored in plain preferences that way, the reviewer calling the private sandbox a reason to need a backup finding. A verdict no stronger than the current one still records its reason but does not change the verdict, so the AI can add context to a gate conclusion without weakening it. A proposed severity is used only when it is lower than the current one; otherwise the verdict's own one-step downgrade applies. This is what stops a review inflating severities. A DOWNGRADE says the finding is real but overstated, so it never takes a finding below review_floor, and never below Low: that is what INFORMATIONAL is for. A DOWNGRADE the floor stops entirely leaves the verdict where it was and records the reviewer's reason with why the severity held, rather than labelling an unchanged severity a downgrade. Once the review pass's answers were actually read, it moved five hardcoded secrets of one benchmark app to Informational under DOWNGRADE, and the scan graded the app A with nothing left to fix. The gate's severity cap is re-applied at the end, so a mitigation established mechanically survives the AI pass. Without that, a confirmation could undo a cap the code itself justified.
    """
    gate = finding.setdefault("gate_result", GateResult().to_dict())
    current = gate.get("verdict", "PASS")
    reason = _clip(reason, 400)
    if verdict == "CHAIN_REQUIRED":
        entry = describe(str(finding.get("vuln_class") or infer_vuln_class(finding)).strip().upper())
        if entry is not None and entry.standalone:
            verdict = "DOWNGRADE"

    if VERDICT_ORDER.index(verdict) <= VERDICT_ORDER.index(current):
        if verdict != "PASS" and reason and reason not in gate.setdefault("reasons", []):
            gate["reasons"].append(reason)
        return

    if verdict == "DOWNGRADE":
        held = normalize_severity(finding.get("severity"))
        floor = review_floor(finding)
        if severity_rank(held) <= severity_rank(floor):
            note = (f"{reason} " if reason else "") + (
                f"Kept at {held}: the CVSS vector, scored for an attacker with local access and "
                f"high privileges, still gives {floor}.")
            if note not in gate.setdefault("reasons", []):
                gate["reasons"].append(note)
            return

    gate["verdict"] = verdict
    if reason and reason not in gate.setdefault("reasons", []):
        gate["reasons"].append(reason)

    if verdict in ("CHAIN_REQUIRED", "FALSE_POSITIVE", "INFORMATIONAL"):
        final = "Informational"
    elif verdict == "DOWNGRADE":
        current_severity = normalize_severity(finding.get("severity"))
        proposed = normalize_severity(proposed_severity or "")
        final = (proposed if proposed_severity
                 and severity_rank(proposed) < severity_rank(current_severity)
                 else lower_severity(current_severity))
        floor = review_floor(finding)
        if severity_rank(final) < severity_rank(floor) <= severity_rank(current_severity):
            final = floor
    else:
        final = finding.get("severity") or gate.get("final_severity") or "Medium"

    cap = gate.get("severity_cap")
    if cap and severity_rank(cap) < severity_rank(final):
        final = normalize_severity(cap)

    finding["severity"] = final
    gate["final_severity"] = final


_SORT_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Order findings for the report.

    Parameters:
        findings: The findings to sort.

    Returns:
        A new list ordered by severity, then title.

    Implementation notes:
        Severity leads so the reader meets the serious findings first. Title breaks ties so that two runs over the same app produce the same order, which makes reports diffable. An unrecognised severity sorts as Medium, keeping it visible in the middle rather than hiding it at the end.
    """
    return sorted(
        findings,
        key=lambda f: (_SORT_ORDER.get(str(f.get("severity", "")).lower(), 2),
                       str(f.get("title") or "").lower()))
