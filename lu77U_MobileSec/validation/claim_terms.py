#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.claim_terms

Purpose:
    Decide whether a finding's prose is actually supported by the code it cites. A model can describe AES misuse convincingly for a snippet that contains no cryptography at all, and this module is how that is caught.

Responsibilities:
    Map security-relevant claims in a description to the API names that would have to appear in real code, extract candidate API tokens from prose, and test a code blob for corroboration.

Dependencies:
    re, dataclasses.

Implementation notes:
    The design is a two-sided vocabulary: triggers are what a model says, aliases are what the code would contain. They are deliberately different word lists -- a model writes "trusts all certificates", the code contains X509TrustManager -- and conflating them is what makes naive keyword checks useless here. Triggers are pre-split into word-boundary patterns and plain substrings at import. A short trigger like "des" or "rsa" must match as a word, or it fires inside unrelated identifiers; a multi-word phrase cannot use word boundaries the same way, so it is matched as a substring.

Security considerations:
    This is a hallucination control, and it fails in the safe direction: a claim with no recognised term is treated as supported, because suppressing findings this module simply does not understand would hide real vulnerabilities.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple


@dataclass(frozen=True)
class ClaimTerm:
    """
    Purpose:
        One security concept, in both the vocabulary a model uses to describe it and the vocabulary the code would use to implement it.

    Attributes:
        id: Stable identifier for the concept.
        triggers: Phrases that indicate the model is claiming this concept.
        aliases: API names and fragments that would appear in code actually doing it.

    Invariants:
        Frozen. Triggers are lowercase; aliases are lowercase and are matched against lowercased code.

    Thread-safety:
        Immutable and safe to share.
    """
    id: str
    triggers: Tuple[str, ...]
    aliases: Tuple[str, ...]


CLAIM_TERMS: Tuple[ClaimTerm, ...] = (
    ClaimTerm("aes", ("aes",),
              ("aes", "secretkeyspec", "cipher.getinstance", "javax.crypto",
               "keygenerator", "ivparameterspec")),
    ClaimTerm("des", ("des", "3des", "triple des"),
              ("des", "desede", "secretkeyspec", "cipher")),
    ClaimTerm("rsa", ("rsa",),
              ("rsa", "keyfactory", "x509encodedkeyspec", "publickey",
               "java.security")),
    ClaimTerm("md5", ("md5",),
              ("md5", "messagedigest", "digestutils")),
    ClaimTerm("sha1", ("sha-1", "sha1"),
              ("sha1", "sha-1", "messagedigest")),
    ClaimTerm("ecb", ("ecb",),
              ("ecb", "cipher.getinstance")),
    ClaimTerm("rawquery", ("rawquery",), ("rawquery",)),
    ClaimTerm("execsql", ("execsql",), ("execsql",)),
    ClaimTerm("jsbridge",
              ("addjavascriptinterface", "javascriptinterface", "js bridge",
               "javascript bridge"),
              ("addjavascriptinterface", "@javascriptinterface")),
    ClaimTerm("jsenabled", ("setjavascriptenabled", "javascript enabled"),
              ("setjavascriptenabled",)),
    ClaimTerm("fileaccess",
              ("setallowfileaccess", "universal file access",
               "file access from urls"),
              ("setallowfileaccess", "setallowuniversalaccessfromfileurls",
               "setallowfileaccessfromfileurls")),
    ClaimTerm("trustmanager",
              ("trustmanager", "trusts all", "trust all certificates",
               "certificate validation"),
              ("x509trustmanager", "trustmanager", "checkservertrusted",
               "sslcontext")),
    ClaimTerm("hostnameverifier",
              ("hostnameverifier", "hostname verification"),
              ("hostnameverifier", "verify(", "allow_all_hostname")),
    ClaimTerm("sslerror", ("onreceivedsslerror",),
              ("onreceivedsslerror", "sslerrorhandler", ".proceed(")),
    ClaimTerm("exec", ("runtime.exec", "runtime.getruntime", "command execution"),
              ("getruntime", ".exec(", "processbuilder")),
    ClaimTerm("dexclassloader",
              ("dexclassloader", "pathclassloader", "dynamic class loading"),
              ("dexclassloader", "pathclassloader", "loadclass")),
    ClaimTerm("pendingintent", ("pendingintent",),
              ("pendingintent", "flag_mutable", "flag_immutable")),
    ClaimTerm("sharedprefs", ("sharedpreferences",),
              ("sharedpreferences", "getsharedpreferences", "putstring")),
    ClaimTerm("biometric", ("biometricprompt", "fingerprintmanager"),
              ("biometricprompt", "fingerprintmanager", "cryptoobject")),
    ClaimTerm("webviewload", ("loadurl",), ("loadurl", "loaddata")),
    ClaimTerm("logging", ("log.d", "log.v", "logcat", "logged to logcat"),
              ("log.d", "log.v", "log.i", "log.e", "log.w", "android.util.log",
               "printstacktrace")),
)

BY_ID: Dict[str, ClaimTerm] = {t.id: t for t in CLAIM_TERMS}

_WORD_TRIGGERS: Tuple[Tuple[str, re.Pattern], ...] = tuple(
    (term.id, re.compile(r"\b" + re.escape(trigger) + r"\b"))
    for term in CLAIM_TERMS
    for trigger in term.triggers
    if re.fullmatch(r"[a-z0-9]+", trigger)
)
_PHRASE_TRIGGERS: Tuple[Tuple[str, str], ...] = tuple(
    (term.id, trigger)
    for term in CLAIM_TERMS
    for trigger in term.triggers
    if not re.fullmatch(r"[a-z0-9]+", trigger)
)


def salient_terms(text: str) -> List[str]:
    """
    Purpose:
        Identify which security concepts a finding's description is claiming.

    Parameters:
        text: The description, or any text.

    Returns:
        Concept identifiers, ordered as the catalogue declares them rather than as they appeared in the text.

    Complexity:
        O(n * t) for text length n and trigger count t.

    Implementation notes:
        Word triggers are tested before phrase triggers, and each concept is recorded once however many of its triggers matched. The result is re-ordered into catalogue order so that two descriptions claiming the same concepts produce identical lists regardless of wording. That determinism matters because these lists are compared during deduplication.
    """
    haystack = str(text or "").lower()
    if not haystack:
        return []
    found: List[str] = []
    for term_id, pattern in _WORD_TRIGGERS:
        if term_id not in found and pattern.search(haystack):
            found.append(term_id)
    for term_id, trigger in _PHRASE_TRIGGERS:
        if term_id not in found and trigger in haystack:
            found.append(term_id)
    return [t.id for t in CLAIM_TERMS if t.id in found]


_API_TOKEN_RE = re.compile(
    r"\b([a-z][a-z0-9]*(?:[A-Z][A-Za-z0-9]*)+|[A-Za-z][\w]*\.[a-z][A-Za-z0-9]*)\b")

_API_STOPWORDS = frozenset({
    "javascript", "javascriptinterface", "webview", "webviewclient", "jsonobject",
    "jsonarray", "arraylist", "hashmap", "stringbuilder", "onreceive", "oncreate",
    "onresume", "onpause", "onstart", "onstop", "ondestroy", "onactivityresult",
    "getintent", "getstring", "getcontext", "getapplicationcontext",
    "isempty", "tostring", "hashcode", "equals",
})


def api_terms(text: str) -> List[str]:
    """
    Purpose:
        Extract API-looking tokens from a description that the claim catalogue does not already cover, so that a specific claim can still be checked against the code.

    Parameters:
        text: The description, or any text.

    Returns:
        Candidate API tokens in order of first appearance, without duplicates.

    Complexity:
        O(n) in text length.

    Implementation notes:
        Tokens are recognised by shape -- camelCase, or a dotted qualified name -- because those are what API references look like in prose and ordinary English words are not. Tokens already covered by the claim catalogue are excluded, since those are handled by the stronger trigger-and-alias mechanism. The stopword list removes tokens that are shaped like APIs but say nothing about security: lifecycle callbacks, collection classes and generic getters appear in almost every snippet and would corroborate anything. Case is preserved in the output because the token is shown to a reader, while matching is done lowercased.
    """
    haystack = str(text or "")
    if not haystack:
        return []
    covered = {t.lower() for _, t in _PHRASE_TRIGGERS}
    covered |= {trig for term in CLAIM_TERMS for trig in term.triggers}
    out: List[str] = []
    for raw in _API_TOKEN_RE.findall(haystack):
        token = raw.strip()
        low = token.lower()
        bare = low.split(".")[-1]
        if low in _API_STOPWORDS or bare in _API_STOPWORDS:
            continue
        if low in covered or bare in covered:
            continue
        if token not in out:
            out.append(token)
    return out


def aliases_for(term_ids: Sequence[str]) -> Tuple[str, ...]:
    """
    Purpose:
        Collect the code-side vocabulary for a set of claimed concepts.

    Parameters:
        term_ids: Concept identifiers, typically from salient_terms.

    Returns:
        The aliases, deduplicated and in order.

    Complexity:
        O(n) in the total number of aliases.

    Implementation notes:
        Unknown identifiers are skipped rather than raising, so a stale or hand-written identifier degrades to contributing nothing.
    """
    out: List[str] = []
    for term_id in term_ids:
        term = BY_ID.get(term_id)
        if term is None:
            continue
        for alias in term.aliases:
            if alias not in out:
                out.append(alias)
    return tuple(out)


def evidence_supports(term_ids: Sequence[str], blob: str) -> bool:
    """
    Purpose:
        Test whether a code blob corroborates the concepts a finding claims.

    Parameters:
        term_ids: Concepts claimed by the description.
        blob: The cited code, lowercased internally before matching.

    Returns:
        True when at least one alias of at least one claimed concept appears in the code.

    Complexity:
        O(n * a) for blob length n and alias count a.

    Implementation notes:
        No claimed concepts returns True. A description that makes no recognised claim is not evidence of a hallucination, and rejecting it would discard every finding this module has no vocabulary for. An empty blob returns False when there were claims, because a claim about code with no code to show is exactly the case this exists to catch. Corroboration requires only one alias, not all. A real finding about certificate validation may show only the trust manager or only the hostname verifier, and demanding both would reject correct findings.
    """
    if not term_ids:
        return True
    haystack = str(blob or "").lower()
    if not haystack:
        return False
    return any(alias in haystack for alias in aliases_for(term_ids))
