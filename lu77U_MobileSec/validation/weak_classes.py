#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.weak_classes

Purpose:
    Recognise the findings that are technically true but are not vulnerabilities on their own -- missing pinning, backup enabled, no obfuscation, a permission being requested -- and record why each one does not stand alone.

Responsibilities:
    Declare the weak-class rules with their reasons, and classify a finding into one of them by vulnerability class or by wording.

Dependencies:
    re, .taxonomy for the class lookup.

Implementation notes:
    These are the findings every mobile scanner produces in bulk and which make a report look thorough while telling the reader nothing. Each rule carries a written reason, not just a flag, because the reason is shown to the user: suppressing a finding without explaining why is indistinguishable from missing it. The chain_eligible flag splits the set in two. Some of these become genuine findings when paired with something concrete -- backup extraction matters once a credential is named in app storage -- while others never do, because the control they describe was never a security boundary. Root detection and obfuscation are in the second group by design. Classification is attempted by vulnerability class first and falls back to wording, so a finding that carries a proper class is judged on that rather than on how it happens to be phrased.

Security considerations:
    This module suppresses findings, so a rule that is too broad hides real vulnerabilities. The patterns are written against the way these specific observations are phrased, and the class-code mapping is preferred precisely because it is exact where the patterns are heuristic.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .taxonomy import describe


@dataclass(frozen=True)
class WeakClassRule:
    """
    Purpose:
        One category of finding that is not reportable on its own, with the explanation of why.

    Attributes:
        id: Stable rule identifier.
        label: Human-readable name.
        patterns: Lowercase substrings that identify this observation in a finding's wording.
        chain_eligible: Whether this can become a real finding when paired with a concrete one.
        codes: Vulnerability class codes that map to this rule exactly.
        reason: The explanation shown to the user, stating what would make it a finding.

    Invariants:
        Frozen. Patterns are lowercase and are matched against normalised wording.

    Thread-safety:
        Immutable and safe to share.
    """
    id: str
    label: str
    patterns: Tuple[str, ...]
    chain_eligible: bool
    codes: Tuple[str, ...] = ()
    reason: str = ""


WEAK_CLASS_RULES: Tuple[WeakClassRule, ...] = (
    WeakClassRule(
        id="WEAK-01",
        label="No certificate pinning",
        codes=("NETWORK-03",),
        patterns=("certificate pinning", "cert pinning", "missing pinning",
                  "ssl pinning", "no pinning"),
        chain_eligible=True,
        reason=(
            "Pinning defends against an attacker who already controls a trusted CA or "
            "the device's trust store. Without one of those, TLS is still doing its "
            "job. It becomes a finding when paired with what the unpinned channel "
            "actually carries."),
    ),
    WeakClassRule(
        id="WEAK-02",
        label="Backup-extractable app data",
        codes=("STORAGE-04",),
        patterns=("allowbackup", "allow backup", "backup enabled",
                  "backup is enabled", "backup-enabled", "adb backup"),
        chain_eligible=True,
        reason=(
            "Backup is a documented platform feature, and the default below "
            "targetSdk 31. What matters is what would be in the backup: name a "
            "credential in app storage and this becomes a real extraction path."),
    ),
    WeakClassRule(
        id="WEAK-03",
        label="Debuggable release build",
        codes=("BUILD-01",),
        patterns=("debuggable", "debug-overrides", "debug overrides"),
        chain_eligible=False,
        reason=(
            "A debuggable build is a release-pipeline defect rather than an "
            "exploitable flaw - attaching a debugger already requires ADB access to "
            "the device. Worth fixing, not worth a severity."),
    ),
    WeakClassRule(
        id="WEAK-04",
        label="Missing anti-tamper control",
        codes=("BUILD-04",),
        patterns=("root detection", "missing root", "rooted device detection",
                  "jailbreak detection", "emulator detection", "tamper detection"),
        chain_eligible=False,
        reason=(
            "These controls run on the device they are trying to check, so an "
            "attacker who has rooted their own phone can always defeat them. Their "
            "absence harms nobody who has not already done so."),
    ),
    WeakClassRule(
        id="WEAK-05",
        label="Cleartext permitted by configuration",
        codes=("NETWORK-02",),
        patterns=("cleartext traffic", "cleartext http traffic",
                  "cleartexttrafficpermitted", "usescleartexttraffic",
                  "cleartext is permitted", "arbitrary loads"),
        chain_eligible=True,
        reason=(
            "The flag permits HTTP; it does not show that anything is sent over it. "
            "Name a request that actually goes out in cleartext, and what it carries, "
            "and this is a genuine finding."),
    ),
    WeakClassRule(
        id="WEAK-06",
        label="Missing binary hardening flags",
        patterns=("missing aslr", "missing pie", "stack canary", "no pie",
                  "binary protection", "relro"),
        chain_eligible=False,
        reason=(
            "PIE and ASLR are mandatory and enforced by the loader on every supported "
            "Android release, so the protection is not actually absent at runtime."),
    ),
    WeakClassRule(
        id="WEAK-07",
        label="Certificate shipped inside the app",
        patterns=("self signed cert", "self-signed cert", "self_signed",
                  "certificate in assets", "bundled certificate"),
        chain_eligible=False,
        reason=(
            "A certificate bundled in the APK is usually the root the app deliberately "
            "pins to - the opposite of a weakness."),
    ),
    WeakClassRule(
        id="WEAK-08",
        label="Third-party data collection",
        patterns=("analytics data", "tracking data", "analytics collection",
                  "telemetry collection", "advertising id", "user tracking"),
        chain_eligible=False,
        reason=(
            "What an analytics SDK collects is a privacy and disclosure question, "
            "answered by the app's policy rather than by its security posture."),
    ),
    WeakClassRule(
        id="WEAK-09",
        label="Clipboard access",
        patterns=("clipboard access", "clipboard manager", "pasteboard access"),
        chain_eligible=True,
        reason=(
            "Android 12 and later show a system notice whenever an app reads the "
            "clipboard, and access is limited to the foreground app. It matters only "
            "if the app puts something sensitive on the clipboard."),
    ),
    WeakClassRule(
        id="WEAK-10",
        label="Code not obfuscated",
        patterns=("missing obfuscation", "no obfuscation", "code obfuscation",
                  "not obfuscated", "obfuscation is not enabled"),
        chain_eligible=False,
        reason=(
            "Obfuscation raises the cost of reading an app; it does not prevent it. "
            "Anything protected by obfuscation alone was never protected."),
    ),
    WeakClassRule(
        id="WEAK-11",
        label="Legacy platform behaviour from SDK levels",
        codes=("BUILD-02",),
        patterns=("minsdkversion", "targetsdkversion", "implicit component export"),
        chain_eligible=True,
        reason=(
            "An SDK level is a statement about which platform defaults apply, not a "
            "defect. It is context for the findings that depend on those defaults - "
            "pair it with one of them."),
    ),
    WeakClassRule(
        id="WEAK-12",
        label="Permissions requested",
        codes=("BUILD-03",),
        patterns=("dangerous permission", "excessive permission",
                  "requests permission"),
        chain_eligible=True,
        reason=(
            "A permission describes what the app could do with a vulnerability, not "
            "that it has one. It widens the impact of another finding; on its own it "
            "is inventory."),
    ),
)

BY_ID: Dict[str, WeakClassRule] = {r.id: r for r in WEAK_CLASS_RULES}
_BY_CODE: Dict[str, WeakClassRule] = {
    code: rule for rule in WEAK_CLASS_RULES for code in rule.codes}


def _wording(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Normalise a finding's title and type into one lowercase string for pattern matching.

    Parameters:
        finding: The finding dict.

    Returns:
        The normalised wording; empty when neither field is present.

    Complexity:
        O(n) in the combined field length.

    Implementation notes:
        Underscores and hyphens collapse to spaces so that "allow_backup", "allow-backup" and "allow backup" all match one pattern. Both fields are joined because a model puts the substance in whichever of them it prefers.
    """
    parts = (finding.get("title") or "", finding.get("vulnerability_type") or "")
    return re.sub(r"[_\-]+", " ", " ".join(str(p) for p in parts)).lower()


def classify_weak(finding: Dict[str, Any]) -> Optional[WeakClassRule]:
    """
    Purpose:
        Decide whether a finding belongs to a weak class, and if so which.

    Parameters:
        finding: The finding dict.

    Returns:
        The matching rule, or None when the finding is not a weak class.

    Complexity:
        O(r * p) for rule count r and patterns per rule p, only on the wording path.

    Implementation notes:
        A finding carrying a recognised vulnerability class is classified by that code alone and never falls through to pattern matching. This is the important case: a model that classified correctly has already said what kind of finding this is, and re-judging it on wording would let a phrase in the title override an accurate classification. Pattern matching applies only when the class code is unknown or absent, which is where a description-shaped guess is the only signal available. The first matching rule wins; rules are ordered so that the more specific observations come first.
    """
    code = str(finding.get("vuln_class") or "").strip().upper()
    if describe(code) is not None:
        return _BY_CODE.get(code)
    return next((rule for rule in WEAK_CLASS_RULES
                 if any(p in _wording(finding) for p in rule.patterns)), None)
