#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.chains

Purpose:
    Find the cases where two individually-modest findings combine into something serious, have the combination confirmed rather than assumed, and write it up as a finding in its own right.

Responsibilities:
    Declare the chain patterns, propose candidate pairs, annotate findings with their relationships, confirm candidates through an AI pass, and synthesise chain findings.

Dependencies:
    .gates for severity handling, ..ai.schema for response coercion, ..utils.cancellation.

Implementation notes:
    Chaining is the answer to the weak-class problem. Missing pinning is not a finding; missing pinning next to a trust-all TrustManager is. Rather than report both as noise or suppress both, the chain patterns name the specific combinations that matter and the result is one finding with a real attack path. Pattern matching alone would produce nonsense -- two WebView findings in unrelated Activities are not a chain. So matching only proposes candidates, and an AI pass answers the question a pattern cannot: whether data actually flows from one component to the other in this app. Candidates are ranked and capped so the cost stays bounded. A small set of pairings is confirmed deterministically instead, where the relationship is definitional rather than dependent on data flow. Those cost no tokens and are marked as auto-confirmed.

Security considerations:
    A chain finding carries a high severity by construction, so a false chain is expensive. The confirmation prompt is explicit that unrelated components and speculative flows must be rejected, and the model is forbidden from inventing components that are not in the findings it was given.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .gates import normalize_severity, severity_rank
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import plural, verbose_print


@dataclass(frozen=True)
class ChainPattern:
    """
    Purpose:
        One named combination of two findings that together form an exploitable path.

    Attributes:
        id: Stable pattern identifier, used as the chain finding's vulnerability class.
        title: The chain's name, shown as the finding title.
        entry_classes: Vulnerability classes that can act as the attacker's way in.
        target_classes: Vulnerability classes that can act as what the entry point reaches.
        impact: What the attacker gains, written for the app owner.
        severity: Severity the chain warrants when confirmed.
        cvss_vector: CVSS vector describing the combination rather than either part.
        entry_keywords: Wording that identifies an entry component when it carries no class.
        target_keywords: Wording that identifies a target component when it carries no class.
        priority: Whether this pattern is evaluated before others when candidates are capped.
        recommendation: How to break the chain, naming the specific fix.

    Invariants:
        Frozen. The CVSS vector describes the chain, which is why it is stated per pattern rather than derived from the components.

    Thread-safety:
        Immutable and safe to share.
    """
    id: str
    title: str
    entry_classes: Tuple[str, ...]
    target_classes: Tuple[str, ...]
    impact: str
    severity: str
    cvss_vector: str
    entry_keywords: Tuple[str, ...] = ()
    target_keywords: Tuple[str, ...] = ()
    priority: bool = False
    recommendation: str = ""


CHAIN_PATTERNS: Tuple[ChainPattern, ...] = (
    ChainPattern(
        id="CHAIN-01",
        title="Deep link reaches a WebView with a native JavaScript bridge",
        entry_classes=("PLATFORM-02", "PLATFORM-01", "PLATFORM-03"),
        target_classes=("PLATFORM-04",),
        entry_keywords=("deep link", "deeplink", "intent-filter", "scheme",
                        "exported activity", "getstringextra", "intent extra"),
        target_keywords=("addjavascriptinterface", "javascript interface",
                         "javascript bridge", "js bridge"),
        impact=(
            "An attacker who can get the victim to open one link - from a web page, "
            "an SMS, a QR code or another installed app - chooses what the WebView "
            "loads. Because a native object is bound into that WebView, the attacker's "
            "page can call every @JavascriptInterface method on it, with the app's own "
            "permissions and data access. This is remote code execution in the app's "
            "context and needs no installed malware."),
        severity="Critical",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        recommendation=(
            "Validate the deep-link URL against an allowlist of exact hosts before it "
            "reaches any WebView - check the parsed host, never a substring - and "
            "reject the javascript:, file: and data: schemes outright. Bind the "
            "JavaScript interface only after the WebView has committed to a trusted "
            "origin, and remove it on navigation away."),
        priority=True,
    ),
    ChainPattern(
        id="CHAIN-02",
        title="Deep link loads an attacker URL into an authenticated WebView",
        entry_classes=("PLATFORM-02", "PLATFORM-01", "PLATFORM-03"),
        target_classes=("PLATFORM-05", "PLATFORM-06"),
        entry_keywords=("deep link", "deeplink", "intent-filter", "scheme",
                        "url parameter", "redirect"),
        target_keywords=("loadurl", "webview loads", "file access", "cookie",
                         "session", "universal access"),
        impact=(
            "The deep link's URL parameter reaches the WebView without a host "
            "allowlist, so an attacker picks the page that renders inside the app's "
            "trusted UI while it still holds the user's session. Depending on the "
            "WebView's settings that means cookie and token theft, local file reads "
            "through file://, or script execution via javascript: and data: URLs."),
        severity="High",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        recommendation=(
            "Parse the incoming URL and compare its host against an exact allowlist. "
            "Reject every scheme except https. Do not rely on contains() or "
            "startsWith() checks - 'trusted.com' matches 'trusted.com.evil.com'."),
        priority=True,
    ),
    ChainPattern(
        id="CHAIN-03",
        title="Exported ContentProvider exposes an injectable SQL query",
        entry_classes=("PLATFORM-01",),
        target_classes=("CODE-01", "STORAGE-03"),
        entry_keywords=("exported content provider", "exported provider"),
        target_keywords=("sql injection", "rawquery", "execsql", "selection"),
        impact=(
            "Any installed app can query the provider, and the query is built by "
            "string concatenation, so the caller controls the SQL. The whole database "
            "is readable - and writable where the provider allows it - by an app that "
            "declares no permissions at all."),
        severity="Critical",
        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        recommendation=(
            "Set android:exported=\"false\" if no other app needs the provider. If it "
            "does, use parameterised selection arguments only, and validate the "
            "projection and sort order against a fixed allowlist."),
    ),
    ChainPattern(
        id="CHAIN-04",
        title="Exported component consumes attacker-controlled Intent data",
        entry_classes=("PLATFORM-01",),
        target_classes=("PLATFORM-03", "PLATFORM-02"),
        entry_keywords=("exported activity", "exported service", "exported receiver"),
        target_keywords=("intent extra", "getstringextra", "intent redirection",
                         "unvalidated"),
        impact=(
            "The component is invokable by any app on the device and acts on the "
            "Intent it is handed without validating it, so a malicious app drives the "
            "target app's privileged behaviour with data of its choosing."),
        severity="High",
        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        recommendation=(
            "Guard the component with a signature-level permission, or unexport it. "
            "Validate every Intent extra before use, and never forward a nested Intent "
            "received from a caller."),
    ),
    ChainPattern(
        id="CHAIN-05",
        title="Backup-enabled app stores credentials in local storage",
        entry_classes=("STORAGE-04",),
        target_classes=("SECRET-01", "STORAGE-03"),
        entry_keywords=("allowbackup", "backup enabled", "backup-enabled"),
        target_keywords=("sharedpreferences", "token", "credential", "password",
                         "session", "plaintext"),
        impact=(
            "`adb backup` copies the app's private storage off the device without root, "
            "and that storage holds a credential. Anyone with a minute of USB access to "
            "an unlocked phone walks away with the user's session."),
        severity="High",
        cvss_vector="AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        recommendation=(
            "Set android:allowBackup=\"false\", or exclude the credential store via "
            "android:dataExtractionRules. Keep tokens in EncryptedSharedPreferences or "
            "the Keystore rather than plain SharedPreferences."),
    ),
    ChainPattern(
        id="CHAIN-06",
        title="WebView file access reachable from attacker-controlled content",
        entry_classes=("PLATFORM-05",),
        target_classes=("PLATFORM-02", "PLATFORM-04", "PLATFORM-01"),
        entry_keywords=("file access", "allowfileaccess", "universal access"),
        target_keywords=("loadurl", "deep link", "intent", "javascript"),
        impact=(
            "The WebView is allowed to read local files from web content, and its URL "
            "is influenced from outside the app. An attacker's page reads the app's "
            "private files - SharedPreferences XML, databases, cached tokens - and "
            "posts them out."),
        severity="High",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        recommendation=(
            "Disable setAllowFileAccessFromFileURLs and "
            "setAllowUniversalAccessFromFileURLs, and set setAllowFileAccess(false) "
            "unless the WebView genuinely needs to render local files."),
    ),
    ChainPattern(
        id="CHAIN-07",
        title="Unprotected broadcast carries sensitive data",
        entry_classes=("PLATFORM-07",),
        target_classes=("SECRET-01", "AUTH-01"),
        entry_keywords=("broadcast", "sendbroadcast", "exported receiver"),
        target_keywords=("token", "session", "credential", "otp", "secret"),
        impact=(
            "The broadcast is sent without a receiver permission, so any app that has "
            "registered for the action receives it - along with the token it carries."),
        severity="High",
        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        recommendation=(
            "Send the broadcast with an explicit component or a signature-level "
            "permission, or use LocalBroadcastManager. Never put a credential in a "
            "system-wide broadcast."),
    ),
    ChainPattern(
        id="CHAIN-08",
        title="Mutable PendingIntent with an implicit base Intent",
        entry_classes=("PLATFORM-08",),
        target_classes=("PLATFORM-01", "PLATFORM-03"),
        entry_keywords=("pendingintent", "flag_mutable", "mutable pending"),
        target_keywords=("implicit", "intent", "exported"),
        impact=(
            "A mutable PendingIntent wrapping an implicit Intent lets whoever receives "
            "it fill in the blanks and have the action executed with the granting app's "
            "identity and permissions."),
        severity="High",
        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        recommendation=(
            "Create PendingIntents with FLAG_IMMUTABLE, and always set an explicit "
            "component on the base Intent."),
    ),
    ChainPattern(
        id="CHAIN-09",
        title="Unpinned TLS carries credentials that are also weakly protected",
        entry_classes=("NETWORK-01",),
        target_classes=("SECRET-01", "CRYPTO-01", "AUTH-01"),
        entry_keywords=("pinning", "cleartext", "trusts user", "tls", "certificate"),
        target_keywords=("token", "credential", "password", "api key", "session"),
        impact=(
            "An attacker positioned on the network - a shared Wi-Fi access point, a "
            "user-installed CA, a hostile VPN - reads the channel, and the channel "
            "carries the credential."),
        severity="High",
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        recommendation=(
            "Pin the API certificate or its issuing key in the network security "
            "config, and stop trusting user-installed CAs for the API domain."),
    ),
    ChainPattern(
        id="CHAIN-10",
        title="Weak cryptography protects data that is locally extractable",
        entry_classes=("CRYPTO-01",),
        target_classes=("STORAGE-03", "STORAGE-04", "SECRET-01"),
        entry_keywords=("ecb", "hardcoded key", "hardcoded iv", "des", "rc4",
                        "md5", "weak cipher"),
        target_keywords=("database", "sharedpreferences", "backup", "local storage",
                         "external storage"),
        impact=(
            "The encryption on the stored data is reversible - a hardcoded key in the "
            "app, or a mode that leaks structure - and the ciphertext is reachable "
            "without root. The encryption buys nothing."),
        severity="High",
        cvss_vector="AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        recommendation=(
            "Use AES-GCM with a key generated in and held by the Android Keystore. A "
            "key compiled into the APK is public."),
    ),
)


def _text_of(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Flatten a finding's descriptive fields into one lowercase blob for keyword matching.

    Parameters:
        finding: The finding dict.

    Returns:
        The combined text.
    """
    return " ".join(str(finding.get(k) or "") for k in
                    ("title", "vulnerability_type", "description", "impact")).lower()


def _class_of(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Read a finding's vulnerability class in normalised form.

    Parameters:
        finding: The finding dict.

    Returns:
        The class code, or an empty string.
    """
    return str(finding.get("vuln_class") or "").strip().upper()


def _plays_role(finding: Dict[str, Any], classes: Sequence[str],
                keywords: Sequence[str]) -> bool:
    """
    Purpose:
        Decide whether a finding can act as one end of a chain pattern.

    Parameters:
        finding: The finding dict.
        classes: Classes acceptable for this role.
        keywords: Wording accepted when the finding carries no class.

    Returns:
        True when the finding fits the role.

    Implementation notes:
        A finding with a class is matched on class alone and never falls back to keywords. This matters: a classified finding has already been told what it is, and letting a stray phrase in its description qualify it for a role would manufacture chains out of wording. Keywords apply only to unclassified findings, which is where rule-engine output and imperfect model output land.
    """
    code = _class_of(finding)
    if code:
        return code in classes
    text = _text_of(finding)
    return any(keyword in text for keyword in keywords)


def find_candidate_chains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Propose every pair of findings that matches a chain pattern.

    Parameters:
        findings: All findings.

    Returns:
        Candidate dicts naming the pattern and the two findings, ordered by priority then severity.

    Complexity:
        O(p * n squared) for p patterns and n findings, which is acceptable because the caller caps how many candidates are evaluated.

    Implementation notes:
        Direction matters, so a pair is considered in both orders -- one finding may be the entry for one pattern and the target for another -- but an unordered pair is recorded once per pattern so the same two findings are not proposed twice under one pattern. Ordering puts priority patterns first and then ranks by the more severe of the two components, so that when the list is truncated it is the least promising candidates that are dropped.
    """
    candidates: List[Dict[str, Any]] = []
    seen: set = set()
    for pattern in sorted(CHAIN_PATTERNS, key=lambda p: (not p.priority, p.id)):
        for i, entry in enumerate(findings):
            if not _plays_role(entry, pattern.entry_classes, pattern.entry_keywords):
                continue
            for j, target in enumerate(findings):
                if i == j:
                    continue
                if not _plays_role(target, pattern.target_classes, pattern.target_keywords):
                    continue
                key = (pattern.id, i, j)
                pair = frozenset((i, j))
                if key in seen or (pattern.id, pair) in seen:
                    continue
                seen.add(key)
                seen.add((pattern.id, pair))
                candidates.append({"pattern": pattern, "entry_index": i,
                                   "target_index": j})
    candidates.sort(key=lambda c: (
        not c["pattern"].priority,
        -max(severity_rank(findings[c["entry_index"]].get("severity")),
             severity_rank(findings[c["target_index"]].get("severity")))))
    return candidates


_CONFIRM_SYSTEM = """You are checking whether two findings from one Android app \
actually combine into the exploit chain proposed, in this specific app.

The proposal is a pattern match: the two findings look like the right shapes. Your \
job is the part a pattern cannot answer - whether attacker-controlled data really \
travels from the first component to the second in this code.

Confirm a chain only when all of these hold:
- Both components exist in the same app and the same execution path.
- The first component is reachable by an attacker who has not compromised the device.
- Data or control genuinely flows from the first to the second. Two WebView findings \
in unrelated Activities do not chain just because both are WebViews.
- The combination is worse than either finding alone.

Reject when the components are in unrelated code, when the flow is speculative, or \
when the same underlying issue is being counted twice.

For each proposal return: confirmed (true/false); a one-line reason when rejecting, or \
when confirming something not obvious from the flow - omit it otherwise; and when \
confirmed, `flow` - at most 6 ordered concrete steps an attacker takes, each one short \
clause naming the component involved. Write the flow so the app's owner can follow it in \
their own code, referencing the files and classes from the findings. Do not invent \
components that are not in the findings you were given."""

_CHAIN_REASON_MAX = 160
_CHAIN_STEP_MAX = 120
_CHAIN_FLOW_MAX_STEPS = 6

_CONFIRM_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "description": "The proposal's id."},
            "confirmed": {"type": "boolean"},
            "reason": {"type": "string", "maxLength": _CHAIN_REASON_MAX,
                       "description": "One short sentence. Omit when confirmed is false "
                                      "and the rejection is obvious from the proposal."},
            "flow": {"type": "array",
                     "items": {"type": "string", "maxLength": _CHAIN_STEP_MAX},
                     "maxItems": _CHAIN_FLOW_MAX_STEPS,
                     "description": "Ordered attacker steps, one short clause each; "
                                    "required when confirmed."},
        },
        "required": ["id", "confirmed"],
    },
}

MAX_CANDIDATES = 48


MAX_RELATED = 5


def _ref(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Build the compact reference used to point at another finding.

    Parameters:
        finding: The finding dict.

    Returns:
        Title, file and line.

    Implementation notes:
        Kept minimal so that related-finding entries stay small and can be compared by equality for deduplication.
    """
    return {"title": finding.get("title") or finding.get("vulnerability_type") or "",
            "file": finding.get("file") or "",
            "line": finding.get("line") or finding.get("line_number") or ""}


def _add_related(finding: Dict[str, Any], entry: Dict[str, Any], reason: str,
                 pattern_id: str = "") -> None:
    """
    Purpose:
        Record a relationship from one finding to another, without duplication.

    Parameters:
        finding: The finding gaining the relationship, mutated in place.
        entry: The finding being pointed at.
        reason: Why they are related.
        pattern_id: The pattern or relationship kind.

    Side effects:
        Appends to the finding's related list.

    Implementation notes:
        Capped, because a finding in a file with many others would otherwise accumulate dozens of relationships and the report section would become unreadable. Deduplicated on target plus pattern, so the same pair under two different patterns is recorded twice -- which is correct, they are different relationships. Relationships start unconfirmed; confirmation is written back later only for chains the model accepted.
    """
    related = finding.setdefault("related_findings", [])
    if len(related) >= MAX_RELATED:
        return
    candidate = {"reason": reason, "pattern": pattern_id,
                 "with": _ref(entry), "confirmed": False}
    for existing in related:
        if existing["with"] == candidate["with"] and existing["pattern"] == pattern_id:
            return
    related.append(candidate)


def annotate_related_findings(findings: List[Dict[str, Any]]) -> int:
    """
    Purpose:
        Attach relationship annotations to findings, so a report can show what sits near what even where no chain was confirmed.

    Parameters:
        findings: All findings, mutated in place.

    Returns:
        The number of relationships added.

    Side effects:
        Mutates findings.

    Implementation notes:
        Two kinds of relationship are added: unconfirmed chain candidates, and same-file co-location. Same-file relationships are deliberately weak and labelled as such. They exist because a reader fixing one issue benefits from seeing the others in the same file, not because proximity implies a chain. Chain candidates are annotated in both directions, so either finding shows the relationship.
    """
    if not findings:
        return 0
    added = 0

    for candidate in find_candidate_chains(findings):
        pattern = candidate["pattern"]
        entry = findings[candidate["entry_index"]]
        target = findings[candidate["target_index"]]
        reason = f"unconfirmed chain candidate: {pattern.title}"
        before = len(entry.get("related_findings", [])) + len(
            target.get("related_findings", []))
        _add_related(entry, target, reason, pattern.id)
        _add_related(target, entry, reason, pattern.id)
        added += (len(entry.get("related_findings", [])) + len(
            target.get("related_findings", []))) - before

    by_file: Dict[str, List[int]] = {}
    for index, finding in enumerate(findings):
        path = str(finding.get("file") or "").strip()
        if path:
            by_file.setdefault(path, []).append(index)

    for path, indexes in by_file.items():
        if len(indexes) < 2:
            continue
        for i in indexes:
            for j in indexes:
                if i == j:
                    continue
                before = len(findings[i].get("related_findings", []))
                _add_related(findings[i], findings[j],
                             "same file", "same-file")
                added += len(findings[i].get("related_findings", [])) - before

    return added


def _mark_confirmed(chain_finding: Dict[str, Any], entry: Dict[str, Any],
                    target: Dict[str, Any], pattern_id: str) -> None:
    """
    Purpose:
        Upgrade the annotations on two components once their chain has been confirmed.

    Parameters:
        chain_finding: The synthesised chain finding.
        entry: The entry component, mutated in place.
        target: The target component, mutated in place.
        pattern_id: The pattern that was confirmed.

    Side effects:
        Sets the confirmed flag and rewrites the reason on the matching annotations.

    Implementation notes:
        Matched on pattern plus reference, so only the annotation for this specific chain is upgraded and other candidate relationships between the same pair stay unconfirmed.
    """
    for finding, other in ((entry, target), (target, entry)):
        for related in finding.get("related_findings") or []:
            if related.get("pattern") == pattern_id and related["with"] == _ref(other):
                related["confirmed"] = True
                related["reason"] = f"confirmed chain: {chain_finding.get('title', '')}"


_AUTO_PAIRINGS: Tuple[Tuple[str, Tuple[str, ...], ChainPattern], ...] = (
    ("WEAK-01", ("NETWORK-01",), ChainPattern(
        id="CHAIN-AUTO-01",
        title="Missing certificate pinning leaves an active TLS bypass unmitigated",
        entry_classes=(), target_classes=(),
        impact="An attacker on the network path - a rogue Wi-Fi access point, a "
               "compromised router - presents any certificate and the app accepts "
               "it. Nothing else in the app would have caught this: pinning is "
               "precisely the mitigation that exists for a bypass like this one.",
        severity="Critical",
        cvss_vector="AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        recommendation="Fix the TLS bypass first - it is the actual defect. Then "
                       "add certificate pinning (a network security config "
                       "pin-set, or OkHttp's CertificatePinner) for the app's own "
                       "endpoints, so a future regression like this one is still "
                       "caught in transit rather than depending on this code path "
                       "alone staying correct.",
    )),
)

MAX_AUTO_CHAINS = 10


def _auto_confirmed_chains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Build the chains whose relationship is definitional and needs no model confirmation.

    Parameters:
        findings: All findings, mutated in place to record chain membership.

    Returns:
        The confirmed chain findings.

    Side effects:
        Mutates findings to record which chain they belong to.

    Implementation notes:
        These pairings are certain by definition rather than dependent on data flow. Missing pinning next to an active TLS bypass is the case: pinning is precisely the control that would have caught the bypass, so their combination needs no reasoning about whether they meet. The entry is located by the weak-class rule that gated it, not by vulnerability class, because the entry here is exactly a finding the gates demoted as chain-required. Every matching target is folded into one chain rather than producing one chain per target, since several bypasses in one app are the same story told repeatedly. Used targets are tracked so a later pairing cannot claim them again. The flow is constructed from the findings themselves, so the steps name the app's own files rather than a generic narrative.
    """
    chains: List[Dict[str, Any]] = []
    used_targets: set = set()
    for weak_rule_id, target_classes, pattern in _AUTO_PAIRINGS:
        entry_index = next(
            (i for i, f in enumerate(findings)
             if (f.get("gate_result") or {}).get("weak_class_rule") == weak_rule_id),
            None)
        if entry_index is None or len(chains) >= MAX_AUTO_CHAINS:
            continue
        target_indices = [
            j for j, target in enumerate(findings)
            if j != entry_index and j not in used_targets
            and _class_of(target) in target_classes]
        if not target_indices:
            continue

        entry = findings[entry_index]
        steps = [f"No certificate pinning or network security config is "
                 f"declared ({entry.get('file') or 'app-wide'})."]
        for j in target_indices:
            target = findings[j]
            steps.append(
                f"{target.get('title') or 'A TLS validation bypass'} accepts any "
                f"certificate at {target.get('file') or 'the connection site'}"
                f"{':' + str(target.get('line')) if target.get('line') else ''}.")
        steps.append("An attacker on the network path intercepts and reads or "
                     "modifies traffic to those endpoints.")

        chain_finding = _build_chain_finding(
            {"pattern": pattern, "entry_index": entry_index,
             "target_index": target_indices[0]},
            findings, {"confirmed": True, "reason": pattern.impact, "flow": steps},
            len(chains) + 1)
        chain_finding["chain"]["auto_confirmed"] = True
        extra = [findings[j].get("title") or findings[j].get("vulnerability_type") or ""
                 for j in target_indices[1:]]
        for title in extra:
            if title and title not in chain_finding["chain"]["components"]:
                chain_finding["chain"]["components"].append(title)
        for j in target_indices:
            used_targets.add(j)
            findings[j].setdefault("chained_into", [])
            if chain_finding["chain"]["id"] not in findings[j]["chained_into"]:
                findings[j]["chained_into"].append(chain_finding["chain"]["id"])
        chains.append(chain_finding)
    return chains


def build_chains(
    findings: List[Dict[str, Any]],
    provider=None,
    verbose: bool = False,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """
    Purpose:
        Produce the confirmed chain findings for a scan.

    Parameters:
        findings: All findings, mutated in place to record chain membership.
        provider: AI provider for confirmation; None returns only the deterministic chains.
        verbose: Traces candidates, confirmations and rejections.
        is_cancelled: Polled before the confirmation request.

    Returns:
        The chain findings, deduplicated.

    Raises:
        ScanCancelled: When the user stopped the scan.

    Side effects:
        Makes one provider request and mutates the component findings.

    Implementation notes:
        Deterministic chains are built first and are returned even when no provider is available, so a run without AI still reports the combinations that are certain. Candidates are capped before the request. The list is already ranked, so truncation drops the least promising rather than an arbitrary tail, and it bounds both the token cost and the size of the response. A failed confirmation request degrades to reporting only the deterministic chains, rather than failing the scan or reporting unconfirmed candidates as real. Rejections are traced individually with the model's reason, so a user can see which combinations were considered and dismissed.
    """
    if not findings:
        return []

    auto_chains = _auto_confirmed_chains(findings)
    if auto_chains:
        verbose_print(
            f"Chains: {plural(len(auto_chains), 'deterministic chain')} confirmed "
            "with no model call", verbose)

    if provider is None:
        return auto_chains
    is_cancelled = is_cancelled or (lambda: False)

    candidates = find_candidate_chains(findings)
    if not candidates:
        verbose_print("Chains: no candidate pairs matched the chain table", verbose)
        return auto_chains
    if len(candidates) > MAX_CANDIDATES:
        verbose_print(
            f"Chains: {len(candidates)} candidates, evaluating the top {MAX_CANDIDATES} "
            "(priority and severity ranked)", verbose)
        candidates = candidates[:MAX_CANDIDATES]

    if is_cancelled():
        raise ScanCancelled()

    try:
        verdicts = _confirm(provider, candidates, findings, verbose)
    except ScanCancelled:
        raise
    except Exception as exc:
        verbose_print(f"Chain confirmation failed ({exc}); reporting no chains", verbose)
        return auto_chains

    chains: List[Dict[str, Any]] = list(auto_chains)
    rejected = 0
    for index, verdict in verdicts.items():
        if not 0 <= index < len(candidates):
            continue
        if not verdict.get("confirmed"):
            rejected += 1
            reason = str(verdict.get("reason") or "no reason given").strip()
            pattern = candidates[index]["pattern"]
            verbose_print(
                f"Chains: rejected {pattern.id} candidate #{index} - {reason}", verbose)
            continue
        candidate = candidates[index]
        chain_finding = _build_chain_finding(candidate, findings, verdict,
                                             len(chains) + 1)
        _mark_confirmed(chain_finding,
                        findings[candidate["entry_index"]],
                        findings[candidate["target_index"]],
                        candidate["pattern"].id)
        chains.append(chain_finding)
    verbose_print(
        f"Chains: {len(chains) - len(auto_chains)} confirmed of "
        f"{plural(len(candidates), 'model-evaluated candidate')} ({rejected} rejected), "
        f"plus {plural(len(auto_chains), 'deterministic chain')}", verbose)
    return _dedupe_chains(chains, verbose)


def _dedupe_chains(chains: List[Dict[str, Any]], verbose: bool = False
                   ) -> List[Dict[str, Any]]:
    """
    Purpose:
        Drop chains that describe the same pattern over the same components.

    Parameters:
        chains: The chain findings.
        verbose: Traces each drop.

    Returns:
        The chains with duplicates removed.

    Implementation notes:
        Components are compared as an unordered set, so the same two findings proposed in both directions under one pattern collapse to a single chain. Needed because the deterministic and model-confirmed paths can independently arrive at the same combination.
    """
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for chain in chains:
        block = chain.get("chain") or {}
        key = (str(block.get("pattern") or ""),
               frozenset(str(c) for c in (block.get("components") or [])))
        if key in seen:
            verbose_print(
                f"Chains: dropped a duplicate {block.get('pattern')} chain over "
                f"the same components", verbose)
            continue
        seen.add(key)
        out.append(chain)
    return out


def _confirm(provider, candidates, findings, verbose) -> Dict[int, Dict[str, Any]]:
    """
    Purpose:
        Ask the provider which candidate chains are real.

    Parameters:
        provider: AI provider.
        candidates: The candidate pairs.
        findings: All findings, indexed by the candidates.
        verbose: Traces a failed request.

    Returns:
        Verdicts keyed by candidate index; empty on failure.

    Implementation notes:
        All candidates go in one request rather than in batches, because the model benefits from seeing them together -- it can recognise that several proposals are the same underlying issue counted more than once, which the prompt asks it to reject. The token budget scales with the number of proposals and is bounded at both ends, since each verdict is small but a confirmed one carries a flow. Verdicts are keyed by the id the model echoes back, and an unparseable id is dropped rather than defaulted, so a malformed response cannot confirm an unrelated candidate.
    """
    payload = []
    for index, candidate in enumerate(candidates):
        pattern = candidate["pattern"]
        entry = findings[candidate["entry_index"]]
        target = findings[candidate["target_index"]]
        payload.append({
            "id": index,
            "proposed_chain": pattern.title,
            "entry": _component_view(entry),
            "target": _component_view(target),
        })
    prompt = ("Check each proposed chain. Return one object per proposal.\n\n"
              + json.dumps(payload, indent=2))
    from ..ai.schema import coerce_to_vuln_list

    max_tokens = min(8000, max(500, len(payload) * 250))
    response = provider.analyze(prompt, system_message=_CONFIRM_SYSTEM,
                                schema=_CONFIRM_SCHEMA, max_tokens=max_tokens)
    if not isinstance(response, dict) or response.get("error"):
        verbose_print(f"Chain request failed: {(response or {}).get('error')}", verbose)
        return {}
    parsed = coerce_to_vuln_list(response.get("response"))
    out: Dict[int, Dict[str, Any]] = {}
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            try:
                out[int(item.get("id"))] = item
            except (TypeError, ValueError):
                continue
    return out


def _component_view(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Build the view of one chain component sent to the confirmation pass.

    Parameters:
        finding: The component finding.

    Returns:
        The view dict.

    Implementation notes:
        File and line are included because the model is asked to decide whether the two components are in the same execution path, which it cannot judge without knowing where they are. The description is whitespace-collapsed and clipped so that a long finding does not crowd out the other proposals in the same request.
    """
    return {
        "title": finding.get("title") or finding.get("vulnerability_type") or "",
        "vuln_class": finding.get("vuln_class") or "",
        "severity": finding.get("severity") or "",
        "file": finding.get("file") or "",
        "line": finding.get("line") or "",
        "description": " ".join(str(finding.get("description") or "").split())[:600],
    }


def _build_chain_finding(candidate, findings, verdict, number: int) -> Dict[str, Any]:
    """
    Purpose:
        Synthesise the finding that represents a confirmed chain.

    Parameters:
        candidate: The pattern and its two component indexes.
        findings: All findings, mutated to record chain membership.
        verdict: The confirmation, carrying the reason and the attack flow.
        number: Sequence number used to build the chain identifier.

    Returns:
        The chain finding.

    Side effects:
        Records the chain identifier on both components, and appends a confirmation note to a component that the gates had marked chain-required.

    Implementation notes:
        The note appended to a chain-required component is what closes the loop from gating: a finding demoted for needing a chain now says which chain it found. The description is assembled from the components, the model's reason and the numbered attack path, so the reader sees the route rather than an assertion that one exists. CWE and OWASP identifiers are taken from the more severe component rather than from the pattern, because the chain's classification is its own pattern id while the standards mapping belongs to the underlying weakness. The chain carries HIGH confidence and names the chain-builder as its source, so deduplication and gating downstream can recognise it as synthesised rather than observed -- which is why the evidence gates exempt it from needing cited code of its own.
    """
    pattern: ChainPattern = candidate["pattern"]
    entry = findings[candidate["entry_index"]]
    target = findings[candidate["target_index"]]
    chain_id = f"chain-{number:03d}"

    flow = [str(step) for step in (verdict.get("flow") or []) if str(step).strip()]
    reason = " ".join(str(verdict.get("reason") or "").split())

    component_titles = [
        entry.get("title") or entry.get("vulnerability_type") or "(untitled)",
        target.get("title") or target.get("vulnerability_type") or "(untitled)",
    ]

    for component in (entry, target):
        component.setdefault("chained_into", []).append(chain_id)
        gate = component.get("gate_result")
        if isinstance(gate, dict) and gate.get("verdict") == "CHAIN_REQUIRED":
            gate.setdefault("reasons", []).append(
                f"Confirmed as part of {chain_id}: {pattern.title}.")

    description_parts = [
        f"Two findings in this app combine into a single exploitable path: "
        f"\"{component_titles[0]}\" and \"{component_titles[1]}\".",
    ]
    if reason:
        description_parts.append(reason)
    if flow:
        description_parts.append(
            "Attack path:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(flow, 1)))

    severity = _chain_severity(pattern, entry, target)
    best_component = (entry if severity_rank(entry.get("severity"))
                      >= severity_rank(target.get("severity")) else target)
    return {
        "title": pattern.title,
        "vulnerability_type": pattern.title,
        "severity": severity,
        "cvss_vector": pattern.cvss_vector,
        "vuln_class": pattern.id,
        "cwe": best_component.get("cwe") or "",
        "owasp_mobile": best_component.get("owasp_mobile") or "",
        "file": entry.get("file") or target.get("file") or "",
        "line": entry.get("line") or "",
        "description": "\n\n".join(description_parts),
        "impact": pattern.impact,
        "recommendation": pattern.recommendation,
        "source": "chain-builder",
        "confidence": "HIGH",
        "chain": {
            "id": chain_id,
            "pattern": pattern.id,
            "priority": pattern.priority,
            "components": component_titles,
            "flow": flow,
        },
    }


def _chain_severity(pattern: ChainPattern, entry, target) -> str:
    """
    Purpose:
        Decide the severity of a confirmed chain.

    Parameters:
        pattern: The chain pattern.
        entry: The entry component.
        target: The target component.

    Returns:
        The chain's severity.

    Implementation notes:
        The pattern's severity applies when it is at least as high as the worse component, which is the normal case -- the point of a chain is that the combination is worse than its parts. When a component is already more severe than the pattern claims, that higher severity carries through rather than being lowered. A chain must never make a finding look less serious than one of its own components.
    """
    best = max(severity_rank(entry.get("severity")), severity_rank(target.get("severity")))
    return (pattern.severity if severity_rank(pattern.severity) >= best
            else normalize_severity(entry.get("severity") if
                                    severity_rank(entry.get("severity")) == best
                                    else target.get("severity")))
