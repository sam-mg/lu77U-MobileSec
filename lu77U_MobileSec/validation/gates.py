#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation.gates

Purpose:
    Decide what each finding is actually worth. A gate either passes it, downgrades it, demotes it to informational, requires it to be chained to something concrete, or refutes it outright as unsupported by its own evidence.

Responsibilities:
    Define the verdict ladder and the severity ladder, implement the individual checks, and run them in order to produce one GateResult per finding.

Dependencies:
    .claim_terms for evidence corroboration, .taxonomy for standalone status and proof requirements, .weak_classes for the non-findings.

Implementation notes:
    Verdicts form a ladder and only ever escalate, so the order checks run in does not change the outcome -- a later weaker verdict cannot undo an earlier stronger one. Severity caps compose independently: several checks can each lower the ceiling, and the lowest wins. Every verdict carries a written reason, and the reasons are shown to the user. A gate that silently suppressed a finding would be indistinguishable from a scanner that missed it. The checks divide into two kinds. Some are mechanical refutations -- the cited code does not contain what the title claims -- and those set a flag saying so, because a finding refuted by its own evidence is different from one merely judged weak. The rest are judgements about reachability, platform defaults and mitigations.

Security considerations:
    This module is where real findings get suppressed if it is wrong. Refutations require the finding to cite code that demonstrably lacks every term it names, and the chain-required verdict defers a finding rather than deleting it. Findings whose evidence could not be resolved are downgraded rather than refuted, because absence of evidence here means the checker failed, not the finding.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .claim_terms import aliases_for, api_terms, evidence_supports, salient_terms
from .taxonomy import is_standalone, required_proof
from .weak_classes import WeakClassRule, classify_weak
from ..utils.verbose import plural

VERDICT_ORDER = ("PASS", "DOWNGRADE", "CHAIN_REQUIRED", "FALSE_POSITIVE",
                 "INFORMATIONAL")

_SEVERITY_LADDER = ("Informational", "Low", "Medium", "High", "Critical")
_SEVERITY_INDEX = {s.lower(): i for i, s in enumerate(_SEVERITY_LADDER)}


@dataclass
class GateResult:
    """
    Purpose:
        The outcome of gating one finding: its verdict, why, and what severity it ends up at.

    Attributes:
        verdict: Position on the verdict ladder, from PASS to INFORMATIONAL.
        reasons: Explanations shown to the user, in the order they were added.
        warnings: Context that does not change the verdict, such as platform-default caveats.
        original_severity: Severity as reported before gating.
        final_severity: Severity after verdict and caps are applied.
        chain_eligible: Whether a chain-required finding could become real when paired.
        weak_class_rule: Identifier of the weak-class rule that matched, if any.
        mechanically_refuted: Whether the finding was contradicted by its own cited code.
        severity_cap: Lowest ceiling any check imposed.
        needs_recitation: Whether the finding cites the wrong line and should be re-cited.

    Invariants:
        The verdict only escalates. The cap only lowers. Reasons are unique and ordered.

    Thread-safety:
        Mutable and owned by one gating call; not shared.
    """
    verdict: str = "PASS"
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    original_severity: str = ""
    final_severity: str = ""
    chain_eligible: bool = False
    weak_class_rule: str = ""
    mechanically_refuted: bool = False
    severity_cap: str = ""
    needs_recitation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Purpose:
            Serialise the result for attachment to a finding and for the report.

        Returns:
            A plain dict of every field.

        Implementation notes:
            The lists are copied so that a consumer mutating the serialised form cannot reach back into the result object.
        """
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "original_severity": self.original_severity,
            "final_severity": self.final_severity,
            "chain_eligible": self.chain_eligible,
            "weak_class_rule": self.weak_class_rule,
            "mechanically_refuted": self.mechanically_refuted,
            "severity_cap": self.severity_cap,
            "needs_recitation": self.needs_recitation,
        }

    def escalate(self, verdict: str, reason: str) -> None:
        """
        Purpose:
            Raise the verdict to at least the given level, and record why.

        Parameters:
            verdict: The verdict this check wants.
            reason: The explanation shown to the user.

        Postconditions:
            The verdict never decreases. The reason is recorded even when the verdict does not change, because a check that found something still has something to say.

        Implementation notes:
            Ordering by position in the ladder is what makes gating order-independent. Reasons are deduplicated so that two checks reaching the same conclusion do not repeat themselves in the report.
        """
        if reason and reason not in self.reasons:
            self.reasons.append(reason)
        if VERDICT_ORDER.index(verdict) > VERDICT_ORDER.index(self.verdict):
            self.verdict = verdict

    def cap(self, severity: str, reason: str) -> None:
        """
        Purpose:
            Impose a ceiling on the final severity.

        Parameters:
            severity: The ceiling this check wants.
            reason: The explanation, optional where the verdict already carries one.

        Postconditions:
            The stored cap is the lowest any check has asked for.

        Implementation notes:
            Caps compose rather than override, so several independent mitigations each lower the ceiling and the strictest applies. A cap is not a verdict: a capped finding can still pass, just at a lower severity.
        """
        severity = normalize_severity(severity)
        if not self.severity_cap or severity_rank(severity) < severity_rank(self.severity_cap):
            self.severity_cap = severity
        if reason and reason not in self.reasons:
            self.reasons.append(reason)


def normalize_severity(value: str) -> str:
    """
    Purpose:
        Map any severity wording onto the canonical ladder.

    Parameters:
        value: Severity text, in any case, or None.

    Returns:
        One of the five canonical severities.

    Implementation notes:
        Several spellings of informational are accepted because findings arrive from a rule engine, from a model and from earlier versions of this tool. An unrecognised value becomes Medium rather than the lowest level. An unreadable severity is an unknown risk, and defaulting downward would quietly hide it.
    """
    text = str(value or "").strip().lower()
    if text in ("info", "informational", "none", "note"):
        return "Informational"
    for level in _SEVERITY_LADDER:
        if text == level.lower():
            return level
    return "Medium"


def severity_rank(severity: str) -> int:
    """
    Purpose:
        Give a severity a comparable numeric rank.

    Parameters:
        severity: Severity text.

    Returns:
        The ladder index, higher being more severe.

    Implementation notes:
        Normalises first, so callers can rank raw model output directly.
    """
    return _SEVERITY_INDEX.get(normalize_severity(severity).lower(), 2)


def lower_severity(severity: str, steps: int = 1) -> str:
    """
    Purpose:
        Step a severity down the ladder.

    Parameters:
        severity: Starting severity.
        steps: How many levels to drop.

    Returns:
        The lowered severity, floored at Informational.
    """
    return _SEVERITY_LADDER[max(0, severity_rank(severity) - steps)]


def check_confidence(finding: Dict[str, Any]) -> Optional[str]:
    """
    Purpose:
        Judge a finding by the confidence it reports about itself.

    Parameters:
        finding: The finding dict.

    Returns:
        A reason to downgrade, or None.

    Implementation notes:
        LOW confidence always downgrades: the model said so itself. MEDIUM downgrades only when nothing backs it up -- no code excerpt and no reproduction step. A medium-confidence finding that shows the code is ordinary and should pass; one that shows nothing is an assertion. Absent confidence is treated as MEDIUM, since rule-engine findings do not report one and should not be penalised for it.
    """
    confidence = str(finding.get("confidence") or "MEDIUM").strip().upper()
    if confidence == "LOW":
        return ("Reported at LOW confidence - treat as a lead to verify rather "
                "than a confirmed issue.")
    if confidence == "MEDIUM":
        has_evidence = bool(
            (finding.get("code_snippet") or finding.get("evidence")
             or finding.get("vulnerable_code") or "").strip())
        has_repro = bool(str(finding.get("proof_of_concept") or "").strip())
        if not has_evidence and not has_repro:
            return ("MEDIUM confidence with no code excerpt or reproduction "
                    "step to support it.")
    return None


def check_evidence(finding: Dict[str, Any]) -> Optional[str]:
    """
    Purpose:
        Require a finding to show something rather than merely assert it.

    Parameters:
        finding: The finding dict.

    Returns:
        A reason to downgrade, or None.

    Implementation notes:
        Two independent failures are caught: almost no supporting text at all, and no way to locate the claim in the app. The length floor is deliberately low. It is meant to catch a one-line assertion, not to demand verbosity. A finding with a file but no excerpt passes, because the file is enough to check the claim by hand.
    """
    blob = " ".join(str(finding.get(k) or "") for k in
                    ("description", "impact", "code_snippet", "evidence",
                     "vulnerable_code", "proof_of_concept")).strip()
    if len(blob) < 40:
        return "No supporting detail: the finding asserts an issue without showing it."

    has_location = bool(str(finding.get("file") or "").strip())
    has_excerpt = bool(str(finding.get("code_snippet")
                           or finding.get("vulnerable_code") or "").strip())
    if not has_location and not has_excerpt:
        return ("Neither a file nor a code excerpt is cited, so the claim cannot "
                "be checked against the app.")
    return None


_SDK_SENSITIVE = (
    (("implicit", "export"),
     "Implicit export only applies below targetSdk 31; confirm the app's "
     "targetSdkVersion before treating this as exploitable."),
    (("pendingintent",),
     "PendingIntent mutability defaults changed at API 31; confirm the app's "
     "targetSdkVersion."),
    (("cleartext",),
     "Cleartext is blocked by default from targetSdk 28; confirm the declared "
     "target and any network security config."),
    (("user ca", "user-installed", "user certificate"),
     "User-added CAs are distrusted by default from targetSdk 24; confirm the "
     "declared target."),
)


def check_platform_context(finding: Dict[str, Any]) -> List[str]:
    """
    Purpose:
        Attach caveats to findings whose exploitability depends on the app's declared SDK level.

    Parameters:
        finding: The finding dict.

    Returns:
        Warning strings, possibly empty.

    Implementation notes:
        These are warnings rather than verdicts. Each of these issues is real below a certain target SDK and inert above it, and the target is not always known at this point, so the reader is told what to confirm rather than having the finding decided for them. All needles of a pattern must be present, so a finding merely mentioning one keyword in passing does not attract an unrelated caveat.
    """
    haystack = " ".join(str(finding.get(k) or "") for k in
                        ("title", "vulnerability_type", "vuln_class")).lower()
    out = []
    for needles, warning in _SDK_SENSITIVE:
        if all(n in haystack for n in needles):
            out.append(warning)
    return out


_JADX_NOISE_RE = re.compile(
    r"^\s*(?:/\*+\s*JADX\s+(?:ERROR|WARN|INFO)\b"
    r"|\*/\s*$"
    r"|\*\s"
    r"|at\s+[\w.$]+\([\w.$]+:\d+\)\s*$"
    r"|(?:[a-z][\w]*\.)+[A-Z]\w*(?:Exception|Error)\s*$)"
)


def _evidence_blob(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Gather every piece of code evidence attached to a finding into one blob.

    Parameters:
        finding: The finding dict.

    Returns:
        The concatenated evidence, possibly empty.

    Implementation notes:
        Several field names are collected because the rule engine, the agent and the chain builder each attach evidence under their own key. Surrounding context lines are included, since a claim is frequently supported by the line above or below the cited one.
    """
    parts: List[str] = []
    for key in ("code_snippet", "vulnerable_code", "evidence"):
        value = finding.get(key)
        if value:
            parts.append(str(value))
    context_lines = (finding.get("code_context") or {}).get("lines")
    if context_lines:
        parts.append("\n".join(str(line) for line in context_lines))
    return "\n".join(parts)


def _has_code_evidence(finding: Dict[str, Any]) -> bool:
    """
    Purpose:
        Report whether a finding attached any code at all.

    Parameters:
        finding: The finding dict.

    Returns:
        True when there is evidence to check.

    Implementation notes:
        Used as a precondition by the corroboration checks: a finding with no code cannot be refuted by its code, and must be judged by the weaker evidence check instead.
    """
    return bool(_evidence_blob(finding).strip())


def check_decompiler_noise(finding: Dict[str, Any]) -> Optional[str]:
    """
    Purpose:
        Refute findings whose cited code is JADX diagnostic output rather than application code.

    Parameters:
        finding: The finding dict.

    Returns:
        A refutation reason, or None.

    Implementation notes:
        JADX writes error comments and stack traces into the source it emits when it cannot decompile a method, and a model reading that output will occasionally report it as a finding. Every non-blank line must match the noise pattern. A snippet that mixes real code with a decompiler comment is left alone, since the real code may well support the claim.
    """
    snippet = str(finding.get("code_snippet") or "").strip()
    if not snippet:
        return None
    lines = [line for line in snippet.splitlines() if line.strip()]
    if not lines or not all(_JADX_NOISE_RE.match(line) for line in lines):
        return None
    return ("The cited line is JADX decompiler diagnostic output (an error/warning "
            "comment or a stack trace frame), not application code, and cannot "
            "support this claim.")


def check_source_resolution(finding: Dict[str, Any]) -> Optional[str]:
    """
    Purpose:
        Downgrade findings whose cited file could not be located unambiguously.

    Parameters:
        finding: The finding dict.

    Returns:
        A reason to downgrade, or None.

    Implementation notes:
        Downgrade rather than refute. An unresolved path means the checker could not look, which says nothing about whether the finding is true -- refuting it would suppress real issues in files whose names collide in the decompiled tree.
    """
    if finding.get("source_unresolved"):
        return ("The cited file could not be resolved to one unambiguous path in "
                "the decompiled tree, so its code could not be checked.")
    return None


def check_claim_evidence(finding: Dict[str, Any]) -> Optional[str]:
    """
    Purpose:
        Refute findings whose title names a security concept that appears nowhere in the code they cite.

    Parameters:
        finding: The finding dict.

    Returns:
        A refutation reason naming the missing vocabulary, or None.

    Implementation notes:
        This is the primary hallucination control. A model describing AES misuse for a snippet containing no cryptography is caught here. Three exemptions matter. Chain findings are synthesised from other findings and cite no code of their own. Unresolved sources mean the evidence could not be fetched. A finding with no recognised claim term is not checkable by this mechanism at all. Each exemption exists so that the check refutes only when it genuinely has grounds. The reason names both what was claimed and what would have had to appear, so the user can judge the refutation rather than take it on trust.
    """
    if finding.get("chain") or finding.get("source") == "chain-builder":
        return None
    if finding.get("source_unresolved"):
        return None
    terms = salient_terms(
        f"{finding.get('title', '')} {finding.get('vulnerability_type', '')}")
    if not terms:
        return None
    if not _has_code_evidence(finding):
        return None
    blob = _evidence_blob(finding)
    if evidence_supports(terms, blob):
        return None
    names = ", ".join(terms)
    shown = ", ".join(aliases_for(terms)[:6])
    return (f"The title names {names} but the cited code contains none of "
            f"[{shown}] - the claim is not supported by the evidence attached to it.")


_NON_CODE_LINE_RE = re.compile(
    r"^\s*(?:"
    r"package\s+[\w.]+\s*;"
    r"|import\s+(?:static\s+)?[\w.*]+\s*;"
    r"|@[\w.]+(?:\([^)]*\))?\s*$"
    r"|(?:public\s+|private\s+|protected\s+|final\s+|abstract\s+|static\s+|sealed\s+)*"
    r"(?:class|interface|enum|@interface|record)\s+\w+[^\{;]*\{?\s*$"
    r")\s*$"
)


def check_evidence_depth(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Judge a finding by how much of the app the AI had actually examined before reporting it.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        May escalate the verdict or lower the severity cap.

    Implementation notes:
        Applies only to agent findings, which carry their region's exploration statistics. A finding written up after the region was forced to stop early, having barely looked at anything, is demoted to informational outright -- it is a note produced under duress rather than a conclusion. A finding citing a file the agent never opened is capped at Medium: it may be right, but it was not read. A shallow region is capped below Critical. A Critical asserted after reading a handful of files has not established the reachability that a Critical implies.
    """
    origin = finding.get("agent_origin")
    if not origin:
        return
    files_read = int(finding.get("region_files_read") or 0)
    searches = int(finding.get("region_searches") or 0)
    region = finding.get("region_key") or "?"

    if origin == "forced_report" and files_read < 3 and searches < 3:
        result.escalate(
            "INFORMATIONAL",
            f"Written up after AI region '{region}' stopped early - it read "
            f"{plural(files_read, 'file')} before the provider failed, so there is "
            "no evidence base behind this. Kept as a note, not a graded finding.")
        return

    if finding.get("cited_file_read") is False:
        result.cap(
            "Medium",
            "The AI did not open the file this finding cites before reporting it "
            "- capped pending confirmation against the source.")

    if files_read < 5:
        result.cap(
            "High",
            f"The AI region behind this finding read only "
            f"{plural(files_read, 'file')} before stopping - too shallow to "
            "support a Critical.")


def check_api_claim(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Refute findings whose title names specific APIs that appear nowhere in the cited code.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        May escalate to FALSE_POSITIVE and set the mechanical-refutation flag.

    Implementation notes:
        Complements check_claim_evidence by covering APIs the claim catalogue does not know about, extracted from the title by shape. Refutation requires every named API to be missing. If even one is present the finding is left alone, because a partially-supported claim is an imprecise finding rather than an invented one.
    """
    if finding.get("chain") or finding.get("source") == "chain-builder":
        return
    if finding.get("source_unresolved"):
        return
    if not _has_code_evidence(finding):
        return
    names = api_terms(
        f"{finding.get('title', '')} {finding.get('vulnerability_type', '')}")
    if not names:
        return
    blob = _evidence_blob(finding).lower()
    missing = [n for n in names if n.lower() not in blob]
    if missing and len(missing) == len(names):
        joined = ", ".join(missing)
        result.escalate(
            "FALSE_POSITIVE",
            f"The title names {joined} but the cited code contains "
            f"{'neither' if len(missing) == 2 else 'none of them'} - the claim is "
            "not supported by its own evidence.")
        result.mechanically_refuted = True


def check_citation_target(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Downgrade findings that cite a package declaration, an import or a bare type declaration instead of the line showing the issue.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        Downgrades, caps at Low, and flags the finding as needing re-citation.

    Implementation notes:
        A common failure mode: the model identifies a real issue in a file and then cites the top of the file rather than the construct. This does not refute the finding, because it may well be true. It marks it for re-citation, which the verification pass can act on, and caps it meanwhile so an unverifiable citation cannot carry a high severity. Every non-blank line must be non-code, so a snippet that includes the import plus the real call is untouched.
    """
    snippet = str(finding.get("code_snippet") or "").strip()
    if not snippet:
        return
    lines = [l for l in snippet.splitlines() if l.strip()]
    if not lines or not all(_NON_CODE_LINE_RE.match(l) for l in lines):
        return
    result.escalate(
        "DOWNGRADE",
        "The cited line is a package/import statement or a bare type declaration, "
        "not the construct this finding claims - it needs re-citing to the line "
        "that shows the issue.")
    result.cap("Low", "")
    result.needs_recitation = True


def check_sql_provenance(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Demote SQL injection findings where the concatenated value provably cannot be attacker-controlled.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        May cap the severity at Informational.

    Implementation notes:
        Acts on provenance computed by the static analyzer, not on a guess. A constant, or a table name the app read out of its own schema, cannot carry an injection however the query was built. Capped rather than refuted: string-built SQL is still worth flagging as a code-quality issue, and provenance analysis can be incomplete.
    """
    prov = finding.get("operand_provenance")
    what = {
        "constant": "a compile-time constant",
        "catalogue": "a table/column name the app read from its own SQLite schema",
    }.get(prov)
    if what:
        result.cap(
            "Informational",
            f"The concatenated value resolves to {what}, so it is not "
            "attacker-controlled - this is a code-quality issue, not an injection.")


def check_webview_mitigations(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Lower the ceiling on WebView findings in proportion to the hardening present near the cited line.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        May cap the severity.

    Implementation notes:
        Each mitigating call found nearby steps the ceiling down one level, so a WebView with several protections in place cannot be reported as Critical. A set of genuinely strong mitigations pins the ceiling at Low regardless of count, because those specific calls close the file-access and navigation paths that make a WebView finding serious. Capped rather than dismissed: mitigations are detected near the line, not proven to apply to it.
    """
    mits = finding.get("webview_mitigations")
    if not mits:
        return
    ladder = ("Critical", "High", "Medium", "Low")
    ceiling = ladder[min(len(mits), len(ladder) - 1)]
    strong = {"setAllowFileAccess(false)", "setAllowFileAccessFromFileURLs(false)",
              "setAllowContentAccess(false)", "setWebViewClient(...)"}
    if len(strong.intersection(mits)) >= 3:
        ceiling = "Low"
    result.cap(
        ceiling,
        f"WebView hardening present near the cited line ({', '.join(mits)}) - "
        "each mitigating call lowers the ceiling.")


def check_vendor_code(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Cap findings located in third-party SDK code.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        May cap the severity at Medium.

    Implementation notes:
        The issue may be real, but the app owner reading this report cannot fix it -- the remediation is to raise it with the SDK vendor or to stop using the SDK. Reporting it at the same severity as code they control misdirects their attention, so the reason says explicitly where the fix belongs.
    """
    sdk = finding.get("vendor_sdk")
    if sdk:
        result.cap(
            "Medium",
            f"vendor SDK ({sdk}) - not modifiable by the app owner; capped, and "
            "best raised with the SDK's maintainer.")


def check_public_identifier(finding: Dict[str, Any], result: GateResult) -> None:
    """
    Purpose:
        Demote findings that report a public, ship-in-the-app identifier as if it were a leaked secret.

    Parameters:
        finding: The finding dict.
        result: The gate result, mutated in place.

    Side effects:
        Rewrites the finding's vulnerability class and caps the severity at Informational.

    Implementation notes:
        Firebase URLs, Google API keys and similar identifiers are designed to be present in a shipped app; what protects them lives on the provider's side. A model finding one in the APK reports it as a hardcoded credential, which is wrong and, in a report, loud. Rule-engine findings are skipped because they already classify these correctly. The class is corrected as well as the severity, so downstream reporting and deduplication both see it as a public identifier rather than a secret. The pattern import is guarded, so an unavailable pattern table disables the check rather than failing gating.
    """
    if finding.get("source") == "static-analyzer":
        return
    try:
        from ..analyzers.agent.patterns import SECRET_PATTERNS
    except Exception:
        return
    haystack = f"{finding.get('title', '')}\n{finding.get('description', '')}\n{_evidence_blob(finding)}"
    for pat in SECRET_PATTERNS:
        if getattr(pat, "public", False) and pat.regex.search(haystack):
            name = pat.name.lower()
            finding["vuln_class"] = (
                "BACKEND-01" if "firebase" in name and "url" in name else "SECRET-03")
            result.cap(
                "Informational",
                f"{pat.name} is a public identifier meant to ship in the app - "
                "the control that protects it is server-side (provider rules / a "
                "client-type or API-key restriction), not the fact that it is in the APK.")
            return


def apply_gates(finding: Dict[str, Any]) -> GateResult:
    """
    Purpose:
        Run every gate against one finding and produce its verdict and final severity.

    Parameters:
        finding: The finding dict. Some checks correct its vulnerability class in place.

    Returns:
        The gate result.

    Side effects:
        May mutate the finding's vuln_class through the public-identifier check.

    Complexity:
        O(n) in the size of the finding's text fields.

    Implementation notes:
        Weak-class classification runs first, because it determines whether the finding is a candidate for chaining or is simply not a finding. Mechanical refutations are evaluated before the judgement checks so that the refutation flag is set early, though the escalate-only ladder means order does not affect the final verdict. Platform warnings are attached last and never change the verdict; they are context for the reader. The final severity is computed once at the end from the verdict and the accumulated cap, rather than being adjusted by each check as it runs, which is what keeps caps composable.
    """
    original = normalize_severity(finding.get("severity"))
    result = GateResult(original_severity=original, final_severity=original)

    rule: Optional[WeakClassRule] = classify_weak(finding)
    if rule is not None:
        result.weak_class_rule = rule.id
        result.chain_eligible = rule.chain_eligible
        verdict = "CHAIN_REQUIRED" if rule.chain_eligible else "INFORMATIONAL"
        result.escalate(verdict, f"{rule.label}. {rule.reason}")

    reason = check_decompiler_noise(finding)
    if reason:
        result.escalate("FALSE_POSITIVE", reason)
        result.mechanically_refuted = True

    reason = check_claim_evidence(finding)
    if reason:
        result.escalate("FALSE_POSITIVE", reason)
        result.mechanically_refuted = True

    check_api_claim(finding, result)

    reason = check_source_resolution(finding)
    if reason:
        result.escalate("DOWNGRADE", reason)

    reason = check_confidence(finding)
    if reason:
        result.escalate("DOWNGRADE", reason)

    reason = check_evidence(finding)
    if reason:
        result.escalate("DOWNGRADE", reason)

    check_evidence_depth(finding, result)
    check_citation_target(finding, result)
    check_sql_provenance(finding, result)
    check_webview_mitigations(finding, result)
    check_vendor_code(finding, result)
    check_public_identifier(finding, result)

    result.warnings.extend(check_platform_context(finding))
    result.final_severity = _final_severity(result)
    return result


def _final_severity(result: GateResult) -> str:
    """
    Purpose:
        Resolve the verdict and the accumulated cap into one severity.

    Parameters:
        result: The gate result.

    Returns:
        The final severity.

    Implementation notes:
        Three of the verdicts collapse to Informational: a refuted finding, one that needs a chain it does not have, and one demoted outright. They are kept in the report at Informational rather than deleted, so the reader can see what was considered and why it was set aside. A downgrade steps down one level rather than collapsing, since it expresses doubt rather than refutation. The cap applies on top and only ever lowers the result, so a check that capped at Medium cannot raise a finding that the verdict already put at Informational.
    """
    if result.verdict in ("CHAIN_REQUIRED", "FALSE_POSITIVE", "INFORMATIONAL"):
        base = "Informational"
    elif result.verdict == "DOWNGRADE":
        base = lower_severity(result.original_severity)
    else:
        base = result.original_severity
    if result.severity_cap and severity_rank(result.severity_cap) < severity_rank(base):
        return result.severity_cap
    return base
