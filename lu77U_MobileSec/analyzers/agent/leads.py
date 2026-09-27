#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.leads

Purpose:
    Turn the rule engine's findings into starting points for the agent, so it begins from established facts rather than exploring the app blind.

Responsibilities:
    Rank the findings, convert them to leads, and render them for the prompt.

Dependencies:
    None beyond the standard library.

Implementation notes:
    Handing the agent the deterministic findings first is what makes the two engines complement each other rather than duplicate each other. The rule engine knows where something matched; the agent can establish whether it is reachable and what it means -- which is the part a pattern cannot answer. The rendered text says explicitly that these are already in the report and are facts rather than guesses, so the agent spends its steps confirming and extending them rather than re-finding them.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

MAX_LEADS = 120

MAX_LEADS_PER_REGION = 24

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "informational": 4, "info": 4}

_CHECK_BY_DETECTOR = {
    "webview": "Read the WebView setup and say what content it loads and "
              "what the bridge exposes.",
    "injection": "Trace where the concatenated value comes from and whether "
                "it is reachable from outside the app.",
    "tls": "Confirm the bypass is reachable in a release build and say what "
          "traffic it exposes.",
    "secrets": "Confirm the value is a real credential and say what it "
              "unlocks.",
    "manifest": "Confirm the component is reachable by another app and what "
               "it exposes if triggered.",
    "network-config": "Confirm what traffic this policy actually covers and "
                      "whether a sensitive endpoint falls outside it.",
    "sdk-inventory": "Confirm the SDK version is what ships in this build "
                     "and whether the app's own code reaches the affected API.",
}


@dataclass(frozen=True)
class Lead:
    """
    Purpose:
        One starting point handed to the agent.

    Attributes:
        file: Where the rule matched.
        line: The matched line.
        title: What the rule found.
        severity: The rule's severity.
        detector: Which detector produced it.

    Invariants:
        Frozen; leads are read-only input to the agent.

    Thread-safety:
        Immutable and safe to share across the fanned-out agents.
    """
    file: str
    line: int
    title: str
    severity: str
    detector: str
    vuln_class: str = ""
    check: str = ""


def _severity_rank(severity: str) -> int:
    """
    Purpose:
        Rank a severity for ordering leads.

    Parameters:
        severity: The severity text.

    Returns:
        The rank, with an unrecognised value treated as middling.
    """
    return _SEVERITY_RANK.get(str(severity or "").strip().lower(), 2)


def _line_of(finding: Dict[str, Any]) -> int:
    """
    Purpose:
        Extract a usable line number from a finding.

    Parameters:
        finding: The finding.

    Returns:
        The line number, or zero when none could be read.

    Implementation notes:
        The normalised field is preferred, and a range yields its start -- which is where the construct begins and what the agent should open the file at.
    """
    for key in ("line_number", "line"):
        value = finding.get(key)
        if value in (None, ""):
            continue
        try:
            return int(str(value).split("-")[0].strip())
        except (TypeError, ValueError):
            continue
    return 0


def _check_for(finding: Dict[str, Any]) -> str:
    """
    Purpose:
        Phrase what the agent should establish about a lead.

    Parameters:
        finding: The finding.

    Returns:
        The instruction.

    Implementation notes:
        Phrased per detector where a specific question applies, and as a general confirm-or-refute otherwise. A concrete question -- whether the concatenated value is reachable, whether the WebView loads remote content -- is what turns a lead into work the agent can finish, rather than an invitation to restate the finding.
    """
    detector = str(finding.get("detector") or "").strip()
    hint = _CHECK_BY_DETECTOR.get(detector)
    if hint:
        return hint
    title = str(finding.get("title") or finding.get("vulnerability_type") or "").strip()
    return (f'Confirm or refute: "{title}".' if title
           else "Confirm or refute this finding against the code.")


def leads_from_findings(findings: Sequence[Dict[str, Any]],
                        max_leads: int = MAX_LEADS) -> List[Lead]:
    """
    Purpose:
        Select and rank the findings worth handing to the agent as starting points.

    Parameters:
        findings: The rule engine's findings.
        max_leads: How many to keep.

    Returns:
        The leads, most important first.

    Implementation notes:
        Ranked by severity, then by whether the rule was confident. Capped, because the leads share the prompt with the code the agent has to read, and a long list crowds out the thing it is meant to point at.
    """
    ordered = sorted(
        findings,
        key=lambda f: (
            _severity_rank(f.get("severity")),
            0 if str(f.get("confidence") or "").strip().upper() == "HIGH" else 1,
            str(f.get("file") or ""),
            _line_of(f),
        ))
    seen: set = set()
    leads: List[Lead] = []
    for finding in ordered:
        file = str(finding.get("file") or "").strip()
        if not file:
            continue
        line = _line_of(finding)
        title = str(finding.get("title") or finding.get("vulnerability_type") or "").strip()
        key = (file, line, title.lower())
        if key in seen:
            continue
        seen.add(key)
        leads.append(Lead(
            file=file, line=line, title=title or "(untitled finding)",
            severity=str(finding.get("severity") or "Medium"),
            detector=str(finding.get("detector") or ""),
            vuln_class=str(finding.get("vuln_class") or ""),
            check=_check_for(finding)))
        if len(leads) >= max_leads:
            break
    return leads


def render_leads(leads: Sequence[Lead], total: int) -> str:
    """
    Purpose:
        Render the leads as the prompt section the agent reads.

    Parameters:
        leads: The selected leads.
        total: How many findings there were in all, so the agent knows it is seeing a subset.

    Returns:
        The prompt text, empty when there are no leads.

    Implementation notes:
        The framing is deliberate: the text states that these are already in the report and are facts about this build. Without that, a model treats them as its own candidate findings and spends its budget re-reporting what the rule engine already established -- producing duplicates rather than the reachability analysis the leads were meant to prompt. The total is shown alongside the count so the agent knows more exist and does not treat the list as exhaustive.
    """
    if not leads:
        return ""
    lines = [
        f"## Confirmed leads - start here ({len(leads)} of {total})",
        "Deterministic scanners already found these and they are already in "
        "the report. They are facts about this build, not guesses. Your job "
        "is to confirm or refute each one against the code and add what a "
        "regex cannot see: where the value comes from, whether the path is "
        "reachable, and what an attacker actually gets. Do NOT re-report a "
        "lead as a new finding - report the flow you proved, or say it is "
        "refuted and why.",
        "",
    ]
    for index, lead in enumerate(leads, start=1):
        lines.append(f"  {index}. [{lead.severity}] {lead.file}:{lead.line}")
        lines.append(f"     {lead.title}")
        lines.append(f"     -> {lead.check}")
    return "\n".join(lines) + "\n"
