#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.findings

Purpose:
    Define the finding type the rule engine produces, and convert it into the dict shape the rest of the pipeline consumes.

Responsibilities:
    Normalise severities, supply a default CVSS vector per severity, and translate between the two representations.

Dependencies:
    dataclasses only.

Implementation notes:
    The rule engine uses a typed finding internally, because its extractors benefit from fixed fields and a normalising constructor. Everything downstream takes dicts, since findings from the AI arrive that way and one shape has to serve both.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

_SEVERITY_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "none": "Informational",
    "error": "High",
    "warning": "Medium",
}


def normalize_severity(value: Optional[str]) -> str:
    """
    Purpose:
        Map a rule's severity onto the canonical ladder.

    Parameters:
        value: Severity text, or None.

    Returns:
        A canonical severity.

    Implementation notes:
        An unrecognised value becomes Medium rather than the lowest level, so a rule with a typo in its severity does not quietly report a serious issue as negligible.
    """
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), "Medium")


_DEFAULT_VECTOR_BY_SEVERITY: Dict[str, str] = {
    "Critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "High": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Medium": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Low": "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "Informational": "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


def default_cvss_vector(severity: str) -> str:
    """
    Purpose:
        Supply a CVSS vector for a rule finding that did not specify one.

    Parameters:
        severity: The finding's severity.

    Returns:
        A representative vector for that severity.

    Implementation notes:
        Rule findings need a vector because severity downstream is computed from one, and a finding without it would be re-derived from its severity word anyway. The vector is representative rather than measured -- it describes a typical finding at that severity, not this specific one. A rule that can be precise should state its own.
    """
    return _DEFAULT_VECTOR_BY_SEVERITY[normalize_severity(severity)]


@dataclass
class SastFinding:
    """
    Purpose:
        One finding produced by the rule engine.

    Attributes:
        title: Short name for the issue.
        severity: Canonical severity, normalised on construction.
        description: What the rule matched and why it matters.
        vuln_class: Taxonomy code, when the rule knows it.
        file: Where it was found.
        line: Line number, zero when not line-specific.

    Invariants:
        The severity is always canonical, because the constructor normalises it.

    Thread-safety:
        A plain data holder.
    """
    title: str
    severity: str
    description: str
    vuln_class: str = ""
    file: str = ""
    line: int = 0
    line_end: int = 0
    recommendation: str = ""
    impact: str = ""
    cwe: str = ""
    owasp_mobile: str = ""
    cvss_vector: str = ""
    confidence: str = "HIGH"
    evidence: str = ""
    detector: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """
        Purpose:
            Normalise the severity at construction.

        Side effects:
            Rewrites the severity field.

        Implementation notes:
            Normalising here rather than at each construction site means every extractor can write the severity in whatever form reads naturally in its rule table, and no consumer has to defend against a variant spelling.
        """
        self.severity = normalize_severity(self.severity)


def to_scan_finding(finding: SastFinding) -> Dict[str, Any]:
    """
    Purpose:
        Convert a rule finding into the dict shape the pipeline consumes.

    Parameters:
        finding: The rule finding.

    Returns:
        The finding as a dict.

    Implementation notes:
        The title is written into both the title and the type field, because the two engines populate them differently and downstream code reads whichever it finds. A default CVSS vector is attached when the rule did not supply one, so every finding reaching validation can have its severity derived the same way.
    """
    out: Dict[str, Any] = {
        "title": finding.title,
        "vulnerability_type": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "file": finding.file,
        "line": str(finding.line) if finding.line else "",
        "line_number": finding.line,
        "line_end": finding.line_end or finding.line,
        "source": "static-analyzer",
        "detector": finding.detector,
        "confidence": finding.confidence,
    }
    for key in ("vuln_class", "recommendation", "impact", "cwe", "owasp_mobile"):
        value = getattr(finding, key)
        if value:
            out[key] = value
    out["cvss_vector"] = finding.cvss_vector or default_cvss_vector(finding.severity)
    if finding.evidence:
        out["code_snippet"] = finding.evidence
    if finding.extra:
        out.update(finding.extra)
    return out


def to_scan_findings(findings: List[SastFinding]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Convert a list of rule findings.

    Parameters:
        findings: The rule findings.

    Returns:
        The findings as dicts.
    """
    return [to_scan_finding(f) for f in findings]
