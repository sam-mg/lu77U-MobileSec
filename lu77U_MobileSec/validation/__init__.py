#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.validation

Purpose:
    Facade for the post-analysis pass that decides which findings survive: deduplication, gating, chain building, taxonomy lookup and weak-class classification.

Responsibilities:
    Re-export the chain helpers, the dedupe helpers, GateResult and apply_gates, the taxonomy tables and predicates, the validator entry points and the weak-class rules.

Dependencies:
    .chains, .dedupe, .gates, .taxonomy, .validator, .weak_classes -- standard library only, so eager re-export is cheap.

Implementation notes:
    This layer exists because an AI pass and a rule pass both produce findings that overlap, contradict, or restate each other. Gating and deduplication run over the union rather than over either source, which is why they live in their own package instead of inside an analyzer.

Security considerations:
    Gates decide what a user is told is safe. Loosening them silently drops real findings, so changes here are security-relevant even though no untrusted input is parsed.
"""

from .chains import (
    CHAIN_PATTERNS, annotate_related_findings, build_chains,
    find_candidate_chains)
from .dedupe import (
    deduplicate, finding_identity, finding_richness, infer_vuln_class)
from .gates import GateResult, apply_gates
from .taxonomy import ALL_CODES, VULN_CLASSES, describe, is_standalone
from .validator import is_rule_finding, sort_findings, validate_findings
from .weak_classes import WEAK_CLASS_RULES, classify_weak

__all__ = [
    "CHAIN_PATTERNS", "annotate_related_findings", "build_chains",
    "find_candidate_chains",
    "deduplicate",
    "finding_identity", "finding_richness", "infer_vuln_class",
    "GateResult", "apply_gates",
    "ALL_CODES", "VULN_CLASSES", "describe", "is_standalone",
    "is_rule_finding", "sort_findings", "validate_findings",
    "WEAK_CLASS_RULES", "classify_weak",
]
