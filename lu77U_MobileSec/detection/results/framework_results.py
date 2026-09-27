#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.results.framework_results

Purpose:
    Hold the outcome of framework identification: which frameworks were detected, which is primary, how confident each detection was, and what evidence supported it.

Responsibilities:
    Store the detections and render the confidence and evidence views the report uses.

Dependencies:
    dataclasses only.

Implementation notes:
    Detections are stored loosely typed because detectors return plain dicts and the set of detectors changes; the accessors here normalise that rather than forcing every detector onto one class.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from ...utils.verbose import verbose_print

@dataclass
class FrameworkDetectionResult:
    """
    Purpose:
        The result of framework identification for one app.

    Attributes:
        detected_frameworks: Every detection, as returned by the detectors.
        primary_framework: The highest-confidence detection, or None.
        confidence_scores: Confidence per framework name.
        detection_timestamp: When detection ran.
        verbose: Whether accessors trace their work.
        MAX_INDICATORS: Cap on evidence items retained per framework.

    Invariants:
        confidence_scores covers every detected framework, so a report can show the alternatives that were considered and not chosen.

    Thread-safety:
        Mutable and owned by one detection run.

    Implementation notes:
        verbose is declared with init=False so it is never a constructor argument, and every method reads it through getattr with a default. Dataclass field ordering would otherwise force it into the signature of every construction site, and the getattr guard means an instance rebuilt from serialised data without the field still works.
    """
    detected_frameworks: List[Any] = field(default_factory=list)
    primary_framework: Optional[Any] = None
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    detection_timestamp: datetime = field(default_factory=datetime.now)
    verbose: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """
        Purpose:
            Trace the creation of the result.

        Side effects:
            Writes one line to the verbose stream.
        """
        if hasattr(self, 'verbose'):
            verbose_print(f"FrameworkDetectionResult created with {len(self.detected_frameworks)} detected frameworks", self.verbose)
    
    def get_primary_framework_name(self) -> str:
        """
        Purpose:
            Name the primary framework for display.

        Returns:
            The framework name, or "Unknown" when nothing was detected.

        Implementation notes:
            Handles both a dict detection and an object one, because the hybrid detector and the individual detectors have historically returned different shapes. Returning "Unknown" rather than None keeps report rendering free of null checks.
        """
        verbose_print("Getting primary framework name", getattr(self, 'verbose', False))
        
        if self.primary_framework:
            if isinstance(self.primary_framework, dict):
                name = self.primary_framework.get('framework', 'Unknown')
                verbose_print(f"Primary framework (dict): {name}", getattr(self, 'verbose', False))
                return name
            else:
                name = getattr(self.primary_framework, 'name', str(self.primary_framework))
                verbose_print(f"Primary framework (object): {name}", getattr(self, 'verbose', False))
                return name
        
        verbose_print("No primary framework found", getattr(self, 'verbose', False))
        return "Unknown"
    
    def get_framework_count(self) -> int:
        """
        Purpose:
            Count the detected frameworks.

        Returns:
            The number of detections.
        """
        count = len(self.detected_frameworks)
        verbose_print(f"Framework count: {count}", getattr(self, 'verbose', False))
        return count
    
    def get_confidence_summary(self) -> Dict[str, str]:
        """
        Purpose:
            Translate numeric confidences into readable bands.

        Returns:
            A mapping from framework name to band.

        Implementation notes:
            Bands exist because a raw confidence invites false precision: the difference between 0.81 and 0.86 is not meaningful, while the difference between High and Low is. The thresholds line up with the floor the fallback detection path applies, so anything reported as Very Low was retained by the hybrid arbitrator rather than accepted on its own.
        """
        verbose_print(f"Generating confidence summary for {len(self.confidence_scores)} frameworks", getattr(self, 'verbose', False))
        
        summary = {}
        confidence_levels = {"High": 0, "Medium": 0, "Low": 0, "Very Low": 0}
        
        for framework, confidence in self.confidence_scores.items():
            if confidence >= 0.8:
                level = "High"
            elif confidence >= 0.5:
                level = "Medium"
            elif confidence >= 0.3:
                level = "Low"
            else:
                level = "Very Low"
            
            summary[framework] = level
            confidence_levels[level] += 1
            verbose_print(f"Framework {framework}: {confidence:.2f} = {level}", getattr(self, 'verbose', False))
        
        verbose_print(f"Confidence distribution: {confidence_levels}", getattr(self, 'verbose', False))
        return summary
    
    MAX_INDICATORS = 25

    def _indicators_by_framework(self) -> Dict[str, List[str]]:
        """
        Purpose:
            Collect the evidence each detector cited, grouped by framework.

        Returns:
            A mapping from framework name to its indicators.

        Implementation notes:
            Malformed entries are skipped rather than raising, since detections come from several detectors and an unexpected shape should cost that detector's evidence, not the whole view. Indicators are deduplicated and capped, because a detector matching on file patterns can return hundreds and the report shows them verbatim.
        """
        evidence: Dict[str, List[str]] = {}
        for entry in self.detected_frameworks or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get('framework') or entry.get('name')
            if not name:
                continue
            found = entry.get('indicators') or []
            if not isinstance(found, (list, tuple)):
                continue
            merged = evidence.setdefault(name, [])
            for item in found:
                text = str(item)
                if text not in merged and len(merged) < self.MAX_INDICATORS:
                    merged.append(text)
        return evidence

    def get_top_frameworks(self, limit: int = 3) -> List[Dict[str, Any]]:
        """
        Purpose:
            Rank the detected frameworks with their confidence bands and supporting evidence, for the report.

        Parameters:
            limit: How many to return.

        Returns:
            Ranked entries carrying name, confidence, band and indicators.

        Implementation notes:
            Showing the runners-up is deliberate. Framework detection is the decision that selects the decompiler and the analyzer, so a reader needs to see that the choice was clear-cut -- or that it was not.
        """
        verbose_print(f"Getting top {limit} frameworks from {len(self.confidence_scores)} total", getattr(self, 'verbose', False))

        sorted_frameworks = sorted(
            self.confidence_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        verbose_print(f"Frameworks sorted by confidence: {[(f, round(c, 3)) for f, c in sorted_frameworks]}", getattr(self, 'verbose', False))

        result = []
        confidence_summary = self.get_confidence_summary()
        evidence = self._indicators_by_framework()

        for framework, confidence in sorted_frameworks[:limit]:
            framework_data = {
                'name': framework,
                'confidence': confidence,
                'confidence_level': confidence_summary.get(framework, 'Unknown'),
                'indicators_found': evidence.get(framework, [])
            }
            result.append(framework_data)
            verbose_print(f"Top framework: {framework} ({confidence:.3f}, {framework_data['confidence_level']})", getattr(self, 'verbose', False))
        
        verbose_print(f"Returning {len(result)} top frameworks", getattr(self, 'verbose', False))
        return result
