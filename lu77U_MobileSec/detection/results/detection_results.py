#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.results.detection_results

Purpose:
    The top-level result of the detection stage, combining framework identification and package information with the errors and warnings gathered along the way.

Responsibilities:
    Hold the detection outputs, accumulate diagnostics, and render the summary the report and dashboard display.

Dependencies:
    dataclasses, the sibling result types, ...utils for duration formatting.

Implementation notes:
    Errors and warnings are accumulated on the result rather than raised, because detection is expected to partly fail on real APKs -- an obfuscated or truncated manifest is ordinary -- and a partial result is still useful.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from .framework_results import FrameworkDetectionResult
from .basic_info_results import BasicInfoResult
from ...utils import format_duration
from ...utils.verbose import verbose_print

@dataclass
class DetectionResult:
    """
    Purpose:
        Everything the detection stage established about one target.

    Attributes:
        target_path: Path that was analysed.
        is_apk: Whether the target is an APK rather than a project directory.
        analysis_timestamp: When detection ran.
        framework_results: Framework identification, or None when that stage failed.
        basic_info: Package information, or None when extraction failed.
        analysis_duration: Seconds the stage took, recorded on success and failure alike.
        errors: Timestamped error messages.
        warnings: Timestamped warning messages.
        verbose: Whether accessors trace their work.

    Invariants:
        Either result field may be None independently; completeness is reported by is_detection_complete rather than assumed.

    Thread-safety:
        Mutable and owned by one detection run.

    Implementation notes:
        verbose is declared with init=False so it is never a constructor argument, and every method reads it through getattr with a default. Dataclass field ordering would otherwise force it into the signature of every construction site, and the getattr guard means an instance rebuilt from serialised data without the field still works.
    """
    target_path: str = ""
    is_apk: bool = False
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    framework_results: Optional[FrameworkDetectionResult] = None
    basic_info: Optional[BasicInfoResult] = None
    
    analysis_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    verbose: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """
        Purpose:
            Trace the creation of the result.

        Side effects:
            Writes one line to the verbose stream.
        """
        if hasattr(self, 'verbose'):
            verbose_print(f"DetectionResult created for: {self.target_path} (APK: {self.is_apk})", self.verbose)
    
    def add_error(self, error_message: str):
        """
        Purpose:
            Record an error that did not stop detection.

        Parameters:
            error_message: What went wrong.

        Side effects:
            Appends a timestamped entry and traces it.

        Implementation notes:
            Timestamped at the point of recording, so that a slow stage's failures can be placed in time against the progress log.
        """
        error_entry = f"{datetime.now()}: {error_message}"
        self.errors.append(error_entry)
        verbose_print(f"Added error to detection: {error_message}", getattr(self, 'verbose', False))
        verbose_print(f"Total errors: {len(self.errors)}", getattr(self, 'verbose', False))
    
    def add_warning(self, warning_message: str):
        """
        Purpose:
            Record a condition worth reporting that did not prevent detection.

        Parameters:
            warning_message: What was noticed.

        Side effects:
            Appends a timestamped entry and traces it.
        """
        warning_entry = f"{datetime.now()}: {warning_message}"
        self.warnings.append(warning_entry)
        verbose_print(f"Added warning to detection: {warning_message}", getattr(self, 'verbose', False))
        verbose_print(f"Total warnings: {len(self.warnings)}", getattr(self, 'verbose', False))
    
    def get_formatted_duration(self) -> str:
        """
        Purpose:
            Render the stage duration for display.

        Returns:
            A human-readable duration.
        """
        return format_duration(self.analysis_duration, getattr(self, 'verbose', False))
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Purpose:
            Build the compact summary the report header and dashboard show.

        Returns:
            A dict that always carries target, type, timestamp, duration and diagnostic counts, plus framework and package fields when those stages succeeded.

        Implementation notes:
            Optional sections are added only when their source result exists, so a caller must check for those keys. The base keys are unconditional, which is what lets a failed detection still render a meaningful header.
        """
        verbose_print("Generating detection summary", getattr(self, 'verbose', False))
        
        summary = {
            'target': self.target_path,
            'type': 'APK' if self.is_apk else 'Project',
            'timestamp': self.analysis_timestamp.isoformat(),
            'duration': self.analysis_duration,
            'duration_formatted': self.get_formatted_duration(),
            'errors': len(self.errors),
            'warnings': len(self.warnings)
        }
        
        verbose_print(f"Base summary created with {len(summary)} fields", getattr(self, 'verbose', False))
        
        if self.framework_results:
            verbose_print("Adding framework results to summary", getattr(self, 'verbose', False))
            summary['primary_framework'] = self.framework_results.get_primary_framework_name()
            summary['framework_count'] = self.framework_results.get_framework_count()
            verbose_print(f"Framework info: {summary['primary_framework']} ({summary['framework_count']} total)", getattr(self, 'verbose', False))
        else:
            verbose_print("No framework results available for summary", getattr(self, 'verbose', False))
        
        if self.basic_info:
            verbose_print("Adding basic info to summary", getattr(self, 'verbose', False))
            summary['package_name'] = self.basic_info.package_name
            summary['app_name'] = self.basic_info.app_name
            summary['file_size_mb'] = round(self.basic_info.get_file_size_mb(), 2)
            verbose_print(f"App info: {summary['app_name']} ({summary['package_name']}) - {summary['file_size_mb']} MB", getattr(self, 'verbose', False))
        else:
            verbose_print("No basic info available for summary", getattr(self, 'verbose', False))
        
        verbose_print(f"Final summary contains {len(summary)} fields", getattr(self, 'verbose', False))
        return summary
    
    def is_detection_complete(self) -> bool:
        """
        Purpose:
            Report whether both detection stages produced a result.

        Returns:
            True when framework results and package information are both present.

        Implementation notes:
            Completeness is about the stages having run, not about them having found anything. An app whose framework could not be identified still has a framework result recording that.
        """
        verbose_print("Checking detection completeness", getattr(self, 'verbose', False))
        
        framework_complete = self.framework_results is not None
        basic_info_complete = self.basic_info is not None
        
        verbose_print(f"Framework results: {'✓' if framework_complete else '✗'}", getattr(self, 'verbose', False))
        verbose_print(f"Basic info: {'✓' if basic_info_complete else '✗'}", getattr(self, 'verbose', False))
        
        is_complete = framework_complete and basic_info_complete
        verbose_print(f"Detection complete: {is_complete}", getattr(self, 'verbose', False))
        
        return is_complete
    
    def has_errors(self) -> bool:
        """
        Purpose:
            Report whether any errors were recorded.

        Returns:
            True when the error list is non-empty.
        """
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """
        Purpose:
            Report whether any warnings were recorded.

        Returns:
            True when the warning list is non-empty.
        """
        return len(self.warnings) > 0
    
    def get_status(self) -> str:
        """
        Purpose:
            Summarise the outcome of detection in one phrase for display.

        Returns:
            One of four status strings.

        Implementation notes:
            Incompleteness outranks errors, and errors outrank warnings, so the phrase always names the most serious thing that happened rather than the most recent.
        """
        verbose_print("Determining detection status", getattr(self, 'verbose', False))
        
        if not self.is_detection_complete():
            status = "Incomplete"
        elif self.has_errors():
            status = "Completed with errors"
        elif self.has_warnings():
            status = "Completed with warnings" 
        else:
            status = "Completed successfully"
            
        verbose_print(f"Detection status: {status}", getattr(self, 'verbose', False))
        return status
