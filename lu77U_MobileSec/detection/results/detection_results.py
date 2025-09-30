"""Main Detection Results for lu77U-MobileSec"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from .framework_results import FrameworkDetectionResult
from .basic_info_results import BasicInfoResult
from ...utils import format_duration
from ...utils.verbose import verbose_print

@dataclass
class DetectionResult:
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
        """Post initialization logging"""
        if hasattr(self, 'verbose'):
            verbose_print(f"DetectionResult created for: {self.target_path} (APK: {self.is_apk})", self.verbose)
    
    def add_error(self, error_message: str):
        """Add an error message to the detection"""
        error_entry = f"{datetime.now()}: {error_message}"
        self.errors.append(error_entry)
        verbose_print(f"Added error to detection: {error_message}", getattr(self, 'verbose', False))
        verbose_print(f"Total errors: {len(self.errors)}", getattr(self, 'verbose', False))
    
    def add_warning(self, warning_message: str):
        """Add a warning message to the detection"""
        warning_entry = f"{datetime.now()}: {warning_message}"
        self.warnings.append(warning_entry)
        verbose_print(f"Added warning to detection: {warning_message}", getattr(self, 'verbose', False))
        verbose_print(f"Total warnings: {len(self.warnings)}", getattr(self, 'verbose', False))
    
    def get_formatted_duration(self) -> str:
        """Get formatted duration string"""
        return format_duration(self.analysis_duration, getattr(self, 'verbose', False))
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the detection results"""
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
        """Check if detection is complete (framework detection and basic info)"""
        verbose_print("Checking detection completeness", getattr(self, 'verbose', False))
        
        framework_complete = self.framework_results is not None
        basic_info_complete = self.basic_info is not None
        
        verbose_print(f"Framework results: {'✓' if framework_complete else '✗'}", getattr(self, 'verbose', False))
        verbose_print(f"Basic info: {'✓' if basic_info_complete else '✗'}", getattr(self, 'verbose', False))
        
        is_complete = framework_complete and basic_info_complete
        verbose_print(f"Detection complete: {is_complete}", getattr(self, 'verbose', False))
        
        return is_complete
    
    def has_errors(self) -> bool:
        """Check if detection has any errors"""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if detection has any warnings"""
        return len(self.warnings) > 0
    
    def get_status(self) -> str:
        """Get detection status string"""
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