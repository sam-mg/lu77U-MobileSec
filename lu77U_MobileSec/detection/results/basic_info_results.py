"""Basic Information Results for lu77U-MobileSec"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from ...utils.verbose import verbose_print

@dataclass
class BasicInfoResult:
    """Basic application information"""
    file_type: str = ""
    file_size: int = 0
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    verbose: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Post initialization logging"""
        if hasattr(self, 'verbose'):
            verbose_print(f"BasicInfoResult created for {self.file_type}: {self.package_name or 'Unknown'}", self.verbose)
    
    def get_component_count(self) -> int:
        """Get total count of Android components"""
        total = len(self.activities) + len(self.services) + len(self.receivers) + len(self.providers)
        verbose_print(f"Calculated component count: {total} (A:{len(self.activities)}, S:{len(self.services)}, R:{len(self.receivers)}, P:{len(self.providers)})", getattr(self, 'verbose', False))
        return total
    
    def get_file_size_mb(self) -> float:
        """Get file size in megabytes"""
        size_mb = self.file_size / (1024 * 1024)
        verbose_print(f"File size: {self.file_size} bytes = {size_mb:.2f} MB", getattr(self, 'verbose', False))
        return size_mb
    
    def get_file_size_formatted(self) -> str:
        """Get formatted file size with appropriate units"""
        verbose_print(f"Formatting file size: {self.file_size} bytes", getattr(self, 'verbose', False))
        
        if self.file_size < 1024:
            result = f"{self.file_size} bytes"
        elif self.file_size < 1024 * 1024:
            result = f"{self.file_size / 1024:.1f} KB"
        elif self.file_size < 1024 * 1024 * 1024:
            result = f"{self.file_size / (1024 * 1024):.1f} MB"
        else:
            result = f"{self.file_size / (1024 * 1024 * 1024):.1f} GB"
            
        verbose_print(f"Formatted file size: {result}", getattr(self, 'verbose', False))
        return result
    
    def get_component_breakdown(self) -> Dict[str, int]:
        """Get breakdown of component counts by type"""
        verbose_print("Generating component breakdown", getattr(self, 'verbose', False))
        
        breakdown = {
            'activities': len(self.activities),
            'services': len(self.services),
            'receivers': len(self.receivers),
            'providers': len(self.providers),
            'total': self.get_component_count()
        }
        
        verbose_print(f"Component breakdown: {breakdown}", getattr(self, 'verbose', False))
        return breakdown
    
    def get_sdk_info(self) -> Dict[str, Any]:
        """Get SDK information summary"""
        verbose_print(f"Generating SDK info: min={self.min_sdk}, target={self.target_sdk}", getattr(self, 'verbose', False))
        
        sdk_info = {
            'min_sdk': self.min_sdk,
            'target_sdk': self.target_sdk,
            'sdk_range': f"{self.min_sdk or 'Unknown'} - {self.target_sdk or 'Unknown'}"
        }
        
        verbose_print(f"SDK info: {sdk_info['sdk_range']}", getattr(self, 'verbose', False))
        return sdk_info
    
    def get_version_info(self) -> Dict[str, Any]:
        """Get version information summary"""
        verbose_print(f"Generating version info: name={self.version_name}, code={self.version_code}", getattr(self, 'verbose', False))
        
        version_info = {
            'version_name': self.version_name,
            'version_code': self.version_code,
            'version_string': f"{self.version_name or 'Unknown'} ({self.version_code or 'Unknown'})"
        }
        
        verbose_print(f"Version info: {version_info['version_string']}", getattr(self, 'verbose', False))
        return version_info
    
    def is_large_app(self, threshold_mb: float = 100.0) -> bool:
        """Check if the app is considered large based on file size"""
        size_mb = self.get_file_size_mb()
        is_large = size_mb > threshold_mb
        verbose_print(f"Large app check: {size_mb:.2f} MB > {threshold_mb} MB = {is_large}", getattr(self, 'verbose', False))
        return is_large
    
    def has_components(self) -> bool:
        """Check if the app has any Android components defined"""
        component_count = self.get_component_count()
        has_any = component_count > 0
        verbose_print(f"Component check: {component_count} components found = {has_any}", getattr(self, 'verbose', False))
        return has_any
    
    def get_main_activities(self) -> List[str]:
        """Get activities that might be main/launcher activities"""
        verbose_print(f"Searching for main activities among {len(self.activities)} activities", getattr(self, 'verbose', False))
        
        main_activities = []
        keywords = ['main', 'launcher', 'splash']
        
        for activity in self.activities:
            activity_name = activity.lower()
            for keyword in keywords:
                if keyword in activity_name:
                    main_activities.append(activity)
                    verbose_print(f"Found main activity: {activity} (contains '{keyword}')", getattr(self, 'verbose', False))
                    break
                    
        verbose_print(f"Found {len(main_activities)} main activities: {main_activities}", getattr(self, 'verbose', False))
        return main_activities
