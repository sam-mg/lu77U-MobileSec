#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.results.basic_info_results

Purpose:
    Hold the package facts read out of an APK -- identity, versions, SDK levels, permissions and declared components -- and present them in report-ready forms.

Responsibilities:
    Store the extracted values and render counts, sizes and groupings.

Dependencies:
    dataclasses only.

Security considerations:
    Every value here comes from an untrusted APK and is attacker-declared. These accessors format but never escape, so whatever renders them must.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from ...utils.verbose import verbose_print

@dataclass
class BasicInfoResult:
    """
    Purpose:
        The package information extracted from one app.

    Attributes:
        file_type: What the target is.
        file_size: Size in bytes.
        package_name: Declared package identifier.
        app_name: Declared application label.
        version_name: Human-readable version.
        version_code: Numeric version.
        min_sdk: Minimum supported SDK level.
        target_sdk: Declared target SDK level.
        permissions: Declared permissions. activities, services, receivers, providers: Declared components.
        analysis_timestamp: When extraction ran.
        verbose: Whether accessors trace their work.

    Invariants:
        Every optional field may be None: an obfuscated or damaged manifest yields partial information, and that is an ordinary outcome rather than a failure.

    Thread-safety:
        Mutable and owned by one detection run.

    Security considerations:
        target_sdk in particular drives later severity decisions, since several platform defaults changed at specific levels. It is declared by the app and must be treated as a claim rather than a fact.

    Implementation notes:
        verbose is declared with init=False so it is never a constructor argument, and every method reads it through getattr with a default. Dataclass field ordering would otherwise force it into the signature of every construction site, and the getattr guard means an instance rebuilt from serialised data without the field still works.
    """
    file_type: str = ""
    file_size: int = 0
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    verbose: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """
        Purpose:
            Trace the creation of the result.

        Side effects:
            Writes one line to the verbose stream.
        """
        if hasattr(self, 'verbose'):
            verbose_print(f"BasicInfoResult created for {self.file_type}: {self.package_name or 'Unknown'}", self.verbose)
    
    def get_component_count(self) -> int:
        """
        Purpose:
            Count every declared component across the four kinds.

        Returns:
            The total.
        """
        total = len(self.activities) + len(self.services) + len(self.receivers) + len(self.providers)
        verbose_print(f"Calculated component count: {total} (A:{len(self.activities)}, S:{len(self.services)}, R:{len(self.receivers)}, P:{len(self.providers)})", getattr(self, 'verbose', False))
        return total
    
    def get_file_size_mb(self) -> float:
        """
        Purpose:
            Express the file size in megabytes.

        Returns:
            The size in MB, unrounded.

        Implementation notes:
            Uses binary megabytes, matching what a file manager reports on the platforms this tool runs on.
        """
        size_mb = self.file_size / (1024 * 1024)
        verbose_print(f"File size: {self.file_size} bytes = {size_mb:.2f} MB", getattr(self, 'verbose', False))
        return size_mb
    
    def get_file_size_formatted(self) -> str:
        """
        Purpose:
            Render the file size with the unit a reader would use.

        Returns:
            A formatted size string.

        Implementation notes:
            Scales through bytes, KB, MB and GB so that a small resource file and a large game both read naturally. Bytes are shown whole; everything above gets one decimal place.
        """
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
        """
        Purpose:
            Break the component counts down by kind for the report.

        Returns:
            Counts per kind plus the total.
        """
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
        """
        Purpose:
            Present the SDK levels together with a readable range.

        Returns:
            The two levels plus a formatted range string.

        Implementation notes:
            Missing levels render as "Unknown" rather than being omitted, because the SDK range is load-bearing context for several findings and its absence is itself worth showing.
        """
        verbose_print(f"Generating SDK info: min={self.min_sdk}, target={self.target_sdk}", getattr(self, 'verbose', False))
        
        sdk_info = {
            'min_sdk': self.min_sdk,
            'target_sdk': self.target_sdk,
            'sdk_range': f"{self.min_sdk or 'Unknown'} - {self.target_sdk or 'Unknown'}"
        }
        
        verbose_print(f"SDK info: {sdk_info['sdk_range']}", getattr(self, 'verbose', False))
        return sdk_info
    
    def get_version_info(self) -> Dict[str, Any]:
        """
        Purpose:
            Present the version name and code together with a readable combination.

        Returns:
            Both values plus a formatted string.
        """
        verbose_print(f"Generating version info: name={self.version_name}, code={self.version_code}", getattr(self, 'verbose', False))
        
        version_info = {
            'version_name': self.version_name,
            'version_code': self.version_code,
            'version_string': f"{self.version_name or 'Unknown'} ({self.version_code or 'Unknown'})"
        }
        
        verbose_print(f"Version info: {version_info['version_string']}", getattr(self, 'verbose', False))
        return version_info
    
    def is_large_app(self, threshold_mb: float = 100.0) -> bool:
        """
        Purpose:
            Report whether the app is large enough that analysis will be slow.

        Parameters:
            threshold_mb: Size above which the app counts as large.

        Returns:
            True when the app exceeds the threshold.

        Implementation notes:
            Used to set expectations before a long decompilation rather than to change behaviour. The threshold is a parameter because what counts as large depends on the machine.
        """
        size_mb = self.get_file_size_mb()
        is_large = size_mb > threshold_mb
        verbose_print(f"Large app check: {size_mb:.2f} MB > {threshold_mb} MB = {is_large}", getattr(self, 'verbose', False))
        return is_large
    
    def has_components(self) -> bool:
        """
        Purpose:
            Report whether the app declares any components at all.

        Returns:
            True when at least one component was found.

        Implementation notes:
            A false result usually means the manifest could not be parsed rather than that the app genuinely has none, since a launchable app must declare at least one activity.
        """
        component_count = self.get_component_count()
        has_any = component_count > 0
        verbose_print(f"Component check: {component_count} components found = {has_any}", getattr(self, 'verbose', False))
        return has_any
    
    def get_main_activities(self) -> List[str]:
        """
        Purpose:
            Guess which activities are entry points, for orienting a reader and for seeding dynamic analysis.

        Returns:
            Activities whose names suggest they are entry points.

        Implementation notes:
            Matched on naming convention rather than on the manifest's intent filters, which this result type does not carry. That makes it a heuristic: it misses an entry activity named unconventionally and picks up any class with "main" in its name. Adequate for its purpose, which is suggesting where to start rather than establishing reachability. Anything depending on real entry points reads the intent filters instead.
        """
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
