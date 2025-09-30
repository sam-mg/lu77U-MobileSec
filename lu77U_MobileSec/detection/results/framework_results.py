"""Framework Detection Results for lu77U-MobileSec"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from ...utils.verbose import verbose_print

@dataclass
class FrameworkDetectionResult:
    """Result of framework detection analysis"""
    detected_frameworks: List[Any] = field(default_factory=list)
    primary_framework: Optional[Any] = None
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    detection_timestamp: datetime = field(default_factory=datetime.now)
    verbose: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Post initialization logging"""
        if hasattr(self, 'verbose'):
            verbose_print(f"FrameworkDetectionResult created with {len(self.detected_frameworks)} detected frameworks", self.verbose)
    
    def get_primary_framework_name(self) -> str:
        """Get the name of the primary detected framework"""
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
        """Get total number of detected frameworks"""
        count = len(self.detected_frameworks)
        verbose_print(f"Framework count: {count}", getattr(self, 'verbose', False))
        return count
    
    def get_confidence_summary(self) -> Dict[str, str]:
        """Get a summary of confidence levels for all detected frameworks"""
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
    
    def get_top_frameworks(self, limit: int = 3) -> List[Dict[str, Any]]:
        """Get top N frameworks by confidence score"""
        verbose_print(f"Getting top {limit} frameworks from {len(self.confidence_scores)} total", getattr(self, 'verbose', False))
        
        sorted_frameworks = sorted(
            self.confidence_scores.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        verbose_print(f"Frameworks sorted by confidence: {[(f, round(c, 3)) for f, c in sorted_frameworks]}", getattr(self, 'verbose', False))
        
        result = []
        confidence_summary = self.get_confidence_summary()
        
        for framework, confidence in sorted_frameworks[:limit]:
            framework_data = {
                'name': framework,
                'confidence': confidence,
                'confidence_level': confidence_summary.get(framework, 'Unknown')
            }
            result.append(framework_data)
            verbose_print(f"Top framework: {framework} ({confidence:.3f}, {framework_data['confidence_level']})", getattr(self, 'verbose', False))
        
        verbose_print(f"Returning {len(result)} top frameworks", getattr(self, 'verbose', False))
        return result
