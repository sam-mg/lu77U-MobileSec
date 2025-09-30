"""Hybrid Framework Detector for lu77U-MobileSec"""

from ..utils.verbose import verbose_print
from .java_detector import JavaDetector
from .kotlin_detector import KotlinDetector
from .flutter_detector import FlutterDetector
from .react_native_detector import ReactNativeDetector
from .native_detector import NativeDetector

class HybridFrameworkDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        verbose_print("HybridFrameworkDetector initialized", self.verbose)
        verbose_print("Initializing individual framework detectors", self.verbose)
        
        self.detectors = [
            JavaDetector(verbose),
            KotlinDetector(verbose),
            FlutterDetector(verbose),
            ReactNativeDetector(verbose),
            NativeDetector(verbose)
        ]
        
        detector_names = [d.__class__.__name__ for d in self.detectors]
        verbose_print(f"Created {len(self.detectors)} detectors: {detector_names}", self.verbose)

    def detect_all_frameworks(self, input_path: str):
        verbose_print(f"Running all framework detectors on: {input_path}", self.verbose)
        verbose_print(f"Starting detection with {len(self.detectors)} detectors", self.verbose)
        
        results = []
        flutter_detected = False
        react_native_detected = False
        
        for i, detector in enumerate(self.detectors, 1):
            detector_name = detector.__class__.__name__
            verbose_print(f"Running detector {i}/{len(self.detectors)}: {detector_name}", self.verbose)
            
            try:
                result = detector.detect(input_path)
                if result:
                    framework_name = result.get('framework', 'Unknown')
                    confidence = result.get('confidence', 0)
                    indicators = result.get('indicators', [])
                    
                    verbose_print(f"{detector_name} detected: {framework_name} (confidence: {confidence:.2f})", self.verbose)
                    verbose_print(f"{detector_name} indicators: {indicators}", self.verbose)
                    
                    results.append(result)
                    
                    # Track high-confidence detections for filtering logic
                    if (framework_name == 'Flutter' and confidence >= 0.8):
                        flutter_detected = True
                        verbose_print("High-confidence Flutter detection confirmed", self.verbose)
                    elif (framework_name == 'React Native' and confidence >= 0.8):
                        react_native_detected = True
                        verbose_print("High-confidence React Native detection confirmed", self.verbose)
                else:
                    verbose_print(f"{detector_name} found no indicators", self.verbose)
            except Exception as e:
                verbose_print(f"Error in {detector_name}: {e}", self.verbose)
                continue
        
        verbose_print(f"Initial detection results: {len(results)} frameworks found", self.verbose)
        verbose_print(f"Flutter strongly detected: {flutter_detected}", self.verbose)
        verbose_print(f"React Native strongly detected: {react_native_detected}", self.verbose)
        
        # Apply filtering logic for conflicting detections
        if flutter_detected or react_native_detected:
            verbose_print("Applying filtering logic for high-confidence cross-platform frameworks", self.verbose)
            filtered_results = []
            
            for result in results:
                framework_name = result.get('framework', 'Unknown')
                
                if framework_name == 'Native (C/C++)':
                    if flutter_detected:
                        verbose_print("Filtering out Native detection - Flutter strongly detected", self.verbose)
                    elif react_native_detected:
                        verbose_print("Filtering out Native detection - React Native strongly detected", self.verbose)
                    continue
                else:
                    verbose_print(f"Keeping result: {framework_name}", self.verbose)
                
                filtered_results.append(result)
            
            verbose_print(f"After filtering: {len(filtered_results)} frameworks remain", self.verbose)
            results = filtered_results
        else:
            verbose_print("No filtering applied - no high-confidence cross-platform frameworks detected", self.verbose)
        
        # Log final results
        final_frameworks = [r.get('framework', 'Unknown') for r in results]
        verbose_print(f"Final detection results: {final_frameworks}", self.verbose)
        
        for result in results:
            framework = result.get('framework', 'Unknown')
            confidence = result.get('confidence', 0)
            verbose_print(f"Final result - {framework}: {confidence:.2f} confidence", self.verbose)
        
        verbose_print(f"Detection results: {results}", self.verbose)
        return results
