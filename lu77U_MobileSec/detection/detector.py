"""Main Mobile Security Detector for lu77U-MobileSec"""

import os
from typing import Optional
from ..utils.verbose import verbose_print
from ..framework_detector.java_detector import JavaDetector
from ..framework_detector.kotlin_detector import KotlinDetector
from ..framework_detector.flutter_detector import FlutterDetector
from ..framework_detector.react_native_detector import ReactNativeDetector
from ..framework_detector.hybrid_detector import HybridFrameworkDetector
from ..framework_detector.native_detector import NativeDetector
from .results.detection_results import DetectionResult
from .results.framework_results import FrameworkDetectionResult
from .extractors.basic_info_extractor import BasicInfoExtractor
from .extractors.logging_config import setup_androguard_logging

class MobileSecurityDetector:
    def __init__(self, verbose=False):
        """Initialize mobile security detector"""
        self.verbose = verbose
        setup_androguard_logging(verbose)
        self.detectors = {
            'java': JavaDetector(verbose=verbose),
            'kotlin': KotlinDetector(verbose=verbose),
            'flutter': FlutterDetector(verbose=verbose),
            'react_native': ReactNativeDetector(verbose=verbose),
            'native': NativeDetector(verbose=verbose)
        }
        self.hybrid_detector = HybridFrameworkDetector(verbose=verbose)
        self.basic_info_extractor = BasicInfoExtractor(verbose=verbose)
        self.detection_result = None
    
    def detect(self, input_path: str) -> Optional[DetectionResult]:
        import time
        start_time = time.time()
        
        if not os.path.exists(input_path):
            verbose_print(f"Input path does not exist: {input_path}", self.verbose)
            return None
        
        self.detection_result = DetectionResult(
            target_path=input_path,
            is_apk=input_path.endswith('.apk')
        )
        try:
            framework_results = self._run_framework_detection(input_path)
            self.detection_result.framework_results = framework_results
            
            basic_info = self.basic_info_extractor.extract_basic_info(input_path)
            self.detection_result.basic_info = basic_info
            
            end_time = time.time()
            self.detection_result.analysis_duration = end_time - start_time
            return self.detection_result
        except Exception as e:
            end_time = time.time()
            self.detection_result.analysis_duration = end_time - start_time
            verbose_print(f"Error during detection: {str(e)}", self.verbose)
            if self.verbose:
                import traceback
                traceback.print_exc()
            return self.detection_result
    
    def _run_framework_detection(self, input_path: str) -> FrameworkDetectionResult:
        """Detect frameworks used in the application"""
        framework_result = FrameworkDetectionResult()
        
        try:
            detected = self.hybrid_detector.detect_all_frameworks(input_path)
            framework_result.detected_frameworks = detected
            
            if detected:
                primary_framework = max(detected, key=lambda x: x.get('confidence', 0))
                framework_result.primary_framework = primary_framework
                verbose_print(f"Primary framework identified: {primary_framework.get('framework', 'Unknown')} (confidence: {primary_framework.get('confidence', 0):.2f})", self.verbose)
                
                for framework in detected:
                    framework_name = framework.get('framework', 'Unknown')
                    confidence = framework.get('confidence', 0)
                    framework_result.confidence_scores[framework_name] = confidence
                    verbose_print(f"Framework: {framework_name}, Confidence: {confidence:.2f}", self.verbose)
            else:
                verbose_print("No frameworks detected by hybrid detector", self.verbose)
        except Exception as e:
            verbose_print(f"Error in hybrid framework detection: {e}", self.verbose)
            detected = []
            highest_confidence = 0
            primary_framework = None
            
            for name, detector in self.detectors.items():
                try:
                    result = detector.detect(input_path)
                    if result and result.get('confidence', 0) >= 0.3:
                        verbose_print(f"{name}: Found framework (confidence {result.get('confidence', 0):.2f})", self.verbose)
                        detected.append(result)
                        framework_result.confidence_scores[name] = result.get('confidence', 0)
                        if result.get('confidence', 0) > highest_confidence:
                            highest_confidence = result.get('confidence', 0)
                            primary_framework = result
                except Exception as detector_error:
                    verbose_print(f"Error in {name} detector: {detector_error}", self.verbose)
                    continue
                    
            framework_result.detected_frameworks = detected
            framework_result.primary_framework = primary_framework
        return framework_result