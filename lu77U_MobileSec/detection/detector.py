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
        verbose_print("Initializing MobileSecurityDetector", self.verbose)
        setup_androguard_logging(verbose)
        verbose_print("Androguard logging configured", self.verbose)
        self.detectors = {
            'java': JavaDetector(verbose=verbose),
            'kotlin': KotlinDetector(verbose=verbose),
            'flutter': FlutterDetector(verbose=verbose),
            'react_native': ReactNativeDetector(verbose=verbose),
            'native': NativeDetector(verbose=verbose)
        }
        verbose_print("Framework detectors initialized", self.verbose)
        self.hybrid_detector = HybridFrameworkDetector(verbose=verbose)
        verbose_print("Hybrid detector initialized", self.verbose)
        self.basic_info_extractor = BasicInfoExtractor(verbose=verbose)
        verbose_print("Basic info extractor initialized", self.verbose)
        self.detection_result = None
        verbose_print("MobileSecurityDetector initialization complete", self.verbose)
    
    def detect(self, input_path: str) -> Optional[DetectionResult]:
        import time
        start_time = time.time()
        verbose_print(f"Starting detection of: {input_path}", self.verbose)
        
        verbose_print("Validating input path", self.verbose)
        if not os.path.exists(input_path):
            verbose_print(f"Input path does not exist: {input_path}", self.verbose)
            return None
        
        verbose_print(f"Input path validated: {input_path}", self.verbose)
        verbose_print(f"Target is APK: {input_path.endswith('.apk')}", self.verbose)
        
        self.detection_result = DetectionResult(
            target_path=input_path,
            is_apk=input_path.endswith('.apk')
        )
        verbose_print("DetectionResult object created", self.verbose)
        try:
            verbose_print("Step 1: Framework Detection", self.verbose)
            framework_results = self._run_framework_detection(input_path)
            self.detection_result.framework_results = framework_results
            verbose_print("Framework detection results stored", self.verbose)
            
            verbose_print("Step 2: Basic Information Extraction", self.verbose)
            basic_info = self.basic_info_extractor.extract_basic_info(input_path)
            self.detection_result.basic_info = basic_info
            verbose_print("Basic information extraction results stored", self.verbose)
            
            end_time = time.time()
            self.detection_result.analysis_duration = end_time - start_time
            verbose_print(f"Detection completed successfully in {self.detection_result.get_formatted_duration()}", self.verbose)
            return self.detection_result
        except Exception as e:
            verbose_print(f"Exception occurred during detection: {type(e).__name__}", self.verbose)
            end_time = time.time()
            self.detection_result.analysis_duration = end_time - start_time
            verbose_print(f"Error during detection after {self.detection_result.get_formatted_duration()}: {str(e)}", self.verbose)
            if self.verbose:
                verbose_print("Printing full traceback for debugging", self.verbose)
                import traceback
                traceback.print_exc()
            verbose_print("Returning partial detection results", self.verbose)
            return self.detection_result
    
    def _run_framework_detection(self, input_path: str) -> FrameworkDetectionResult:
        """Detect frameworks used in the application"""
        verbose_print("Running framework detection", self.verbose)
        framework_result = FrameworkDetectionResult()
        verbose_print("FrameworkDetectionResult object created", self.verbose)
        
        try:
            verbose_print("Attempting hybrid framework detection", self.verbose)
            detected = self.hybrid_detector.detect_all_frameworks(input_path)
            verbose_print(f"Hybrid detector found {len(detected) if detected else 0} frameworks", self.verbose)
            framework_result.detected_frameworks = detected
            
            if detected:
                verbose_print("Processing detected frameworks", self.verbose)
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
            verbose_print("Falling back to individual detector approach", self.verbose)
            detected = []
            highest_confidence = 0
            primary_framework = None
            
            verbose_print("Running individual framework detectors", self.verbose)
            for name, detector in self.detectors.items():
                try:
                    verbose_print(f"Running {name} detector", self.verbose)
                    result = detector.detect(input_path)
                    if result and result.get('confidence', 0) >= 0.3:
                        verbose_print(f"{name} detector: Found framework with confidence {result.get('confidence', 0):.2f}", self.verbose)
                        detected.append(result)
                        framework_result.confidence_scores[name] = result.get('confidence', 0)
                        if result.get('confidence', 0) > highest_confidence:
                            highest_confidence = result.get('confidence', 0)
                            primary_framework = result
                            verbose_print(f"New primary framework candidate: {name} (confidence: {highest_confidence:.2f})", self.verbose)
                    else:
                        verbose_print(f"{name} detector: No framework detected or low confidence", self.verbose)
                except Exception as detector_error:
                    verbose_print(f"Error in {name} detector: {detector_error}", self.verbose)
                    continue
                    
            verbose_print(f"Individual detectors completed. Found {len(detected)} frameworks", self.verbose)
            framework_result.detected_frameworks = detected
            framework_result.primary_framework = primary_framework
        verbose_print(f"Framework detection complete. Found {len(framework_result.detected_frameworks)} frameworks", self.verbose)
        return framework_result