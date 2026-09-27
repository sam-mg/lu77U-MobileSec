#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.detector

Purpose:
    The first stage of a scan: work out what the APK is -- which framework built it, what it declares about itself -- so that the right analyzer and decompiler are chosen.

Responsibilities:
    Own the per-framework detectors and the hybrid arbitrator, run detection, extract basic package information, and time the whole stage.

Dependencies:
    The framework detectors, the result types, the basic-info extractor, and the androguard logging setup.

Implementation notes:
    Detection is arranged as a primary path with a fallback. The hybrid detector considers all frameworks together and can recognise an app that combines several; if it fails, the individual detectors are run separately and the most confident wins. The fallback is less accurate but keeps a scan going rather than abandoning it over a detector bug.

Security considerations:
    Everything here reads an untrusted APK. An app can plant the markers of a framework it does not use, so detection is advisory: every analyzer must tolerate input that does not match what detection claimed.
"""

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
    """
    Purpose:
        Runs framework detection and basic package extraction over an APK.

    Attributes:
        verbose: Whether detection activity is traced.
        detectors: Per-framework detectors, used only on the fallback path.
        hybrid_detector: The primary detector, which considers all frameworks together.
        basic_info_extractor: Extracts package identity from the APK.
        detection_result: The most recent result, retained after detect returns.

    Invariants:
        detection_result is None until detect has been called, and is populated afterwards even when detection partly failed.

    Thread-safety:
        Not safe to share. detection_result is instance state overwritten by each call, so concurrent scans need separate instances.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct the detector set and quieten androguard.

        Parameters:
            verbose: Enables tracing and is forwarded to every detector.

        Side effects:
            Configures androguard and loguru logging process-wide.

        Implementation notes:
            The logging setup runs here rather than at import because it depends on the verbosity of this particular run. It is process-wide, so constructing a detector reconfigures logging for everything.
        """
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
        """
        Purpose:
            Identify the app: its framework and its declared package information.

        Parameters:
            input_path: Path to the APK or to an extracted directory.

        Returns:
            The detection result, or None when the path does not exist. On a partial failure the result is still returned, carrying whatever was established.

        Side effects:
            Reads the APK and records the elapsed time on the result.

        Implementation notes:
            A missing path returns None, which is the one case a caller cannot proceed from. Every other failure returns a partial result, because framework detection and package extraction are independent and one failing does not make the other worthless. The duration is recorded on both the success and failure paths, so a scan that spent a long time failing to detect is visible in the report rather than silently fast. The traceback is printed only under verbose.

        Security considerations:
            The APK is untrusted input and androguard's parsers are the code reading it, which is why the whole body is guarded rather than trusting the library not to raise.
        """
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
        """
        Purpose:
            Determine which frameworks the app uses and which is primary.

        Parameters:
            input_path: Path to the APK.

        Returns:
            The framework result, carrying every detected framework, the primary one, and the per-framework confidence scores.

        Implementation notes:
            The hybrid detector runs first because it can recognise a genuinely hybrid app -- a React Native shell around native modules, for instance -- which running detectors independently cannot. Its primary framework is the highest-confidence one rather than the first matched, since several detectors legitimately fire on the same app. The fallback path runs each detector independently and applies a confidence floor, discarding weak matches that the hybrid arbitrator would have weighed against each other. Each detector is individually guarded so one failing does not lose the results of the others. Confidence scores are recorded for every framework, not just the winner, so a report can show that detection was ambiguous rather than presenting a close call as certain.
        """
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
                        framework_result.confidence_scores[
                            result.get('framework', name)] = result.get('confidence', 0)
                        if result.get('confidence', 0) > highest_confidence:
                            highest_confidence = result.get('confidence', 0)
                            primary_framework = result
                except Exception as detector_error:
                    verbose_print(f"Error in {name} detector: {detector_error}", self.verbose)
                    continue
                    
            framework_result.detected_frameworks = detected
            framework_result.primary_framework = primary_framework
        return framework_result
