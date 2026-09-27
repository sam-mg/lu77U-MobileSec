#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector.hybrid_detector

Purpose:
    Run every framework detector over one app and reconcile their answers, so that an app matching several frameworks is described correctly rather than by whichever detector ran first.

Responsibilities:
    Own the detector set, collect every detection, and suppress the ones that are artifacts of another framework's presence.

Dependencies:
    Every detector module.

Implementation notes:
    Reconciliation is the reason this exists. Real apps legitimately match more than one detector -- a Flutter app contains DEX, a React Native app contains native libraries -- and reporting every match would be as useless as reporting only one.
"""

from ..utils.verbose import verbose_print
from .java_detector import JavaDetector
from .kotlin_detector import KotlinDetector
from .flutter_detector import FlutterDetector
from .react_native_detector import ReactNativeDetector
from .native_detector import NativeDetector
from .enhanced_detector import EnhancedFrameworkDetector
from .cordova_detector import CordovaDetector
from .xamarin_detector import XamarinDetector
from .unity_detector import UnityDetector
from .unreal_detector import UnrealDetector
from .libgdx_detector import LibGDXDetector
from .kony_detector import KonyDetector

class HybridFrameworkDetector:
    """
    Purpose:
        Runs all detectors and reconciles their results.

    Attributes:
        verbose: Whether detection is traced.
        detectors: Every detector, in the order they run.

    Invariants:
        Returns a list, possibly empty. Order of detection is preserved, so the caller ranks by confidence rather than by position.

    Thread-safety:
        Not safe to share, since the detectors it holds are not.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Construct one instance of every detector.

        Parameters:
            verbose: Enables tracing and is forwarded to each detector.

        Implementation notes:
            The enhanced detector runs last. It is the broadest of the set and its results are most useful as corroboration of what the specific detectors already found.
        """
        self.verbose = verbose
        
        self.detectors = [
            JavaDetector(verbose),
            KotlinDetector(verbose),
            FlutterDetector(verbose),
            ReactNativeDetector(verbose),
            NativeDetector(verbose),
            CordovaDetector(verbose),
            XamarinDetector(verbose),
            UnityDetector(verbose),
            UnrealDetector(verbose),
            LibGDXDetector(verbose),
            KonyDetector(verbose),
            EnhancedFrameworkDetector(verbose)
        ]

    def detect_all_frameworks(self, input_path: str):
        """
        Purpose:
            Detect every framework present and filter out the results that are side effects of another.

        Parameters:
            input_path: Path to an APK or a project directory.

        Returns:
            The surviving detections, each with framework, indicators and confidence.

        Side effects:
            Reads the target repeatedly, once per detector.

        Implementation notes:
            Every detector is individually guarded, so one failing costs its own result rather than the whole detection stage. The filtering rule is narrow and deliberate: a native-code detection is dropped when Flutter, React Native, Java or Kotlin was detected with high confidence. Every one of those ships native libraries, so the native detector fires on all of them and reporting it would suggest a hand-written native component that does not exist. Nothing else is filtered, because the other combinations are genuinely informative -- a Unity game with a Java wrapper really does have both. The confidence thresholds differ by framework: cross-platform frameworks must be detected strongly before they suppress anything, while Java and Kotlin need only moderate confidence, since their detection is already exclusion-based and rarely fires spuriously. Expo is treated as implying React Native, since it is a distribution of it and the same decompiler applies.

        Known limitations:
            Each detector reads the APK independently, so a full detection pass opens the archive a dozen times.
        """
        results = []
        flutter_detected = False
        react_native_detected = False
        expo_detected = False
        java_or_kotlin_detected = False

        for i, detector in enumerate(self.detectors, 1):
            detector_name = detector.__class__.__name__

            try:
                result = detector.detect(input_path)
                if result:
                    framework_name = result.get('framework', 'Unknown')
                    confidence = result.get('confidence', 0)
                    indicators = result.get('indicators', [])

                    verbose_print(f"{detector_name} detected: {framework_name} (confidence: {confidence:.2f})", self.verbose)
                    verbose_print(f"{detector_name} indicators: {indicators}", self.verbose)

                    results.append(result)

                    if (framework_name == 'Flutter' and confidence >= 0.8):
                        flutter_detected = True
                        verbose_print("High-confidence Flutter detection confirmed", self.verbose)
                    elif (framework_name == 'React Native' and confidence >= 0.8):
                        react_native_detected = True
                        verbose_print("High-confidence React Native detection confirmed", self.verbose)
                    elif (framework_name == 'Expo' and confidence >= 0.8):
                        expo_detected = True
                        react_native_detected = True
                        verbose_print("High-confidence Expo detection confirmed", self.verbose)
                    elif framework_name in ('Java', 'Kotlin') and confidence >= 0.5:
                        java_or_kotlin_detected = True
                        verbose_print(f"{framework_name} detection confirmed", self.verbose)
            except Exception as e:
                verbose_print(f"Error in {detector_name}: {e}", self.verbose)
                continue

        if flutter_detected or react_native_detected or java_or_kotlin_detected:
            verbose_print("Applying filtering logic for high-confidence frameworks", self.verbose)
            filtered_results = []

            for result in results:
                framework_name = result.get('framework', 'Unknown')

                if framework_name == 'Native (C/C++)':
                    if flutter_detected:
                        verbose_print("Filtering out Native detection - Flutter strongly detected", self.verbose)
                    elif react_native_detected:
                        verbose_print("Filtering out Native detection - React Native strongly detected", self.verbose)
                    elif java_or_kotlin_detected:
                        verbose_print("Filtering out Native detection - Java/Kotlin strongly detected", self.verbose)
                    continue
                else:
                    verbose_print(f"Keeping result: {framework_name}", self.verbose)

                filtered_results.append(result)

            verbose_print(f"After filtering: {len(filtered_results)} frameworks remain", self.verbose)
            results = filtered_results
        
        final_frameworks = [r.get('framework', 'Unknown') for r in results]
        verbose_print(f"Final detection results: {final_frameworks}", self.verbose)
        
        for result in results:
            framework = result.get('framework', 'Unknown')
            confidence = result.get('confidence', 0)
            verbose_print(f"Final result - {framework}: {confidence:.2f} confidence", self.verbose)
        
        verbose_print(f"Detection results: {results}", self.verbose)
        return results
