"""Hybrid Framework Detector for lu77U-MobileSec"""

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
    def __init__(self, verbose=False):
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
                        # Every installable Android APK has a DEX (Java/Kotlin)
                        # entry point; bundled .so libraries are near-universal
                        # (crypto, media codecs, ad/analytics SDKs, SQLite,
                        # ...) and are auxiliary, not evidence the app's
                        # *primary* framework is native C/C++ development.
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
