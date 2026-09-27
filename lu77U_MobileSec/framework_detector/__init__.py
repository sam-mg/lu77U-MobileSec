#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.framework_detector

Purpose:
    Facade for framework fingerprinting. Exposes every per-framework detector, the enhanced detector that arbitrates between them, and the framework name constants, so that a caller comparing a detection result against a constant never has to reach into two packages.

Responsibilities:
    Re-export the thirteen detector classes and the FRAMEWORK_* constants together with TECH_DETECTION_MAP.

Dependencies:
    The sibling detector modules and ..config.constants.

Implementation notes:
    The constants come out of config rather than being redefined here, so that a detector and its consumer can never disagree about the spelling of a framework name; the strings are persisted in reports and compared across process boundaries, so a drift would be silent.

Security considerations:
    Detectors read entries from an untrusted APK by name and by content signature; they must not extract or execute anything they find.
"""

from .base_detector import BaseFrameworkDetector
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
from ..config.constants import (
    FRAMEWORK_FLUTTER, FRAMEWORK_REACT_NATIVE, FRAMEWORK_CORDOVA,
    FRAMEWORK_XAMARIN, FRAMEWORK_UNITY, FRAMEWORK_UNREAL,
    FRAMEWORK_LIBGDX, FRAMEWORK_EXPO, FRAMEWORK_KONY,
    FRAMEWORK_JAVA, FRAMEWORK_KOTLIN, FRAMEWORK_HYBRID,
    TECH_DETECTION_MAP
)

__all__ = [
    'BaseFrameworkDetector',
    'JavaDetector',
    'KotlinDetector',
    'FlutterDetector',
    'ReactNativeDetector',
    'NativeDetector',
    'EnhancedFrameworkDetector',
    'CordovaDetector',
    'XamarinDetector',
    'UnityDetector',
    'UnrealDetector',
    'LibGDXDetector',
    'KonyDetector',
    'FRAMEWORK_FLUTTER',
    'FRAMEWORK_REACT_NATIVE',
    'FRAMEWORK_CORDOVA',
    'FRAMEWORK_XAMARIN',
    'FRAMEWORK_UNITY',
    'FRAMEWORK_UNREAL',
    'FRAMEWORK_LIBGDX',
    'FRAMEWORK_EXPO',
    'FRAMEWORK_KONY',
    'FRAMEWORK_JAVA',
    'FRAMEWORK_KOTLIN',
    'FRAMEWORK_HYBRID',
    'TECH_DETECTION_MAP'
]
