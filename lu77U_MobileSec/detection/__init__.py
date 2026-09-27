#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection

Purpose:
    Facade for the first stage of a run: identify what the APK is before deciding how to take it apart.

Responsibilities:
    Re-export the detector, its three result types and the manifest and basic-info extractors, plus the androguard logging setup.

Dependencies:
    .detector, .results, .extractors -- androguard underneath.

Security considerations:
    Detection parses an untrusted APK and its manifest. androguard is noisy and can emit parser internals at warning level, so setup_androguard_logging is exported alongside the extractors to keep that output from leaking into user-facing logs.
"""

from .detector import MobileSecurityDetector
from .results import DetectionResult, FrameworkDetectionResult, BasicInfoResult
from .extractors import BasicInfoExtractor, ManifestParser, setup_androguard_logging

__all__ = [
    'MobileSecurityDetector',
    'DetectionResult', 
    'FrameworkDetectionResult',
    'BasicInfoResult',
    'BasicInfoExtractor',
    'ManifestParser',
    'setup_androguard_logging'
]
