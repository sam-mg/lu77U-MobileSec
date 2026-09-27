#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.results

Purpose:
    Facade for the typed results detection produces, kept in their own package so that consumers can depend on the shapes without importing androguard.

Responsibilities:
    Re-export FrameworkDetectionResult, BasicInfoResult and DetectionResult.

Dependencies:
    .framework_results, .basic_info_results, .detection_results -- standard library only.
"""

from .framework_results import FrameworkDetectionResult
from .basic_info_results import BasicInfoResult
from .detection_results import DetectionResult

__all__ = [
    'FrameworkDetectionResult',
    'BasicInfoResult',
    'DetectionResult'
]
