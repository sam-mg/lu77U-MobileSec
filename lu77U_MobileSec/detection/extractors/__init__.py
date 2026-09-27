#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.extractors

Purpose:
    Facade for the components that pull facts out of an APK: package identity, manifest contents, and the androguard logging setup they both need.

Responsibilities:
    Re-export BasicInfoExtractor, ManifestParser and setup_androguard_logging.

Dependencies:
    .basic_info_extractor, .manifest_parser, .logging_config -- androguard underneath.

Security considerations:
    Every value these extractors return originates in an untrusted APK and must be escaped before it reaches a report or a shell.
"""

from .basic_info_extractor import BasicInfoExtractor
from .manifest_parser import ManifestParser
from .logging_config import setup_androguard_logging

__all__ = [
    'BasicInfoExtractor',
    'ManifestParser', 
    'setup_androguard_logging'
]
