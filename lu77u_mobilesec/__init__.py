#!/usr/bin/env python3
"""
lu77U-MobileSec - Professional Mobile Security Analysis & Vulnerability Patching Tool

A comprehensive mobile security analysis tool that automatically detects vulnerabilities 
in Android applications and generates AI-powered security patches across Java/Kotlin, 
React Native, and Flutter frameworks.

Author: Sam MG Harish (lu77_u)
License: Apache Software License 2.0
"""

__version__ = "1.0.0"
__author__ = "Sam MG Harish (lu77_u)"
__license__ = "Apache-2.0"
__email__ = "sammgharish@gmail.com"

# Main orchestrator
from .core.orchestrator import MobileSecAnalyzer

# CLI interface
from .cli.app import main, run

# Core analyzers
from .core.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer
from .core.analyzers.react_native_analyzer import ReactNativeAnalyzer
from .core.analyzers.flutter_analyzer import FlutterAnalyzer

# Framework detector
from .core.detectors.framework_detector import FrameworkDetector

# System doctor
from .system.doctor.main_doctor import MobileSecDoctor

__all__ = [
    "MobileSecAnalyzer",
    "main",
    "run", 
    "JavaKotlinAnalyzer",
    "ReactNativeAnalyzer",
    "FlutterAnalyzer",
    "FrameworkDetector",
    "MobileSecDoctor",
]
