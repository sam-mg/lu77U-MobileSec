#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis

Purpose:
    Facade for the dynamic pipeline: device control, traffic interception, runtime instrumentation, UI driving and the verification pass that confirms or drops static findings.

Responsibilities:
    Re-export the managers, the UI automator, the visual check, the orchestrator and run_dynamic_verification.

Dependencies:
    .adb_manager, .mitmproxy_manager, .frida_manager, .ui_automator, .visual_checker, .dynamic_analyzer, .verify_tools, .verifier.

Security considerations:
    Everything here drives a real device or emulator: it installs and launches an untrusted APK, proxies its traffic through a local mitmproxy with a trusted CA, and injects Frida into the running process. This pipeline is for devices the operator owns and is prepared to wipe; the CA and the instrumentation both weaken the device's security posture for as long as they are installed.
"""

from .adb_manager import ADBManager
from .mitmproxy_manager import MitmproxyManager
from .frida_manager import FridaManager
from .ui_automator import UIAutomator
from .visual_checker import run_google_visual_check
from .dynamic_analyzer import DynamicAnalyzer
from .verify_tools import VerifyTools
from .verifier import run_dynamic_verification

__all__ = [
    "ADBManager",
    "MitmproxyManager",
    "FridaManager",
    "UIAutomator",
    "run_google_visual_check",
    "DynamicAnalyzer",
    "VerifyTools",
    "run_dynamic_verification",
]
