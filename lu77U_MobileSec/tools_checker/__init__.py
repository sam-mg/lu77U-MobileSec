#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker

Purpose:
    Facade for the preflight checks that decide whether an analysis can run at all: JADX for decompilation and a reachable AI provider for the agent pass, plus the optional Ghidra check for native libraries.

Responsibilities:
    Re-export the individual checkers plus the aggregate requirement and status helpers used by the dashboard's readiness panel.

Dependencies:
    .jadx_checker, .ghidra_checker, .ollama_checker, .analysis_checker.

Security considerations:
    Checkers probe for local executables and contact the configured AI endpoint. They report presence and reachability only and must never surface an API key in their results.
"""

from .jadx_checker import check_jadx_configured
from .ghidra_checker import check_ghidra_configured
from .ollama_checker import check_ollama_configured, check_ai_provider_configured
from .analysis_checker import check_analysis_requirements, get_analysis_status

__all__ = [
    'check_jadx_configured',
    'check_ghidra_configured',
    'check_ollama_configured',
    'check_ai_provider_configured',
    'check_analysis_requirements',
    'get_analysis_status',
]
