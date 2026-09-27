#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers

Purpose:
    Namespace for the per-framework analyzers, and the one place that names the Java/Kotlin analyzer as the default path for a standard Android app.

Responsibilities:
    Re-export JavaKotlinAnalyzer. The framework-specific analyzers are not re-exported, because each pulls in heavyweight tooling that a run should only load once detection has actually selected that framework.

Dependencies:
    .java_kotlin_analyzer.

Security considerations:
    Analyzers invoke external decompilers on untrusted APKs; keeping the non-default ones out of this facade means they are never loaded by a caller that does not intend to run them.
"""

from .java_kotlin_analyzer import JavaKotlinAnalyzer

__all__ = ['JavaKotlinAnalyzer']
