#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.layout

Purpose:
    Name the directories a cross-platform analysis root shares, in a module that imports nothing.

Implementation notes:
    Kept apart from the base analyzer so the rule engine's Dart extractor, the Flutter recovery helpers, the React Native overview and the native-library helpers can share the name without importing the base analyzer, which imports the rule engine and would close an import cycle.
"""

PLATFORM_DIR = "platform"
