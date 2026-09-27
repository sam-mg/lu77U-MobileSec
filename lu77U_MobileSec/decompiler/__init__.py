#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler

Purpose:
    Facade for decompilation. Re-exports the Java/Kotlin decompiler, which is the path taken for a standard Android app.

Responsibilities:
    Re-export JavaKotlinDecompiler.

Dependencies:
    .java_kotlin_decompiler, which in turn shells out to JADX.

Security considerations:
    Decompilation runs third-party tooling over an attacker-supplied APK. Argument construction and output-path containment are enforced in the decompiler module itself, not here.
"""

from .java_kotlin_decompiler import JavaKotlinDecompiler

__all__ = ['JavaKotlinDecompiler']
