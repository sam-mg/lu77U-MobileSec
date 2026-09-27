#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.registry

Purpose:
    Map a detected framework name to the analyzer that handles it, without importing every analyzer to do so.

Responsibilities:
    Hold the framework-to-analyzer table and resolve a name to a class.

Dependencies:
    The base analyzer type; the concrete analyzers are imported on demand.

Implementation notes:
    Each entry is a factory rather than a class, so importing this module costs nothing. Importing every analyzer eagerly would pull in the whole decompiler and tooling chain for frameworks the scan will never touch. Several names map to the same analyzer deliberately: Java, Kotlin, generic, unknown and native all take the Dalvik path, because that is the correct treatment for an app that is not one of the recognised cross-platform frameworks. Mapping unknown to the Java analyzer rather than to nothing is what lets an unrecognised app still be analysed properly.
"""

from typing import Callable, Dict, Optional, Type

from .base import BaseAnalyzer


def _java_kotlin() -> Type[BaseAnalyzer]:
    """
    Purpose:
        Import and return the Java and Kotlin analyzer.

    Returns:
        The analyzer class.

    Implementation notes:
        The import is inside the function so that selecting one analyzer does not load the others and their tooling.
    """
    from .java_kotlin_analyzer import JavaKotlinAnalyzer
    return JavaKotlinAnalyzer


def _flutter() -> Type[BaseAnalyzer]:
    """
    Purpose:
        Import and return the Flutter analyzer.

    Returns:
        The analyzer class.

    Implementation notes:
        The import is inside the function so that selecting one analyzer does not load the others and their tooling.
    """
    from .flutter_analyzer import FlutterAnalyzer
    return FlutterAnalyzer


def _react_native() -> Type[BaseAnalyzer]:
    """
    Purpose:
        Import and return the React Native analyzer.

    Returns:
        The analyzer class.

    Implementation notes:
        The import is inside the function so that selecting one analyzer does not load the others and their tooling.
    """
    from .react_native_analyzer import ReactNativeAnalyzer
    return ReactNativeAnalyzer


def _cordova() -> Type[BaseAnalyzer]:
    """
    Purpose:
        Import and return the Cordova analyzer.

    Returns:
        The analyzer class.

    Implementation notes:
        The import is inside the function so that selecting one analyzer does not load the others and their tooling.
    """
    from .cordova_analyzer import CordovaAnalyzer
    return CordovaAnalyzer


def _xamarin() -> Type[BaseAnalyzer]:
    """
    Purpose:
        Import and return the Xamarin and MAUI analyzer.

    Returns:
        The analyzer class.

    Implementation notes:
        The import is inside the function so that selecting one analyzer does not load the others and their tooling.
    """
    from .xamarin_analyzer import XamarinAnalyzer
    return XamarinAnalyzer


_REGISTRY: Dict[str, Callable[[], Type[BaseAnalyzer]]] = {
    "java": _java_kotlin,
    "kotlin": _java_kotlin,
    "generic": _java_kotlin,
    "unknown": _java_kotlin,
    "native (c/c++)": _java_kotlin,
    "flutter": _flutter,
    "react native": _react_native,
    "expo": _react_native,
    "cordova": _cordova,
    "xamarin": _xamarin,
    ".net maui": _xamarin,
    "maui": _xamarin,
}


def get_analyzer_class(framework_name: str) -> Optional[Type[BaseAnalyzer]]:
    """
    Purpose:
        Resolve a framework name to its analyzer.

    Parameters:
        framework_name: The detected framework.

    Returns:
        The analyzer class, or None when the framework has no analyzer.

    Implementation notes:
        The name is normalised before lookup, since it arrives from detectors that differ in casing and spacing. None means the framework is recognised but not deeply analysable -- the game engines, for instance -- and the caller reports that rather than falling back to an analyzer that would produce nothing useful.
    """
    factory = _REGISTRY.get((framework_name or "").strip().lower())
    return factory() if factory else None
