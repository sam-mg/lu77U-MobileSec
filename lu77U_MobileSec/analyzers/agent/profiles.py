#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.profiles

Purpose:
    Describe each framework to the agent: which file extensions are source, which are resources, and which prompt and heuristics apply.

Responsibilities:
    Declare the profile type and the per-framework profiles.

Dependencies:
    dataclasses only.

Implementation notes:
    The agent loop is framework-agnostic; everything it needs to know about a particular framework is in its profile. That is what lets one loop serve Java, Flutter, React Native, Cordova and Xamarin without branching on framework at every step.
"""

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class SourceProfile:
    """
    Purpose:
        What the agent needs to know about one framework's recovered output.

    Attributes:
        key: Profile identifier, selecting the prompt.
        source_exts: Extensions treated as application source.
        resource_exts: Extensions treated as resources rather than code.

    Invariants:
        Frozen, and shared across every agent working on one scan.

    Thread-safety:
        Immutable and safe to share.
    """
    key: str

    source_exts: Tuple[str, ...]

    resource_exts: Tuple[str, ...] = field(default_factory=tuple)

    noise_fragments: Tuple[str, ...] = field(default_factory=tuple)

    generated_stems: Tuple[str, ...] = field(default_factory=tuple)

    generated_stem_prefixes: Tuple[str, ...] = field(default_factory=tuple)

    resource_globs: Tuple[str, ...] = field(default_factory=tuple)

    summary_candidates: Tuple[str, ...] = field(default_factory=tuple)

    summary_label: str = "Manifest"

    summary_missing: str = "(no summary file found)"

    android_resource_filters: bool = False


JAVA_KOTLIN = SourceProfile(
    key="java_kotlin",
    source_exts=(".java", ".kt"),
    resource_exts=(".xml", ".smali"),
    noise_fragments=(
        "/androidx/", "/android/", "/kotlin/", "/kotlinx/", "/com/google/",
        "/org/jetbrains/", "/org/intellij/",
    ),
    generated_stems=("R", "BuildConfig"),
    generated_stem_prefixes=("R$",),
    resource_globs=("resources/res/xml", "resources/res/raw", "resources/res/values/strings.xml"),
    summary_candidates=("resources/AndroidManifest.xml", "AndroidManifest.xml"),
    summary_label="AndroidManifest.xml",
    summary_missing="(AndroidManifest.xml not found)",
    android_resource_filters=True,
)

FLUTTER = SourceProfile(
    key="flutter",
    source_exts=(".asm", ".s", ".S", ".dis", ".dart", ".java", ".kt"),
    resource_exts=(".txt", ".xml"),
    noise_fragments=(
        "/dart/", "/flutter/", "/package:flutter/", "/sdk/",
        "/androidx/", "/android/", "/kotlin/", "/kotlinx/", "/com/google/",
        "/org/jetbrains/", "/org/intellij/",
    ),
    resource_globs=("flutter_scan_overview.txt", "pp.txt", "objs.txt",
                    "snapshot_strings/libapp_key_strings.txt", "snapshot_strings/libapp_strings.txt",
                    "platform/resources/AndroidManifest.xml"),
    summary_candidates=("flutter_scan_overview.txt", "pp.txt"),
    summary_label="Flutter scan overview (falls back to the object pool, pp.txt)",
    summary_missing="(Flutter overview and pp.txt not found - recovery may have failed)",
)

REACT_NATIVE = SourceProfile(
    key="react_native",
    source_exts=(".js", ".jsx", ".ts", ".tsx", ".java", ".kt"),
    resource_exts=(".txt", ".xml", ".json"),
    noise_fragments=(
        "/node_modules/react-native/", "/node_modules/", "metro-", "regenerator",
        "/framework_modules/", "/com/facebook/", "/androidx/", "/android/", "/kotlin/",
        "/kotlinx/", "/com/google/", "/org/jetbrains/",
    ),
    resource_globs=("rn_scan_overview.txt", "package-metadata.json", "modules.txt", "secrets.txt",
                    "platform/resources/AndroidManifest.xml"),
    summary_candidates=("rn_scan_overview.txt", "package-metadata.json"),
    summary_label="React Native scan overview (falls back to the bundle metadata)",
    summary_missing="(React Native overview and bundle metadata not found - recovery may have failed)",
)

CORDOVA = SourceProfile(
    key="cordova",
    source_exts=(".js", ".html", ".htm"),
    resource_exts=(".css", ".json", ".xml"),
    noise_fragments=(
        "/cordova.js", "/cordova_plugins.js", "/cordova-js-src/",
        "/jquery", "/angular", "/bootstrap", "/react", "/vue", "/lodash",
        "/underscore", "/moment", "/polyfill",
    ),
    resource_globs=("config.xml", "index.html", "www/index.html"),
    summary_candidates=("config.xml", "www/index.html", "index.html"),
    summary_label="Cordova config.xml",
    summary_missing="(config.xml not found - the app's whitelist/plugin config was not recovered)",
)

XAMARIN = SourceProfile(
    key="xamarin",
    source_exts=(".cs", ".txt"),
    resource_exts=(".xml", ".json", ".config"),
    noise_fragments=(
        "/System.", "/Microsoft.", "/Mono.", "/Xamarin.Forms", "/Xamarin.Essentials",
        "/netstandard", "/mscorlib", "/Java.Interop", "/FSharp.",
        "/Newtonsoft.Json", "/SQLitePCLRaw",
    ),
    resource_globs=("assemblies.txt",),
    summary_candidates=("assemblies.txt",),
    summary_label="Recovered .NET assemblies",
    summary_missing="(no assembly inventory - extraction recovered nothing to list)",
)

PROFILES = {p.key: p for p in (JAVA_KOTLIN, FLUTTER, REACT_NATIVE, CORDOVA, XAMARIN)}
