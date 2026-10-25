#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.native_loading

Purpose:
    Find the native libraries a cross-platform app's own code loads, and where it loads them, so the agent is pointed at them instead of reading the bridge and stopping there.

Responsibilities:
    Index the libraries bundled in the platform layer, read the app's manifest package, and match the app's own load calls -- System.loadLibrary in Java/Kotlin, a lib*.so literal handed to dart:ffi in Dart -- against them.

Dependencies:
    re, pathlib, the manifest summariser, the Ghidra runner's list of framework runtimes.

Implementation notes:
    A Flutter or React Native app bundles a dozen native libraries, nearly all of them the framework's runtime or a plugin's, and the few the developer wrote are the only ones worth decompiling. What marks a library as the app's is that the app's own code loads it, so the match is made from the load call, not from the file. A real scan read the Dart FFI bridge to a custom library twice and never inspected the library itself, because nothing it was shown named the library as the app's.

Security considerations:
    Everything read here comes from an untrusted APK and is matched as text with bounded regular expressions; nothing is executed, and every returned path is relative to the analysis root.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List

from ..layout import PLATFORM_DIR

_LOAD_LIBRARY_RE = re.compile(r"System\.loadLibrary\(\s*\"([\w.+-]{1,64})\"\s*\)")
_SO_LITERAL_RE = re.compile(r"[\"'](lib[\w.+-]{1,64}\.so)[\"']")
_MANIFEST_PACKAGE_RE = re.compile(r"package ([\w.]+)")
_PREFERRED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


@dataclass
class LoadedLibrary:
    """
    Purpose:
        A bundled native library the app's own code loads.

    Attributes:
        name: The library file name, such as libfoo.so.
        path: The bundled copy to inspect, relative to the analysis root, preferring arm64-v8a.
        loaded_from: Where the app loads it, as "file:line".
    """
    name: str
    path: str
    loaded_from: List[str] = field(default_factory=list)


def manifest_package(root) -> str:
    """
    Purpose:
        Read the app's package name from the decompiled manifest.

    Parameters:
        root: The analysis root.

    Returns:
        The package, or an empty string when the manifest is missing or unreadable.
    """
    from ..sast.extractors.manifest import summarise_manifest
    manifest = Path(root) / PLATFORM_DIR / "resources" / "AndroidManifest.xml"
    lines = summarise_manifest(manifest) if manifest.is_file() else []
    match = _MANIFEST_PACKAGE_RE.search(lines[0]) if lines else None
    return match.group(1) if match else ""


def bundled_libraries(root) -> Dict[str, str]:
    """
    Purpose:
        Index the native libraries bundled in the platform layer.

    Parameters:
        root: The analysis root.

    Returns:
        Library name to its path relative to the root, preferring the arm64-v8a copy.

    Implementation notes:
        Several ABIs usually ship the same library; arm64-v8a is preferred because it is what current devices run and what a Frida hook would attach to.
    """
    root = Path(root)
    lib_dir = root / PLATFORM_DIR / "resources" / "lib"
    found: Dict[str, str] = {}
    if not lib_dir.is_dir():
        return found
    rank = {abi: i for i, abi in enumerate(_PREFERRED_ABIS)}
    for so in sorted(lib_dir.glob("*/*.so"), key=lambda p: rank.get(p.parent.name, len(rank))):
        found.setdefault(so.name, so.relative_to(root).as_posix())
    return found


def app_code_files(root, package: str, dirs: Iterable[str] = ()) -> List[Path]:
    """
    Purpose:
        List the files that hold the app's own code: its Java/Kotlin package in the platform layer, plus the given recovered directories.

    Parameters:
        root: The analysis root.
        package: The app's package from the manifest; without it the platform layer is not searched.
        dirs: Recovered directories, relative to the root, that are the app's own code.

    Returns:
        The files, in a stable order.
    """
    root = Path(root)
    files: List[Path] = []
    if package:
        java_dir = root / PLATFORM_DIR / "sources" / Path(*package.split("."))
        if java_dir.is_dir():
            files += sorted(p for p in java_dir.rglob("*") if p.suffix in (".java", ".kt"))
    for rel in dirs:
        base = root / rel
        if base.is_dir():
            files += sorted(p for p in base.rglob("*") if p.is_file() and p.suffix in (".dart", ".js"))
    return files


def app_loaded_libraries(root, code_files: Iterable[Path], skip: Iterable[str] = ()) -> List[LoadedLibrary]:
    """
    Purpose:
        Find the bundled libraries the app's own code loads.

    Parameters:
        root: The analysis root.
        code_files: The app's own code files.
        skip: Library names never to report, such as framework runtimes.

    Returns:
        The libraries, in name order, each with where it is loaded.

    Implementation notes:
        Only names that are actually bundled count, so a load call for a system library or a string that merely looks like a file name is ignored. Each library keeps at most a few load sites, which is enough to show the agent the bridge.
    """
    root = Path(root)
    bundled = bundled_libraries(root)
    skipped = set(skip)
    found: Dict[str, LoadedLibrary] = {}
    for path in code_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(lines, 1):
            names = [f"lib{n}.so" for n in _LOAD_LIBRARY_RE.findall(line)] + _SO_LITERAL_RE.findall(line)
            for name in names:
                if name not in bundled or name in skipped:
                    continue
                entry = found.setdefault(name, LoadedLibrary(name=name, path=bundled[name]))
                where = f"{rel}:{number}"
                if where not in entry.loaded_from and len(entry.loaded_from) < 3:
                    entry.loaded_from.append(where)
    return [found[name] for name in sorted(found)]


def render_native_section(libraries: List[LoadedLibrary], bundled: Dict[str, str]) -> List[str]:
    """
    Purpose:
        Render the overview lines for the app's native libraries.

    Parameters:
        libraries: The libraries the app's own code loads.
        bundled: Every bundled library, name to path.

    Returns:
        The lines, empty when nothing is bundled.

    Implementation notes:
        The app's libraries are named with their path and load site and an instruction to inspect them, because that is the step agents skipped; everything else bundled is one line of names, since it is framework or plugin code.
    """
    if not bundled:
        return []
    out = ["Native libraries:"]
    if libraries:
        for lib in libraries:
            out.append(f"  {lib.path}  loaded by the app at {', '.join(lib.loaded_from)} "
                       "- inspect_native it: its code is the developer's, not the framework's")
    else:
        out.append("  none loaded by the app's own code")
    own = {lib.name for lib in libraries}
    others = sorted(name for name in bundled if name not in own)
    if others:
        out.append("  other bundled libraries (framework runtimes, plugins and the Dart/JS snapshot "
                   "recovered above - not decompiled): " + ", ".join(others[:20]))
    return out
