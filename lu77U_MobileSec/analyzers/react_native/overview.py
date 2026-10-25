#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.react_native.overview

Purpose:
    Describe a recovered React Native app in one short file the agent reads first: how it was built, where everything is, which native modules Java exposes to JavaScript and who calls them, and where the WebView bridges, storage keys and endpoints are.

Responsibilities:
    Read the engine and bytecode version from the bundle, the architecture markers from the native libraries, the React Native version and the native modules from the decompiled platform layer, and the JavaScript-side usage from the app-region modules; render the overview within a size bound.

Dependencies:
    re, zipfile, pathlib, the Metro module layout, the manifest summariser.

Implementation notes:
    React Native's attack surface is split the same way Flutter's is: the JavaScript holds the logic, and Java holds the native modules -- classes extending ReactContextBaseJavaModule whose @ReactMethod methods any JavaScript running in the app can call by the name getName() returns. A module that no app code calls is still exposed, which is why the native-module map lists every app-owned module and says plainly when nothing in the bundle calls it. The JavaScript side is read from the app region only, because the framework's own modules mention every API there is.

Security considerations:
    Everything parsed here comes from an untrusted APK and is read as text with bounded regular expressions; nothing is executed.
"""

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..layout import PLATFORM_DIR
from ..agent.native_loading import (LoadedLibrary, app_code_files, app_loaded_libraries, bundled_libraries,
                                     manifest_package, render_native_section)
from ..agent.patterns import find_secrets
from ...decompiler.rn_metro import APP_DIR

OVERVIEW_NAME = "rn_scan_overview.txt"
HERMES_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
MAX_OVERVIEW_CHARS = 5500
MAX_LIST = 8

_JAVA_NOISE = ("/com/facebook/", "/androidx/", "/android/", "/kotlin/", "/kotlinx/",
               "/com/google/", "/org/jetbrains/", "/okhttp3/", "/okio/")
_MODULE_CLASS_RE = re.compile(
    r"class\s+(\w+)\s+extends\s+(?:[\w.]+\.)?(ReactContextBaseJavaModule|BaseJavaModule|Native\w*Spec)\b")
_GET_NAME_RE = re.compile(r"String\s+getName\(\)\s*\{\s*return\s+(?:\"([^\"]+)\"|([A-Za-z_][\w.]*))\s*;")
_STRING_CONST_RE = re.compile(r"\b([A-Z_][A-Z0-9_]*)\s*=\s*\"([^\"]+)\"\s*;")
_REACT_METHOD_RE = re.compile(
    r"@(?:[\w.]+\.)?ReactMethod\b(?:\([^)]*\))?\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
    r"public\s+(?:final\s+)?(?:abstract\s+)?[\w.<>\[\]]+\s+(\w+)\s*\(([^)]*)\)")
_RN_VERSION_RE = re.compile(r"\"(major|minor|patch)\"\)?\s*,\s*(\d+)")
_JS_NATIVE_RE = re.compile(r"NativeModules\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*[\"']([^\"']+)[\"']\s*\])"
                           r"(?:\s*\.\s*([A-Za-z_$][\w$]*))?")
_JS_TURBO_RE = re.compile(r"TurboModuleRegistry\s*\.\s*(?:get|getEnforcing)\s*(?:<[^>]*>)?\s*\(\s*[\"']([^\"']+)[\"']")
_STORAGE_KEY_RE = re.compile(r"\b(?:setItem|getItem|removeItem|mergeItem)\s*\(\s*[\"']([^\"']{1,120})[\"']")
_URL_RE = re.compile(r"[\"'`](https?://[^\"'`\s]{3,200})[\"'`]")
_GATE_RE = re.compile(
    r"\b((?:is|has|can)_?(?:premium|pro|paid|vip|admin|subscribed|subscriber|unlocked|licen[cs]ed|plus|gold"
    r"|member|staff|superuser|entitled|trial|purchased)(?:_?(?:user|account|member|access|enabled|active"
    r"|status|tier|plan|mode))?)\b", re.IGNORECASE)
_WEBVIEW_PROPS = ("onMessage", "injectedJavaScript", "originWhitelist", "javaScriptEnabled",
                  "allowFileAccess", "allowUniversalAccessFromFileURLs", "mixedContentMode")


@dataclass
class NativeModuleInfo:
    """
    Purpose:
        One Java class exposed to JavaScript as a native module.

    Attributes:
        js_name: The name JavaScript reaches it by, from getName().
        java_class: The class name.
        file: The decompiled file, relative to the analysis root.
        methods: Its @ReactMethod methods as "name(params)".
        app_owned: Whether it is in the app's own package rather than a library's.
    """
    js_name: str
    java_class: str
    file: str
    methods: List[str] = field(default_factory=list)
    app_owned: bool = False


def bundle_engine(bundle_path) -> Tuple[str, Optional[int]]:
    """
    Purpose:
        Identify how a bundle was compiled.

    Parameters:
        bundle_path: The extracted bundle.

    Returns:
        ("hermes", bytecode version) for Hermes bytecode, ("javascript", None) otherwise.

    Implementation notes:
        The Hermes header is the 8-byte magic followed by the bytecode version as a little-endian 32-bit integer. The version matters because each tool supports a range of versions and the patching techniques that work differ between them.
    """
    try:
        with open(bundle_path, "rb") as handle:
            head = handle.read(16)
    except OSError:
        return "javascript", None
    if head[:8] == HERMES_MAGIC and len(head) >= 12:
        return "hermes", int.from_bytes(head[8:12], "little")
    return "javascript", None


def native_library_markers(apk_path) -> List[str]:
    """
    Purpose:
        Read what the APK's native libraries say about the engine and the architecture.

    Parameters:
        apk_path: The APK.

    Returns:
        Short descriptions of the engine and architecture libraries present.

    Implementation notes:
        libreactnativejni.so is the old bridge's JNI glue and libfabricjni.so / libturbomodulejsijni.so the new architecture's; which one is present decides whether bridge-level techniques apply at all. A bundle can still be Hermes bytecode with neither engine library visible in a split APK, so this is reported alongside, not instead of, the bundle header.
    """
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = {Path(n).name for n in zf.namelist() if n.startswith("lib/")}
    except (zipfile.BadZipFile, OSError):
        return []
    out = []
    if "libhermes.so" in names:
        out.append("engine library: libhermes.so (Hermes)")
    if "libjsc.so" in names:
        out.append("engine library: libjsc.so (JavaScriptCore)")
    new_arch = sorted(names & {"libfabricjni.so", "libturbomodulejsijni.so",
                               "libreact_newarchdefaults.so", "libappmodules.so"})
    if new_arch:
        out.append("new-architecture libraries present (Fabric/TurboModules): " + ", ".join(new_arch))
    if "libreactnativejni.so" in names:
        out.append("old-bridge library present (libreactnativejni.so) - bridge hooks such as "
                   "CatalystInstanceImpl may apply")
    return out


def react_native_version(root: Path) -> str:
    """
    Purpose:
        Read the React Native version compiled into the platform layer.

    Parameters:
        root: The analysis root.

    Returns:
        "major.minor.patch", or an empty string when it cannot be found.
    """
    candidates = list((root / PLATFORM_DIR).glob("sources/com/facebook/react/modules/systeminfo/ReactNativeVersion.java"))
    for path in candidates:
        try:
            parts = dict(_RN_VERSION_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
        if {"major", "minor", "patch"} <= parts.keys():
            return f"{parts['major']}.{parts['minor']}.{parts['patch']}"
    return ""


def find_native_modules(root: Path, owner_package: str = "") -> List[NativeModuleInfo]:
    """
    Purpose:
        List the Java classes the platform layer exposes to JavaScript as native modules.

    Parameters:
        root: The analysis root.
        owner_package: The app's package from the manifest, which marks a module as the app's own.

    Returns:
        The modules, app-owned first.

    Implementation notes:
        A module is a class extending ReactContextBaseJavaModule or BaseJavaModule, or a codegen Native*Spec; its JavaScript name is what getName() returns, read either as a literal or through a string constant in the same file, which is how specs and Kotlin companions usually write it. React Native's own modules under com.facebook are skipped -- they are the framework, present in every app. A method is callable from JavaScript only when it carries @ReactMethod, so only those are listed. A codegen spec and its implementation share one JavaScript name, so they are merged into one entry under the implementation class with the union of their methods; an implementation that leaves getName() to its spec takes the spec's name, since otherwise the two would be listed as unrelated modules and the implementation under a name JavaScript never uses.
    """
    java_root = root / PLATFORM_DIR / "sources"
    if not java_root.is_dir():
        return []
    found: List[NativeModuleInfo] = []
    inherits: Dict[int, str] = {}
    for path in sorted(java_root.rglob("*.java")):
        rel = path.relative_to(root).as_posix()
        if any(noise in f"/{rel}" for noise in _JAVA_NOISE):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "ReactMethod" not in text and "getName" not in text:
            continue
        cls = _MODULE_CLASS_RE.search(text)
        if not cls:
            continue
        constants = dict(_STRING_CONST_RE.findall(text))
        name_match = _GET_NAME_RE.search(text)
        js_name = ""
        if name_match:
            js_name = name_match.group(1) or constants.get(name_match.group(2).rsplit(".", 1)[-1], "")
        if not js_name:
            js_name = constants.get("NAME", "")
        methods = []
        for method, params in _REACT_METHOD_RE.findall(text):
            simple = ", ".join(p.strip().split()[-1] if p.strip() else "" for p in params.split(",") if p.strip())
            methods.append(f"{method}({simple})")
        package_path = owner_package.replace(".", "/")
        owned = bool(package_path) and f"/sources/{package_path}/" in f"/{rel}"
        if not js_name and cls.group(2).startswith("Native"):
            inherits[len(found)] = cls.group(2)
        found.append(NativeModuleInfo(js_name=js_name or cls.group(1), java_class=cls.group(1),
                                      file=rel, methods=methods, app_owned=owned))
    names = {module.java_class: module.js_name for module in found}
    for index, spec in inherits.items():
        found[index].js_name = names.get(spec, found[index].js_name)
    merged: Dict[str, NativeModuleInfo] = {}
    for module in found:
        current = merged.get(module.js_name)
        if current is None:
            merged[module.js_name] = module
            continue
        keep = module if current.java_class.startswith("Native") and current.java_class.endswith("Spec") else current
        other = current if keep is module else module
        keep.methods = keep.methods + [m for m in other.methods if m not in keep.methods]
        keep.app_owned = keep.app_owned or other.app_owned
        merged[module.js_name] = keep
    result = list(merged.values())
    result.sort(key=lambda m: (not m.app_owned, m.js_name))
    return result


def _app_lines(root: Path) -> Iterable[Tuple[str, int, str]]:
    """
    Purpose:
        Walk the app-region JavaScript line by line.

    Parameters:
        root: The analysis root.

    Returns:
        (relative path, line number, line) triples.
    """
    app_dir = root / APP_DIR
    if not app_dir.is_dir():
        return
    for path in sorted(app_dir.glob("*.js")):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(lines, 1):
            yield rel, number, line


def js_usage(root: Path) -> Dict[str, List[Tuple[str, str]]]:
    """
    Purpose:
        Collect what the app-region JavaScript does with native modules, WebViews, storage and the network.

    Parameters:
        root: The analysis root.

    Returns:
        Category to (detail, "file:line") pairs: "native" (module or module.method), "webview" (the prop used), "storage" (the key), "url", "secret" and "gate" (an entitlement or role flag).

    Implementation notes:
        Secrets use the typed credential patterns rather than the identifier-shaped heuristic, which matched property names such as thirdPartyCookiesEnabled on a real bundle while the actual key was buried; values are withheld unless the pattern marks them as public identifiers, matching the rest of the tool, and the location is enough for the agent to read it. Entitlement and role flags (isPremium, hasProAccess, isAdmin) are listed because a gate the client decides is the most common logic flaw in these apps and the least visible to a reader scanning for sinks: a real scan read the screen holding the gate and never reported it. The names are whole identifiers, so isProduction or isProcessing do not match.
    """
    first_seen: Dict[Tuple[str, str], str] = {}

    def add(kind: str, detail: str, where: str):
        """
        Purpose:
            Record one usage once, keeping the first place it was seen.

        Parameters:
            kind: The category.
            detail: What was found.
            where: "file:line".

        Implementation notes:
            A dict keyed on (category, detail) does the deduplication and keeps discovery order, so the overview lists each lead at its first occurrence without comparing credential-bearing text by hand.
        """
        first_seen.setdefault((kind, detail), where)

    for rel, number, line in _app_lines(root):
        where = f"{rel}:{number}"
        for name, bracket, method in _JS_NATIVE_RE.findall(line):
            module = name or bracket
            if module:
                add("native", f"{module}.{method}" if method else module, where)
        for name in _JS_TURBO_RE.findall(line):
            add("native", name, where)
        for prop in _WEBVIEW_PROPS:
            if prop in line:
                add("webview", prop, where)
        for key in _STORAGE_KEY_RE.findall(line):
            add("storage", key, where)
        for url in _URL_RE.findall(line):
            add("url", url, where)
        for gate in _GATE_RE.findall(line):
            add("gate", gate, where)
        for secret in find_secrets(line, max_results=4):
            label = (f"{secret['name']}: {secret['value'][:60]}" if secret["public"]
                     else f"{secret['name']} (value withheld - read the file)")
            add("secret", label, where)
    found: Dict[str, List[Tuple[str, str]]] = {
        k: [] for k in ("native", "webview", "storage", "url", "secret", "gate")}
    for (kind, detail), where in first_seen.items():
        found[kind].append((detail, where))
    return found


def _bullets(pairs: List[Tuple[str, str]], limit: int = MAX_LIST) -> List[str]:
    """
    Purpose:
        Render (detail, location) pairs as bounded bullet lines.

    Parameters:
        pairs: The pairs.
        limit: How many to show.

    Returns:
        The lines, with a count of any left out.
    """
    lines = [f"    {detail}  ({where})" for detail, where in pairs[:limit]]
    if len(pairs) > limit:
        lines.append(f"    ... (+{len(pairs) - limit} more; search_code finds the rest)")
    return lines


def render_overview(*, engine: str, hbc_version: Optional[int], markers: List[str],
                    rn_version: str, tree_summary: str, modules: List[NativeModuleInfo],
                    usage: Dict[str, List[Tuple[str, str]]], manifest_lines: List[str],
                    hermes_secrets: str = "", native_lines: Optional[List[str]] = None) -> str:
    """
    Purpose:
        Compose the React Native overview.

    Parameters:
        engine: "hermes" or "javascript".
        hbc_version: The Hermes bytecode version, when Hermes.
        markers: Engine and architecture markers from the native libraries.
        rn_version: The React Native version, when found.
        tree_summary: How the bundle was split into app and framework modules.
        modules: The native modules found on the Java side.
        usage: What the app-region JavaScript does.
        manifest_lines: The manifest summary.
        hermes_secrets: hermes-decomp's own secret scan, when it ran.
        native_lines: The native-library section, naming the libraries the app's own code loads.

    Returns:
        The overview text, bounded to MAX_OVERVIEW_CHARS.

    Implementation notes:
        Ordered by how much each part changes what the agent does next: the build (which decides how the code reads and which techniques apply), the layout, the manifest, the native-module map, then the WebView, storage, network and secret leads. Each native module is joined to the JavaScript that calls it by name, and a module nothing calls is flagged as exposed regardless, because any JavaScript that runs in the app -- injected through a WebView bridge, a patched bundle or a debugger -- can call it.
    """
    out: List[str] = []
    if engine == "hermes":
        out.append(f"Build: Hermes bytecode (HBC version {hbc_version}) - decompiled by hermes-decomp; "
                   "names, strings and module structure are recovered, logic reads as reconstructed JS.")
    else:
        out.append("Build: plain JavaScript bundle (JSC, or Hermes compiling from source at runtime) - "
                   "the shipped code itself, split into Metro modules and reformatted onto short lines.")
    if rn_version:
        out.append(f"React Native {rn_version}")
    out += markers
    out.append("")
    out.append("Where things are:")
    out.append(f"  {APP_DIR}/            the app's own modules plus the libraries it imports ({tree_summary})")
    out.append("  framework_modules/     React Native itself - noise unless a lead goes there")
    out.append(f"  {PLATFORM_DIR}/sources/       Java/Kotlin: native modules, ReactPackage registration, MainActivity")
    out.append(f"  {PLATFORM_DIR}/resources/AndroidManifest.xml")
    if manifest_lines:
        out.append("")
        out += manifest_lines
    out.append("")

    calls = usage.get("native", [])
    if modules:
        out.append("Native modules (Java -> callable from any JS in the app as NativeModules.<name>):")
        for module in modules[:12]:
            owner = "app" if module.app_owned else "library"
            methods = ", ".join(module.methods[:6]) or "no @ReactMethod found"
            out.append(f"  {module.js_name} [{owner}] {module.file}: {methods}")
            used = [where for detail, where in calls if detail.split(".", 1)[0] == module.js_name]
            if used:
                out.append(f"    called from JS: {', '.join(used[:4])}")
            elif module.app_owned:
                out.append("    not called from the app's JS - still exposed to any JS that runs in the app")
        if len(modules) > 12:
            out.append(f"  ... (+{len(modules) - 12} more native modules)")
    else:
        out.append("Native modules: none found outside React Native itself.")
    other_calls = [(d, w) for d, w in calls
                   if d.split(".", 1)[0] not in {m.js_name for m in modules}]
    if other_calls:
        out.append("  JS also requests:")
        out += _bullets(other_calls)
    out.append("")
    if native_lines:
        out += native_lines
        out.append("")

    for kind, title in (("gate", "Entitlement and role flags in app code (a gate only the client checks is "
                                 "bypassable - find where each is set and whether the server re-checks it)"),
                        ("webview", "WebView bridge props in app code"),
                        ("storage", "AsyncStorage keys written/read"),
                        ("url", "URLs in app code"),
                        ("secret", "Credential-shaped strings in app code")):
        if usage.get(kind):
            out.append(f"{title}:")
            out += _bullets(usage[kind])
    if hermes_secrets.strip():
        out.append("hermes-decomp secret scan (whole string table):")
        out += ["    " + line for line in hermes_secrets.strip().splitlines()[:6]]

    text = "\n".join(out).rstrip() + "\n"
    if len(text) > MAX_OVERVIEW_CHARS:
        text = text[:MAX_OVERVIEW_CHARS].rsplit("\n", 1)[0] + "\n... (truncated; search the sources for more)\n"
    return text


def app_package(root) -> str:
    """
    Purpose:
        Read the app's package name from the decompiled manifest.

    Parameters:
        root: The analysis root.

    Returns:
        The package, or an empty string when the manifest is missing or unreadable.
    """
    return manifest_package(root)


def app_native_libraries(root, package: str = "") -> List[LoadedLibrary]:
    """
    Purpose:
        Find the bundled native libraries the app's own Java/Kotlin or JavaScript loads.

    Parameters:
        root: The analysis root.
        package: The app's package from the manifest; read from it when empty.

    Returns:
        The libraries, each with where it is loaded.

    Implementation notes:
        Shared by the overview, which names them to the agent, and the graph, which makes inspecting them part of coverage. React Native's own runtimes are skipped, as Ghidra refuses them anyway.
    """
    from ...decompiler.ghidra_runner import RUNTIME_LIBRARIES
    package = package or manifest_package(root)
    files = app_code_files(root, package, (APP_DIR,))
    return app_loaded_libraries(root, files, RUNTIME_LIBRARIES)


def write_rn_overview(root, apk_path, bundle_path, tree_summary: str = "") -> Optional[Path]:
    """
    Purpose:
        Gather everything the overview needs and write it into the analysis root.

    Parameters:
        root: The analysis root.
        apk_path: The APK, for the native-library markers.
        bundle_path: The extracted bundle, for the engine and version.
        tree_summary: How the bundle was split into app and framework modules.

    Returns:
        The written file, or None when it could not be written.

    Side effects:
        Reads the recovered output and writes one file.
    """
    root = Path(root)
    try:
        from ..sast.extractors.manifest import summarise_manifest
        manifest = root / PLATFORM_DIR / "resources" / "AndroidManifest.xml"
        manifest_lines = summarise_manifest(manifest) if manifest.is_file() else []
        package = app_package(root)
        engine, version = bundle_engine(bundle_path)
        secrets_path = root / "secrets.txt"
        hermes_secrets = secrets_path.read_text(encoding="utf-8", errors="ignore") if secrets_path.is_file() else ""
        native_lines = render_native_section(app_native_libraries(root, package), bundled_libraries(root))
        text = render_overview(
            engine=engine, hbc_version=version, markers=native_library_markers(apk_path),
            rn_version=react_native_version(root), tree_summary=tree_summary,
            modules=find_native_modules(root, package), usage=js_usage(root),
            manifest_lines=manifest_lines, hermes_secrets=hermes_secrets,
            native_lines=native_lines)
        target = root / OVERVIEW_NAME
        target.write_text(text, encoding="utf-8")
        return target
    except Exception:
        return None
