#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.react_native.graph

Purpose:
    Build the structural graph for a React Native app's recovered JavaScript, so the AI phase can fan out across coherent regions instead of scanning one undifferentiated tree.

Responsibilities:
    Walk the recovered output, score each unit for security-relevant signals, and assemble the graph.

Dependencies:
    The shared graph types.

Implementation notes:
    The recovered output takes two shapes and both are handled. A decompiler that emits per-module files gives natural units; one that emits a single reconstructed bundle does not, so that case is split into function-sized pieces first -- an agent handed one multi-megabyte file could not work with it. Every builder here returns None rather than raising when it cannot produce a graph, because the graph is an optimisation: without one the agent falls back to a single pass over the whole tree, which is slower and shallower but still works.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional

from ..agent.code_graph import CodeGraph, CodeNode
from ..agent.patterns import (MAX_REFS_PER_NODE as _MAX_REFS_PER_NODE,
                              MAX_STRINGS_PER_NODE as _MAX_STRINGS_PER_NODE,
                              REQUIRE_RE as _REQUIRE_RE,
                              SECRET_RE as _SECRET_RE,
                              STRING_LITERAL_RE as _STRING_LITERAL_RE)
from ...utils.verbose import plural, verbose_print

_JS_EXTS = (".js", ".jsx", ".ts", ".tsx")

_NOISE_FRAGMENTS = ("/node_modules/", "metro-", "regenerator")

_SINK_FAMILIES: Dict[str, tuple] = {
    "network": ("fetch(", "XMLHttpRequest", "axios."),
    "storage": ("AsyncStorage", "react-native-fs", "RNFS", "MMKV"),
    "secure_storage": ("react-native-keychain", "EncryptedStorage", "expo-secure-store"),
    "webview": ("WebView", "injectedJavaScript", "onMessage", "postMessage"),
    "eval": ("eval(", "new Function("),
    "crypto": ("crypto-js", "CryptoJS", "createCipher", "createHash"),
    "deeplink": ("Linking.getInitialURL", "Linking.openURL", "Linking.addEventListener"),
    "logging": ("console.log", "console.warn", "console.error"),
    "native_module": ("NativeModules", "TurboModuleRegistry"),
}


_FUNC_HEADER_RE = re.compile(
    r'^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(')
_ENTRY_MARKER = "AppRegistry.registerComponent"


def _is_noise(rel: str) -> bool:
    """
    Purpose:
        Recognise files that are library or generated code rather than the app's own.

    Parameters:
        rel: The file's path relative to the source root.

    Returns:
        True when the file should be excluded from the graph.

    Implementation notes:
        Matched against a normalised path with a leading separator, so a fragment matches a whole path component rather than part of a name. Excluding these is what keeps the graph about the application: bundled libraries dwarf the app's own code in every one of these frameworks, and an agent handed them would spend its budget on code the app owner cannot change.
    """
    probe = "/" + rel.replace("\\", "/")
    return any(frag in probe for frag in _NOISE_FRAGMENTS)


def _scan_content(content: str) -> tuple:
    """
    Purpose:
        Score one recovered module for security-relevant signals.

    Parameters:
        content: The module's text.

    Returns:
        The signal families found and the derived role.
    """
    signals: Dict[str, List[str]] = {}
    for family, keys in _SINK_FAMILIES.items():
        hits = [k for k in keys if k in content]
        if hits:
            signals[family] = hits[:4]

    strings: List[str] = []
    for m in _STRING_LITERAL_RE.finditer(content):
        lit = m.group(1)
        if _SECRET_RE.search(lit) and lit not in strings:
            strings.append(lit[:80])
            if len(strings) >= _MAX_STRINGS_PER_NODE:
                break

    refs: List[str] = []
    for m in _REQUIRE_RE.finditer(content):
        ref = m.group(1)
        if ref not in refs:
            refs.append(ref)
            if len(refs) >= _MAX_REFS_PER_NODE:
                break

    return signals, strings, refs


def _split_single_file(bundle_path: Path, functions_dir: Path, verbose: bool) -> Dict[str, str]:
    """
    Purpose:
        Split a single reconstructed bundle into function-sized pieces.

    Parameters:
        bundle_path: The reconstructed bundle.
        functions_dir: Where the pieces are written.
        verbose: Traces failures.

    Returns:
        A mapping from written piece to its source region.

    Side effects:
        Writes the pieces to disk.

    Implementation notes:
        Necessary because a whole bundle is far larger than any useful context window, so without splitting the agent could neither read it nor navigate it. Split on function boundaries rather than by size, so each piece is a coherent unit the agent can reason about rather than an arbitrary slice through the middle of one.
    """
    try:
        lines = bundle_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        verbose_print(f"Could not read {bundle_path} to split: {exc}", verbose)
        return {}

    starts: List[tuple] = []
    for i, line in enumerate(lines):
        m = _FUNC_HEADER_RE.match(line)
        if m:
            starts.append((i, m.group(1)))
    if not starts:
        return {}

    functions_dir.mkdir(parents=True, exist_ok=True)
    mapping: Dict[str, str] = {}
    for idx, (start_line, name) in enumerate(starts):
        end_line = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start_line:end_line])
        safe_name = re.sub(r"[^A-Za-z0-9_.$-]", "_", name)[:80] or f"fn{idx}"
        filename = f"{idx:04d}_{safe_name}.js"
        try:
            (functions_dir / filename).write_text(body, encoding="utf-8")
        except OSError as exc:
            verbose_print(f"Could not write split function file {filename}: {exc}", verbose)
            continue
        mapping[name] = f"functions/{filename}"
    verbose_print(f"Split {bundle_path.name} into {plural(len(mapping), 'function file')}", verbose)
    return mapping


def _build_single_file_nodes(bundle_path: Path, root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build nodes for a bundle that arrived as one reconstructed file.

    Parameters:
        bundle_path: The reconstructed bundle.
        root: Output root, for relative paths.
        verbose: Traces progress.

    Returns:
        The nodes.

    Side effects:
        Writes the split pieces and reads them back.

    Implementation notes:
        Falls back to treating the whole bundle as one node when splitting produced nothing, so an unsplittable bundle still enters the graph rather than being dropped entirely.
    """
    nodes: Dict[str, CodeNode] = {}
    mapping = _split_single_file(bundle_path, root / "functions", verbose)

    if not mapping:
        try:
            content = bundle_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return nodes
        signals, strings, refs = _scan_content(content)
        role = "entry-module" if _ENTRY_MARKER in content else "app-module"
        nodes["bundle"] = CodeNode(cls="bundle", file=bundle_path.name, role=role,
                                   signals=signals, strings=strings, refs=refs)
        return nodes

    for name, rel_path in mapping.items():
        try:
            content = (root / rel_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        signals, strings, refs = _scan_content(content)
        role = "entry-module" if _ENTRY_MARKER in content else "app-module"
        node = CodeNode(cls=name, file=rel_path, role=role,
                        signals=signals, strings=strings, refs=refs)
        nodes.setdefault(name, node)
    return nodes


def _build_module_dir_nodes(js_files: List[Path], root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build a node per recovered module file.

    Parameters:
        js_files: The recovered module files.
        root: Output root, for relative paths.
        verbose: Traces progress.

    Returns:
        The nodes.

    Implementation notes:
        The straightforward case: the decompiler already recovered module boundaries, so each file is a unit.
    """
    nodes: Dict[str, CodeNode] = {}
    for fp in js_files:
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = fp.name
        if _is_noise(rel):
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            verbose_print(f"Could not read {fp}: {exc}", verbose)
            continue

        cls = fp.stem
        signals, strings, refs = _scan_content(content)
        role = "entry-module" if _ENTRY_MARKER in content else "app-module"
        nodes[rel] = CodeNode(cls=cls, file=rel, role=role,
                              signals=signals, strings=strings, refs=refs)
    return nodes


_MODULE_ID_RE = re.compile(r"^(\d+)(?:_.*)?\.js$")
_HEADER_DEPS_RE = re.compile(r"^//\s*Dependencies:\s*\[([\d,\s]*)\]", re.MULTILINE)


def _build_module_tree_nodes(root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build nodes over a Metro module tree: the app region's modules and the app's own native modules.

    Parameters:
        root: The analysis root holding app_modules/ and framework_modules/.
        verbose: Traces unreadable files.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the app-region modules and the decompiled platform layer.

    Implementation notes:
        The app region is already the app plus what it imports, so every module in it is flagged -- a screen that gates a feature on a client-side flag or a module holding a key matches no sink pattern, and those are the findings that matter here. Module 0 is the entry. Refs follow each module's Metro dependency list within the app region, so the agent can walk from a screen to the helper that does the work. The app's own native modules are added as nodes of their own, always flagged, because a @ReactMethod is callable by any JavaScript in the app whether or not the bundle calls it. Framework modules are left out entirely.
    """
    from ...decompiler.rn_metro import APP_DIR
    from .overview import app_package, find_native_modules

    app_dir = root / APP_DIR
    files: Dict[int, Path] = {}
    for path in sorted(app_dir.glob("*.js")):
        match = _MODULE_ID_RE.match(path.name)
        if match:
            files[int(match.group(1))] = path
    nodes: Dict[str, CodeNode] = {}
    deps_of: Dict[str, List[int]] = {}
    for module_id, path in sorted(files.items()):
        rel = path.relative_to(root).as_posix()
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            verbose_print(f"Could not read {path}: {exc}", verbose)
            continue
        signals, strings, _refs = _scan_content(content)
        header = _HEADER_DEPS_RE.search(content[:2000])
        deps_of[rel] = [int(x) for x in header.group(1).replace(" ", "").split(",") if x.isdigit()] if header else []
        role = "app-entry" if module_id == 0 else "app-code"
        nodes[rel] = CodeNode(cls=path.stem, file=rel, role=role, signals=signals, strings=strings)
    for rel, deps in deps_of.items():
        targets = [files[d].relative_to(root).as_posix() for d in deps if d in files]
        nodes[rel].refs = [t for t in targets if t in nodes][:_MAX_REFS_PER_NODE]
    for module in find_native_modules(root, app_package(root)):
        if module.app_owned:
            nodes[module.file] = CodeNode(cls=module.java_class, file=module.file, role="native-module",
                                          signals={"native_module": [module.js_name] + module.methods[:3]})
    verbose_print(f"RN graph: {plural(len(files), 'app-region module')} from the Metro module tree", verbose)
    return nodes


def build_rn_graph(js_root, verbose: bool = False) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the graph over a React Native app's recovered JavaScript.

    Parameters:
        js_root: Root of the recovered output.
        verbose: Traces progress.

    Returns:
        The graph, or None when there was nothing to build from.

    Side effects:
        Reads and may split the recovered files.

    Implementation notes:
        Chooses the node builder by what the recovery actually produced: a Metro module tree (app_modules/ beside framework_modules/), which is what the analyzer writes for both Hermes and plain bundles; otherwise per-module files or a single reconstructed bundle from an external decompiler. With a module tree, the native libraries the app's own code loads are attached as the graph's native libraries, so inspecting them counts toward coverage; a real scan otherwise read the JNI bridge and never opened the library behind it.
    """
    try:
        root = Path(js_root)
        if not root.is_dir():
            verbose_print(f"RN graph: source root {root} is not a directory", verbose)
            return None

        from ...decompiler.rn_metro import APP_DIR
        if (root / APP_DIR).is_dir():
            nodes = _build_module_tree_nodes(root, verbose)
        else:
            js_files = sorted(
                f for ext in _JS_EXTS for f in root.rglob(f"*{ext}") if f.is_file())
            if not js_files:
                verbose_print("RN graph: no JS files found; falling back", verbose)
                return None
            single_file = next((f for f in js_files if f.name == "bundle.js"), None)
            if single_file is not None and len(js_files) == 1:
                nodes = _build_single_file_nodes(single_file, root, verbose)
            else:
                nodes = _build_module_dir_nodes(js_files, root, verbose)

        if not nodes:
            verbose_print("RN graph: no nodes recovered; falling back", verbose)
            return None

        native_libs = []
        if (root / APP_DIR).is_dir():
            from ..agent.code_graph import NativeLib
            from .overview import app_native_libraries
            native_libs = [NativeLib(path=lib.path, loaded_by=lib.loaded_from)
                           for lib in app_native_libraries(root)]
        graph = CodeGraph(package="react-native-bundle", nodes=nodes, native_libs=native_libs)
        verbose_print(
            f"RN graph built: {plural(len(nodes), 'node')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"RN graph build failed ({exc}); falling back to file tree", verbose)
        return None
