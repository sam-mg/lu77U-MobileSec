#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.flutter.graph

Purpose:
    Build the structural graph over a recovered Flutter app -- Blutter's disassembly and object pool for a release build, the recovered Dart source for a debug build, or libapp.so's strings when neither was possible, plus the Java/Kotlin platform layer -- so the AI phase fans out across the app's own code instead of the Flutter framework.

Responsibilities:
    Walk the recovered output, classify each Dart library as app code, a third-party package or Flutter SDK code, score it for security-relevant signals, link app code to the packages it calls, add the platform-channel handlers on the Java side, and assemble the graph.

Dependencies:
    The shared graph types, the recovery helpers in .recovered, the snapshot string layout.

Implementation notes:
    A real Blutter recovery is a few app libraries beside hundreds of Flutter framework ones, and the framework's own networking, platform-channel and logging code matches every sink pattern there is. Scoring every file therefore flags the framework and not the app -- on a real app the app's main.dart was not flagged at all. So when Blutter's per-package layout is present, Flutter SDK libraries are left out of the graph (they stay readable through the tools), the app's own libraries are always flagged, and third-party packages are flagged only when they touch a sink. An obfuscated build has no package layout; there every file is scored on its signals, as before. Every builder returns None rather than raising when it cannot produce a graph, because the graph is an optimisation: without one the agent falls back to a single pass over the whole tree.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..agent.code_graph import CodeGraph, CodeNode, NativeLib
from ..agent.native_loading import (LoadedLibrary, app_code_files, app_loaded_libraries, bundled_libraries,
                                     manifest_package, render_native_section)
from ..agent.patterns import (SECRET_RE as _SECRET_RE, STRING_LITERAL_RE as _STRING_LITERAL_RE)
from . import recovered
from ...decompiler.dart_snapshot import ALL_STRINGS_NAME, CHANNEL_RE, KEY_STRINGS_NAME, SNAPSHOT_DIR
from ...utils.verbose import plural, verbose_print

_SINK_FAMILIES: Dict[str, tuple] = {
    "network": ("HttpClient", "package:http", "Dio(", "dio.", "WebSocket("),
    "tls": ("badCertificateCallback", "HttpOverrides", "createHttpClient", "SecurityContext"),
    "storage": ("SharedPreferences", "path_provider", "sqflite", "Hive.", "File("),
    "secure_storage": ("flutter_secure_storage", "FlutterSecureStorage"),
    "crypto": ("pointycastle", "package:encrypt", "Cipher(", "Digest("),
    "webview": ("webview_flutter", "InAppWebView", "javascriptMode", "loadUrl", "loadRequest"),
    "platform_channel": ("MethodChannel", "EventChannel", "BasicMessageChannel"),
    "ffi": ("dart:ffi", "DynamicLibrary"),
    "logging": ("debugPrint(", "print("),
}

_MAX_STRINGS_ON_POOL_NODE = 20
_MAX_STRINGS_PER_ASM_NODE = 6
_MAX_REFS_PER_NODE = 8
_PACKAGE_REACH_DEPTH = 2

_ENTRY_HINT_RE = re.compile(r"main", re.IGNORECASE)
_FFI_HINT = ("dart:ffi", "DynamicLibrary")
_CALL_TARGET_RE = re.compile(r";\s*\[package:([A-Za-z0-9_]+)/([^\]\s]+\.dart)\]")


def _scan_asm_content(content: str) -> tuple:
    """
    Purpose:
        Score a unit of recovered disassembly or Dart source for security-relevant signals.

    Parameters:
        content: The disassembly or source text.

    Returns:
        The signal families found, the derived role, and the credential-shaped string literals.

    Implementation notes:
        Matched on the symbol names Blutter preserves rather than on code shape, since the output is disassembly and there is no syntax to parse. The same names appear in real Dart source, so a debug build is scored the same way.
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
            if len(strings) >= _MAX_STRINGS_PER_ASM_NODE:
                break

    role = "app-class"
    if any(hint in content for hint in _FFI_HINT):
        role = "native-bridge"

    return role, signals, strings


def _rel(path: Path, root: Path) -> str:
    """
    Purpose:
        Express a path relative to the analysis root.

    Parameters:
        path: The file.
        root: The analysis root.

    Returns:
        The relative path, or the path as given when it is outside the root.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _reachable(edges: Dict[str, Set[str]], starts: Set[str], depth: int) -> Set[str]:
    """
    Purpose:
        Find what the app's own code reaches through package calls or imports, up to a bounded depth.

    Parameters:
        edges: Each file's outgoing references to package files.
        starts: The app's own files.
        depth: How many hops to follow.

    Returns:
        The package files reached, excluding the starting files.

    Implementation notes:
        Two hops covers the shape that matters -- the app calls a package's public API, which calls the module doing the work, such as a plugin's method-channel implementation -- without pulling in a crypto or database library's internals, which match every sink pattern and are not where an app's mistakes are.
    """
    seen: Set[str] = set()
    frontier = set(starts)
    for _ in range(depth):
        nxt = set()
        for node in frontier:
            for target in edges.get(node, ()):
                if target not in seen and target not in starts:
                    seen.add(target)
                    nxt.add(target)
        frontier = nxt
    return seen


def _build_flat_asm_nodes(files: List[Path], root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build a node per disassembly file when the files cannot be attributed to packages.

    Parameters:
        files: The disassembly files.
        root: Output root, for relative paths.
        verbose: Traces unreadable files.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the disassembly files.

    Implementation notes:
        This is the obfuscated-build case, where Blutter writes every library flat under asm/ with a scrambled name. Nothing distinguishes app code from framework code, so every file is scored on its signals alone and the main library, when its name survives, is marked as the entry point.
    """
    nodes: Dict[str, CodeNode] = {}
    for fp in files:
        rel = _rel(fp, root)
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            verbose_print(f"Could not read {fp}: {exc}", verbose)
            continue
        role, signals, strings = _scan_asm_content(content)
        if role == "app-class" and _ENTRY_HINT_RE.search(fp.stem):
            role = "entry-point"
        nodes[rel] = CodeNode(cls=fp.stem, file=rel, role=role, signals=signals, strings=strings)
    return nodes


def _build_package_asm_nodes(groups: Dict[str, List[Path]], app_packages: Set[str], root: Path,
                             pool: Dict[str, recovered.PoolEntry], verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build nodes for a Blutter recovery laid out by package: the app's own libraries, and the third-party libraries its code actually reaches.

    Parameters:
        groups: Disassembly files grouped by Dart package.
        app_packages: The app's own packages.
        root: Output root, for relative paths.
        pool: The parsed object pool, used to surface the strings the app's code loads.
        verbose: Traces unreadable files.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the disassembly files.

    Implementation notes:
        App libraries take a role that is always flagged, because the app's own code is the subject of the scan whether or not it matches a sink pattern -- a hardcoded flag check or a custom crypto routine matches none. Their credential-shaped strings include those resolved through the pool references they make, since Blutter writes an object load as a pool offset and the string itself sits in pp.txt. A third-party library is kept only when the app's code reaches it within two calls, read from Blutter's call-target annotations, and is never flagged: on a real app, scoring every package flagged 136 files of a crypto library's internals, while the reachable set was the 18 API entry points the app actually calls, and on a lab app with the usual storage, database, WebView and crypto plugins, flagging the reachable ones that touch a sink still sent a third of the agent's steps into sqflite and pointycastle internals. Packages stay in the graph, linked from the app code that calls them, so a lead can still be followed into one; the app's misuse of a package is in the app's code, which is always flagged. Logging is ignored for packages, since a dependency's own print calls are not app behaviour and the pattern also matches words like fingerprint(; a package counts as a native bridge only when it actually opens a DynamicLibrary, because Blutter's call annotations mention dart:ffi in many packages that merely use FFI-backed SDK helpers. The Flutter SDK is left out entirely.
    """
    contents: Dict[str, str] = {}
    packages_of: Dict[str, str] = {}
    for package, files in sorted(groups.items()):
        if recovered.package_kind(package, app_packages) not in ("app", "package"):
            continue
        for fp in files:
            rel = _rel(fp, root)
            try:
                contents[rel] = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                verbose_print(f"Could not read {fp}: {exc}", verbose)
                continue
            packages_of[rel] = package

    edges: Dict[str, Set[str]] = {}
    for rel, content in contents.items():
        targets: List[str] = []
        for target_pkg, target_path in _CALL_TARGET_RE.findall(content):
            target_rel = f"asm/{target_pkg}/{target_path}"
            if target_rel != rel and target_rel in contents and target_rel not in targets:
                targets.append(target_rel)
        edges[rel] = targets
    app_files = {rel for rel, package in packages_of.items() if package in app_packages}
    reached = _reachable({k: set(v) for k, v in edges.items()}, app_files, _PACKAGE_REACH_DEPTH)

    nodes: Dict[str, CodeNode] = {}
    for rel in sorted(app_files | reached):
        content = contents[rel]
        package = packages_of[rel]
        role, signals, strings = _scan_asm_content(content)
        if rel in app_files:
            if role != "native-bridge":
                role = "app-entry" if rel.endswith("/main.dart") else "app-code"
            for value in recovered.app_pool_strings([root / rel], pool):
                if _SECRET_RE.search(value) and value[:80] not in strings:
                    strings.append(value[:80])
        else:
            signals.pop("logging", None)
            if role == "native-bridge" and "DynamicLibrary" not in content:
                role = "app-class"
                signals.pop("ffi", None)
            if role != "native-bridge":
                role = "dart-package"
                signals, strings = {}, []
        nodes[rel] = CodeNode(cls=f"{package}/{Path(rel).stem}", file=rel, role=role,
                              signals=signals, strings=strings[:_MAX_STRINGS_PER_ASM_NODE])
    for rel, node in nodes.items():
        node.refs = [t for t in edges.get(rel, []) if t in nodes][:_MAX_REFS_PER_NODE]
    verbose_print(f"Flutter graph: app code reaches {plural(len(reached), 'package library', 'package libraries')}", verbose)
    return nodes


def _build_referenced_pool_node(files: List[Path], root: Path, pp_txt: Path,
                                pool: Dict[str, recovered.PoolEntry]) -> Optional[CodeNode]:
    """
    Purpose:
        Build the object-pool node from only the entries the app's own code loads.

    Parameters:
        files: The app's own disassembly files.
        root: Output root, for relative paths.
        pp_txt: The object pool file.
        pool: The parsed object pool.

    Returns:
        The node, or None when none of those entries holds a credential-shaped string.

    Implementation notes:
        Scanning the whole pool for credential-shaped strings mostly finds the Flutter engine's own messages and URLs, because the pool holds every constant in the snapshot. Following the references the app's own functions make keeps the node to strings this app actually uses, including those inside const objects; third-party packages are left out because their constants are the package author's, not this app's.
    """
    strings = [value[:80] for value in recovered.app_pool_strings(files, pool) if _SECRET_RE.search(value)]
    if not strings:
        return None
    return CodeNode(cls="ObjectPool", file=_rel(pp_txt, root), role="app-class",
                    strings=strings[:_MAX_STRINGS_ON_POOL_NODE])


def _build_object_pool_node(pp_txt: Path, root: Path, verbose: bool) -> Optional[CodeNode]:
    """
    Purpose:
        Build a single node for Blutter's object pool.

    Parameters:
        pp_txt: The object pool file.
        root: Output root, for relative paths.
        verbose: Traces failures.

    Returns:
        The node, or None when the pool is unreadable.

    Implementation notes:
        Treated as one node rather than split, because it has no structure to divide along -- it is a flat list of every constant in the snapshot. It matters disproportionately for Flutter: with the code reduced to disassembly, the pool is where hardcoded URLs, keys and credentials remain plainly readable, so it is the highest-value region in a Flutter graph.
    """
    try:
        content = pp_txt.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        verbose_print(f"Could not read {pp_txt}: {exc}", verbose)
        return None

    strings: List[str] = []
    for m in _STRING_LITERAL_RE.finditer(content):
        lit = m.group(1)
        if _SECRET_RE.search(lit) and lit not in strings:
            strings.append(lit[:80])
            if len(strings) >= _MAX_STRINGS_ON_POOL_NODE:
                break

    if not strings:
        return None
    rel = _rel(pp_txt, root)
    return CodeNode(cls="ObjectPool", file=rel, role="app-class", strings=strings)


_SOURCE_IMPORT_RE = re.compile(r"""^\s*(?:import|export|part)\s+['"]([^'"]+\.dart)['"]""", re.MULTILINE)


def _resolve_source_import(target: str, importer: Path, root: Path) -> Optional[Path]:
    """
    Purpose:
        Resolve an import, export or part directive in recovered Dart source to a recovered file.

    Parameters:
        target: The URI in the directive.
        importer: The file containing it.
        root: The analysis root.

    Returns:
        The recovered file, or None for an SDK import or a file that was not recovered.

    Implementation notes:
        A package: URI maps to dart_packages/<package>/lib/..., and a relative URI to a path beside the importer. The result must stay inside the root, so a crafted relative import cannot point the graph at a file elsewhere on disk.
    """
    from ...decompiler.dart_kernel import PACKAGES_DIR

    if target.startswith("dart:"):
        return None
    if target.startswith("package:"):
        package, _, rest = target[len("package:"):].partition("/")
        candidate = root / PACKAGES_DIR / package / "lib" / rest
    elif ":" in target:
        return None
    else:
        candidate = importer.parent / target
    try:
        resolved = candidate.resolve()
        if root.resolve() not in resolved.parents or not resolved.is_file():
            return None
    except OSError:
        return None
    return resolved


def _build_source_nodes(root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build nodes over the Dart source recovered from a debug build.

    Parameters:
        root: The analysis root.
        verbose: Traces unreadable files.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the recovered sources.

    Implementation notes:
        The app's own files are always flagged and main.dart is its entry. A debug build carries the full source of every dependency, so a package file is kept only when the app's imports reach it within two hops, and is flagged only when it touches a sink other than logging -- the same rule as for a release build, and for the same reason: a library implementing crypto or a database is not where the app's mistakes are, its API entry point is.
    """
    from ...decompiler.dart_kernel import APP_DIR

    app_dir = root / APP_DIR
    if not app_dir.is_dir():
        return {}
    contents: Dict[str, str] = {}
    edges: Dict[str, Set[str]] = {}
    pending = sorted(app_dir.rglob("*.dart"))
    app_files = {_rel(fp, root) for fp in pending}
    depth_of: Dict[str, int] = {rel: 0 for rel in app_files}
    while pending:
        fp = pending.pop(0)
        rel = _rel(fp, root)
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            verbose_print(f"Could not read {fp}: {exc}", verbose)
            continue
        contents[rel] = content
        edges[rel] = set()
        if depth_of[rel] >= _PACKAGE_REACH_DEPTH:
            continue
        for target in _SOURCE_IMPORT_RE.findall(content):
            resolved = _resolve_source_import(target, fp, root)
            if resolved is None:
                continue
            target_rel = _rel(resolved, root)
            if target_rel in app_files:
                continue
            edges[rel].add(target_rel)
            if target_rel not in depth_of:
                depth_of[target_rel] = depth_of[rel] + 1
                pending.append(resolved)

    nodes: Dict[str, CodeNode] = {}
    for rel, content in sorted(contents.items()):
        role, signals, strings = _scan_asm_content(content)
        if rel in app_files:
            if role != "native-bridge":
                role = "app-entry" if rel.endswith("/main.dart") else "app-code"
            nodes[rel] = CodeNode(cls=Path(rel).stem, file=rel, role=role, signals=signals, strings=strings)
            continue
        package = rel.split("/")[1] if rel.count("/") > 1 else ""
        if role == "native-bridge":
            signals.pop("logging", None)
        else:
            role, signals, strings = "dart-package", {}, []
        nodes[rel] = CodeNode(cls=f"{package}/{Path(rel).stem}", file=rel, role=role,
                              signals=signals, strings=strings)
    for rel, node in nodes.items():
        node.refs = sorted(t for t in edges.get(rel, ()) if t in nodes)[:_MAX_REFS_PER_NODE]
    return nodes


def _build_platform_nodes(root: Path, names: Set[str], verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Add the Java/Kotlin files that answer the app's platform channels.

    Parameters:
        root: The analysis root.
        names: Channel and method names seen on the Dart side.
        verbose: Traces unreadable files.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the decompiled platform sources.

    Implementation notes:
        A file is a handler when it carries one of the names as a string literal, which survives R8 renaming. These files are where root, emulator, debugger and integrity checks usually live in a Flutter app, because Dart cannot make those checks itself, so they are flagged even with no other signal.
    """
    java_root = root / recovered.PLATFORM_DIR
    hits = recovered.java_literal_hits(java_root, root, names)
    files: Dict[str, List[str]] = {}
    for name, locations in hits.items():
        for location in locations:
            rel = location.rsplit(":", 1)[0]
            files.setdefault(rel, [])
            if name not in files[rel]:
                files[rel].append(name)
    nodes: Dict[str, CodeNode] = {}
    for rel, matched in sorted(files.items()):
        nodes[rel] = CodeNode(cls=Path(rel).stem, file=rel, role="platform-channel-handler",
                              signals={"platform_channel": sorted(matched)[:4]})
    if nodes:
        verbose_print(f"Flutter graph: {plural(len(nodes), 'platform-channel handler')} on the Java side", verbose)
    return nodes


def _snapshot_key_strings(root: Path) -> List[str]:
    """
    Purpose:
        Read the key strings recovered from libapp.so, when the Dart side could only be read that way.

    Parameters:
        root: The analysis root.

    Returns:
        The strings, one per entry; empty when there are none.
    """
    path = root / SNAPSHOT_DIR / KEY_STRINGS_NAME
    try:
        return [line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line]
    except OSError:
        return []


def _build_snapshot_nodes(root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Stand in for the Dart side when only libapp.so's strings were recovered: the key-strings file, and the app's own Java/Kotlin package.

    Parameters:
        root: The analysis root.
        verbose: Traces what was added.

    Returns:
        The nodes, keyed by relative path; empty when the analysis has disassembly or source instead.

    Implementation notes:
        Both are app-code nodes, so they are flagged: the agent has to read them before finishing and the file review covers them. With no Dart logic to follow, the app's own Java/Kotlin is the only code of the app that can be read line by line, and the key strings are the only view into the Dart side, so neither may be left unread.
    """
    nodes: Dict[str, CodeNode] = {}
    if (root / "asm").is_dir() or (root / "dart_source").is_dir():
        return nodes
    key_strings = _snapshot_key_strings(root)
    if key_strings:
        rel = f"{SNAPSHOT_DIR}/{KEY_STRINGS_NAME}"
        nodes[rel] = CodeNode(cls="libapp.so strings", file=rel, role="app-code",
                              signals={"strings": [f"{len(key_strings)} key strings"]},
                              strings=key_strings[:_MAX_STRINGS_PER_ASM_NODE])
    for path in app_code_files(root, manifest_package(root)):
        rel = _rel(path, root)
        nodes.setdefault(rel, CodeNode(cls=path.stem, file=rel, role="app-code"))
    if nodes:
        verbose_print(f"Flutter graph: no Dart disassembly - {plural(len(nodes), 'node')} from "
                      "libapp.so strings and the app's own Java/Kotlin", verbose)
    return nodes


def channel_names(root: Path) -> Set[str]:
    """
    Purpose:
        Collect every channel and method name the Dart side uses, from whichever form of Dart the analysis has.

    Parameters:
        root: The analysis root.

    Returns:
        The names.

    Side effects:
        Reads the recovered Dart files, the object pool and the snapshot's key strings.
    """
    names: Set[str] = set()
    for call in collect_channel_calls(root):
        names.update(n for n in (call.channel, call.method) if n and n != "?")
    pp_txt = root / "pp.txt"
    if pp_txt.is_file():
        pool = recovered.parse_object_pool(pp_txt.read_text(encoding="utf-8", errors="ignore"))
        for _kind, name in recovered.channel_names_by_object(pool).values():
            if not name.startswith("flutter/"):
                names.add(name)
    names.update(text for text in _snapshot_key_strings(root) if CHANNEL_RE.match(text))
    return names


def collect_channel_calls(root: Path) -> List[recovered.ChannelCall]:
    """
    Purpose:
        Find the platform-channel calls in the app and its packages.

    Parameters:
        root: The analysis root.

    Returns:
        The calls, app first.

    Side effects:
        Reads the recovered Dart files and the object pool.

    Implementation notes:
        Flutter SDK libraries are skipped because the framework's own channels (flutter/platform, flutter/textinput and the like) are not app behaviour. In an obfuscated build, where nothing can be attributed, every library is searched.
    """
    from ...decompiler.dart_kernel import APP_DIR, PACKAGES_DIR

    calls: List[recovered.ChannelCall] = []
    asm_dir = root / "asm"
    if asm_dir.is_dir():
        pool: Dict[str, recovered.PoolEntry] = {}
        pp_txt = root / "pp.txt"
        if pp_txt.is_file():
            pool = recovered.parse_object_pool(pp_txt.read_text(encoding="utf-8", errors="ignore"))
        channels = recovered.channel_names_by_object(pool)
        groups = recovered.asm_packages(asm_dir)
        apps = recovered.find_app_packages(groups)
        ordered = sorted(groups.items(), key=lambda item: (item[0] not in apps, item[0]))
        for package, files in ordered:
            if recovered.package_kind(package, apps) == "sdk":
                continue
            for fp in files:
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "invoke" not in text and "::send" not in text:
                    continue
                calls.extend(recovered.asm_channel_calls(_rel(fp, root), text, channels))
    for base in (root / APP_DIR, root / PACKAGES_DIR):
        if not base.is_dir():
            continue
        for fp in sorted(base.rglob("*.dart")):
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            _declared, found = recovered.source_channel_calls(_rel(fp, root), text)
            calls.extend(found)
    return calls


def build_flutter_graph(blutter_out, verbose: bool = False) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the graph over a recovered Flutter app.

    Parameters:
        blutter_out: The analysis root: Blutter's output directory for a release build, or the recovered-source directory for a debug build.
        verbose: Traces progress.

    Returns:
        The graph, or None when the output is unusable.

    Side effects:
        Reads the recovered files.
    """
    try:
        root = Path(blutter_out)
        if not root.is_dir():
            verbose_print(f"Flutter graph: Blutter output {root} is not a directory", verbose)
            return None

        nodes: Dict[str, CodeNode] = {}

        pool: Dict[str, recovered.PoolEntry] = {}
        pp_txt = root / "pp.txt"
        if pp_txt.is_file():
            try:
                pool = recovered.parse_object_pool(pp_txt.read_text(encoding="utf-8", errors="ignore"))
            except OSError as exc:
                verbose_print(f"Could not read {pp_txt}: {exc}", verbose)

        asm_dir = root / "asm"
        package_mode = False
        if asm_dir.is_dir():
            groups = recovered.asm_packages(asm_dir)
            app_packages = recovered.find_app_packages(groups)
            if app_packages:
                package_mode = True
                nodes.update(_build_package_asm_nodes(groups, app_packages, root, pool, verbose))
                verbose_print(f"Flutter graph: {plural(len(app_packages), 'app package')} "
                              f"({', '.join(sorted(app_packages))}); Flutter SDK libraries left "
                              "out of the graph", verbose)
                if pp_txt.is_file():
                    in_scope = [f for package, files in groups.items()
                                if recovered.package_kind(package, app_packages) == "app"
                                for f in files]
                    pool_node = _build_referenced_pool_node(in_scope, root, pp_txt, pool)
                    if pool_node is not None:
                        nodes["ObjectPool"] = pool_node
            else:
                nodes.update(_build_flat_asm_nodes(
                    [f for files in groups.values() for f in files], root, verbose))
        nodes.update(_build_source_nodes(root, verbose))
        nodes.update(_build_snapshot_nodes(root, verbose))

        if pp_txt.is_file() and not package_mode:
            pool_node = _build_object_pool_node(pp_txt, root, verbose)
            if pool_node is not None:
                nodes["ObjectPool"] = pool_node

        if (root / recovered.PLATFORM_DIR).is_dir():
            nodes.update(_build_platform_nodes(root, channel_names(root), verbose))

        if not nodes:
            verbose_print("Flutter graph: no nodes recovered; falling back", verbose)
            return None

        native_libs = [NativeLib(path=lib.path, loaded_by=lib.loaded_from)
                       for lib in flutter_native_libraries(root)]
        graph = CodeGraph(package="flutter-app", nodes=nodes, native_libs=native_libs)
        verbose_print(
            f"Flutter graph built: {plural(len(nodes), 'node')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Flutter graph build failed ({exc}); falling back to file tree", verbose)
        return None


def flutter_native_libraries(root) -> List[LoadedLibrary]:
    """
    Purpose:
        Find the bundled native libraries the app's own Dart or Java/Kotlin code loads.

    Parameters:
        root: The analysis root.

    Returns:
        The libraries, each with where it is loaded.

    Implementation notes:
        The app's code is its own Dart packages' disassembly (or recovered source) and its own Java/Kotlin package; a lib*.so literal there is what dart:ffi opens. When only libapp.so's strings were recovered, a string that is exactly a bundled library's name counts too, since the snapshot holds the literal dart:ffi was given; it is matched as a whole line because snapshot strings carry no quotes. Shared by the overview, which names the libraries to the agent, and the graph, which makes inspecting them part of coverage. The Flutter engine and the app snapshot are runtimes and are skipped.
    """
    from ...decompiler.dart_kernel import APP_DIR
    from ...decompiler.ghidra_runner import RUNTIME_LIBRARIES
    root = Path(root)
    dirs = [APP_DIR]
    asm_dir = root / "asm"
    if asm_dir.is_dir():
        apps = recovered.find_app_packages(recovered.asm_packages(asm_dir))
        dirs += [f"asm/{package}" for package in sorted(apps)]
    files = app_code_files(root, manifest_package(root), dirs)
    libraries = {lib.name: lib for lib in app_loaded_libraries(root, files, RUNTIME_LIBRARIES)}
    snapshot = root / SNAPSHOT_DIR / ALL_STRINGS_NAME
    if snapshot.is_file():
        bundled = bundled_libraries(root)
        try:
            lines = snapshot.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            lines = []
        for number, line in enumerate(lines, 1):
            name = line.strip()
            if name in bundled and name not in RUNTIME_LIBRARIES and name not in libraries:
                libraries[name] = LoadedLibrary(
                    name=name, path=bundled[name],
                    loaded_from=[f"{SNAPSHOT_DIR}/{ALL_STRINGS_NAME}:{number}"])
    return [libraries[name] for name in sorted(libraries)]


def write_flutter_overview(root, mode: str, packages: Optional[Dict[str, str]] = None,
                           verbose: bool = False) -> Optional[Path]:
    """
    Purpose:
        Write the overview file the agent reads first: build mode, layout, packages, the Dart-to-Java platform-channel map and the app's own strings.

    Parameters:
        root: The analysis root.
        mode: "release" for a Blutter recovery, "debug" for recovered Dart source, "strings" when only libapp.so's strings were recovered.
        packages: Third-party Dart packages, name to version; derived from Blutter's layout when omitted.
        verbose: Traces what was found.

    Returns:
        The written file, or None when it could not be written.

    Side effects:
        Reads the recovered output and writes one file into the root.

    Implementation notes:
        Written into the analysis root so it is an ordinary readable file and the profile's summary hook shows it in the opening context, replacing what used to be the first page of pp.txt -- which is mostly Flutter engine strings. The channel map is computed once here rather than discovered by the agent, because joining the two halves of a Flutter app otherwise costs it a search per method name on each side.
    """
    from ...decompiler.dart_kernel import APP_DIR, PACKAGES_DIR

    root = Path(root)
    try:
        app_packages: List[str] = []
        pool_strings: List[str] = []
        declared: Set[str] = set()
        packages = dict(packages or {})
        asm_dir = root / "asm"
        if asm_dir.is_dir():
            groups = recovered.asm_packages(asm_dir)
            apps = recovered.find_app_packages(groups)
            app_packages = sorted(apps)
            for package in groups:
                if recovered.package_kind(package, apps) == "package":
                    packages.setdefault(package, "")
            pp_txt = root / "pp.txt"
            if pp_txt.is_file():
                pool = recovered.parse_object_pool(pp_txt.read_text(encoding="utf-8", errors="ignore"))
                declared = {name for _kind, name in recovered.channel_names_by_object(pool).values()
                            if not name.startswith("flutter/")}
                objs_txt = root / "objs.txt"
                objects = (recovered.parse_object_dump(objs_txt.read_text(encoding="utf-8", errors="ignore"))
                           if objs_txt.is_file() else {})
                pool_strings = recovered.app_pool_strings(
                    [f for package in apps for f in groups.get(package, [])], pool, objects)
        if (root / APP_DIR).is_dir():
            app_packages = app_packages or [f"{APP_DIR}/ (the app's lib/ tree)"]
            for base in (root / APP_DIR, root / PACKAGES_DIR):
                for fp in sorted(base.rglob("*.dart")) if base.is_dir() else []:
                    try:
                        text = fp.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    found, _calls = recovered.source_channel_calls(_rel(fp, root), text)
                    declared.update(name for _kind, name, _line in found if not name.startswith("flutter/"))
        if mode == "strings":
            key_strings = _snapshot_key_strings(root)
            declared.update(text for text in key_strings if CHANNEL_RE.match(text))
            pool_strings = key_strings[:recovered.MAX_APP_POOL_STRINGS]
        calls = collect_channel_calls(root)
        has_platform = (root / recovered.PLATFORM_DIR).is_dir()
        names = declared | {n for c in calls for n in (c.channel, c.method) if n != "?"}
        java_hits = recovered.java_literal_hits(root / recovered.PLATFORM_DIR, root, names) if has_platform else {}
        native_lines = render_native_section(flutter_native_libraries(root), bundled_libraries(root))
        text = recovered.render_overview(
            mode=mode, root=root, app_packages=app_packages, packages=packages, calls=calls,
            declared_channels=declared, java_hits=java_hits, pool_strings=pool_strings,
            has_platform=has_platform, native_lines=native_lines)
        target = root / recovered.OVERVIEW_NAME
        target.write_text(text, encoding="utf-8")
        verbose_print(f"Flutter overview written: {recovered.summarise_calls(calls)}", verbose)
        return target
    except Exception as exc:
        verbose_print(f"Flutter overview could not be written: {exc}", verbose)
        return None
