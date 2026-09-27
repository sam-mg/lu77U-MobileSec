#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.flutter.graph

Purpose:
    Build the structural graph for the output Blutter recovers from a Flutter snapshot, so the AI phase can fan out across coherent regions instead of scanning one undifferentiated tree.

Responsibilities:
    Walk the recovered output, score each unit for security-relevant signals, and assemble the graph.

Dependencies:
    The shared graph types.

Implementation notes:
    Blutter produces two quite different artifacts: per-class disassembly and a single object pool listing every constant in the snapshot. They are turned into different kinds of node, because the disassembly carries structure while the pool is where hardcoded strings and keys actually live. Every builder here returns None rather than raising when it cannot produce a graph, because the graph is an optimisation: without one the agent falls back to a single pass over the whole tree, which is slower and shallower but still works.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional

from ..agent.code_graph import CodeGraph, CodeNode
from ..agent.patterns import (MAX_STRINGS_PER_NODE as _MAX_STRINGS_PER_NODE,
                              SECRET_RE as _SECRET_RE,
                              STRING_LITERAL_RE as _STRING_LITERAL_RE)
from ...utils.verbose import plural, verbose_print

_SINK_FAMILIES: Dict[str, tuple] = {
    "network": ("HttpClient", "package:http", "Dio(", "dio.", "WebSocket("),
    "tls": ("badCertificateCallback", "HttpOverrides", "createHttpClient"),
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

_ENTRY_HINT_RE = re.compile(r"main", re.IGNORECASE)
_FFI_HINT = ("dart:ffi", "DynamicLibrary")


def _scan_asm_content(content: str) -> tuple:
    """
    Purpose:
        Score a unit of recovered disassembly for security-relevant signals.

    Parameters:
        content: The disassembly text.

    Returns:
        The signal families found and the derived role.

    Implementation notes:
        Matched on the symbol names Blutter preserves rather than on code shape, since the output is disassembly and there is no syntax to parse.
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


def _build_asm_nodes(asm_dir: Path, root: Path, verbose: bool) -> Dict[str, CodeNode]:
    """
    Purpose:
        Build a node per unit of recovered disassembly.

    Parameters:
        asm_dir: Blutter's disassembly directory.
        root: Output root, for relative paths.
        verbose: Traces progress.

    Returns:
        The nodes, keyed by relative path.

    Side effects:
        Reads the disassembly files.

    Implementation notes:
        Files are processed in sorted order so the graph is identical between runs over the same app, which keeps region assignment and therefore the report stable.
    """
    nodes: Dict[str, CodeNode] = {}
    for fp in sorted(p for p in asm_dir.rglob("*") if p.is_file()):
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = str(fp)
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            verbose_print(f"Could not read {fp}: {exc}", verbose)
            continue

        role, signals, strings = _scan_asm_content(content)
        if role == "app-class" and _ENTRY_HINT_RE.search(fp.stem):
            role = "entry-point"

        cls = fp.stem
        nodes[rel] = CodeNode(cls=cls, file=rel, role=role, signals=signals, strings=strings)
    return nodes


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
    try:
        rel = str(pp_txt.relative_to(root))
    except ValueError:
        rel = pp_txt.name
    return CodeNode(cls="ObjectPool", file=rel, role="app-class", strings=strings)


def build_flutter_graph(blutter_out, verbose: bool = False) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the graph over Blutter's recovered output.

    Parameters:
        blutter_out: Blutter's output directory.
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

        asm_dir = root / "asm"
        if asm_dir.is_dir():
            nodes.update(_build_asm_nodes(asm_dir, root, verbose))
        else:
            verbose_print(f"Flutter graph: no asm/ directory under {root}", verbose)

        pp_txt = root / "pp.txt"
        if pp_txt.is_file():
            pool_node = _build_object_pool_node(pp_txt, root, verbose)
            if pool_node is not None:
                nodes["ObjectPool"] = pool_node

        if not nodes:
            verbose_print("Flutter graph: no nodes recovered; falling back", verbose)
            return None

        graph = CodeGraph(package="flutter-app", nodes=nodes, native_libs=[])
        verbose_print(
            f"Flutter graph built: {plural(len(nodes), 'node')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Flutter graph build failed ({exc}); falling back to file tree", verbose)
        return None
