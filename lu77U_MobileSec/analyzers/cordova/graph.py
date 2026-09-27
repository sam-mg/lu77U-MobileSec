#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.cordova.graph

Purpose:
    Build the structural graph for a Cordova app's bundled web assets, so the AI phase can fan out across coherent regions instead of scanning one undifferentiated tree.

Responsibilities:
    Walk the recovered output, score each unit for security-relevant signals, and assemble the graph.

Dependencies:
    The shared graph types.

Implementation notes:
    HTML and JavaScript are scanned differently: an HTML file's interest is what it loads and which origins it permits, while a script's is the sinks it reaches. The scan is told which it is looking at rather than inferring it per pattern. Every builder here returns None rather than raising when it cannot produce a graph, because the graph is an optimisation: without one the agent falls back to a single pass over the whole tree, which is slower and shallower but still works.
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

_SOURCE_EXTS = (".js", ".html", ".htm")

_NOISE_FRAGMENTS = (
    "/cordova.js", "/cordova_plugins.js", "/cordova-js-src/",
    "/jquery", "/angular", "/bootstrap", "/react", "/vue", "/lodash",
    "/underscore", "/moment", "/polyfill",
)

_SINK_FAMILIES: Dict[str, tuple] = {
    "dom_xss": ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
                ".html(", "$(", "dangerouslySetInnerHTML"),
    "eval": ("eval(", "new Function(", "setInterval(\"", "setTimeout(\""),
    "network": ("XMLHttpRequest", "fetch(", "$.ajax", "$.get(", "$.post(", "WebSocket("),
    "cordova_exec": ("cordova.exec", "exec(function", "require('cordova/exec')",
                     'require("cordova/exec")'),
    "inappbrowser": ("InAppBrowser", "window.open(", "cordova.InAppBrowser",
                     "iab.", "_blank"),
    "file": ("requestFileSystem", "resolveLocalFileSystemURL", "LocalFileSystem",
             "cordova-plugin-file", "FileReader", "FileTransfer"),
    "storage": ("localStorage", "sessionStorage", "openDatabase(",
                "sqlitePlugin", "window.indexedDB"),
    "webintent": ("WebIntent", "webintent", "startActivity", "getExtra"),
    "geolocation": ("navigator.geolocation",),
    "crypto": ("CryptoJS", "crypto-js", "md5(", "sha1("),
    "deeplink": ("handleOpenURL", "universalLinks", "window.location.href ="),
    "logging": ("console.log", "console.warn", "console.error"),
}


_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)

_ENTRY_MARKERS = ("deviceready", "cordova.js", "<html")


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


def _scan_content(content: str, is_html: bool) -> tuple:
    """
    Purpose:
        Score one web asset for security-relevant signals.

    Parameters:
        content: The file's text.
        is_html: Whether it is markup rather than script.

    Returns:
        The signal families found and the derived role.

    Implementation notes:
        Only a few examples per family are kept, because the graph carries these as hints for the agent and an exhaustive list would bloat the prompt without telling it more. The markup flag changes what counts as interesting: inline handlers and permitted origins in HTML, sink calls in script.
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
    ref_iter = _SCRIPT_SRC_RE.finditer(content) if is_html else _REQUIRE_RE.finditer(content)
    for m in ref_iter:
        ref = m.group(1)
        if ref not in refs:
            refs.append(ref)
            if len(refs) >= _MAX_REFS_PER_NODE:
                break

    return signals, strings, refs


def build_cordova_graph(www_root, verbose: bool = False) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the graph over a Cordova app's web assets.

    Parameters:
        www_root: Root of the extracted assets.
        verbose: Traces progress.

    Returns:
        The graph, or None when there was nothing to build from.

    Side effects:
        Reads the asset files.
    """
    try:
        root = Path(www_root)
        if not root.is_dir():
            verbose_print(f"Cordova graph: source root {root} is not a directory", verbose)
            return None

        source_files = sorted(
            f for ext in _SOURCE_EXTS for f in root.rglob(f"*{ext}") if f.is_file())
        if not source_files:
            verbose_print("Cordova graph: no HTML/JS files found; falling back", verbose)
            return None

        nodes: Dict[str, CodeNode] = {}
        for fp in source_files:
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

            is_html = fp.suffix.lower() in (".html", ".htm")
            signals, strings, refs = _scan_content(content, is_html)
            role = "entry-page" if (is_html and any(m in content for m in _ENTRY_MARKERS)) \
                else ("page" if is_html else "app-script")
            nodes[rel] = CodeNode(cls=fp.stem, file=rel, role=role,
                                  signals=signals, strings=strings, refs=refs)

        if not nodes:
            verbose_print("Cordova graph: no app nodes recovered; falling back", verbose)
            return None

        graph = CodeGraph(package="cordova-webview", nodes=nodes, native_libs=[])
        verbose_print(
            f"Cordova graph built: {plural(len(nodes), 'node')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Cordova graph build failed ({exc}); falling back to file tree", verbose)
        return None
