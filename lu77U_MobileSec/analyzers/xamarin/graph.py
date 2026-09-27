#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.xamarin.graph

Purpose:
    Build the structural graph for a Xamarin app's decompiled C# or its assembly string sidecars, so the AI phase can fan out across coherent regions instead of scanning one undifferentiated tree.

Responsibilities:
    Walk the recovered output, score each unit for security-relevant signals, and assemble the graph.

Dependencies:
    The shared graph types.

Implementation notes:
    The same builder serves both the decompiled and the degraded path. When C# was recovered the nodes are real source; when only string sidecars exist they are the strings, which still carry the endpoints and credentials that most Xamarin findings come from. Every builder here returns None rather than raising when it cannot produce a graph, because the graph is an optimisation: without one the agent falls back to a single pass over the whole tree, which is slower and shallower but still works.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..agent.code_graph import CodeGraph, CodeNode
from ..agent.patterns import (MAX_STRINGS_PER_NODE as _MAX_STRINGS_PER_NODE,
                              SECRET_RE as _SECRET_RE,
                              STRING_LITERAL_RE as _STRING_LITERAL_RE)
from ...utils.verbose import plural, verbose_print

_NOISE_FRAGMENTS = (
    "/System.", "/Microsoft.", "/Mono.", "/Xamarin.Forms", "/Xamarin.Essentials",
    "/netstandard", "/mscorlib", "/Java.Interop", "/FSharp.",
    "/Newtonsoft.Json", "/SQLitePCLRaw", "/AndroidX.", "/Android.Support",
)

_SINK_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "tls": ("ServerCertificateValidationCallback",
            "ServerCertificateCustomValidationCallback",
            "DangerousAcceptAnyServerCertificateValidator",
            "RemoteCertificateValidationCallback"),
    "network": ("HttpClient", "WebClient", "HttpWebRequest", "RestClient",
                "WebRequest.Create", "ClientWebSocket"),
    "webview": ("Xamarin.Forms.WebView", "Android.Webkit.WebView", "WebViewSource",
                "AddJavascriptInterface", "EvaluateJavascript", "LoadUrl",
                "JavascriptEnabled", "HybridWebView", "BlazorWebView"),
    "sql": ("SqliteCommand", "SQLiteConnection", "SQLiteAsyncConnection",
            "ExecuteNonQuery", "CommandText", "SqlCommand", "db.Query"),
    "prefs": ("Preferences.Set", "Preferences.Get", "ISharedPreferences",
              "Application.Current.Properties", "SecureStorage"),
    "storage": ("File.WriteAllText", "File.ReadAllText", "FileStream",
                "Environment.GetFolderPath", "GetExternalFilesDir",
                "Isolated Storage", "IsolatedStorageFile"),
    "crypto": ("System.Security.Cryptography", "Aes.Create", "AesManaged",
               "TripleDES", "DESCryptoServiceProvider", "MD5", "SHA1",
               "RC2CryptoServiceProvider", "Rfc2898DeriveBytes",
               "CipherMode.ECB"),
    "serialization": ("BinaryFormatter", "TypeNameHandling", "XmlSerializer",
                      "JavaScriptSerializer", "LosFormatter"),
    "ipc": ("Intent.GetStringExtra", "GetStringExtra", "Intent.Extras",
            "OnNewIntent", "IntentFilter", "StartActivity"),
    "native": ("DllImport", "Marshal.", "JNIEnv", "unsafe "),
    "logging": ("Android.Util.Log", "Console.WriteLine", "Debug.WriteLine",
                "Trace.Write"),
    "reflection": ("Activator.CreateInstance", "Assembly.Load", "Type.GetType",
                   "InvokeMember"),
}

_ANDROID_ATTR_RE = re.compile(
    r"\[\s*(Activity|Service|BroadcastReceiver|ContentProvider)\b([^\]]*)\]",
    re.IGNORECASE)
_EXPORTED_RE = re.compile(r"Exported\s*=\s*true", re.IGNORECASE)
_INTENT_FILTER_RE = re.compile(
    r"\[\s*IntentFilter\s*\([^\]]*?new\s*\[\]\s*\{([^}]*)\}", re.DOTALL)

_TYPE_DECL_RE = re.compile(
    r"^\s*(?:public|internal|protected|private)?\s*(?:sealed|abstract|static|partial\s+)*"
    r"\s*(?:class|struct|record|interface)\s+([A-Za-z_]\w*)",
    re.MULTILINE)

_MAX_FILES = 20000


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
    return any(fragment in probe for fragment in _NOISE_FRAGMENTS)


def _scan(content: str) -> Tuple[Dict[str, List[str]], List[str], str, List[str]]:
    """
    Purpose:
        Score one decompiled file or string sidecar for security-relevant signals.

    Parameters:
        content: The file's text.

    Returns:
        The signal families found, the identifiers seen, the derived role and the notable strings.

    Implementation notes:
        Returns more than the other framework scanners because a Xamarin node can be either real source or a bare string list, and the caller needs enough to build a useful node from either.
    """
    signals: Dict[str, List[str]] = {}
    for family, keys in _SINK_FAMILIES.items():
        hits = [k for k in keys if k in content]
        if hits:
            signals[family] = hits[:4]

    strings: List[str] = []
    for match in _STRING_LITERAL_RE.finditer(content):
        literal = match.group(1)
        if _SECRET_RE.search(literal) and literal not in strings:
            strings.append(literal[:80])
            if len(strings) >= _MAX_STRINGS_PER_NODE:
                break

    role = "class"
    attr = _ANDROID_ATTR_RE.search(content)
    if attr:
        kind = attr.group(1).lower()
        kind = {"broadcastreceiver": "receiver", "contentprovider": "provider"}.get(
            kind, kind)
        exported = bool(_EXPORTED_RE.search(attr.group(2)))
        role = f"exported-{kind}" if exported else kind

    actions: List[str] = []
    for match in _INTENT_FILTER_RE.finditer(content):
        for raw in match.group(1).split(","):
            action = raw.strip().strip('"').rsplit(".", 1)[-1]
            if action and action not in actions:
                actions.append(action)
        if actions:
            if not role.startswith("exported") and role != "class":
                role = f"exported-{role}"
            break

    return signals, strings, role, actions[:4]


def build_xamarin_graph(source_root, verbose: bool = False) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the graph over a Xamarin app's recovered output.

    Parameters:
        source_root: Root of the recovered output.
        verbose: Traces progress.

    Returns:
        The graph, or None when there was nothing to build from.

    Side effects:
        Reads the recovered files.
    """
    try:
        root = Path(source_root)
        if not root.is_dir():
            verbose_print(f"Xamarin graph: {root} is not a directory", verbose)
            return None

        files = sorted(p for p in root.rglob("*.cs") if p.is_file())[:_MAX_FILES]
        if not files:
            verbose_print("Xamarin graph: no decompiled C# found; falling back", verbose)
            return None

        nodes: Dict[str, CodeNode] = {}
        for path in files:
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = path.name
            if _is_noise(rel):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                verbose_print(f"Could not read {path}: {exc}", verbose)
                continue

            signals, strings, role, actions = _scan(content)
            declared = _TYPE_DECL_RE.search(content)
            nodes[rel] = CodeNode(
                cls=(declared.group(1) if declared else path.stem),
                file=rel, role=role, signals=signals, strings=strings,
                intent_actions=actions)

        if not nodes:
            verbose_print("Xamarin graph: no app types recovered; falling back", verbose)
            return None

        graph = CodeGraph(package="xamarin-dotnet", nodes=nodes, native_libs=[])
        verbose_print(
            f"Xamarin graph built: {plural(len(nodes), 'type')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Xamarin graph build failed ({exc}); falling back to file tree",
                      verbose)
        return None
