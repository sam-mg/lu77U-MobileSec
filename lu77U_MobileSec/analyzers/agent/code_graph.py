#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.code_graph

Purpose:
    Build the structural map of an Android app the agent works from: which classes exist, which are reachable from outside, what security-relevant APIs each touches, and how they call each other.

Responsibilities:
    Scan the APK's classes, classify roles from the manifest, record sinks and strings, resolve call edges, tie classes back to decompiled files, and prune what is not worth examining.

Dependencies:
    androguard's analysis object, the ownership classifier, the pattern tables, the call graph.

Implementation notes:
    Without a graph the agent can only read files in some order and hope. With one it can start at the app's entry points, follow calls, and know which classes touch a sink before opening them -- which is the difference between examining an app and sampling it. Nodes are built from the bytecode rather than from the decompiled source, because the bytecode is complete and reliable while decompilation partly fails on most real apps. Source paths are then attached where they resolve, so the agent can read what the graph points at. Only the app's own classes are included. The platform and bundled libraries would dominate the graph, and neither is code the app owner can change.

Security considerations:
    Everything here is derived from an untrusted APK. The graph decides what the agent examines, so a class wrongly pruned is never analysed at all -- which is why pruning is restricted to nodes with no role, no edges and no signals.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .patterns import (MAX_STRINGS_PER_NODE as _MAX_STRINGS_PER_NODE, SECRET_RE as _SECRET_RE)
from ...utils.verbose import plural, verbose_print

_FRAMEWORK_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Lcom/google/", "Lorg/jetbrains/", "Lorg/intellij/", "Ldalvik/",
    "Lorg/xmlpull/", "Lorg/apache/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/",
    "Lorg/hamcrest/", "Ljunit/", "Lorg/junit/",
)

_VENDOR_PREFIXES = (
    "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/squareup/", "Lcom/google/gson/",
    "Lorg/chromium/", "Lcom/fasterxml/",
    "Lio/reactivex/", "Lrx/", "Lcom/jakewharton/",
    "Lcom/appsflyer/", "Lcom/adjust/", "Lcom/mixpanel/", "Lcom/amplitude/",
    "Lcom/segment/", "Lcom/clevertap/", "Lcom/braze/", "Lcom/appboy/",
    "Lcom/onesignal/", "Lio/branch/", "Lcom/moengage/", "Lcom/netcore/",
    "Lio/sentry/", "Lcom/bugsnag/", "Lcom/crashlytics/", "Lcom/newrelic/",
    "Lcom/instabug/", "Lcom/datadog/",
    "Lcom/facebook/", "Ltwitter4j/", "Lcom/paypal/", "Lcom/stripe/",
    "Lcom/razorpay/", "Lcom/phonepe/", "Lorg/npci/",
    "Lco/hyperverge/", "Lcom/onfido/", "Lcom/jumio/", "Lcom/regula/",
    "Lcom/bumptech/", "Lcom/airbnb/", "Lcom/github/", "Lde/hdodenhof/",
    "Lcom/theartofdev/", "Lcom/scottyab/", "Lcom/journeyapps/",
    "Lorg/greenrobot/", "Lbutterknife/", "Ldagger/", "Ljavax/inject/",
    "Lcom/mikepenz/", "Lcom/nostra13/", "Lcom/tencent/", "Lcom/alibaba/",
    "Lcom/huawei/", "Lcom/xiaomi/", "Lcom/miui/",
    "Lcom/facebook/stetho/", "Lcom/facebook/flipper/", "Lleakcanary/",
    "Lcom/squareup/leakcanary/",
)

_SINK_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "sql": ("->execSQL", "->rawQuery", "SQLiteDatabase;->query", "->compileStatement"),
    "prefs": ("SharedPreferences", "getDefaultSharedPreferences"),
    "logging": ("Landroid/util/Log;",),
    "crypto": ("Ljavax/crypto/Cipher;", "MessageDigest;", "SecretKeySpec",
               "IvParameterSpec", "Ljava/security/"),
    "webview": ("->loadUrl", "->loadData", "addJavascriptInterface",
                "setJavaScriptEnabled", "->evaluateJavascript", "setAllowFileAccess"),
    "runtime": ("Ljava/lang/Runtime;->exec", "ProcessBuilder"),
    "storage": ("getExternalStorage", "->openFileOutput", "MODE_WORLD",
                "getExternalFilesDir", "Landroid/os/Environment;"),
    "uri": ("->getLastPathSegment", "->getQueryParameter"),
    "native": ("Ljava/lang/System;->loadLibrary", "Ljava/lang/System;->load"),
    "ipc": ("->getStringExtra", "->getData", "->getSerializableExtra",
            "->getParcelableExtra"),
    "display": ("Landroid/widget/TextView;->setText",),
}


_JS_BRIDGE_ANNOTATIONS = ("@android.webkit.JavascriptInterface", "@JavascriptInterface")
_JS_BRIDGE_METHOD_RE = re.compile(
    r"@(?:android\.webkit\.)?JavascriptInterface\b[^{]*?\b([A-Za-z_$][\w$]*)\s*\(",
    re.DOTALL)
_MAX_BRIDGE_SCAN_FILES = 60000

_ACC_SYNTHETIC = 0x1000

_MAX_METHODS_SHOWN = 12
_MAX_REFS_SHOWN = 8
_MAX_CALLS_PER_NODE = 40
_MAX_BRIDGE_FANOUT = 12
_DEFAULT_MAX_ENTRIES = 120
_DEFAULT_MAX_CHARS = 20000

@dataclass
class CodeNode:
    """
    Purpose:
        One class in the graph, with what is known about it.

    Attributes:
        cls: The class name.
        file: The decompiled source path, when one resolved.
        descriptor: The bytecode descriptor.
        source_available: Whether the decompiled source was found.
        role: What the manifest says it is, such as an exported component.
        extends: Its superclass.
        methods: Its methods.
        signals: Security-relevant API families it touches, with examples.
        strings: Notable string literals, filtered to the credential-shaped ones.
        refs: Classes it references.
        calls: Classes it calls.
        intent_actions: Intent actions it handles.

    Thread-safety:
        Built once and read-only afterwards, so the fanned-out agents can share it.
    """
    cls: str
    file: str
    descriptor: str = ""
    source_available: bool = True
    role: str = "class"
    extends: str = ""
    methods: List[str] = field(default_factory=list)
    signals: Dict[str, List[str]] = field(default_factory=dict)
    strings: List[str] = field(default_factory=list)
    refs: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    intent_actions: List[str] = field(default_factory=list)

    @property
    def exported(self) -> bool:
        """
        Purpose:
            Whether this class is reachable from outside the app.

        Returns:
            True for an exported component.

        Implementation notes:
            Exported components are where attacker-controlled data enters, so this drives both seed selection during partitioning and the reachability reasoning the agent does.
        """
        return self.role.startswith("exported")

    @property
    def flagged(self) -> bool:
        """
        Purpose:
            Whether this class is worth an agent's attention.

        Returns:
            True when it is exported, touches a sink, holds a notable string, or bridges to JavaScript.

        Implementation notes:
            This is the filter that decides what gets partitioned into regions. A class with none of these is plumbing: still readable through the tools if the agent follows a call into it, but not worth allocating budget to.
        """
        return self.exported or bool(self.signals) or bool(self.strings) \
            or self.role == "native-bridge"

@dataclass
class NativeLib:
    """
    Purpose:
        A native library the app bundles, and the classes that load it.

    Attributes:
        path: The library's path.
        loaded_by: Classes that load it.

    Implementation notes:
        Recording who loads a library is what lets the fan-out attach it to the regions that might care, rather than leaving native code invisible to every agent.
    """
    path: str
    loaded_by: List[str] = field(default_factory=list)


def _match_node_for_file(nodes: Dict[str, "CodeNode"], path: str) -> Optional["CodeNode"]:
    """
    Purpose:
        Find the node corresponding to a source file path.

    Parameters:
        nodes: The graph's nodes.
        path: The file path.

    Returns:
        The node, or None.

    Implementation notes:
        Matched tolerantly, because a path can arrive from the decompiler, from a finding or from model output, each spelled slightly differently.
    """
    if not path:
        return None
    norm = str(path).strip().lstrip("./").replace("\\", "/")
    norm = norm.split(":", 1)[0]
    for n in nodes.values():
        if n.file == norm or n.file.endswith("/" + norm) or norm.endswith("/" + n.file):
            return n
    base = norm.rsplit("/", 1)[-1]
    for n in nodes.values():
        if n.file.rsplit("/", 1)[-1] == base:
            return n
    return None

@dataclass
class CodeGraph:
    """
    Purpose:
        The app's classes, their properties and the calls between them.

    Attributes:
        package: The app's package.
        nodes: The classes, keyed by descriptor.
        native_libs: The bundled native libraries.
        call_graph: The method-level call graph.

    Invariants:
        Contains the app's own classes only. Read-only after construction.

    Thread-safety:
        Safe to share across the fanned-out agents, which only query it.
    """
    package: str
    nodes: Dict[str, CodeNode]
    native_libs: List[NativeLib] = field(default_factory=list)
    call_graph: Any = None
    ownership: Dict[str, Any] = field(default_factory=dict)

    def display_name(self, key: str) -> str:
        """
        Purpose:
            Render a class name readably, disambiguating where short names collide.

        Parameters:
            key: The node key.

        Returns:
            The display name.

        Implementation notes:
            Shortened where the short name is unique and qualified where it is not, so prompts stay readable without the agent confusing two same-named classes from different packages -- which in an obfuscated app is common.
        """
        node = self.nodes.get(key)
        if node is None:
            return key
        if self._name_counts().get(node.cls, 0) <= 1:
            return node.cls
        pkg = (node.descriptor or key).lstrip("L").rstrip(";").rsplit("/", 2)
        return f"{pkg[-2]}.{node.cls}" if len(pkg) >= 2 else node.cls

    def _name_counts(self) -> Dict[str, int]:
        """
        Purpose:
            Count how many classes share each short name.

        Returns:
            The counts.

        Implementation notes:
            Computed once and reused, since it is consulted for every name rendered and recomputing it per call would be quadratic.
        """
        cached = getattr(self, "_name_count_cache", None)
        if cached is None or len(cached) != len(set(n.cls for n in self.nodes.values())):
            cached = {}
            for n in self.nodes.values():
                cached[n.cls] = cached.get(n.cls, 0) + 1
            object.__setattr__(self, "_name_count_cache", cached)
        return cached

    def flagged_files(self) -> List[str]:
        """
        Purpose:
            List the files worth examining: the flagged classes with source, plus the native libraries.

        Returns:
            The paths.

        Implementation notes:
            Classes with no resolved source are excluded, because the agent cannot read them -- they are still in the graph for reachability, but pointing an agent at a file that does not exist wastes a step.
        """
        files = [n.file for n in self.nodes.values()
                 if n.flagged and n.source_available]
        files += [lib.path for lib in self.native_libs]
        return files

    def node_for_file(self, path: str) -> Optional[CodeNode]:
        """
        Purpose:
            Find the node for a source file.

        Parameters:
            path: The file path.

        Returns:
            The node, or None.

        Implementation notes:
            Used to annotate a finding with what the graph knows about its file, which is how the verification phase gets its structural hints.
        """
        return _match_node_for_file(self.nodes, path)

    def matches_surface(self, node: "CodeNode", surface) -> bool:
        """
        Purpose:
            Decide whether a class belongs to an attack surface.

        Parameters:
            node: The class.
            surface: The surface.

        Returns:
            True when it belongs.

        Implementation notes:
            Several independent tests, any of which suffices: the declared role, an exported role where the surface wants exported components, a matching sink family, handled intent actions, or a recognised secret. A class can belong to a surface for any of those reasons and requiring more than one would leave most of the interesting code unassigned.
        """
        role = node.role or ""
        if role in surface.roles:
            return True
        if "exported" in surface.roles and role.startswith("exported"):
            return True
        if surface.sink_families & set(node.signals):
            return True
        if surface.wants_intent_actions and node.intent_actions:
            return True
        if surface.wants_secrets and self._has_typed_secret(node):
            return True
        return False

    @staticmethod
    def _has_typed_secret(node: "CodeNode") -> bool:
        """
        Purpose:
            Whether a class holds a string that classifies as a credential.

        Parameters:
            node: The class.

        Returns:
            True when one of its strings matches a credential pattern.

        Implementation notes:
            Classified through the shared pattern table rather than by a local heuristic, so what counts as a secret here is what counts as one in the rule engine and the gates.
        """
        from .patterns import classify_secret
        return any(classify_secret(s) is not None for s in node.strings)

    def subgraph_of(self, keys) -> "CodeGraph":
        """
        Purpose:
            Build a graph containing only the named classes.

        Parameters:
            keys: The classes to keep.

        Returns:
            The subgraph.

        Implementation notes:
            The call graph is carried through rather than rebuilt, so an agent working on a region can still ask reachability questions whose answers run through code outside it -- which is exactly the question worth asking about a region boundary.
        """
        wanted = set(keys)
        return CodeGraph(package=self.package,
                         nodes={k: v for k, v in self.nodes.items() if k in wanted},
                         native_libs=[],
                         call_graph=self.call_graph,
                         ownership=self.ownership)

    def subgraph(self, surface) -> "CodeGraph":
        """
        Purpose:
            Build a graph containing the classes on one attack surface.

        Parameters:
            surface: The surface.

        Returns:
            The subgraph.
        """
        picked = {
            key: node for key, node in self.nodes.items()
            if node.flagged and self.matches_surface(node, surface)
        }
        libs = list(self.native_libs) if surface.wants_native_libs else []
        return CodeGraph(package=self.package, nodes=picked, native_libs=libs,
                         call_graph=self.call_graph, ownership=self.ownership)

    def structure_summary(self) -> str:
        """
        Purpose:
            Summarise the app's shape for the agent's opening context.

        Returns:
            The summary.

        Implementation notes:
            Gives the agent the scale and composition of what it is looking at before it starts, so it can plan its budget rather than discovering the size one read at a time.
        """
        lines = []
        entries = sorted((n for n in self.nodes.values() if n.exported),
                         key=lambda n: n.cls.lower())
        if entries:
            lines.append("Entry points (externally reachable):")
            for n in entries:
                sig = ("; ".join(f"{f}({', '.join(sorted(set(v))[:3])})"
                                 for f, v in n.signals.items())) or "-"
                lines.append(f"  [{n.role}] {n.cls} ({n.file}) - {sig}")
        if self.native_libs:
            lines.append("Native libraries (Frida/objdump targets):")
            for lib in self.native_libs:
                by = (" - loaded by " + ", ".join(lib.loaded_by)) if lib.loaded_by else ""
                lines.append(f"  {lib.path}{by}")
        return "\n".join(lines)

    def render(self, max_entries: int = _DEFAULT_MAX_ENTRIES,
              max_chars: int = _DEFAULT_MAX_CHARS) -> str:
        """
        Purpose:
            Render the graph as the prompt section the agent reads.

        Parameters:
            max_entries: How many nodes to include.
            max_chars: Hard ceiling on the rendered length.

        Returns:
            The rendered graph.

        Implementation notes:
            Bounded twice, by entry count and by characters, because node renderings vary enormously in length -- a class with many sinks and strings is far longer than a bare one, so an entry count alone does not bound the context cost. Nodes are ordered so the most interesting appear first, which means a truncated rendering still shows the agent the entry points and the sinks rather than an arbitrary alphabetical prefix.
        """
        entries = list(self.nodes.values())
        ordered = sorted(
            entries,
            key=lambda n: (0 if n.exported else 1 if n.flagged else 2, n.cls.lower()),
        )
        shown = ordered[:max_entries]
        overflow = ordered[max_entries:]

        entry_pts = [n for n in shown if n.exported]
        signalled = [n for n in shown if not n.exported and n.flagged]
        plain = [n for n in shown if not n.flagged]

        out: List[str] = []
        out.append(
            f"## App code map ({self.package}) - "
            f"{plural(len(self.nodes), 'app class', 'app classes')}, "
            f"{plural(len(self.native_libs), 'native lib')}")
        out.append(
            "Each entry: [role] Class (file) - the security-relevant APIs it "
            "calls and any hardcoded strings. Start from flagged entries, "
            "read those files to confirm, and inspect native libs.")

        if entry_pts:
            out.append("\n### Entry points (externally reachable - attacker-facing)")
            out += [self._render_node(n) for n in entry_pts]
        if signalled:
            out.append("\n### App classes with security signals")
            out += [self._render_node(n) for n in signalled]
        if plain:
            out.append("\n### App classes without detected signals "
                       "(read if the above don't explain the app)")
            out.append("  " + ", ".join(
                self.display_name(n.descriptor or n.cls) for n in plain))
        if self.native_libs:
            out.append("\n### Native libraries (use inspect_native)")
            for lib in self.native_libs:
                by = (" - loaded by " + ", ".join(lib.loaded_by)) if lib.loaded_by else ""
                out.append(f"  {lib.path}{by}")
        if overflow:
            out.append(f"\n... (+{plural(len(overflow), 'more app class', 'more app classes')} not shown; "
                       f"use list_files/search_code)")
        text = "\n".join(out)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... [app code map truncated; use list_files/search_code]"
        return text

    def _render_node(self, n: CodeNode) -> str:
        """
        Purpose:
            Render one node for the prompt.

        Parameters:
            n: The node.

        Returns:
            The rendered line.

        Implementation notes:
            Compact by design: role, sinks and notable strings on one line. The agent uses this to choose what to open, so it needs enough to judge and no more.
        """
        head = f"[{n.role}"
        if n.intent_actions:
            head += ": " + ",".join(n.intent_actions[:2])
        where = n.file if n.source_available else f"{n.file} - NOT DECOMPILED, do not read"
        head += f"] {self.display_name(n.descriptor or n.cls)} ({where})"
        if n.extends and n.extends not in ("Object", "AppCompatActivity"):
            head += f" extends {n.extends}"
        bits: List[str] = []
        if n.signals:
            sig = "; ".join(
                f"{fam}({', '.join(sorted(set(v))[:4])})" for fam, v in n.signals.items())
            bits.append("sinks: " + sig)
        if n.strings:
            quoted = ", ".join('"' + s + '"' for s in n.strings[:3])
            bits.append("hardcoded: " + quoted)
        if n.refs:
            bits.append("refs: " + ", ".join(
                self.display_name(r) for r in n.refs[:5] if r in self.nodes))
        detail = ("\n    " + " | ".join(bits)) if bits else ""
        return head + detail

    def to_json(self) -> dict:
        """
        Purpose:
            Serialise the graph for checkpointing and inspection.

        Returns:
            The graph as plain data.
        """
        return {
            "package": self.package,
            "nodes": [
                {
                    "key": n.descriptor, "class": n.cls, "file": n.file, "role": n.role,
                    "extends": n.extends, "methods": n.methods,
                    "signals": n.signals, "strings": n.strings, "refs": n.refs,
                    "intent_actions": n.intent_actions,
                }
                for n in self.nodes.values()
            ],
            "native_libs": [{"path": l.path, "loaded_by": l.loaded_by}
                            for l in self.native_libs],
        }

def _descriptor_to_short(desc: str) -> str:
    """
    Purpose:
        Reduce a class descriptor to its short name.

    Parameters:
        desc: The descriptor.

    Returns:
        The short name.
    """
    inner = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    return inner.split("/")[-1]

def _outer_descriptor(desc: str) -> str:
    """
    Purpose:
        Reduce an inner class descriptor to its outer class.

    Parameters:
        desc: The descriptor.

    Returns:
        The outer class descriptor.

    Implementation notes:
        Inner classes are attributed to their outer class, because they decompile into the same file and treating them separately would give the agent several nodes pointing at one source.
    """
    inner = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    return "L" + inner.split("$", 1)[0] + ";"


def _descriptor_to_file(desc: str) -> str:
    """
    Purpose:
        Derive the decompiled source path a class would occupy.

    Parameters:
        desc: The descriptor.

    Returns:
        The relative path.

    Implementation notes:
        A first guess, verified later against the actual decompiled tree, because the decompiler renames classes whose names collide or are invalid.
    """
    inner = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    inner = inner.split("$", 1)[0]
    return f"sources/{inner}.java"

def is_vendor_class(desc: str) -> bool:
    """
    Purpose:
        Whether a class belongs to a bundled third-party SDK.

    Parameters:
        desc: The descriptor.

    Returns:
        True for vendor code.
    """
    if any(desc.startswith(p) for p in _VENDOR_PREFIXES):
        return True
    probe = desc.lstrip("L")
    return any(probe.startswith(p) for p in _sdk_package_prefixes())


def _sdk_package_prefixes():
    """
    Purpose:
        The package prefixes identifying known SDKs.

    Returns:
        The prefixes.

    Implementation notes:
        Derived from the SDK inventory's signatures, so one table serves both recognising an SDK and excluding it from the graph.
    """
    global _SDK_PREFIX_CACHE
    if _SDK_PREFIX_CACHE is None:
        try:
            from ..sast.extractors.sdk_inventory import SDK_SIGNATURES
            _SDK_PREFIX_CACHE = tuple(
                sorted({p.strip("/") + "/" for entry in SDK_SIGNATURES.values()
                        for p in entry[1]}))
        except Exception:
            _SDK_PREFIX_CACHE = ()
    return _SDK_PREFIX_CACHE


_SDK_PREFIX_CACHE = None
_SDK_BY_PREFIX_CACHE = None


def _sdk_names_by_prefix():
    """
    Purpose:
        Map each SDK prefix to the SDK's name.

    Returns:
        The mapping.

    Implementation notes:
        Lets a finding in vendor code name which SDK it is in, which is what tells the reader where the fix belongs.
    """
    global _SDK_BY_PREFIX_CACHE
    if _SDK_BY_PREFIX_CACHE is None:
        pairs = []
        try:
            from ..sast.extractors.sdk_inventory import SDK_SIGNATURES
            for name, entry in SDK_SIGNATURES.items():
                for prefix in entry[1]:
                    pairs.append((prefix.strip("/") + "/", name))
        except Exception:
            pairs = []
        _SDK_BY_PREFIX_CACHE = tuple(sorted(pairs, key=lambda p: -len(p[0])))
    return _SDK_BY_PREFIX_CACHE


_SOURCE_ROOTS = ("sources/", "resources/", "src/", "java/", "smali/")


def vendor_sdk_for_path(rel_path: str) -> Optional[str]:
    """
    Purpose:
        Identify which SDK a source path belongs to.

    Parameters:
        rel_path: The source path.

    Returns:
        The SDK name, or None.

    Implementation notes:
        Attached to findings so the gates can cap their severity and say which vendor to raise them with, rather than reporting them as the app owner's code.
    """
    if not rel_path:
        return None
    probe = str(rel_path).replace("\\", "/").lstrip("/")
    for root in _SOURCE_ROOTS:
        if probe.startswith(root):
            probe = probe[len(root):]
            break
    if not probe:
        return None
    for prefix, name in _sdk_names_by_prefix():
        if probe.startswith(prefix):
            return name
    for descriptor in _VENDOR_PREFIXES + _FRAMEWORK_PREFIXES:
        package = descriptor.lstrip("L")
        if package in ("android/", "java/", "javax/", "dalvik/"):
            continue
        if probe.startswith(package):
            return package.strip("/").replace("/", ".")
    return None


def _is_app_class(desc: str, package: str) -> bool:
    """
    Purpose:
        Whether a class belongs to the application.

    Parameters:
        desc: The descriptor.
        package: The app's package.

    Returns:
        True for application code.
    """
    if any(desc.startswith(p) for p in _FRAMEWORK_PREFIXES):
        return False
    if is_vendor_class(desc):
        return False
    short = _descriptor_to_short(desc)
    base = short.split("$", 1)[0]
    if base in ("R", "BuildConfig") or base.startswith("R$"):
        return False
    return desc.startswith("L")

def analyze_apk_for_code_graph(apk_path: str, verbose: bool = False):
    """
    Purpose:
        Parse the APK into the analysis object the graph is built from.

    Parameters:
        apk_path: Path to the APK.
        verbose: Traces progress.

    Returns:
        The parsed analysis.

    Side effects:
        Parses the APK, which is slow for a large app.

    Implementation notes:
        Separated from graph construction so the caller can start it in the background while decompilation runs, since the two are independent and doing them in sequence adds minutes to every scan.
    """
    try:
        from loguru import logger
        logger.disable("androguard")
        try:
            from androguard.misc import AnalyzeAPK
            a, _d, dx = AnalyzeAPK(apk_path)
        finally:
            logger.enable("androguard")
        return a, dx
    except Exception as exc:
        verbose_print(f"APK analysis for code graph failed ({exc})", verbose)
        return None


def build_code_graph(apk_path: str, jadx_output_dir=None,
                     verbose: bool = False, preloaded=None,
                     leads=None) -> Optional[CodeGraph]:
    """
    Purpose:
        Build the code graph for an app.

    Parameters:
        apk_path: Path to the APK.
        jadx_output_dir: The decompiled tree, used to resolve source paths.
        verbose: Traces construction.
        preloaded: An already-parsed analysis, reused instead of reparsing the APK.
        leads: The deterministic scanners' findings, used to protect their files from pruning.

    Returns:
        The graph, or None when it could not be built.

    Side effects:
        Parses the APK unless one was preloaded, and reads the decompiled tree.

    Implementation notes:
        The preloaded analysis is what lets the caller start APK parsing in the background while decompilation runs, since the two are independent and doing them in sequence adds minutes to every scan of a large app. Ownership classification runs first, since everything after it operates on the app's own classes only. Manifest roles are applied before scanning, so a class known to be exported is flagged even if its code touches nothing recognisable -- an entry point matters regardless of what it contains. Source paths are resolved against the decompiled tree rather than assumed from the package, because the decompiler renames colliding and invalid class names. Pruning happens last and is deliberately conservative: only nodes with no edges, no role, no signals and no intent actions are dropped, and files named by the leads are protected outright.
    """
    try:
        if preloaded is not None:
            a, dx = preloaded
        else:
            from loguru import logger
            logger.disable("androguard")
            try:
                from androguard.misc import AnalyzeAPK
                a, _d, dx = AnalyzeAPK(apk_path)
            finally:
                logger.enable("androguard")

        package = a.get_package() or ""
        roles, actions = _manifest_roles(a)

        from .ownership import classify_packages, descriptor_to_fqn, is_app_descriptor
        components = []
        for getter in ("get_activities", "get_services", "get_receivers", "get_providers"):
            try:
                components.extend(getattr(a, getter)() or [])
            except Exception:
                pass
        verdict = classify_packages(dx, package, manifest_components=components,
                                    verbose=verbose)
        owner = verdict["owner"]

        nodes: Dict[str, CodeNode] = {}
        native_by_class: Dict[str, bool] = {}
        app_descriptors: List[str] = []
        class_roles: Dict[str, str] = {}

        raw_calls: Dict[str, set] = {}
        vendor_hops: Dict[str, set] = {}
        synthetic_skipped = 0
        for c in dx.get_classes():
            desc = c.name
            if not is_app_descriptor(desc, owner):
                continue
            try:
                if c.get_vm_class().get_access_flags() & _ACC_SYNTHETIC:
                    synthetic_skipped += 1
                    continue
            except Exception:
                pass
            app_descriptors.append(desc)
            short = _descriptor_to_short(desc)
            base = short.split("$", 1)[0]
            is_outer = "$" not in short
            file = _descriptor_to_file(desc)
            key = _outer_descriptor(desc)
            fq = descriptor_to_fqn(desc)
            role = roles.get(fq, "")
            if role:
                class_roles[desc] = role
            node = nodes.get(key)
            if node is None:
                node = CodeNode(cls=base, file=file, descriptor=key)
                nodes[key] = node
            if role and not node.role.startswith("exported"):
                node.role = role
            if actions.get(fq) and not node.intent_actions:
                node.intent_actions = actions[fq]
            if c.extends and (is_outer or not node.extends):
                node.extends = _descriptor_to_short(str(c.extends))

            _scan_class(c, node, package, native_by_class,
                        node_key=key, raw_calls=raw_calls.setdefault(key, set()),
                        vendor_hops=vendor_hops)

        native_libs = _native_libs(jadx_output_dir)
        _resolve_edges(nodes, raw_calls)
        _bridge_vendor_edges(nodes, vendor_hops)

        loaders = [d for d, is_nat in native_by_class.items() if is_nat]
        for d_ in loaders:
            if d_ in nodes and not nodes[d_].exported:
                nodes[d_].role = "native-bridge"
        loader_names = sorted({nodes[d_].cls for d_ in loaders if d_ in nodes})
        graph_names = {d_: n.cls for d_, n in nodes.items()}
        for lib in native_libs:
            lib.loaded_by = loader_names
        protected = set(loaders)
        for lead in leads or []:
            node = _match_node_for_file(nodes, getattr(lead, "file", ""))
            if node is not None:
                protected.add(node.descriptor)
        _prune_isolated(nodes, protected=protected)

        bridges = set(loaders)
        for node in nodes.values():
            called = [graph_names[r] for r in node.refs
                      if r in bridges and r != node.descriptor]
            if called:
                node.signals.setdefault("native-call", [])
                node.signals["native-call"] = sorted(set(node.signals["native-call"]) | set(called))[:4]

        if not nodes:
            verbose_print("Code graph: no app classes found; falling back", verbose)
            return None

        _flag_js_bridges(jadx_output_dir, nodes, verbose)
        source_stats = _verify_source_paths(nodes, jadx_output_dir, verbose)

        from .call_graph import build_call_graph
        method_graph = build_call_graph(dx, app_descriptors, class_roles,
                                        verbose=verbose)

        ownership_stats = dict(verdict["stats"])
        ownership_stats["synthetic_classes_skipped"] = synthetic_skipped
        ownership_stats.update({f"source_{k}": v for k, v in source_stats.items()})
        graph = CodeGraph(package=package, nodes=nodes, native_libs=native_libs,
                          call_graph=method_graph, ownership=ownership_stats)
        verbose_print(
            f"Code graph built: {plural(len(nodes), 'app class', 'app classes')}, "
            f"{plural(len(graph.flagged_files()), 'flagged file')}", verbose)
        return graph
    except Exception as exc:
        verbose_print(f"Code graph build failed ({exc}); falling back to file tree", verbose)
        return None

_RENAMED_PKG_RE = re.compile(r"^p\d{3,}(?=[A-Za-z_])")

_RENAMED_CLASS_RE = re.compile(r"/\* JADX INFO: renamed from: ([\w.$]+)")

_PACKAGE_DECL_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)


def _original_package(declared: str) -> str:
    """
    Purpose:
        Recover a class's original package from a decompiler-renamed declaration.

    Parameters:
        declared: The declared package.

    Returns:
        The original package.

    Implementation notes:
        JADX renames packages that collide or are invalid identifiers and records the original in a comment. Recovering it is what lets a bytecode descriptor match the file the class actually decompiled to.
    """
    return ".".join(_RENAMED_PKG_RE.sub("", seg) for seg in declared.split("."))


def _build_source_index(jadx_output_dir) -> Dict[str, str]:
    """
    Purpose:
        Index the decompiled tree by original class name, so graph nodes can find their source.

    Parameters:
        jadx_output_dir: The decompiled tree.

    Returns:
        A mapping from class name to relative source path.

    Complexity:
        One pass over the decompiled Java files, reading the head of each.

    Implementation notes:
        Only the head of each file is read, since the package declaration and the rename comment are at the top and reading whole files would be prohibitive on a large app. The rename comment is preferred over the declared package, because for a renamed class the declaration shows the new name and only the comment shows what the bytecode calls it. The first path wins for a given name, so a duplicate does not overwrite an already-indexed file.
    """
    index: Dict[str, str] = {}
    if not jadx_output_dir:
        return index
    root = Path(jadx_output_dir)
    sources = root / "sources"
    base = sources if sources.is_dir() else root
    try:
        for path in base.rglob("*.java"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    head = handle.read(2048)
            except OSError:
                continue
            decl = _PACKAGE_DECL_RE.search(head)
            declared = decl.group(1) if decl else ""
            renamed = _RENAMED_CLASS_RE.search(head)
            if renamed and "." in renamed.group(1):
                original = _original_package(renamed.group(1))
            else:
                pkg = _original_package(declared)
                original = f"{pkg}.{path.stem}" if pkg else path.stem
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                continue
            index.setdefault(original, rel)
    except OSError:
        return index
    return index


def _verify_source_paths(nodes: Dict[str, "CodeNode"], jadx_output_dir,
                         verbose: bool) -> Dict[str, int]:
    """
    Purpose:
        Attach real source paths to the nodes, or mark them as having none.

    Parameters:
        nodes: The graph's nodes, mutated in place.
        jadx_output_dir: The decompiled tree.
        verbose: Traces the outcome.

    Returns:
        Counts of how many nodes resolved and how many did not.

    Side effects:
        Updates each node's source path and availability.

    Implementation notes:
        The derived path is checked against the index rather than trusted, because decompilation fails for some classes and renames others. Marking a node as having no source keeps it in the graph for reachability while stopping the agent being sent to open a file that is not there. The counts are returned because they become the report's scope notice: a large unresolved fraction explains why several findings look under-evidenced.
    """
    stats = {"checked": len(nodes), "missing": 0, "repaired": 0}
    if not jadx_output_dir:
        return stats
    root = Path(jadx_output_dir)
    if not root.is_dir():
        return stats

    unresolved = [n for n in nodes.values() if not (root / n.file).is_file()]
    if not unresolved:
        return stats

    index = _build_source_index(jadx_output_dir)
    for node in unresolved:
        fqn = node.file.split("/", 1)[-1][:-len(".java")].replace("/", ".") \
            if node.file.endswith(".java") else ""
        real = index.get(fqn)
        if real and (root / real).is_file():
            node.file = real
            stats["repaired"] += 1
        else:
            node.source_available = False
            stats["missing"] += 1

    if stats["repaired"]:
        verbose_print(
            f"Code graph: resolved {plural(stats['repaired'], 'renamed source path')} "
            "through the decompiler's own rename records (JADX renames classes "
            "and packages it cannot write verbatim on this filesystem)", verbose)
    if stats["missing"]:
        verbose_print(
            f"Code graph: {plural(stats['missing'], 'class', 'classes')} of "
            f"{stats['checked']} were never emitted by the decompiler and are "
            "marked unreadable (their edges are kept, but the agent is told not "
            "to read them)", verbose)
    return stats


def _flag_js_bridges(jadx_output_dir, nodes: Dict[str, "CodeNode"], verbose: bool) -> None:
    """
    Purpose:
        Mark classes that expose methods to JavaScript in a WebView.

    Parameters:
        jadx_output_dir: The decompiled tree.
        nodes: The graph's nodes.
        verbose: Traces progress.

    Side effects:
        Updates node roles.

    Implementation notes:
        Detected from the decompiled source rather than the bytecode, because the annotation is what marks a bridge method and it survives into the source more reliably than it can be recovered from the class metadata. Files are pre-filtered by a byte scan for the annotation name before being decoded, and the scan is capped, so this stays cheap on a large tree.

    Security considerations:
        A JavaScript bridge is the highest-value target in an Android app -- it gives page content a path into native code with the app's permissions -- so flagging it makes those classes seeds for the agent rather than incidental nodes.
    """
    if not jadx_output_dir:
        return
    root = Path(jadx_output_dir)
    if not root.is_dir():
        return
    by_file = {n.file: n for n in nodes.values()}
    scanned = flagged = 0
    try:
        for jf in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_BRIDGE_SCAN_FILES:
                break
            try:
                data = jf.read_bytes()
            except OSError:
                continue
            if b"JavascriptInterface" not in data:
                continue
            text = data.decode("utf-8", errors="ignore")
            if not any(a in text for a in _JS_BRIDGE_ANNOTATIONS):
                continue
            try:
                rel = str(jf.relative_to(root))
            except ValueError:
                continue
            node = by_file.get(rel)
            if node is None:
                continue
            methods = []
            for m in _JS_BRIDGE_METHOD_RE.finditer(text):
                name = m.group(1)
                if name and name not in methods:
                    methods.append(name)
                if len(methods) >= 6:
                    break
            node.signals.setdefault("js_bridge", [])
            node.signals["js_bridge"] = sorted(set(node.signals["js_bridge"]) | set(methods))[:6]
            flagged += 1
    except Exception as exc:
        verbose_print(f"JS-bridge annotation scan failed ({exc}); skipping", verbose)
        return
    if flagged:
        verbose_print(
            f"JS-bridge scan: flagged {plural(flagged, 'class', 'classes')} exposing "
            f"@JavascriptInterface methods (scanned {plural(scanned, 'source file')})", verbose)

def _manifest_roles(a) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """
    Purpose:
        Read component roles and intent actions from the manifest.

    Parameters:
        a: The parsed APK.

    Returns:
        The role per class and the intent actions per class.

    Implementation notes:
        The manifest is what establishes reachability from outside the app, so these roles are what the partitioner seeds regions from and what the agent reasons about first.
    """
    roles: Dict[str, str] = {}
    actions: Dict[str, List[str]] = {}
    android = "{http://schemas.android.com/apk/res/android}"
    kind = {"activity": "activity", "activity-alias": "activity",
            "provider": "provider", "service": "service", "receiver": "receiver"}
    try:
        mx = a.get_android_manifest_xml()
    except Exception:
        return roles, actions
    for tag, base_role in kind.items():
        for el in mx.iter(tag):
            name = el.get(android + "name")
            if not name:
                continue
            exp = el.get(android + "exported")
            has_if = el.find("intent-filter") is not None
            is_exported = (exp == "true") or (exp is None and has_if)
            roles[name] = f"exported-{base_role}" if is_exported else base_role
            acts = [ae.get(android + "name", "").split(".")[-1]
                    for ae in el.iter("action")]
            if acts:
                actions[name] = [x for x in acts if x and x != "MAIN"]
    return roles, actions

def _scan_class(c, node: CodeNode, package: str, native_by_class: Dict[str, bool],
                node_key: str = "", raw_calls: Optional[set] = None,
                vendor_hops: Optional[Dict[str, set]] = None) -> None:
    """
    Purpose:
        Record what one class touches: its methods, the sink families it reaches, its notable strings and its references.

    Parameters:
        c: The class analysis.
        node: The node to populate.
        package: The app's package.
        native_by_class: Which classes load native libraries.
        node_key: This node's key, used when recording its outgoing edges.
        raw_calls: Collects the call targets found, resolved into edges later.
        vendor_hops: Collects application classes linked only through vendor code, reconnected later.

    Side effects:
        Populates the node and the two collecting maps.

    Implementation notes:
        Sinks are recorded by family with a few examples rather than exhaustively, since the node summary is prompt context and the agent needs to know what kind of thing a class touches, not every call. Strings are filtered to the credential-shaped ones, because an unfiltered list of every literal in a class would be enormous and uninformative. Calls are collected raw rather than resolved here, because a target's node may not exist yet when this runs. Vendor hops are recorded separately so that application classes reaching each other only through a library -- a callback registered with an SDK being the common case -- can be reconnected once the vendor classes are excluded.
    """
    if raw_calls is None:
        raw_calls = set()
    app_prefix = "L" + package.replace(".", "/") + "/" if package else None
    for m in c.get_methods():
        mname = m.name
        if mname not in ("<init>", "<clinit>") and mname not in node.methods:
            if len(node.methods) < _MAX_METHODS_SHOWN:
                node.methods.append(mname)
        for (owner, meth, _off) in m.get_xref_to():
            call = f"{owner.name}->{meth.name}"
            for fam, keys in _SINK_FAMILIES.items():
                if any(k in call for k in keys):
                    node.signals.setdefault(fam, [])
                    if meth.name not in node.signals[fam] and len(node.signals[fam]) < 6:
                        node.signals[fam].append(meth.name)
                    if fam == "native":
                        native_by_class[node_key] = True
            owner_base = _outer_descriptor(owner.name)
            if owner_base != node_key and owner_base not in raw_calls:
                raw_calls.add(owner_base)
            if vendor_hops is not None and is_vendor_class(owner_base):
                vendor_hops.setdefault(owner_base, set()).add(node_key)
            if owner_base != node_key and owner_base not in node.refs \
                    and len(node.refs) < _MAX_REFS_SHOWN \
                    and not is_vendor_class(owner_base) \
                    and not owner_base.startswith(_FRAMEWORK_PREFIXES):
                node.refs.append(owner_base)
        try:
            em = m.get_method()
            for ins in em.get_instructions():
                if ins.get_name().startswith("const-string"):
                    lit = _const_string_value(ins.get_output())
                    if lit and _SECRET_RE.search(lit) and lit not in node.strings \
                            and len(node.strings) < _MAX_STRINGS_PER_NODE:
                        node.strings.append(lit[:60])
        except Exception:
            continue

def _resolve_edges(nodes: Dict[str, "CodeNode"], raw_calls: Dict[str, set]) -> None:
    """
    Purpose:
        Turn raw call references into edges between graph nodes.

    Parameters:
        nodes: The graph's nodes.
        raw_calls: The recorded call targets.

    Side effects:
        Populates each node's call list.

    Implementation notes:
        Targets outside the graph are dropped, so an edge into the platform or a bundled library terminates rather than expanding the graph into code the reader cannot change.
    """
    for key, callees in raw_calls.items():
        node = nodes.get(key)
        if node is None:
            continue
        for target in sorted(callees):
            if target != key and target in nodes and target not in node.calls:
                node.calls.append(target)
                if len(node.calls) >= _MAX_CALLS_PER_NODE:
                    break


def _bridge_vendor_edges(nodes: Dict[str, "CodeNode"], vendor_hops: Dict[str, set]) -> None:
    """
    Purpose:
        Reconnect application classes that only reach each other through vendor code.

    Parameters:
        nodes: The graph's nodes.
        vendor_hops: Application classes linked via a vendor class.

    Side effects:
        Adds edges between the application classes.

    Implementation notes:
        Vendor classes are excluded from the graph, which breaks paths that pass through them -- a callback registered with a library and invoked back into the app being the common case. Bridging those preserves the reachability relationship without pulling the library in. Without this the agent would conclude that a callback handler is unreachable, which is precisely wrong: a handler invoked by a library is frequently reachable from outside the app.
    """
    for callers in vendor_hops.values():
        if not 2 <= len(callers) <= _MAX_BRIDGE_FANOUT:
            continue
        resolved = sorted({_outer_descriptor(d) for d in callers})
        resolved = [r for r in resolved if r in nodes]
        for source in resolved:
            node = nodes[source]
            for target in resolved:
                if target != source and target not in node.calls \
                        and len(node.calls) < _MAX_CALLS_PER_NODE:
                    node.calls.append(target)


def _prune_isolated(nodes: Dict[str, "CodeNode"],
                    protected: Optional[set] = None) -> None:
    """
    Purpose:
        Remove nodes that contribute nothing to the analysis.

    Parameters:
        nodes: The graph's nodes.
        protected: Nodes never to remove.

    Side effects:
        Deletes nodes.

    Implementation notes:
        Deliberately conservative: a node is removed only when it has no edges, no manifest role, no intent actions and a plain class role. Anything with a signal, a string or a role stays. Pruning matters because a decompiled app contains many small data classes that would otherwise become regions of their own and consume budget.

    Security considerations:
        A pruned node is never examined, so the conditions are strict. Nothing flagged for any reason is eligible.
    """
    degree: Dict[str, int] = {key: 0 for key in nodes}
    for key, node in nodes.items():
        for target in node.calls:
            if target in degree:
                degree[key] += 1
                degree[target] += 1
    protected = protected or set()
    for key in [k for k, n in nodes.items()
                if degree.get(k, 0) == 0
                and k not in protected
                and n.role in ("", "class")
                and not n.intent_actions]:
        del nodes[key]


def _const_string_value(output: str) -> str:
    """
    Purpose:
        Extract the literal from a constant-loading instruction.

    Parameters:
        output: The instruction text.

    Returns:
        The string, or empty when none was found.
    """
    m = re.search(r'"(.*)"', output)
    return m.group(1) if m else ""

def _native_libs(jadx_output_dir) -> List[NativeLib]:
    """
    Purpose:
        List the native libraries in the decompiled output.

    Parameters:
        jadx_output_dir: The decompiled tree.

    Returns:
        The libraries.

    Implementation notes:
        Recorded so the fan-out can attach them to regions and the agent can inspect them, since native code is invisible to everything else in the graph.
    """
    if not jadx_output_dir:
        return []
    root = Path(jadx_output_dir)
    seen: Dict[str, Path] = {}
    try:
        for so in sorted(root.rglob("*.so")):
            if so.name not in seen:
                seen[so.name] = so
    except Exception:
        return []
    libs = []
    for so in seen.values():
        try:
            rel = str(so.relative_to(root))
        except ValueError:
            rel = so.name
        libs.append(NativeLib(path=rel))
    return libs
