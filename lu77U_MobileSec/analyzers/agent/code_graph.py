"""App code graph — a security-relevant map of the app's own code for the agent."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...utils.verbose import verbose_print

_FRAMEWORK_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Lcom/google/", "Lorg/jetbrains/", "Lorg/intellij/", "Ldalvik/",
    "Lorg/xmlpull/", "Lorg/apache/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/",
    "Lorg/hamcrest/", "Ljunit/", "Lorg/junit/",
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

_SECRET_RE = re.compile(
    r"(secret|passw|api[_-]?key|token|credential|private[_-]?key|"
    r"-----BEGIN|https?://|[A-Za-z0-9+/]{24,}={0,2})",
    re.IGNORECASE,
)

_MAX_STRINGS_PER_NODE = 6
_MAX_METHODS_SHOWN = 12
_DEFAULT_MAX_ENTRIES = 120

@dataclass
class CodeNode:
    cls: str                       # short class name (no package)
    file: str                      # agent-facing path, e.g. sources/…/Foo.java
    role: str = "class"            # exported-provider / exported-activity / activity / …
    extends: str = ""
    methods: List[str] = field(default_factory=list)
    signals: Dict[str, List[str]] = field(default_factory=dict)   # family -> details
    strings: List[str] = field(default_factory=list)              # hardcoded-ish
    refs: List[str] = field(default_factory=list)                 # app classes referenced
    intent_actions: List[str] = field(default_factory=list)

    @property
    def exported(self) -> bool:
        return self.role.startswith("exported")

    @property
    def flagged(self) -> bool:
        """Worth the agent reading before it finishes."""
        return self.exported or bool(self.signals) or bool(self.strings) \
            or self.role == "native-bridge"

@dataclass
class NativeLib:
    path: str
    loaded_by: List[str] = field(default_factory=list)

@dataclass
class CodeGraph:
    package: str
    nodes: Dict[str, CodeNode]
    native_libs: List[NativeLib] = field(default_factory=list)

    def flagged_files(self) -> List[str]:
        """Files the agent should examine before reporting (+ native libs)."""
        files = [n.file for n in self.nodes.values() if n.flagged]
        files += [lib.path for lib in self.native_libs]
        return files

    def node_for_file(self, path: str) -> Optional[CodeNode]:
        """The node whose source file matches ``path`` (tolerant of a leading
        ``sources/`` and of a cited line suffix). Lets Phase 2 annotate each
        finding with its class's role/sinks for more targeted runtime proofs."""
        if not path:
            return None
        norm = str(path).strip().lstrip("./").replace("\\", "/")
        norm = norm.split(":", 1)[0]  # drop any "file:line" suffix
        for n in self.nodes.values():
            if n.file == norm or n.file.endswith("/" + norm) or norm.endswith("/" + n.file):
                return n
        base = norm.rsplit("/", 1)[-1]
        for n in self.nodes.values():
            if n.file.rsplit("/", 1)[-1] == base:
                return n
        return None

    def structure_summary(self) -> str:
        """Compact structure view for the dynamic-verification phase: just the
        entry points (externally reachable → adb-invokable) and native libs
        (Frida targets). Much smaller than the full static map."""
        lines = []
        entries = sorted((n for n in self.nodes.values() if n.exported),
                         key=lambda n: n.cls.lower())
        if entries:
            lines.append("Entry points (externally reachable):")
            for n in entries:
                sig = ("; ".join(f"{f}({', '.join(sorted(set(v))[:3])})"
                                 for f, v in n.signals.items())) or "—"
                lines.append(f"  [{n.role}] {n.cls} ({n.file}) — {sig}")
        if self.native_libs:
            lines.append("Native libraries (Frida/objdump targets):")
            for lib in self.native_libs:
                by = (" — loaded by " + ", ".join(lib.loaded_by)) if lib.loaded_by else ""
                lines.append(f"  {lib.path}{by}")
        return "\n".join(lines)

    def render(self, max_entries: int = _DEFAULT_MAX_ENTRIES) -> str:
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
            f"## App code map ({self.package}) — {len(self.nodes)} app class(es), "
            f"{len(self.native_libs)} native lib(s)")
        out.append(
            "Each entry: [role] Class (file) — the security-relevant APIs it "
            "calls and any hardcoded strings. Start from flagged entries, "
            "read those files to confirm, and inspect native libs.")

        if entry_pts:
            out.append("\n### Entry points (externally reachable — attacker-facing)")
            out += [self._render_node(n) for n in entry_pts]
        if signalled:
            out.append("\n### App classes with security signals")
            out += [self._render_node(n) for n in signalled]
        if plain:
            out.append("\n### App classes without detected signals "
                       "(read if the above don't explain the app)")
            out.append("  " + ", ".join(n.cls for n in plain))
        if self.native_libs:
            out.append("\n### Native libraries (use inspect_native)")
            for lib in self.native_libs:
                by = (" — loaded by " + ", ".join(lib.loaded_by)) if lib.loaded_by else ""
                out.append(f"  {lib.path}{by}")
        if overflow:
            out.append(f"\n... (+{len(overflow)} more app class(es) not shown; "
                       f"use list_files/search_code)")
        return "\n".join(out)

    def _render_node(self, n: CodeNode) -> str:
        head = f"[{n.role}"
        if n.intent_actions:
            head += ": " + ",".join(n.intent_actions[:2])
        head += f"] {n.cls} ({n.file})"
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
            bits.append("refs: " + ", ".join(n.refs[:5]))
        detail = ("\n    " + " | ".join(bits)) if bits else ""
        return head + detail

    def to_json(self) -> dict:
        return {
            "package": self.package,
            "nodes": [
                {
                    "class": n.cls, "file": n.file, "role": n.role,
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
    """``Ljakhar/aseem/diva/NotesProvider$DBHelper;`` -> ``NotesProvider$DBHelper``."""
    inner = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    return inner.split("/")[-1]

def _descriptor_to_file(desc: str) -> str:
    """Class descriptor -> the JADX source path the agent's ``read_file`` uses.
    Nested/anonymous classes (``Foo$Bar``, ``Foo$1``) collapse to ``Foo.java``."""
    inner = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    inner = inner.split("$", 1)[0]
    return f"sources/{inner}.java"

def _is_app_class(desc: str, package: str) -> bool:
    if any(desc.startswith(p) for p in _FRAMEWORK_PREFIXES):
        return False
    short = _descriptor_to_short(desc)
    base = short.split("$", 1)[0]
    if base in ("R", "BuildConfig") or base.startswith("R$"):
        return False
    return desc.startswith("L")

def build_code_graph(apk_path: str, jadx_output_dir=None,
                     verbose: bool = False) -> Optional[CodeGraph]:
    """Build the app code graph from ``apk_path`` via androguard, or ``None``.

    ``jadx_output_dir`` (optional) is used only to validate/repair computed
    source paths against what JADX actually emitted. Any failure returns
    ``None`` so the caller falls back to the flat file tree.
    """
    try:
        from loguru import logger
        logger.disable("androguard")
        try:
            from androguard.misc import AnalyzeAPK
            a, _d, dx = AnalyzeAPK(apk_path)
        finally:
            logger.enable("androguard")

        package = a.get_package() or ""
        roles, actions = _manifest_roles(a)

        nodes: Dict[str, CodeNode] = {}
        native_by_class: Dict[str, bool] = {}

        for c in dx.get_classes():
            desc = c.name
            if not _is_app_class(desc, package):
                continue
            short = _descriptor_to_short(desc)
            base = short.split("$", 1)[0]
            is_outer = "$" not in short
            file = _descriptor_to_file(desc)
            node = nodes.get(base)
            if node is None:
                node = CodeNode(cls=base, file=file)
                fq = f"{package}.{base}" if package else base
                node.role = roles.get(fq, node.role)
                node.intent_actions = actions.get(fq, [])
                nodes[base] = node
            # Prefer the OUTER class's superclass for display; only fall back to
            # a nested class's ``extends`` if we never see the outer class.
            if c.extends and (is_outer or not node.extends):
                node.extends = _descriptor_to_short(str(c.extends))

            _scan_class(c, node, package, native_by_class)

        # native-bridge role + native lib linkage
        native_libs = _native_libs(jadx_output_dir)
        loaders = [b for b, is_nat in native_by_class.items() if is_nat]
        for b in loaders:
            if b in nodes and not nodes[b].exported:
                nodes[b].role = "native-bridge"
        for lib in native_libs:
            lib.loaded_by = loaders
        bridges = set(loaders)
        for node in nodes.values():
            called = [r for r in node.refs if r in bridges and r != node.cls]
            if called:
                node.signals.setdefault("native-call", [])
                node.signals["native-call"] = sorted(set(node.signals["native-call"]) | set(called))[:4]

        if not nodes:
            verbose_print("Code graph: no app classes found; falling back", verbose)
            return None

        graph = CodeGraph(package=package, nodes=nodes, native_libs=native_libs)
        verbose_print(
            f"Code graph built: {len(nodes)} app class(es), "
            f"{len(graph.flagged_files())} flagged file(s)", verbose)
        return graph
    except Exception as exc:  # pragma: no cover - best-effort enhancement
        verbose_print(f"Code graph build failed ({exc}); falling back to file tree", verbose)
        return None

def _manifest_roles(a) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Map fully-qualified component name -> role + intent-filter actions.

    A component is 'exported' when ``android:exported="true"`` or (unset and it
    declares an intent-filter) — the platform default.
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

def _scan_class(c, node: CodeNode, package: str, native_by_class: Dict[str, bool]) -> None:
    """Annotate ``node`` with methods, sink signals, hardcoded strings, refs."""
    app_prefix = "L" + package.replace(".", "/") + "/" if package else None
    for m in c.get_methods():
        mname = m.name
        if mname not in ("<init>", "<clinit>") and mname not in node.methods:
            if len(node.methods) < _MAX_METHODS_SHOWN:
                node.methods.append(mname)
        # outgoing calls -> sink families + app-class refs + native loader
        for (owner, meth, _off) in m.get_xref_to():
            call = f"{owner.name}->{meth.name}"
            for fam, keys in _SINK_FAMILIES.items():
                if any(k in call for k in keys):
                    node.signals.setdefault(fam, [])
                    if meth.name not in node.signals[fam] and len(node.signals[fam]) < 6:
                        node.signals[fam].append(meth.name)
                    if fam == "native":
                        native_by_class[node.cls] = True
            if app_prefix and owner.name.startswith(app_prefix):
                ref = _descriptor_to_short(owner.name).split("$", 1)[0]
                if ref != node.cls and ref not in node.refs and len(node.refs) < 8:
                    node.refs.append(ref)
        # hardcoded-secret string constants
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

def _const_string_value(output: str) -> str:
    """androguard const-string output looks like ``v2, "the literal"``."""
    m = re.search(r'"(.*)"', output)
    return m.group(1) if m else ""

def _native_libs(jadx_output_dir) -> List[NativeLib]:
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