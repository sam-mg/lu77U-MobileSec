#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.rn_metro

Purpose:
    Turn a React Native bundle into one readable file per Metro module, sorted into the app's own region and the React Native framework, whatever form the bundle shipped in.

Responsibilities:
    Read hermes-decomp's per-module extraction, split a plain-JavaScript Metro bundle into its modules and lay the minified code out on readable lines, decide which modules belong to the app, and write the module tree with path containment enforced.

Dependencies:
    re, pathlib.

Implementation notes:
    Metro wraps every module the same way whatever the engine -- a factory, a numeric id and a dependency list -- and module 0 is the entry, index.js. Its dependencies are the framework (react-native, whose closure is most of the bundle) and the app's root component. That shape is what lets the app be separated from the framework without source maps or file paths, which release bundles do not carry: the app region is everything the entry's non-framework dependencies reach, minus what react-native reaches. Third-party libraries the app imports (storage, WebView, navigation) land in the app region too, which is intended -- they are reached only because the app uses them. A plain bundle is minified onto a few enormous lines; it is reformatted onto short lines so the agent can page through it and cite a line, and the formatter only ever inserts whitespace, so it can mis-break a line but never change a token.

Security considerations:
    The bundle is attacker-controlled. Module names come from it and are reduced to safe characters before becoming file names, every write is checked to stay inside the output directory, and nothing recovered is executed.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..utils.verbose import plural, verbose_print

APP_DIR = "app_modules"
FRAMEWORK_DIR = "framework_modules"
MAX_MODULES = 50000

_EXTRACTED_NAME_RE = re.compile(r"^(\d+)_(.*)\.js$")
_HEADER_ID_RE = re.compile(r"^//\s*Module ID:\s*(\d+)", re.MULTILINE)
_HEADER_NAME_RE = re.compile(r"^//\s*Name:\s*(.+)$", re.MULTILINE)
_HEADER_DEPS_RE = re.compile(r"^//\s*Dependencies:\s*\[([\d,\s]*)\]", re.MULTILINE)
_DEFINE_RE = re.compile(r"__d\(\s*function")
_TAIL_RE = re.compile(r"\}\s*,\s*(\d+)\s*,\s*\[([\d,\s]*)\]\s*(?:,\s*\"([^\"\n]{0,200})\")?\s*\)")
_SAFE_RE = re.compile(r"[^A-Za-z0-9_.$-]")
_FACTORY_PARAMS_RE = re.compile(r"^function\s*\(([^)]*)\)")
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new",
                   "delete", "void", "throw", "instanceof", "yield", "await"}


@dataclass
class MetroModule:
    """
    Purpose:
        One Metro module.

    Attributes:
        id: The module's numeric id.
        name: The name hermes-decomp recovered, or the verbose name a dev bundle carries; empty when none survived.
        deps: The ids of the modules it requires, in order.
        code: The module's code, as it will be written.
    """
    id: int
    name: str = ""
    deps: List[int] = field(default_factory=list)
    code: str = ""


@dataclass
class ModuleTree:
    """
    Purpose:
        The module tree written for one bundle.

    Attributes:
        entry: The entry module's id.
        app_ids: Ids of the modules in the app region, the entry included.
        framework_ids: Ids of the framework modules.
        files: Module id to its path relative to the analysis root.
        names: Module id to its recovered name.
        deps: Module id to its dependency ids.
    """
    entry: int
    app_ids: Set[int] = field(default_factory=set)
    framework_ids: Set[int] = field(default_factory=set)
    files: Dict[int, str] = field(default_factory=dict)
    names: Dict[int, str] = field(default_factory=dict)
    deps: Dict[int, List[int]] = field(default_factory=dict)


def _parse_ids(text: str) -> List[int]:
    """
    Purpose:
        Parse a comma-separated id list.

    Parameters:
        text: The list's contents, without brackets.

    Returns:
        The ids.
    """
    return [int(part) for part in text.replace(" ", "").split(",") if part.isdigit()]


def read_extracted_modules(extract_dir) -> List[MetroModule]:
    """
    Purpose:
        Read the per-module files hermes-decomp's extract command writes.

    Parameters:
        extract_dir: The extraction directory.

    Returns:
        The modules, by id.

    Implementation notes:
        Each file starts with a comment header giving the module id, the recovered name and the dependency list; the header is authoritative, and the file name is only a fallback for the id when the header is missing.
    """
    modules: Dict[int, MetroModule] = {}
    for path in sorted(Path(extract_dir).glob("*.js"))[:MAX_MODULES]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        head = text[:2000]
        id_match = _HEADER_ID_RE.search(head)
        name_match = _HEADER_NAME_RE.search(head)
        deps_match = _HEADER_DEPS_RE.search(head)
        file_match = _EXTRACTED_NAME_RE.match(path.name)
        if id_match:
            module_id = int(id_match.group(1))
        elif file_match:
            module_id = int(file_match.group(1))
        else:
            continue
        name = name_match.group(1).strip() if name_match else (file_match.group(2) if file_match else "")
        if name in ("?", "None"):
            name = ""
        modules[module_id] = MetroModule(id=module_id, name=name,
                                         deps=_parse_ids(deps_match.group(1)) if deps_match else [],
                                         code=text)
    return [modules[k] for k in sorted(modules)]


def split_plain_bundle(text: str) -> List[MetroModule]:
    """
    Purpose:
        Split a plain-JavaScript Metro bundle into its modules.

    Parameters:
        text: The bundle.

    Returns:
        The modules, with formatted code and a header like hermes-decomp's.

    Complexity:
        O(n) in the bundle size, plus the formatter's linear pass per module.

    Implementation notes:
        Every module definition starts with "__d(function" and ends with "},<id>,[<deps>]" optionally followed by a verbose name, so a module spans from one definition to the next and its id and dependencies are read from the last such tail inside that span -- the last, because the final span also carries the trailing __r() calls that start the app. The Metro runtime prelude defines __d but never calls it with a function literal, so it is not mistaken for a module.
    """
    starts = [m.start() for m in _DEFINE_RE.finditer(text)]
    modules: List[MetroModule] = []
    for index, start in enumerate(starts[:MAX_MODULES]):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        segment = text[start:end]
        tail = None
        for tail in _TAIL_RE.finditer(segment):
            pass
        if tail is None:
            continue
        body = segment[len("__d("):tail.start() + 1]
        module = MetroModule(id=int(tail.group(1)),
                             name=(tail.group(3) or "").strip() or _export_name(body),
                             deps=_parse_ids(tail.group(2)))
        header = (f"// Module ID: {module.id}\n// Name: {module.name or '?'}\n"
                  f"// Dependencies: {module.deps}\n\n")
        module.code = header + format_js(body)
        modules.append(module)
    return modules


def _export_name(factory: str) -> str:
    """
    Purpose:
        Name a plain-bundle module after its first named export, the way hermes-decomp names Hermes modules.

    Parameters:
        factory: The module's factory function source.

    Returns:
        The export name, or an empty string when the module only has a default export or none.

    Implementation notes:
        A Metro factory's sixth parameter is the module's exports object, whatever the minifier renamed it to, so assignments to it name what the module provides; "default" and "__esModule" say nothing about the module and are skipped.
    """
    params = _FACTORY_PARAMS_RE.match(factory)
    if not params:
        return ""
    names = [p.strip() for p in params.group(1).split(",")]
    if len(names) < 6 or not names[5]:
        return ""
    for match in re.finditer(r"\b" + re.escape(names[5]) + r"\.([A-Za-z_$][\w$]*)\s*=(?!=)", factory):
        if match.group(1) not in ("default", "__esModule"):
            return match.group(1)
    return ""


def format_js(code: str, indent: str = "  ") -> str:
    """
    Purpose:
        Lay minified JavaScript out on short, indented lines.

    Parameters:
        code: The minified code.
        indent: One level of indentation.

    Returns:
        The reformatted code.

    Complexity:
        O(n) in the code size.

    Implementation notes:
        A line break goes after "{" and ";" and around "}", but only outside strings, template literals, regular expressions and comments, which are tracked with a small state machine. A "/" starts a regular expression when the last significant character or keyword could not end an expression -- the usual heuristic, which can misjudge a few edge cases; when it does, only the line breaks inside that stretch are affected, because nothing but whitespace is ever inserted. Semicolons inside parentheses are left alone so a for(;;) header stays on one line.
    """
    out: List[str] = []
    depth = 0
    paren = 0
    i = 0
    n = len(code)
    last_sig = ""
    last_word = ""
    template_stack: List[int] = []

    def newline():
        """
        Purpose:
            End the current line and indent the next one.
        """
        while out and out[-1] in (" ", "\t"):
            out.pop()
        if out and out[-1] != "\n" and not out[-1].endswith("\n"):
            out.append("\n")
        out.append(indent * max(depth, 0))

    while i < n:
        ch = code[i]
        if ch in "'\"":
            j = i + 1
            while j < n and code[j] != ch and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            out.append(code[i:j + 1])
            i = j + 1
            last_sig, last_word = ch, ""
            continue
        if ch == "`" or (ch == "}" and template_stack and template_stack[-1] == depth):
            if ch == "}":
                template_stack.pop()
            j = i + 1
            while j < n:
                if code[j] == "\\":
                    j += 2
                    continue
                if code[j] == "`":
                    break
                if code[j] == "$" and j + 1 < n and code[j + 1] == "{":
                    break
                j += 1
            if j < n and code[j] == "$":
                out.append(code[i:j + 2])
                template_stack.append(depth)
                i = j + 2
                last_sig, last_word = "{", ""
            else:
                out.append(code[i:j + 1])
                i = j + 1
                last_sig, last_word = "`", ""
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "/":
            j = code.find("\n", i)
            j = n if j < 0 else j
            out.append(code[i:j])
            i = j
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "*":
            j = code.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(code[i:j])
            i = j
            continue
        if ch == "/" and (last_sig == "" or last_sig in _REGEX_PRECEDERS or last_word in _REGEX_KEYWORDS):
            j = i + 1
            in_class = False
            while j < n and code[j] != "\n":
                c = code[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    break
                j += 1
            j += 1
            while j < n and (code[j].isalnum() or code[j] == "_"):
                j += 1
            out.append(code[i:j])
            i = j
            last_sig, last_word = "/", ""
            continue
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (code[j].isalnum() or code[j] in "_$"):
                j += 1
            word = code[i:j]
            out.append(word)
            i = j
            last_sig, last_word = word[-1], word
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        if ch == "{":
            out.append("{")
            depth += 1
            newline()
        elif ch == "}":
            depth = max(0, depth - 1)
            newline()
            out.append("}")
            nxt = code[i + 1] if i + 1 < n else ""
            if nxt not in (";", ",", ")", ".", "]") and nxt:
                newline()
        elif ch == ";" and paren == 0:
            out.append(";")
            newline()
        elif ch == "\n":
            newline()
        else:
            out.append(ch)
        if not ch.isspace():
            last_sig, last_word = ch, ""
        i += 1
    text = "".join(out)
    return "\n".join(line.rstrip() for line in text.split("\n") if line.strip()) + "\n"


def _closure(starts: Iterable[int], deps: Dict[int, List[int]]) -> Set[int]:
    """
    Purpose:
        Collect every module reachable from some starting modules.

    Parameters:
        starts: The starting module ids.
        deps: Each module's dependencies.

    Returns:
        The reachable ids, the starts included.
    """
    seen: Set[int] = set()
    stack = [s for s in starts if s in deps]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(d for d in deps.get(current, ()) if d not in seen and d in deps)
    return seen


LIBRARY_MARKERS = (
    '"RNCWebView', '"RNCAsyncStorage"', '"RNAsyncStorage"', '"AsyncStorageError"', '"[AsyncStorage]',
    '"[@RNC/AsyncStorage]', "CryptoJS", '"RNCNetInfo', '"RNGestureHandlerModule"', '"ReanimatedModule"',
    '"RNSScreen', '"RNCSafeArea', '"RNKeychainManager"', '"RNEncryptedStorage"', '"@@redux/INIT',
)


def library_modules(modules: List[MetroModule], candidates: Set[int]) -> Set[int]:
    """
    Purpose:
        Pick out the third-party library modules among the app-region candidates.

    Parameters:
        modules: All modules.
        candidates: The ids still counted as app code.

    Returns:
        The candidate ids whose code carries a library's own marker string.

    Implementation notes:
        A Hermes bundle keeps no file paths, so every npm package the app imports sits in the app region beside the app's own screens: a benchmark app had react-native-webview's origin matcher and all of crypto-js there, and the analysis reported their internals as the app's flaws. Each marker is a string only that library's own code carries - its native module or component name, its error-message prefix, the global its UMD wrapper registers - so an app module that merely uses the library (which reaches it through a module id) does not match.
    """
    return {m.id for m in modules if m.id in candidates and any(marker in m.code for marker in LIBRARY_MARKERS)}


def classify_modules(modules: List[MetroModule]) -> Tuple[int, Set[int], Set[int]]:
    """
    Purpose:
        Split a bundle's modules into the app region and the framework.

    Parameters:
        modules: All modules.

    Returns:
        The entry id, the app-region ids (entry included) and the framework ids.

    Implementation notes:
        The entry is module 0, Metro's main module, or the lowest id when there is no 0. The framework root is the entry dependency that another entry dependency also reaches -- the app's root component imports react-native, never the reverse -- taking the one with the largest closure; that closure is the framework. Picking simply the largest closure would choose the app's root, whose closure contains react-native's. When no dependency is shared that way, the module with the most direct dependencies is taken, which is react-native's index in every Metro bundle. Every other dependency of the entry is an app root, and the app region is what those roots reach outside the framework. Third-party libraries the app imports are then taken out: a module carrying a library's marker (library_modules) is a barrier, and the app region is recomputed without passing through one, so a library and everything only it reaches go to the framework side while a small re-export module the app imports directly stays. A module reached by nothing at all is counted as framework, since the app's own code is always reachable from its entry.
    """
    deps = {m.id: m.deps for m in modules}
    if not deps:
        return 0, set(), set()
    entry = 0 if 0 in deps else min(deps)
    roots = [d for d in deps.get(entry, []) if d in deps]
    if not roots:
        return entry, {entry}, set(deps) - {entry}
    closures = {root: _closure([root], deps) for root in roots}
    shared = [root for root in roots
              if any(root in closures[other] for other in roots if other != root)]
    if shared:
        framework_root = max(shared, key=lambda root: (len(closures[root]), -root))
    else:
        framework_root = max(deps, key=lambda mid: (len(deps[mid]), -mid))
    framework = _closure([framework_root], deps)
    app_roots = [root for root in roots if root not in framework]
    app = (_closure(app_roots, deps) - framework) | {entry}
    libraries = library_modules(modules, app - {entry} - set(app_roots))
    if libraries:
        barred = {mid: [d for d in ds if d not in libraries] for mid, ds in deps.items()}
        app = (_closure(app_roots, barred) - framework - libraries) | {entry}
    return entry, app, set(deps) - app


def _safe_file_name(module: MetroModule) -> str:
    """
    Purpose:
        Build a safe, recognisable file name for a module.

    Parameters:
        module: The module.

    Returns:
        "<id>_<name>.js", or "<id>.js" when no name survived.

    Security considerations:
        The name comes from the bundle; only letters, digits and a few punctuation characters are kept, and the length is bounded.
    """
    name = _SAFE_RE.sub("_", module.name)[:60].strip("._") if module.name else ""
    return f"{module.id}_{name}.js" if name else f"{module.id}.js"


def write_module_tree(modules: List[MetroModule], root, verbose: bool = False) -> Optional[ModuleTree]:
    """
    Purpose:
        Write the modules into app_modules/ and framework_modules/ under the analysis root.

    Parameters:
        modules: All modules.
        root: The analysis root.
        verbose: Traces the split.

    Returns:
        The written tree, or None when there were no modules.

    Side effects:
        Creates the two directories and writes one file per module.

    Security considerations:
        Every target is resolved and checked to lie inside the root before writing.
    """
    if not modules:
        return None
    root = Path(root)
    entry, app, framework = classify_modules(modules)
    tree = ModuleTree(entry=entry, app_ids=app, framework_ids=framework)
    resolved_root = root.resolve()
    for module in modules:
        folder = APP_DIR if module.id in app else FRAMEWORK_DIR
        rel = f"{folder}/{_safe_file_name(module)}"
        target = (root / rel).resolve()
        if resolved_root not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(module.code, encoding="utf-8")
        tree.files[module.id] = rel
        tree.names[module.id] = module.name
        tree.deps[module.id] = module.deps
    verbose_print(f"Metro modules: {plural(len(app), 'app-region module')}, "
                  f"{plural(len(framework), 'framework module')} (entry {entry})", verbose)
    return tree
