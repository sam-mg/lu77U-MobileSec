#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.flutter.recovered

Purpose:
    Read the structure out of a recovered Flutter app -- Blutter's per-library disassembly and object pool for a release build, or the original Dart source for a debug build -- and tie the Dart side to the Android platform code it talks to.

Responsibilities:
    Parse the object pool, sort Dart libraries into the app's own code, third-party packages and the Flutter SDK, find the functions in a disassembly file with their libapp.so offsets, extract platform-channel call sites, cross-reference them into the decompiled Java/Kotlin, and write the overview the agent reads first.

Dependencies:
    re, pathlib.

Implementation notes:
    Blutter lays its disassembly out as asm/<package>/<library>.dart, so the top directory under asm/ is the Dart package. That is what makes the app-versus-framework split possible: a typical app has one or two of its own files beside hundreds of Flutter framework files, and without the split the framework's own platform-channel and networking code outscores the app's. Platform channels are where Flutter hands control to Java/Kotlin, so a channel name and its method strings are the thread that joins the two halves of the app; the same literals appear on both sides even when R8 has renamed every Java class.

Security considerations:
    Everything parsed here is derived from an untrusted APK. It is read as text and matched with bounded regular expressions; nothing is executed, and every path handed back is relative to the tree it was found in.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..layout import PLATFORM_DIR
from ...decompiler.blutter_runner import BLUTTER_INFO_NAME
from ...utils.verbose import plural

FLUTTER_SDK_PACKAGES = frozenset((
    "flutter", "flutter_web_plugins", "flutter_localizations", "flutter_driver",
    "flutter_test", "sky_engine", "dart", ".dart_tool",
))

OVERVIEW_NAME = "flutter_scan_overview.txt"

MAX_OVERVIEW_CHARS = 5500
MAX_CHANNEL_SITES = 40
MAX_JAVA_HITS_PER_NAME = 4
MAX_APP_POOL_STRINGS = 40

_POOL_ENTRY_RE = re.compile(r"^\[pp\+(0x[0-9a-fA-F]+)\]\s?(.*)$")
_QUOTED_RE = re.compile(r'"((?:[^"\\\n]|\\.){1,400})"')
_POOL_REF_RE = re.compile(r"\[pp\+(0x[0-9a-fA-F]+)\]")
_OBJ_REF_RE = re.compile(r"Obj!\w+@([0-9a-f]+)")
_OBJ_BLOCK_RE = re.compile(r"^Obj!\w+@([0-9a-f]+) : \{")
_CHANNEL_OBJ_RE = re.compile(r"Obj!((?:Optional)?MethodChannel|EventChannel|BasicMessageChannel)@([0-9a-fA-F]+)")
_STRING_LOAD_RE = re.compile(r'^\s*//\s*0x[0-9a-fA-F]+:\s*r\d+\s*=\s*"((?:[^"\\]|\\.){1,200})"\s*$')
_INVOKE_RE = re.compile(r"(?:MethodChannel|BasicMessageChannel)::(invoke(?:Map|List)?Method|send)\b")
_BL_ADDR_RE = re.compile(r"^\s*//\s+(0x[0-9a-fA-F]+):\s+bl\b")
_FUNC_ADDR_RE = re.compile(r"^\s*//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+)(?:,\s*size:\s*(0x[0-9a-fA-F]+))?")
_FUNC_DECL_RE = re.compile(r"^\s{2}(?!//)(.*?)([A-Za-z_$][\w$]*|[<>=+\-*/%~\[\]]+)\s*\(.*\)\s*(?:async\*?\s*|sync\*\s*)?\{\s*$")
_CLASS_DECL_RE = re.compile(r"^(?:abstract\s+)?class\s+(\S+)")
_MAIN_RE = re.compile(r"\bvoid\s+main\s*\(")

_DART_CHANNEL_RE = re.compile(
    r"\b(MethodChannel|EventChannel|BasicMessageChannel|OptionalMethodChannel)\s*\(\s*['\"]([^'\"\n]{1,200})['\"]")
_DART_INVOKE_RE = re.compile(
    r"\binvoke(?:Map|List)?Method\s*(?:<[^>\n]{0,80}>)?\s*\(\s*['\"]([^'\"\n]{1,200})['\"]")

_SUMMARY_LINE_RE = re.compile(r"^\s*// 0x[0-9a-fA-F]+: (\S.*)$")
_ASSIGN_RE = re.compile(r"^r\d+ = (.+)$")
_PLAIN_CALL_RE = re.compile(r"^([A-Za-z_$][\w$.<>=]*)\(\)$")
_STATIC_FIELD_RE = re.compile(r"^(?:LoadStaticField|InitLateStaticField|InitLateFinalStaticField)\(")
_CALL_TARGET_RE = re.compile(r";\s*\[((?:package|dart):[^\]]+)\]\s*(\S+)")
_SKIPPED_CALLS = frozenset((
    "AllocateArray", "AllocateClosure", "AllocateContext", "AllocateGrowableArray", "Await",
    "InitAsync", "ReturnAsync", "ReturnAsyncNotFuture", "ReturnAsyncStar",
    "StackOverflowSharedWithFPURegs", "StackOverflowSharedWithoutFPURegs",
    "NullCastErrorSharedWithFPURegs", "NullCastErrorSharedWithoutFPURegs",
    "NullErrorSharedWithFPURegs", "NullErrorSharedWithoutFPURegs",
    "RangeErrorSharedWithFPURegs", "RangeErrorSharedWithoutFPURegs",
))
MAX_DIGEST_VALUE_CHARS = 240
_JAVA_NOISE = ("/io/flutter/", "/androidx/", "/android/", "/kotlin/", "/kotlinx/",
               "/com/google/", "/org/jetbrains/", "/org/intellij/")


@dataclass
class PoolEntry:
    """
    Purpose:
        One slot of Blutter's object pool.

    Attributes:
        offset: The pool offset, as written in the disassembly ("0xa040").
        header: The entry's first line, such as 'String: "isRooted"' or 'Obj!MethodChannel@3a7681 : {'.
        strings: Every string literal inside the entry, including those in an object's fields.
    """
    offset: str
    header: str
    strings: List[str] = field(default_factory=list)


@dataclass
class DartFunction:
    """
    Purpose:
        One function in a Blutter disassembly file.

    Attributes:
        name: The function's name as Blutter wrote it.
        owner: The enclosing class, "::" for a top-level function.
        addr: Its offset in libapp.so, which is what a Frida hook attaches to.
        size: Its size in bytes, as written.
        start_line: The 1-based line of its declaration.
        end_line: The 1-based line of its last line.
    """
    name: str
    owner: str
    addr: str
    size: str
    start_line: int
    end_line: int


@dataclass
class ChannelCall:
    """
    Purpose:
        One place where Dart code sends a message over a platform channel.

    Attributes:
        channel: The channel name, or "?" when the channel object could not be resolved.
        method: The method name passed to invokeMethod, or "?".
        file: The Dart-side file, relative to the analysis root.
        line: The 1-based line of the call.
        function: The enclosing function, "Owner::name" when known.
        addr: The libapp.so offset of the call instruction, release builds only.
    """
    channel: str
    method: str
    file: str
    line: int
    function: str = ""
    addr: str = ""


def parse_object_pool(text: str) -> Dict[str, PoolEntry]:
    """
    Purpose:
        Index Blutter's pp.txt by pool offset.

    Parameters:
        text: The pool dump.

    Returns:
        Entries keyed by lower-cased offset.

    Complexity:
        O(n) in the dump size.

    Implementation notes:
        An entry runs from its [pp+...] line to the next one, so an object's field lines -- where a string held by a widget or a channel actually lives -- belong to the object that owns them.
    """
    entries: Dict[str, PoolEntry] = {}
    current: Optional[PoolEntry] = None
    for line in text.splitlines():
        match = _POOL_ENTRY_RE.match(line)
        if match:
            current = PoolEntry(offset=match.group(1).lower(), header=match.group(2).strip())
            entries[current.offset] = current
            current.strings.extend(_QUOTED_RE.findall(match.group(2)))
        elif current is not None:
            current.strings.extend(_QUOTED_RE.findall(line))
    return entries


def parse_object_dump(text: str) -> Dict[str, List[str]]:
    """
    Purpose:
        Index Blutter's objs.txt: the strings held anywhere inside each top-level object.

    Parameters:
        text: The object dump.

    Returns:
        Object id (the hex after @) to the string literals in its block, nested objects included.

    Complexity:
        O(n) in the dump size.

    Implementation notes:
        A const widget tree is dumped here, not in pp.txt: the pool holds only a list of references (List<Widget>(4) [Obj!ListTile@...]) and each object's block, with every nested object written inline, is in objs.txt. A real app's developer menu kept a gateway secret and a debug key in const SelectableText widgets, and both were invisible to a search of the pool. A block runs from its unindented Obj! header to the next unindented closing brace.
    """
    objects: Dict[str, List[str]] = {}
    current: Optional[List[str]] = None
    for line in text.splitlines():
        match = _OBJ_BLOCK_RE.match(line)
        if match:
            current = objects.setdefault(match.group(1), [])
            continue
        if current is None:
            continue
        if line == "}":
            current = None
            continue
        current.extend(_QUOTED_RE.findall(line))
    return objects


def channel_names_by_object(pool: Dict[str, PoolEntry]) -> Dict[str, Tuple[str, str]]:
    """
    Purpose:
        Map each channel object in the pool to its kind and name.

    Parameters:
        pool: The parsed object pool.

    Returns:
        Object id (the hex after @) to (channel class, channel name).

    Implementation notes:
        A channel's name is its first string field, which is how Blutter dumps a const MethodChannel. A channel object with no string field is left out rather than given a guessed name.
    """
    out: Dict[str, Tuple[str, str]] = {}
    for entry in pool.values():
        match = _CHANNEL_OBJ_RE.search(entry.header)
        if match and entry.strings:
            out[match.group(2).lower()] = (match.group(1), entry.strings[0])
    return out


def asm_packages(asm_dir: Path) -> Dict[str, List[Path]]:
    """
    Purpose:
        Group Blutter's disassembly files by Dart package.

    Parameters:
        asm_dir: Blutter's asm/ directory.

    Returns:
        Package name to its files, sorted; files directly under asm/ are grouped under "".

    Implementation notes:
        Files directly under asm/ are what an obfuscated build produces, where Blutter cannot name the package. Callers treat that group as unknown rather than as app code.
    """
    groups: Dict[str, List[Path]] = {}
    for path in sorted(p for p in asm_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(asm_dir)
        package = rel.parts[0] if len(rel.parts) > 1 else ""
        groups.setdefault(package, []).append(path)
    return groups


def find_app_packages(groups: Dict[str, List[Path]]) -> Set[str]:
    """
    Purpose:
        Work out which Dart packages are the app's own code.

    Parameters:
        groups: The disassembly grouped by package.

    Returns:
        The app's package names; empty when they cannot be told apart.

    Implementation notes:
        The app is the package that defines the top-level main(), which Blutter keeps in that library's "::" class. A package with a main.dart under it counts too, for the rare build where main was inlined away. Every Flutter SDK package is excluded, so a framework file with "main" in it can never be mistaken for the app.
    """
    apps: Set[str] = set()
    for package, files in groups.items():
        if not package or package in FLUTTER_SDK_PACKAGES:
            continue
        for path in files:
            if path.name == "main.dart":
                apps.add(package)
                break
            try:
                head = path.read_text(encoding="utf-8", errors="ignore")[:200000]
            except OSError:
                continue
            if _MAIN_RE.search(head) and "class :: {" in head:
                apps.add(package)
                break
    return apps


def package_kind(package: str, app_packages: Set[str]) -> str:
    """
    Purpose:
        Classify a Dart package.

    Parameters:
        package: The package name; empty for an unattributed file.
        app_packages: The app's own packages.

    Returns:
        "app", "sdk", "package" or "unknown".
    """
    if not package:
        return "unknown"
    if package in app_packages:
        return "app"
    if package in FLUTTER_SDK_PACKAGES:
        return "sdk"
    return "package"


def parse_functions(lines: List[str]) -> List[DartFunction]:
    """
    Purpose:
        List the functions in one Blutter disassembly file with their libapp.so offsets.

    Parameters:
        lines: The file's lines.

    Returns:
        The functions, in file order.

    Implementation notes:
        Blutter writes each function as a declaration line ending in "{", then a "** addr: 0x..., size: 0x..." comment. The declaration is taken as the nearest such line above the addr comment, and a function ends where the next one's declaration begins, so the span always covers the function's own instructions.
    """
    owner = "::"
    pending: Optional[Tuple[str, int]] = None
    functions: List[DartFunction] = []
    for index, line in enumerate(lines, 1):
        cls = _CLASS_DECL_RE.match(line)
        if cls:
            owner = cls.group(1)
            pending = None
            continue
        decl = _FUNC_DECL_RE.match(line)
        if decl:
            name = "<anonymous closure>" if "<anonymous closure>" in line else decl.group(2)
            pending = (name, index)
            continue
        addr = _FUNC_ADDR_RE.match(line)
        if addr and pending:
            if functions and functions[-1].end_line >= pending[1]:
                functions[-1].end_line = pending[1] - 1
            functions.append(DartFunction(
                name=pending[0], owner=owner, addr=addr.group(1).lower(),
                size=(addr.group(2) or "").lower(), start_line=pending[1], end_line=len(lines)))
            pending = None
    return functions


def _function_at(functions: List[DartFunction], line: int) -> Optional[DartFunction]:
    """
    Purpose:
        Find the function containing a line.

    Parameters:
        functions: The file's functions.
        line: A 1-based line number.

    Returns:
        The function, or None for a line outside every function.
    """
    for function in functions:
        if function.start_line <= line <= function.end_line:
            return function
    return None


def asm_channel_calls(rel_path: str, text: str, channels: Dict[str, Tuple[str, str]]) -> List[ChannelCall]:
    """
    Purpose:
        Find the platform-channel calls in one Blutter disassembly file.

    Parameters:
        rel_path: The file's path relative to the analysis root.
        text: The file's contents.
        channels: Channel object ids to names, from the pool.

    Returns:
        The calls found.

    Implementation notes:
        Blutter annotates every call target, so an invokeMethod call is recognisable by name. The method name is the last string literal loaded before the call and the channel is the last channel object loaded, both reset at each function boundary so a value from one function is never attributed to the next. The call instruction's own address is kept, because that is a precise place to hook in a later dynamic check.
    """
    lines = text.splitlines()
    functions = parse_functions(lines)
    calls: List[ChannelCall] = []
    last_string = "?"
    last_channel = "?"
    current_fn: Optional[DartFunction] = None
    for index, line in enumerate(lines, 1):
        function = _function_at(functions, index)
        if function is not current_fn:
            current_fn = function
            last_string, last_channel = "?", "?"
        string_load = _STRING_LOAD_RE.match(line)
        if string_load:
            last_string = string_load.group(1)
            continue
        channel_ref = _CHANNEL_OBJ_RE.search(line)
        if channel_ref:
            known = channels.get(channel_ref.group(2).lower())
            if known:
                last_channel = known[1]
        if _INVOKE_RE.search(line):
            addr = _BL_ADDR_RE.match(line)
            calls.append(ChannelCall(
                channel=last_channel, method=last_string, file=rel_path, line=index,
                function=f"{function.owner}::{function.name}" if function else "",
                addr=addr.group(1).lower() if addr else ""))
    return calls


def source_channel_calls(rel_path: str, text: str) -> Tuple[List[Tuple[str, str, int]], List[ChannelCall]]:
    """
    Purpose:
        Find channel declarations and invokeMethod calls in Dart source.

    Parameters:
        rel_path: The file's path relative to the analysis root.
        text: The Dart source.

    Returns:
        The declared channels as (kind, name, line), and the calls.

    Implementation notes:
        Used for debug builds, where the real source is available. A call's channel is the one declared most recently above it in the file, which is right for the usual one-channel-per-class shape and is labelled "?" when the file declares none.
    """
    declared: List[Tuple[str, str, int]] = []
    calls: List[ChannelCall] = []
    last_channel = "?"
    for index, line in enumerate(text.splitlines(), 1):
        for kind, name in _DART_CHANNEL_RE.findall(line):
            declared.append((kind, name, index))
            last_channel = name
        for method in _DART_INVOKE_RE.findall(line):
            calls.append(ChannelCall(channel=last_channel, method=method, file=rel_path, line=index))
    return declared, calls


def java_literal_hits(java_root: Path, root: Path, literals: Iterable[str]) -> Dict[str, List[str]]:
    """
    Purpose:
        Find where each channel or method name appears as a string literal in the decompiled Java/Kotlin.

    Parameters:
        java_root: The decompiled platform sources.
        root: The analysis root, for relative paths.
        literals: The names to look for.

    Returns:
        Name to "file:line" locations, bounded per name.

    Implementation notes:
        Matching the exact quoted literal is what makes this work on R8-obfuscated code: class and method names are renamed, but the strings a MethodCallHandler compares the incoming method name against are not. Framework packages are skipped because io.flutter's own channel plumbing would otherwise match every common name.
    """
    wanted = {name for name in literals if name and name != "?"}
    hits: Dict[str, List[str]] = {name: [] for name in wanted}
    if not wanted or not java_root.is_dir():
        return hits
    quoted = {f'"{name}"': name for name in wanted}
    for path in sorted(java_root.rglob("*")):
        if path.suffix not in (".java", ".kt") or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(noise in f"/{rel}" for noise in _JAVA_NOISE):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, 1):
            for literal, name in quoted.items():
                if literal in line and len(hits[name]) < MAX_JAVA_HITS_PER_NAME:
                    hits[name].append(f"{rel}:{index}")
    return hits


def app_pool_strings(app_files: Iterable[Path], pool: Dict[str, PoolEntry],
                     objects: Optional[Dict[str, List[str]]] = None) -> List[str]:
    """
    Purpose:
        Collect the strings the app's own code loads from the object pool.

    Parameters:
        app_files: The app's disassembly files.
        pool: The parsed object pool.
        objects: The parsed object dump, so a pool entry that only references objects -- a const widget list -- yields the strings inside them.

    Returns:
        The distinct strings, in first-use order, bounded.

    Implementation notes:
        The pool holds every constant in the snapshot, the framework's included, so searching it blind for secrets drowns in noise. Following only the pool references the app's own functions make narrows it to the app's strings, and resolving object entries includes strings held in a const object's fields -- which is where a value assigned to a widget's field, a hardcoded key among them, actually sits.
    """
    seen: Set[str] = set()
    out: List[str] = []
    for path in app_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for offset in _POOL_REF_RE.findall(text):
            entry = pool.get(offset.lower())
            if entry is None:
                continue
            values = list(entry.strings)
            for object_id in _OBJ_REF_RE.findall(entry.header) if objects else ():
                values += objects.get(object_id, [])
            for value in values:
                if len(value) >= 4 and value not in seen:
                    seen.add(value)
                    out.append(value)
                    if len(out) >= MAX_APP_POOL_STRINGS:
                        return out
    return out


def read_blutter_info(root: Path) -> str:
    """
    Purpose:
        Read the Dart version and build flags Blutter reported, when they were saved.

    Parameters:
        root: The analysis root.

    Returns:
        The saved lines, or an empty string.
    """
    path = root / BLUTTER_INFO_NAME
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def render_overview(*, mode: str, root: Path, app_packages: Iterable[str],
                    packages: Dict[str, str], calls: List[ChannelCall],
                    declared_channels: Iterable[str], java_hits: Dict[str, List[str]],
                    pool_strings: List[str], has_platform: bool,
                    native_lines: Optional[List[str]] = None) -> str:
    """
    Purpose:
        Compose the overview the agent reads before anything else.

    Parameters:
        mode: "release" for a Blutter recovery, "debug" for recovered Dart source, "strings" when only libapp.so's strings were recovered.
        root: The analysis root.
        app_packages: The app's own Dart packages.
        packages: Third-party Dart packages, name to version (version may be empty).
        calls: Platform-channel call sites found on the Dart side.
        declared_channels: Channel names known from the pool or the source, including ones with no call found.
        java_hits: Where each channel and method name appears in the Java/Kotlin.
        pool_strings: Strings the app's own code loads from the pool, or in strings mode the key strings from libapp.so.
        native_lines: The native-library section, naming the libraries the app's own code loads.
        has_platform: Whether the Java/Kotlin platform layer was decompiled.

    Returns:
        The overview text, bounded to MAX_OVERVIEW_CHARS.

    Implementation notes:
        The agent's opening context shows only a bounded slice of this file, so the most decision-relevant parts come first: what kind of build this is and therefore how to read it, where each artifact lives, the manifest's exported components (this overview replaces the manifest summary a Java scan opens with), the channels the app's own code uses, the native libraries it loads, and the strings it holds. Channels only third-party plugins use are one line at the end: on a lab app with the usual plugins, their dozens of pigeon calls filled the bound and pushed the app's strings and native libraries out of the file entirely.
    """
    out: List[str] = []
    if mode == "debug":
        out.append("Build: DEBUG - the original Dart source was recovered from "
                   "assets/flutter_assets/kernel_blob.bin, comments included. Read it as source.")
    elif mode == "strings":
        out.append("Build: RELEASE (AOT) - libapp.so could NOT be disassembled (Blutter needs an "
                   "arm64-v8a slice and a Dart version it supports). Only its strings were "
                   "recovered, so the Dart program logic cannot be read. Base a Dart-side finding "
                   "on a string together with the platform layer or a native library, and say in "
                   "the finding what could not be checked.")
    else:
        out.append("Build: RELEASE (AOT) - libapp.so was recovered by Blutter into pseudo-Dart "
                   "disassembly. Names, strings and call targets are real; read logic from the "
                   "annotated instructions.")
    info = read_blutter_info(root)
    if info:
        out.append(info)
    out.append("")
    out.append("Where things are:")
    if mode == "debug":
        out.append("  dart_source/            the app's own Dart source")
        out.append("  dart_packages/<pkg>/    third-party pub package source")
    elif mode == "strings":
        out.append("  snapshot_strings/libapp_key_strings.txt  the libapp.so strings worth reading: endpoints, keys, SQL, channels, sensitive words")
        out.append("  snapshot_strings/libapp_strings.txt      every libapp.so string, one per line (search it with an explicit path)")
    else:
        out.append("  asm/<package>/<lib>.dart  disassembly per Dart library; '** addr: 0x...' is the libapp.so offset to hook")
        out.append("  pp.txt                  object pool: every constant, incl. strings held in object fields")
        out.append("  objs.txt                object dump")
        out.append("  blutter_frida.js        Blutter's Frida template with Dart object decoding")
    if has_platform:
        out.append(f"  {PLATFORM_DIR}/sources/       Java/Kotlin platform layer (MethodChannel handlers, plugins, root/integrity checks)")
        out.append(f"  {PLATFORM_DIR}/resources/AndroidManifest.xml  the real manifest: exported components, deep links")
    manifest = root / PLATFORM_DIR / "resources" / "AndroidManifest.xml"
    if has_platform and manifest.is_file():
        from ..sast.extractors.manifest import summarise_manifest
        out.append("")
        out += summarise_manifest(manifest)
    out.append("")
    apps = sorted(app_packages)
    if mode == "strings":
        out.append("App's own Dart packages: (not recoverable without disassembly)")
    else:
        out.append("App's own Dart packages: " + (", ".join(apps) if apps else
                   "(not identifiable - obfuscated build; treat every library as potentially app code)"))
    if packages:
        listed = ", ".join(f"{n} {v}".strip() for n, v in sorted(packages.items()))
        out.append("Third-party Dart packages: " + listed)
    out.append("")

    app_prefixes = tuple(f"asm/{name}/" for name in apps) + ("dart_source/",)
    app_calls = [c for c in calls if c.file.startswith(app_prefixes)]
    app_channels = sorted({c.channel for c in app_calls})
    other_channels = sorted(({c.channel for c in calls} | set(declared_channels)) - set(app_channels) - {"?"})
    if app_calls:
        out.append("Platform channels the app's own code uses (Dart -> Android). Each method string below "
                   "is matched against the Java/Kotlin MethodCallHandler that answers it:")
        shown = 0
        for name in app_channels:
            label = f'"{name}"' if name != "?" else "(channel not resolved)"
            java = java_hits.get(name) or []
            out.append(f"  channel {label}" + (f"  - Java: {', '.join(java)}" if java else ""))
            for call in (c for c in app_calls if c.channel == name):
                if shown >= MAX_CHANNEL_SITES:
                    break
                where = f"{call.file}:{call.line}"
                if call.function:
                    where += f" in {call.function}"
                if call.addr:
                    where += f" (libapp.so+{call.addr})"
                method_hits = java_hits.get(call.method) or []
                java_part = f"  -> Java: {', '.join(method_hits)}" if method_hits else (
                    "  -> no Java literal found" if has_platform else "")
                out.append(f'    invokeMethod "{call.method}" at {where}{java_part}')
                shown += 1
        if len(app_calls) > shown:
            out.append(f"  ... (+{len(app_calls) - shown} more call sites not listed; "
                       "search_code for invokeMethod)")
        out.append("")
    elif calls or declared_channels:
        out.append("Platform channels: none used by the app's own Dart code.")
        out.append("")
    else:
        out.append("Platform channels: none found on the Dart side.")
        out.append("")

    if native_lines:
        out += native_lines
        out.append("")

    if pool_strings and mode == "strings":
        out.append("Key strings from libapp.so (the app's and its packages' together - "
                   "nothing without disassembly tells them apart):")
        for value in pool_strings:
            out.append(f'  "{value[:160]}"')
        out.append("")
    elif pool_strings:
        out.append("Strings the app's own code loads (from the object pool and the const objects it references):")
        for value in pool_strings:
            out.append(f'  "{value[:160]}"')
        out.append("")

    if other_channels:
        out.append("Plugin channels (third-party packages - follow one only when a lead goes there): "
                   + ", ".join(other_channels[:15])
                   + (f" (+{len(other_channels) - 15} more)" if len(other_channels) > 15 else ""))

    text = "\n".join(out).rstrip() + "\n"
    if len(text) > MAX_OVERVIEW_CHARS:
        text = text[:MAX_OVERVIEW_CHARS].rsplit("\n", 1)[0] + "\n... (truncated; search pp.txt / the sources for more)\n"
    return text


def _call_target(lines: List[str], index: int) -> str:
    """
    Purpose:
        Find the resolved callee Blutter annotated on the instructions under a summary line.

    Parameters:
        lines: The file's lines.
        index: The 0-based index of the summary line.

    Returns:
        "Owner::name (package)" when an annotation was found within the next two lines, otherwise "".

    Implementation notes:
        Blutter writes the readable summary first and the raw instructions beneath it, and only the raw "bl" line carries the resolved target. Two lines is enough for a direct call; a dispatch-table call has no annotation at all and keeps its bare name. A mixin application's generated owner name ("_MixinApplication378&Object&SqfliteDatabaseMixin&...") is cut to its last component, the mixin that actually defines the method.
    """
    for follow in lines[index + 1:index + 3]:
        if _SUMMARY_LINE_RE.match(follow):
            break
        match = _CALL_TARGET_RE.search(follow)
        if match:
            package = match.group(1).split("/", 1)[0].replace("package:", "")
            owner, sep, name = match.group(2).rpartition("::")
            owner = owner.rsplit("&", 1)[-1]
            return f"{owner}{sep}{name} ({package})"
    return ""


def _digest_value(value: str, lines: List[str], index: int) -> str:
    """
    Purpose:
        Decide whether one register assignment carries meaning worth keeping in a digest, and render it.

    Parameters:
        value: The right-hand side of the assignment.
        lines: The file's lines, for resolving a call's target.
        index: The 0-based index of the summary line.

    Returns:
        The rendered text, or "" to drop the line.

    Implementation notes:
        Kept: string literals, booleans, named functions and closures, constant instances and calls, because those are what a security reading of compiled Dart turns on - the query text, the key, the flag value, the API invoked. Dropped: register shuffles, allocation and async plumbing, integer immediates and dispatch-table calls, which have no name to read.
    """
    if value.startswith('"'):
        return value[:MAX_DIGEST_VALUE_CHARS]
    if value in ("true", "false"):
        return value
    if value.startswith(("Function '", "Closure:")):
        return "" if "<anonymous closure>" in value else value[:MAX_DIGEST_VALUE_CHARS]
    if value.startswith("Instance_"):
        return value
    if _STATIC_FIELD_RE.match(value):
        target = _call_target(lines, index)
        return f"static field {target}" if target else ""
    call = _PLAIN_CALL_RE.match(value)
    if call and call.group(1) not in _SKIPPED_CALLS:
        target = _call_target(lines, index)
        return f"call {target or call.group(1) + '()'}"
    return ""


_INT_ASSIGN_RE = re.compile(r"^r\d+ = (-?\d+)$")
_STORE_RE = re.compile(r"^(?:StoreField|ArrayStore):")
_XOR_RE = re.compile(r"^eor\s+\w+, \w+, #(0x[0-9a-fA-F]+|\d+)$")
_CATCH_ENTRY_RE = re.compile(r"^sub\s+SP, fp, #")
_CLOSURE_REF_RE = re.compile(r"AnonymousClosure: \((0x[0-9a-fA-F]+)\)")
_OBJ_ID_RE = re.compile(r"Obj!\w+@([0-9a-fA-F]+)")
MIN_INT_ARRAY = 6
MAX_OBJECT_STRINGS = 12
MAX_CLOSURE_CALLS = 3


def _object_strings(lines: List[str], index: int, objects: Optional[Dict[str, List[str]]],
                    pool: Optional[Dict[str, PoolEntry]] = None) -> str:
    """
    Purpose:
        Render the strings held inside the const object or const list a summary line loads.

    Parameters:
        lines: The file's lines.
        index: The 0-based index of the summary line.
        objects: The object dump index, or None.
        pool: The object pool index, or None.

    Returns:
        ' {"a", "b"}' with the first few distinct strings, or "" when there are none.

    Implementation notes:
        A const widget or record never shows its contents in the disassembly - the code loads the object by its id - so a secret kept in a const field (a flag on a page, a key on a menu row) was invisible to a reviewer reading the digest. The raw lines under the summary name the object (Obj!X@id) or only the pool slot it lives in ([pp+0x...]); a const list of widgets is loaded as one slot whose pool entry lists the objects, so the slot is followed to those objects too. Strings come from the object dump, nested objects included, and from the pool entry itself.
    """
    if not objects and not pool:
        return ""
    ids: List[str] = []
    seen: List[str] = []
    for follow in lines[index + 1:index + 3]:
        if _SUMMARY_LINE_RE.match(follow):
            break
        ids += [m.lower() for m in _OBJ_ID_RE.findall(follow)]
        slot = _POOL_REF_RE.search(follow)
        entry = (pool or {}).get(slot.group(1).lower()) if slot else None
        if entry is not None:
            ids += [m.lower() for m in _OBJ_REF_RE.findall(entry.header)]
            seen += [value[:120] for value in entry.strings if value.strip()]
    for obj_id in ids:
        for value in (objects or {}).get(obj_id, []):
            if value.strip():
                seen.append(value[:120])
    distinct: List[str] = []
    for value in seen:
        if value not in distinct:
            distinct.append(value)
        if len(distinct) >= MAX_OBJECT_STRINGS:
            break
    return (" {" + ", ".join(f'"{v}"' for v in distinct) + "}") if distinct else ""


def _closure_target(lines: List[str], index: int, functions: Dict[str, DartFunction]) -> str:
    """
    Purpose:
        Say which function an anonymous closure created on this line runs, and what that function calls.

    Parameters:
        lines: The file's lines.
        index: The 0-based index of the summary line.
        functions: The file's functions by address.

    Returns:
        A description of the closure's body, or "anonymous closure" when its body is elsewhere.

    Implementation notes:
        A deep-link screen that schedules a post-frame callback in initState, which then submits the transfer, reads in the digest as initState creating a closure and nothing more - and a reviewer concluded the screen only pre-fills a form. Naming the closure's line, its signature (a Duration parameter marks a frame callback) and the app calls it makes is what shows that work starts without the user.
    """
    for follow in lines[index + 1:index + 3]:
        if _SUMMARY_LINE_RE.match(follow):
            break
        match = _CLOSURE_REF_RE.search(follow)
        if not match:
            continue
        target = functions.get(match.group(1).lower())
        if target is None:
            return "anonymous closure (body in another file)"
        decl = lines[target.start_line - 1].strip().rstrip("{").strip()
        calls: List[str] = []
        for body_index in range(target.start_line, min(target.end_line, len(lines))):
            if not _SUMMARY_LINE_RE.match(lines[body_index]):
                continue
            callee = _call_target(lines, body_index)
            if callee and "(flutter)" not in callee and "(dart:" not in callee and callee not in calls:
                calls.append(callee)
            if len(calls) >= MAX_CLOSURE_CALLS:
                break
        note = " - a frame callback, run after the next frame without user action" if "Duration" in decl else ""
        made = f", which calls {', '.join(calls)}" if calls else ""
        return f"closure -> line {target.start_line} {decl}{note}{made}"
    return "anonymous closure"


_TEXT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _{}-.:/@!?,=+#")
_COMMON_BIGRAMS = frozenset((
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of",
    "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll",
    "be", "ma", "si", "om", "ur", "ag", "fl", "la", "ke", "ey", "ad", "mi", "cr", "et", "ec",
    "ok", "ki", "pa", "ss", "wo", "rd", "ac", "ct", "ap", "pi", "us", "od", "ge", "di", "ta",
))
MIN_DECODE_LENGTH = 8
MAX_DECODE_SHIFT = 32


def _text_score(codes: List[int]) -> float:
    """
    Purpose:
        Score how much a run of character codes reads as text.

    Parameters:
        codes: The character codes.

    Returns:
        0.0 when any code is outside printable ASCII or fewer than half are letters, otherwise the share of codes that are letters, digits or the punctuation keys and flags use.
    """
    if not codes or not all(32 <= c < 127 for c in codes):
        return 0.0
    chars = [chr(c) for c in codes]
    if sum(ch.isalpha() for ch in chars) * 2 < len(chars):
        return 0.0
    return sum(ch in _TEXT_CHARS for ch in chars) / len(chars)


def _bigram_score(codes: List[int]) -> float:
    """
    Purpose:
        Score how word-like a run of character codes is.

    Parameters:
        codes: The character codes.

    Returns:
        The share of adjacent letter pairs, case-folded, that are common in English; 0.0 when there are none.

    Implementation notes:
        Character classes alone cannot tell an XORed key from the key: both are mostly letters. Common bigrams can - "secret_admin_key" is full of them, "YOIXO^uKNGCD" has almost none.
    """
    text = "".join(chr(c).lower() if 0 <= c < 0x110000 else " " for c in codes)
    pairs = [text[i:i + 2] for i in range(len(text) - 1) if text[i:i + 2].isalpha()]
    return sum(pair in _COMMON_BIGRAMS for pair in pairs) / len(pairs) if pairs else 0.0


def _decode_int_array(values: List[int]) -> str:
    """
    Purpose:
        Find the simple encoding an integer array hides text behind, when it is one.

    Parameters:
        values: The array's values.

    Returns:
        A digest fragment naming the decoding and the text, or "" when no decoding reads clearly better than the raw values.

    Implementation notes:
        Apps hide a flag or key as char codes shifted by a constant or XORed with one byte, and decode it at runtime; the decoding arithmetic is an immediate the digest drops. A real lab app's flag was stored shifted by five, which put two codes above 126, so the array was shown as bare numbers and never reported, while a sibling shifted by one kept its readable-looking characters and was. Shifts up to 32 either way and every single-byte XOR key are tried; a candidate counts only when every character is printable, at least half are letters and nearly all are letters, digits or key punctuation, and it beats the raw reading clearly - in character classes, or in how word-like it is when the raw values are letter soup. Candidates are ranked by character score plus how word-like they are, since several shifts of one array can all be printable letters; on a tie, shifts are preferred over XOR and small shifts over large ones. Short arrays are left alone, since a few random bytes decode to something printable by chance, and so are evenly spaced runs, since a counter or lookup table XORs into the alphabet.
    """
    if len(values) < MIN_DECODE_LENGTH or len({b - a for a, b in zip(values, values[1:])}) == 1:
        return ""
    raw = _text_score(values)
    best = (0.0, 0, "", [], 0.0)
    candidates = []
    for k in range(1, MAX_DECODE_SHIFT + 1):
        candidates.append((k, f"minus {k}", [v - k for v in values]))
        candidates.append((k, f"plus {k}", [v + k for v in values]))
    for key in range(1, 256):
        candidates.append((100 + key, f"xor 0x{key:02x}", [v ^ key for v in values]))
    for cost, how, codes in candidates:
        score = _text_score(codes)
        if score < 0.9:
            continue
        rank = score + _bigram_score(codes)
        if rank > best[4] or (rank == best[4] and cost < best[1]):
            best = (score, cost, how, codes, rank)
    score, _cost, how, codes, _rank = best
    if score < 0.9:
        return ""
    if score < raw + 0.1 and _bigram_score(codes) < _bigram_score(values) + 0.2:
        return ""
    return f' decodes ({how}) as "' + "".join(chr(c) for c in codes[:120]) + '"'


def _int_array_row(values: List[int]) -> str:
    """
    Purpose:
        Render a run of integer stores as one array row.

    Parameters:
        values: The stored values, as the disassembly shows them.

    Returns:
        The row text.

    Implementation notes:
        Small integers are stored tagged (shifted left by one), so a run whose values are all even is shown halved. When every value then falls in printable ASCII the characters are shown too, since an encoded string - a flag or key built from char codes - is what such a constant array usually is. When a constant shift or a single-byte XOR turns the values into clearly better text, that decoding is shown as well (_decode_int_array).
    """
    if all(v % 2 == 0 for v in values):
        values = [v // 2 for v in values]
    shown = ", ".join(str(v) for v in values[:64]) + (", ..." if len(values) > 64 else "")
    chars = ""
    if all(32 <= v < 127 for v in values):
        chars = ' chars "' + "".join(chr(v) for v in values[:120]) + '"'
    return f"int array ({len(values)}): {shown}{chars}{_decode_int_array(values)}"


def digest_disassembly(text: str, objects: Optional[Dict[str, List[str]]] = None,
                       pool: Optional[Dict[str, PoolEntry]] = None) -> str:
    """
    Purpose:
        Reduce a Blutter disassembly file to what a reviewer reads it for, keeping each kept line's real line number.

    Parameters:
        text: The file's contents.
        objects: The object dump index from parse_object_dump, used to show what const objects hold; None leaves them as bare names.
        pool: The object pool index from parse_object_pool, used to follow a const list's pool slot to the objects it lists.

    Returns:
        One "<line>: <text>" row per kept line, in file order.

    Complexity:
        O(n) in the number of lines, plus the body of each closure it names.

    Implementation notes:
        A release build's Dart is around ten raw instructions per meaningful statement, so a whole screen of app code runs to tens of thousands of characters, most of it frame setup and register moves. The digest keeps class and function declarations, string loads, booleans, named callbacks, constants and resolved calls, and drops the rest; a typical file shrinks by an order of magnitude while every literal and call survives. It also keeps what review transcripts showed a reader needs and cannot recover from calls alone: the strings inside a loaded const object, a run of integer stores as one array (an encoded string), an XOR with a constant, the body an anonymous closure runs, and where a function returns and where an exception handler begins - a fallback written in a catch block reads as a second, unexplained client without that. Line numbers are the file's own, so a finding cited from the digest points at the real line and validation reads the real code there. Consecutive identical rows are collapsed, since the same constant loaded twice in a row says nothing new.
    """
    lines = text.splitlines()
    functions = {f.addr: f for f in parse_functions(lines)}
    out: List[str] = []
    last = ""
    run: List[int] = []
    run_start = 0
    after_return = False

    def flush() -> None:
        """
        Purpose:
            Emit the pending integer run as an array row when it is long enough.

        Side effects:
            Appends to the output and clears the run.
        """
        if len(run) >= MIN_INT_ARRAY:
            out.append(f"{run_start + 1}: {_int_array_row(run)}")
        run.clear()

    for index, line in enumerate(lines):
        rendered = ""
        if _CLASS_DECL_RE.match(line):
            rendered = line.strip().rstrip("{").strip()
            after_return = False
        elif _FUNC_DECL_RE.match(line):
            rendered = "fn " + line.strip().rstrip("{").strip()
            after_return = False
        else:
            summary = _SUMMARY_LINE_RE.match(line)
            if summary is None:
                continue
            content = summary.group(1).strip()
            integer = _INT_ASSIGN_RE.match(content)
            if integer:
                if not run:
                    run_start = index
                run.append(int(integer.group(1)))
                continue
            if run and _STORE_RE.match(content):
                continue
            flush()
            assign = _ASSIGN_RE.match(content)
            xor = _XOR_RE.match(content)
            if assign:
                value = assign.group(1).strip()
                if value == "Function '<anonymous closure>':.":
                    rendered = _closure_target(lines, index, functions)
                elif value.startswith("const [") and "Instance of" in value:
                    held = _object_strings(lines, index, objects, pool)
                    rendered = f"const list of {value.count('Instance of')} objects{held}" if held else ""
                else:
                    rendered = _digest_value(value, lines, index)
                    if rendered.startswith("Instance_"):
                        rendered += _object_strings(lines, index, objects, pool)
            elif xor:
                rendered = f"xor with #{xor.group(1)}"
            elif content == "ret":
                rendered = "return"
                after_return = True
            elif after_return and _CATCH_ENTRY_RE.match(content):
                rendered = "catch: exception handler starts here"
                after_return = False
        if rendered and rendered != last:
            out.append(f"{index + 1}: {rendered}")
        if rendered:
            last = rendered
    flush()
    return "\n".join(out)


class LiteralLocator:
    """
    Purpose:
        Find the place in the app's own disassembly that loads a given string, directly or inside a const object.

    Attributes:
        root: The Flutter analysis root.

    Thread-safety:
        Not safe to share between threads; it caches lazily and is meant for one pass over one scan's findings.
    """

    def __init__(self, root):
        """
        Purpose:
            Remember the root; nothing is read until the first lookup.

        Parameters:
            root: The Flutter analysis root.
        """
        self.root = Path(root)
        self._files: Optional[List[Path]] = None
        self._objects: Optional[Dict[str, List[str]]] = None
        self._pool: Optional[Dict[str, PoolEntry]] = None

    def _load(self) -> None:
        """
        Purpose:
            Read the app's disassembly file list, the object dump and the pool once.

        Side effects:
            Reads objs.txt and pp.txt when present.
        """
        if self._files is not None:
            return
        asm_dir = self.root / "asm"
        groups = asm_packages(asm_dir) if asm_dir.is_dir() else {}
        self._files = [path for package in sorted(find_app_packages(groups))
                       for path in sorted(groups.get(package, []))]
        objs = self.root / "objs.txt"
        pool = self.root / "pp.txt"
        try:
            self._objects = parse_object_dump(objs.read_text(encoding="utf-8", errors="ignore")) if objs.is_file() else {}
            self._pool = parse_object_pool(pool.read_text(encoding="utf-8", errors="ignore")) if pool.is_file() else {}
        except OSError:
            self._objects, self._pool = {}, {}

    def complete(self, prefix: str) -> Optional[str]:
        """
        Purpose:
            Recover the full string a shortened quotation stands for.

        Parameters:
            prefix: The start of the string, as a model quoted it before cutting it short.

        Returns:
            The one pool or object-dump string that starts with it, or None when none or several do.

        Implementation notes:
            Models shorten long secrets when they quote them ('pvgw_live_secr...'), and a shortened value never matches exactly. Eight characters is the shortest prefix tried, and an ambiguous prefix is refused rather than guessed.
        """
        if len(prefix) < 8:
            return None
        self._load()
        pool_strings = [text for entry in (self._pool or {}).values() for text in entry.strings]
        object_strings = [text for strings in (self._objects or {}).values() for text in strings]
        matches = {text for text in pool_strings + object_strings if text.startswith(prefix)}
        return matches.pop() if len(matches) == 1 else None

    def locate(self, literal: str) -> Optional[Tuple[str, int]]:
        """
        Purpose:
            Find the first line of the app's own disassembly that loads the string or a const object holding it.

        Parameters:
            literal: The string, without quotes.

        Returns:
            The file relative to the root and the 1-based line, or None when the app's code never loads it.

        Implementation notes:
            A string the code loads directly appears as a quoted literal on a summary line. One held inside a const object - a widget tree, a config record - never appears in the disassembly itself: the code loads the object, by its pool offset or its Obj! id, so those are searched too, along with a pool entry that only lists the object (a const List<Widget> of tiles is loaded as one pool slot naming each tile). A match on a raw instruction line is moved up to the summary line above it, which is what a reader and the evidence gates read. Strings shorter than four characters are not looked up, since they match everywhere.
        """
        if len(literal) < 4:
            return None
        self._load()
        holders = {obj_id for obj_id, strings in (self._objects or {}).items() if literal in strings}
        needles = [f'"{literal}"'] + [f"@{obj_id}" for obj_id in sorted(holders)]
        needles += [f"[pp+{entry.offset}]" for entry in (self._pool or {}).values()
                    if literal in entry.strings or holders & set(_OBJ_REF_RE.findall(entry.header))]
        for path in self._files or []:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for index, line in enumerate(lines):
                if any(needle in line for needle in needles):
                    hit = next((back for back in range(index, max(-1, index - 4), -1)
                                if _SUMMARY_LINE_RE.match(lines[back])), index)
                    return path.relative_to(self.root).as_posix(), hit + 1
        return None


def summarise_calls(calls: List[ChannelCall]) -> str:
    """
    Purpose:
        Describe the channel calls found, for the verbose trace.

    Parameters:
        calls: The calls.

    Returns:
        A one-line summary.
    """
    channels = {c.channel for c in calls if c.channel != "?"}
    return (f"{plural(len(calls), 'platform-channel call')} over "
            f"{plural(len(channels), 'channel')}")
