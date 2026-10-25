#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.tools

Purpose:
    The tool surface the static analysis agent works through: listing and reading decompiled source, searching it, inspecting native libraries, and querying the call graph.

Responsibilities:
    Confine every path to the decompiled tree, bound every result, and return errors the agent can act on.

Dependencies:
    The source profile, the call graph.

Implementation notes:
    Every method returns text, including its errors, because the agent reads the result rather than handling an exception. An error that names what went wrong and suggests a correction is what lets the agent recover in one step instead of retrying variants. Results are bounded everywhere. The agent's context is the scarce resource, and an unbounded file read or search result would consume the budget it needs for the rest of the region.

Security considerations:
    Paths come from model output and are confined to the decompiled tree by resolving them and checking containment before any read. There is no write capability here at all -- the static agent reads, and nothing else.
"""

import hmac
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...decompiler.ghidra_runner import NativeDecompilation, decompile_native_library
from ...utils.verbose import plural
from ...utils.xml_utils import is_framework_layout_file
from .patterns import find_endpoints, find_secrets
from .profiles import JAVA_KOTLIN, SourceProfile

MAX_READ_CHARS = 12000
MAX_LINE_CHARS = 2000
MAX_TREE_ENTRIES = 400
MAX_SEARCH_MATCHES = 60
MAX_LIST_ENTRIES = 200
MAX_RESOURCE_ENTRIES = 150
MAX_NATIVE_STRINGS = 4000
MIN_NATIVE_STRING_LEN = 5
MAX_NATIVE_SIGNAL_ITEMS = 20

_RISKY_NATIVE_SYMBOLS = frozenset((
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
    "execve", "fork", "dlopen", "dlsym", "mprotect", "ptrace", "strcpy",
    "strcat", "sprintf", "vsprintf", "gets", "memcpy", "scanf",
))

_JNI_SYMBOL_RE = re.compile(r"Java_[A-Za-z0-9_]+")


def _extract_native_strings(data: bytes) -> List[str]:
    """
    Purpose:
        Recover the printable string constants embedded in a native library's bytes.

    Parameters:
        data: The library's raw bytes.

    Returns:
        The distinct printable runs, in order, bounded in count.

    Complexity:
        O(n) in the number of bytes.

    Implementation notes:
        A pure-Python printable-run scan rather than shelling out to the strings binary, so the signal is available on any host and needs no extra dependency. A run is a maximal sequence of printable ASCII at least MIN_NATIVE_STRING_LEN long, which is what filters the byte soup down to the URLs, symbol names and embedded secrets worth reading. Deduplicated and capped at MAX_NATIVE_STRINGS because a stripped library holds far more strings than the agent's context can hold, and the cap keeps a large library from exhausting it.
    """
    out: List[str] = []
    seen = set()
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            continue
        if len(current) >= MIN_NATIVE_STRING_LEN:
            text = current.decode("ascii", "ignore")
            if text not in seen:
                seen.add(text)
                out.append(text)
                if len(out) >= MAX_NATIVE_STRINGS:
                    return out
        current = bytearray()
    if len(current) >= MIN_NATIVE_STRING_LEN:
        text = current.decode("ascii", "ignore")
        if text not in seen:
            out.append(text)
    return out


def _native_signal_summary(symbols: str, strings: List[str]) -> str:
    """
    Purpose:
        Turn a native library's symbols and strings into the security leads worth surfacing: risky imports, the JNI surface, endpoints and credential candidates.

    Parameters:
        symbols: The dynamic-symbol listing, or an empty string when it could not be produced.
        strings: The printable strings recovered from the library.

    Returns:
        The formatted signal sections, or an empty string when nothing notable was found.

    Implementation notes:
        Risky functions are matched against the exact symbol name, taken as the last token of each line and stripped of its @version suffix, rather than by substring, so filesystem does not read as a use of system. The signals are presented as leads for the agent to weigh with the native library and evidence skills, not as a scored verdict: a native library legitimately imports many of these, and reachability from the app's own code is what the finding turns on. Credential values are withheld and only the kind and severity are named, matching the secrets extractor, except for the public identifiers the pattern table marks as designed to ship.
    """
    names = set()
    for line in symbols.splitlines():
        parts = line.split()
        if not parts:
            continue
        names.add(parts[-1].split("@", 1)[0])

    sections: List[str] = []

    risky = sorted(name for name in names if name in _RISKY_NATIVE_SYMBOLS)
    if risky:
        sections.append("\n## Risky imported/exported symbols (leads)\n" +
                        "\n".join(f"  {name}" for name in risky[:MAX_NATIVE_SIGNAL_ITEMS]))

    joined = "\n".join(strings)
    jni = sorted(set(_JNI_SYMBOL_RE.findall(symbols)) | set(_JNI_SYMBOL_RE.findall(joined)))
    if jni:
        shown = jni[:MAX_NATIVE_SIGNAL_ITEMS]
        more = f"\n  ... (+{len(jni) - len(shown)} more)" if len(jni) > len(shown) else ""
        sections.append("\n## JNI entry points (Java <-> native surface)\n" +
                        "\n".join(f"  {name}" for name in shown) + more)

    endpoints = find_endpoints(joined, max_results=MAX_NATIVE_SIGNAL_ITEMS)
    if endpoints:
        lines = []
        for e in endpoints:
            tags = " [cleartext]" if e["cleartext"] else ""
            tags += " [sensitive path]" if e["sensitive_path"] else ""
            lines.append(f"  {e['url']}{tags}")
        sections.append("\n## Embedded endpoints\n" + "\n".join(lines))

    secrets = find_secrets(joined, max_results=MAX_NATIVE_SIGNAL_ITEMS)
    if secrets:
        lines = []
        for s in secrets:
            if s["public"]:
                lines.append(f"  [public identifier] {s['name']}: {s['value']}")
            else:
                lines.append(f"  [{s['severity']}] {s['name']} (value withheld)")
        sections.append("\n## Credential candidates (verify reachability before reporting)\n" +
                        "\n".join(lines))

    return "\n".join(sections)

_DECOMPILATION_PREAMBLE = (
    "JNI entry points first, then functions calling risky imports, then the rest. This is "
    "pseudo-C reconstructed by a decompiler: names like param_1/local_18 and the types are "
    "inferred, but control flow, constants, buffer sizes and call targets come from the "
    "binary. Calls through the JNIEnv/JavaVM table are annotated with the JNI function "
    "they reach. In a finding, put this view's line number in \"line\" (as with read_file) "
    "and name the function and its address in the description."
)

_NATIVE_FUNCTION_HEADER_RE = re.compile(r"^// ---- (\S+) @ ([0-9A-Fa-f:]+) ")
_NATIVE_CITABLE_CALLS = _RISKY_NATIVE_SYMBOLS | frozenset((
    "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "fopen", "open",
))


def _native_function_spans(view: List[str]) -> List[tuple]:
    """
    Purpose:
        Find where each decompiled function sits in a native view.

    Parameters:
        view: The view's lines, as native_view returns them.

    Returns:
        One (name, entry, first_code_line, last_code_line) tuple per function, 1-based and inclusive, excluding the header comment and trailing blank lines.
    """
    spans = []
    current = None
    for lineno, line in enumerate(view, 1):
        header = _NATIVE_FUNCTION_HEADER_RE.match(line)
        if header or line.startswith("## "):
            if current:
                spans.append(current)
            current = [header.group(1), header.group(2), lineno + 1, lineno] if header else None
            continue
        if current and line.strip():
            current[3] = lineno
    if current:
        spans.append(current)
    return [tuple(span) for span in spans if span[3] >= span[2]]


def native_function_span(view: List[str], line: int):
    """
    Purpose:
        Find the decompiled function a line of a native view belongs to.

    Parameters:
        view: The view's lines.
        line: A 1-based line number.

    Returns:
        (header_line, last_code_line), 1-based and inclusive, or None when the line is not inside a function.

    Implementation notes:
        The span starts at the generated header comment rather than the signature, because the header carries the function's name, address and imports, which is what a reader of an excerpt needs to place it.
    """
    for _, _, first, last in _native_function_spans(view):
        if first <= line <= last:
            return first - 1, last
    return None

def locate_native_citation(view: List[str], start: int, end: int, raw_line, text: str):
    """
    Purpose:
        Turn a native finding's citation into a line span of decompiled code, repairing a citation that does not point into any function.

    Parameters:
        view: The native view's lines.
        start: The cited first line, 0 when none parsed.
        end: The cited last line.
        raw_line: The finding's line field exactly as the model wrote it, which may be an address.
        text: The finding's title and description, used to recognise the function and the call it is about.

    Returns:
        The (start, end) span to show, or None when nothing in the view can be tied to the finding.

    Implementation notes:
        A cited line inside a function is trusted as is. Otherwise the model has usually cited the function's entry address, or a number past the end that would clamp onto the symbol table, so the function is found by its address and then by its name appearing in the text, the full JNI name before the bare method name. Within that function the span narrows to the first line calling an API the finding names, such as strcpy or strncmp, so the excerpt highlights the defect rather than the whole function. Only calls in a fixed list are matched, because a word like "access" in a title would otherwise match the function's own signature.
    """
    spans = _native_function_spans(view)
    if not spans:
        return None
    if start > 0 and any(first <= start <= last for _, _, first, last in spans):
        return start, max(start, end)

    raw = str(raw_line or "").strip().lower()
    raw = raw[2:] if raw.startswith("0x") else raw
    target = None
    if raw and re.fullmatch(r"[0-9a-f:]+", raw):
        wanted = raw.lstrip("0")
        target = next((span for span in spans
                       if hmac.compare_digest(span[1].lower().lstrip("0"), wanted)), None)
    if target is None:
        target = next((span for span in spans
                       if re.search(r"\b" + re.escape(span[0]) + r"\b", text)), None)
    if target is None:
        for span in spans:
            method = span[0].rsplit("_", 1)[-1] if span[0].startswith("Java_") else ""
            if len(method) >= 4 and re.search(r"\b" + re.escape(method) + r"\b", text):
                target = span
                break
    if target is None:
        return None

    _, _, first, last = target
    lowered = text.lower()
    named = [call for call in sorted(_NATIVE_CITABLE_CALLS)
             if re.search(r"\b" + re.escape(call) + r"\b", lowered)]
    for lineno in range(first, last + 1):
        if any(re.search(r"\b" + re.escape(call) + r"\s*\(", view[lineno - 1]) for call in named):
            return lineno, lineno
    return first, last


def _render_decompilation(decompiled: NativeDecompilation) -> List[str]:
    """
    Purpose:
        Lay out a library's decompiled functions in the order the agent should read them.

    Parameters:
        decompiled: The Ghidra result.

    Returns:
        The lines of the decompiled view, or an empty list when there is no code to show.

    Implementation notes:
        JNI entry points come first because they are where data from Java enters, then functions that call a risky import, then named functions, then Ghidra's FUN_ placeholders. A large library has thousands of functions and the agent will read only the first pages, so the order decides what it actually sees. Each function is headed with its address and the imports it calls, which is what a finding cites when the library is stripped. The preamble says plainly that this is reconstructed pseudo-C, so names and types are not reported as if the developer wrote them.
    """
    functions = [f for f in decompiled.functions if f.code.strip()]
    if not functions:
        return []

    def rank(function) -> tuple:
        """
        Purpose:
            Sort key placing the most security-relevant functions first.

        Parameters:
            function: A decompiled function.

        Returns:
            The key: a priority tier, then the entry address.
        """
        if function.name == "JNI_OnLoad" or function.name.startswith("Java_"):
            tier = 0
        elif any(c.split("@", 1)[0] in _RISKY_NATIVE_SYMBOLS for c in function.calls):
            tier = 1
        elif not function.name.startswith("FUN_"):
            tier = 2
        else:
            tier = 3
        return (tier, function.entry)

    shown = len(functions)
    total = max(decompiled.function_count, shown)
    note = (f" - first {shown} of {total} functions (cut off by the decompilation budget)"
            if decompiled.truncated or shown < total else f" - {shown} functions")
    lines = [
        f"## Decompiled native code (Ghidra, {decompiled.language or 'unknown target'}){note}",
        _DECOMPILATION_PREAMBLE,
        "",
    ]
    for function in sorted(functions, key=rank):
        calls = f" - calls {', '.join(function.calls)}" if function.calls else ""
        lines.append(f"// ---- {function.name} @ {function.entry} ({function.size} bytes){calls}")
        lines += function.code.split("\n")
        lines.append("")
    return lines


_RES_QUALIFIER_RE = re.compile(r"^(values|drawable|layout|color|mipmap|anim|menu)-")

_JADX_BLOCK_START_RE = re.compile(r"/\*+\s*JADX\s+(?:ERROR|WARN|INFO)\b")
_JADX_MARKER = "/* JADX diagnostic collapsed here - decompiler output, not app code */"


def _collapse_jadx_noise(lines: List[str]) -> List[str]:
    """
    Purpose:
        Collapse the decompiler's error comments and stack traces into a marker.

    Parameters:
        lines: The file's lines.

    Returns:
        The lines with noise collapsed.

    Implementation notes:
        JADX writes multi-line error comments and stack traces into the source it emits for methods it could not decompile. Left in, they consume the agent's context and are occasionally reported as findings -- a model reading a stack trace in a source file will sometimes describe it as one. Collapsed to a marker rather than deleted, so the agent can see that something was undecompilable there rather than reading past a silent gap.
    """
    out = list(lines)
    i, n = 0, len(out)
    while i < n:
        if _JADX_BLOCK_START_RE.search(out[i]):
            if "*/" in out[i]:
                out[i] = _JADX_MARKER
                i += 1
                continue
            j = i + 1
            while j < n and "*/" not in out[j]:
                j += 1
            out[i] = _JADX_MARKER
            for k in range(i + 1, min(j, n - 1) + 1):
                out[k] = ""
            i = j + 1
        else:
            i += 1
    return out

_NOT_A_FILE_HINTS = {
    "androidmanifest.xml": (
        "The manifest is not a readable file in this tree - it is already "
        "rendered for you in the 'App resources' block of your context. Read "
        "the components it names instead."),
}

def _is_resource_variant_dir(rel: str) -> bool:
    """
    Purpose:
        Recognise a per-configuration resource directory.

    Parameters:
        rel: The directory path.

    Returns:
        True when it is a configuration variant.

    Implementation notes:
        An app ships the same resources for many densities, locales and orientations. Only the base directory is worth reading; the variants differ in values rather than in structure, and listing them all buries the file tree.
    """
    parts = rel.replace(os.sep, "/").split("/")
    for i, seg in enumerate(parts):
        if seg == "res" and i + 1 < len(parts):
            return bool(_RES_QUALIFIER_RE.match(parts[i + 1]))
    return False

class AgentTools:
    """
    Purpose:
        The bounded read-only tool surface the static agent uses.

    Attributes:
        root: The decompiled tree, which every path is confined to.
        profile: The framework profile, selecting extensions and noise filters.

    Invariants:
        No path escapes the tree. No method writes. Every result is bounded.

    Thread-safety:
        One instance per region agent; the read-position state is per instance.
    """
    def __init__(self, jadx_output_dir, profile: SourceProfile = JAVA_KOTLIN,
                 call_graph=None):
        """
        Purpose:
            Construct the tool surface over a decompiled tree.

        Parameters:
            jadx_output_dir: The decompiled tree.
            profile: The framework profile, selecting extensions and noise filters.
            call_graph: The call graph backing the reachability queries; None disables them.

        Postconditions:
            The root is resolved, so containment checks compare against a real path rather than one that could still traverse.
        """
        self.root = Path(jadx_output_dir).resolve()
        self.profile = profile
        self.call_graph = call_graph
        self._read_progress: Dict[str, int] = {}
        self._native_documents: Dict[str, object] = {}
        self._basename_index: Optional[Dict[str, List[str]]] = None

    def _suggest(self, rel_path: str) -> str:
        """
        Purpose:
            Suggest a correction when the agent asked for a path that does not exist.

        Parameters:
            rel_path: The requested path.

        Returns:
            A suggestion, or an empty string.

        Implementation notes:
            A near-miss path is the commonest agent mistake -- a missing prefix, a wrong separator, a guessed directory. Suggesting the closest real path turns a wasted step into a corrected one, which matters directly because the step budget is tight.
        """
        name = Path((rel_path or "").strip()).name.lower()
        if not name:
            return ""
        if self._basename_index is None:
            index: Dict[str, List[str]] = {}
            try:
                for path in self.root.rglob("*"):
                    if not path.is_file():
                        continue
                    rel = self._rel(path)
                    if self._is_framework(rel):
                        continue
                    entries = index.setdefault(path.name.lower(), [])
                    if len(entries) < 8:
                        entries.append(rel)
            except OSError:
                index = {}
            self._basename_index = index
        matches = self._basename_index.get(name) or []
        if not matches:
            return ""
        listed = ", ".join(matches[:5])
        return f" Did you mean: {listed}"

    def _resolve(self, rel_path: str) -> Path:
        """
        Purpose:
            Resolve a requested path within the decompiled tree, refusing anything that escapes it.

        Parameters:
            rel_path: The requested path.

        Returns:
            The resolved path.

        Raises:
            ValueError: When the path resolves outside the tree.

        Security considerations:
            This is the containment control for the whole tool surface. The path is fully resolved first and then checked against the resolved root, so traversal sequences and symlinked directories are both caught -- a comparison on the unresolved string would miss both. A leading separator is stripped, so a cited absolute path is treated as relative rather than escaping immediately.
        """
        rel_path = (rel_path or "").strip().lstrip("/")
        candidate = (self.root / rel_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"path escapes sandbox: {rel_path!r}")
        return candidate

    def _rel(self, path: Path) -> str:
        """
        Purpose:
            Express a path relative to the tree, for display.

        Parameters:
            path: The path.

        Returns:
            The relative path, or the original when it lies outside.
        """
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def _is_framework(self, rel: str) -> bool:
        """
        Purpose:
            Recognise framework and generated files the agent should not spend steps on.

        Parameters:
            rel: The file's relative path.

        Returns:
            True when the file is noise.

        Implementation notes:
            Filters by the profile's own noise fragments, so each framework excludes its own libraries, and additionally filters the Android resource variants that would otherwise dominate a listing.
        """
        probe = "/" + rel.replace(os.sep, "/")
        if any(frag in probe for frag in self.profile.noise_fragments):
            return True
        if not self.profile.android_resource_filters:
            return False
        if "/res/" not in probe:
            return False
        if is_framework_layout_file(Path(rel).name):
            return True
        return _is_resource_variant_dir(rel)

    def is_framework_path(self, rel: str) -> bool:
        """
        Purpose:
            Tell code outside the tool surface whether a path is framework or generated noise under this profile.

        Parameters:
            rel: The file's relative path.

        Returns:
            True when the file is noise.

        Implementation notes:
            The review pass picks its files from the graph and the leads rather than from a listing, so it needs the same filter the listings apply, without reaching into the private helper.
        """
        return self._is_framework(rel)

    def list_files(self, path: str = "") -> str:
        """
        Purpose:
            List the files and directories at a path.

        Parameters:
            path: The directory to list; the tree root when omitted.

        Returns:
            The listing, or an error the agent can act on.

        Implementation notes:
            Framework and generated entries are filtered out, and the result is bounded. A raw listing of a decompiled tree is thousands of entries of mostly library code, which would exhaust the agent's context before it read anything.
        """
        try:
            base = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not base.exists():
            return f"ERROR: not found: {path}"
        if base.is_file():
            return f"{self._rel(base)} ({base.stat().st_size} bytes) [file]"

        entries = []
        for child in sorted(base.iterdir()):
            rel = self._rel(child)
            if child.is_dir():
                entries.append(f"{rel}/  [dir]")
            else:
                entries.append(f"{rel}  ({child.stat().st_size} bytes)")
        if len(entries) > MAX_LIST_ENTRIES:
            extra = len(entries) - MAX_LIST_ENTRIES
            entries = entries[:MAX_LIST_ENTRIES] + [f"... (+{extra} more)"]
        return "\n".join(entries) if entries else "(empty directory)"

    def _page(self, key: str, lines: List[str], start_line: Optional[int], tool: str) -> str:
        """
        Purpose:
            Return the next bounded page of a line-oriented document, with a line-number gutter, remembering where the reader stopped.

        Parameters:
            key: Identifies the document, so each one keeps its own read position.
            lines: The document's lines.
            start_line: Where to start; continues from the last page when omitted.
            tool: The tool name the continuation hint tells the agent to call again.

        Returns:
            The numbered page, with a continuation hint when more remains, or a note that the end was already reached.

        Implementation notes:
            Shared by read_file and the decompiled view of inspect_native, so both page identically and the agent learns one convention. A single line longer than MAX_LINE_CHARS is cut with a note saying so: a page always includes at least one whole line, and minified JavaScript carries lines of over a hundred thousand characters, so without the cap one read of a bundle would flood the agent's context. A document small enough to fit in one page restarts from the top when asked for again, since re-showing it costs no more than the note would.
        """
        total_lines = len(lines)
        first_line = max(1, start_line) if start_line is not None else self._read_progress.get(key, 1)

        if first_line > total_lines:
            total_chars = sum(len(l) + 1 for l in lines)
            if start_line is None and total_chars <= MAX_READ_CHARS:
                first_line = 1
            else:
                return (
                    f"NOTE: already read to the end of this file - {total_lines} lines "
                    "total, nothing more to show. Pass start_line to jump elsewhere if "
                    "needed."
                )

        selected: List[str] = []
        used_chars = 0
        last_line = first_line - 1
        for lineno in range(first_line, total_lines + 1):
            line_text = lines[lineno - 1]
            if len(line_text) > MAX_LINE_CHARS:
                line_text = (line_text[:MAX_LINE_CHARS]
                             + f" ... [line truncated: {len(line_text)} chars; search_code finds text inside it]")
            entry_len = len(line_text) + 1
            if selected and used_chars + entry_len > MAX_READ_CHARS:
                break
            selected.append(line_text)
            used_chars += entry_len
            last_line = lineno

        self._read_progress[key] = last_line + 1

        width = len(str(total_lines))
        numbered = "\n".join(
            f"{lineno:>{width}}| {line}"
            for lineno, line in zip(range(first_line, last_line + 1), selected)
        )
        if last_line < total_lines:
            numbered += (
                f"\n... (showing lines {first_line}-{last_line} of {total_lines}; call "
                f"{tool} again on this path to continue from line {last_line + 1}, "
                f"or pass start_line to jump elsewhere)"
            )
        return numbered

    def read_file(self, path: str, start_line: Optional[int] = None) -> str:
        """
        Purpose:
            Read a file, in bounded pages, with line numbers.

        Parameters:
            path: The file to read.
            start_line: Where to start; continues from the last read when omitted.

        Returns:
            The numbered page, or an error the agent can act on.

        Implementation notes:
            The read position is remembered per file, so an agent asking to read the same file again continues rather than restarting. Without that, reading a long file would loop over its opening page until the step budget ran out. Line numbers are included because a finding has to cite one, and a model counting lines itself gets it wrong. Decompiler noise is collapsed first, so the page the agent sees is code rather than error comments. A directory is listed rather than refused, since asking to read one is an easy mistake and listing it is what the agent wanted next anyway. Reading past the end reports that rather than returning empty, so the agent knows it has finished the file instead of re-reading it.

        Security considerations:
            The path is confined to the decompiled tree. Decoding is lenient, since decompiled output can contain undecodable bytes.
        """
        try:
            target = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if target.is_dir():
            return self.list_files(path)
        if not target.exists() or not target.is_file():
            hint = _NOT_A_FILE_HINTS.get(Path((path or "").strip()).name.lower())
            if hint:
                return f"ERROR: not a file: {path}. {hint}"
            return f"ERROR: not a file: {path}.{self._suggest(path)}"
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return f"ERROR: could not read {path}: {e}"

        lines = _collapse_jadx_noise(content.splitlines()) or [""]
        return self._page(str(target), lines, start_line, "read_file")

    def inspect_native(self, path: str, start_line: Optional[int] = None) -> str:
        """
        Purpose:
            Summarise a native library: its security signals, its decompiled C when Ghidra is configured, and its symbols.

        Parameters:
            path: The library.
            start_line: Where to start in the decompiled view; continues from the last page when omitted.

        Returns:
            The summary or the next page of it, or an error.

        Implementation notes:
            With Ghidra configured, the view is the signals, then the decompiled functions with JNI entry points first, then the symbol table, paged exactly like read_file so a large library can be read through rather than cut off. The decompilation is what lets the agent follow a Java string from GetStringUTFChars into a strcpy or a comparison against a constant, which a symbol table cannot show. Without Ghidra, or when it cannot decompile this library, the output is the symbols and signals as before, bounded to one page, with a line saying why there is no code so the agent does not present inferences as something it read. The symbol dump needs objdump; the string scan and the signals derived from it are pure Python, so they are produced even where objdump is absent rather than failing the whole inspection. The built view is cached per library for the life of this tool surface, so paging does not repeat the work.
        """
        try:
            target = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists() or not target.is_file():
            return f"ERROR: not a file: {path}"
        if target.suffix != ".so":
            return f"ERROR: not a native library (.so): {path}"

        document = self._cached_native_document(target, path)
        if isinstance(document, str):
            return document
        return self._page(f"native:{target}", document, start_line, "inspect_native")

    def native_view(self, path: str) -> Optional[List[str]]:
        """
        Purpose:
            Return the decompiled view of a native library exactly as inspect_native numbers it, so a line the agent cited can be turned back into code.

        Parameters:
            path: The library, relative to the tree.

        Returns:
            The view's lines, or None when the path is not a library in the tree or no decompiled code is available for it.

        Side effects:
            Runs objdump, and Ghidra if this library has not been decompiled in this process yet.

        Implementation notes:
            Report enrichment calls this after the agent has finished, so the Ghidra run is normally a cache hit. Line numbers stay stable because the view is built the same way every time from the same library: the signals and the decompiled functions come first, and only the symbol table, which comes last, carries the path string.
        """
        try:
            target = self._resolve(path)
        except ValueError:
            return None
        if not target.is_file() or target.suffix != ".so":
            return None
        document = self._cached_native_document(target, path)
        return None if isinstance(document, str) else list(document)

    def _cached_native_document(self, target: Path, path: str):
        """
        Purpose:
            Build a library's native view once per tool surface and reuse it.

        Parameters:
            target: The resolved library.
            path: The path as the caller gave it.

        Returns:
            What _native_document returns for this library.
        """
        key = f"native:{target}"
        document = self._native_documents.get(key)
        if document is None:
            document = self._native_document(target, path)
            self._native_documents[key] = document
        return document

    def _native_document(self, target: Path, path: str):
        """
        Purpose:
            Build the view inspect_native pages through.

        Parameters:
            target: The resolved library.
            path: The path as the agent gave it, used in place of the absolute one in tool output.

        Returns:
            A list of lines when decompiled code is available, otherwise the finished single-page text.

        Side effects:
            Runs objdump, and Ghidra on first request for this library.
        """
        if shutil.which("objdump") is None:
            symbols = ""
            header = "## Dynamic symbols\n(objdump is not installed on this host - symbols unavailable)"
        else:
            try:
                result = subprocess.run(
                    ["objdump", "-T", str(target)],
                    capture_output=True, text=True, timeout=15)
                symbols = ((result.stdout or "").strip()
                           or (result.stderr or "").strip()).replace(str(target), path, 1)
            except Exception as e:
                symbols = ""
                header = f"## Dynamic symbols\n(objdump failed: {e})"
            else:
                header = "## Dynamic symbols\n" + (symbols or "(no symbols found)")

        try:
            strings = _extract_native_strings(target.read_bytes())
        except Exception:
            strings = []

        decompiled = decompile_native_library(target)
        imports = sorted({c for f in decompiled.functions for c in f.calls})
        signals = _native_signal_summary("\n".join([symbols] + imports), strings)

        code_lines = _render_decompilation(decompiled)
        if not code_lines:
            reason = decompiled.error or "Ghidra decompiled no functions from this library"
            output = (header + ("\n" + signals if signals else "")
                      + f"\n\n## Decompiled code\n(unavailable: {reason}. Only the symbols and "
                        "strings above were read - do not describe function bodies.)")
            if len(output) > MAX_READ_CHARS:
                output = output[:MAX_READ_CHARS] + f"\n... [truncated at {MAX_READ_CHARS} chars]"
            return output

        lines: List[str] = []
        if signals:
            lines += signals.strip("\n").split("\n") + [""]
        lines += code_lines + [""] + header.split("\n")
        return lines

    def search_code(self, pattern: str, path: str = "") -> str:
        """
        Purpose:
            Search the decompiled source for a pattern.

        Parameters:
            pattern: The search pattern.
            path: The subtree to search; everything when omitted.

        Returns:
            The matches with their locations, or an error.

        Implementation notes:
            This is how the agent navigates: it searches for a sink or an API and then reads around the hits, rather than reading files in order. Framework files are excluded and results are bounded, so a common term returns a usable sample rather than thousands of hits from bundled libraries. A search given an explicit path also covers resource files such as the manifest: without that, a search scoped to AndroidManifest.xml silently returned no matches, which an agent reasonably read as the app exporting nothing.
        """
        if not pattern:
            return "ERROR: empty pattern"
        try:
            base = self._resolve(path) if path else self.root
        except ValueError as e:
            return f"ERROR: {e}"
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        matches: List[str] = []
        for file_path in self._iter_source_files(base, include_resources=bool(path)):
            rel = self._rel(file_path)
            if not path and self._is_framework(rel):
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        if regex.search(line):
                            snippet = line.strip()[:200]
                            matches.append(f"{rel}:{lineno}: {snippet}")
                            if len(matches) >= MAX_SEARCH_MATCHES:
                                matches.append(f"... (stopped at {MAX_SEARCH_MATCHES} matches)")
                                return "\n".join(matches)
            except Exception:
                continue
        return "\n".join(matches) if matches else "(no matches)"


    _NO_GRAPH = ("ERROR: no call graph is available for this app (it is built "
                 "from the DEX, and could not be). Use search_code instead.")

    def _method_or_error(self, query: str):
        """
        Purpose:
            Resolve a method query to a graph node, or produce an error naming the near misses.

        Parameters:
            query: The method the agent named.

        Returns:
            The node, or an error message.

        Implementation notes:
            Listing the near misses is what makes the failure recoverable: an agent that named a method imprecisely can pick the right one from the alternatives rather than guessing again.
        """
        hits = self.call_graph.find(query)
        if not hits:
            return None, (f"ERROR: no app method matches {query!r}. Names are "
                          "matched on the method name, the class, or a full key "
                          "like 'Lcom/x/Foo;->bar(I)V'. Only the app's own code "
                          "is in the graph - framework and SDK methods are not.")
        if len(hits) > 1:
            listed = "\n".join(f"  {n.key}   ({n.file})" for n in hits[:12])
            more = f"\n  … and {len(hits) - 12} more" if len(hits) > 12 else ""
            return None, (f"{plural(len(hits), 'app method')} match {query!r}; ask "
                          f"again with one of these exact keys:\n{listed}{more}")
        return hits[0], ""

    def callees(self, method: str) -> str:
        """
        Purpose:
            List what a method calls.

        Parameters:
            method: The method.

        Returns:
            The callees, or an error.
        """
        if self.call_graph is None:
            return self._NO_GRAPH
        node, err = self._method_or_error(method)
        if node is None:
            return err
        out = self.call_graph.callees(node.key)
        if not out:
            reached = (f"; it does reach {', '.join(node.sinks)} APIs outside "
                       "the app." if node.sinks else ".")
            return (f"{node.label} ({node.file}) calls nothing else in the "
                    f"app's own code{reached}")
        lines = [f"{node.label} ({node.file}) calls:"]
        for n in out:
            sink = ("   [" + "; ".join(f"{f}: {', '.join(v[:3])}"
                                       for f, v in n.sinks.items()) + "]") if n.sinks else ""
            lines.append(f"  -> {n.label}  ({n.file}){sink}")
        return "\n".join(lines)

    def callers(self, method: str) -> str:
        """
        Purpose:
            List what calls a method.

        Parameters:
            method: The method.

        Returns:
            The callers, or an error.

        Implementation notes:
            The query the agent uses to establish reachability: walking back from a sink toward something an attacker can reach.
        """
        if self.call_graph is None:
            return self._NO_GRAPH
        node, err = self._method_or_error(method)
        if node is None:
            return err
        out = self.call_graph.callers(node.key)
        if not out:
            return (f"Nothing in the app's own code calls {node.label} "
                    f"({node.file}). It is either an entry point the platform "
                    "invokes, or dead code.")
        lines = [f"{node.label} ({node.file}) is called by:"]
        for n in out:
            mark = "  [ENTRY POINT]" if n.is_entry else ""
            lines.append(f"  <- {n.label}  ({n.file}){mark}")
        return "\n".join(lines)

    def call_path(self, source: str, target: str) -> str:
        """
        Purpose:
            Show a call path between two methods.

        Parameters:
            source: The starting method.
            target: The method to reach.

        Returns:
            The path, or a statement that none was found within the search bounds.

        Implementation notes:
            A concrete path is the strongest evidence a finding can carry, because a reader can follow it through their own code. The absence of one is reported as bounded rather than absolute, so the agent does not report unreachability the search merely failed to disprove.
        """
        if self.call_graph is None:
            return self._NO_GRAPH
        from .call_graph import render_path

        src, err = self._method_or_error(source)
        if src is None:
            return err
        dst, err = self._method_or_error(target)
        if dst is None:
            return err
        paths = self.call_graph.paths(src.key, dst.key)
        if not paths:
            callers = self.call_graph.callers(dst.key)
            hint = ""
            if callers:
                hint = ("\nIt is reached from: "
                        + ", ".join(n.label for n in callers[:6]))
            return (f"No call path from {src.label} to {dst.label} within the "
                    f"app's own code. {dst.label} is not reachable from that "
                    f"context, so its other callers are the relevant ones.{hint}")
        out = [f"{plural(len(paths), 'path')} from {src.label} to {dst.label}:"]
        for i, path in enumerate(paths, 1):
            out.append(f"\n[path {i}]")
            out.append(render_path(self.call_graph, path))
        return "\n".join(out)

    def find_method(self, query: str) -> str:
        """
        Purpose:
            Find methods matching a query.

        Parameters:
            query: The search text.

        Returns:
            The matches, or an error.
        """
        if self.call_graph is None:
            return self._NO_GRAPH
        hits = self.call_graph.find(query)
        if not hits:
            return (f"No app method matches {query!r}. Only the app's own code is "
                    "in the graph - framework and SDK methods are not.")
        lines = [f"{plural(len(hits), 'app method')} matching {query!r}:"]
        for n in hits:
            mark = "  [ENTRY POINT]" if n.is_entry else ""
            sink = ("  sinks: " + ", ".join(n.sinks)) if n.sinks else ""
            lines.append(
                f"  {n.key}\n      {n.file} - {plural(len(n.callers), 'caller')}, "
                f"{plural(len(n.callees), 'callee')}{mark}{sink}")
        return "\n".join(lines)

    def entry_points(self) -> str:
        """
        Purpose:
            List the methods reachable from outside the app.

        Returns:
            The entry points.

        Implementation notes:
            Where an agent starts when it wants to establish whether anything an attacker controls reaches a sink it has found.
        """
        if self.call_graph is None:
            if self.profile.key == "flutter":
                return self._flutter_entry_points()
            if self.profile.key == "react_native":
                return self._react_native_entry_points()
            return self._NO_GRAPH
        nodes = self.call_graph.entry_points()
        if not nodes:
            return "No entry-point methods were identified in the app's own code."
        return "\n".join(
            [f"{plural(len(nodes), 'entry point')} - attacker-reachable, "
             "start here:"]
            + [f"  {n.key}   ({n.file})" for n in nodes])

    def _flutter_entry_points(self) -> str:
        """
        Purpose:
            Answer an entry-point request for a Flutter app, which has no DEX call graph for the Dart side.

        Returns:
            Where a Flutter app is entered: its main library, its platform channels and its exported components.

        Implementation notes:
            Agents ask for entry points first by habit, and on a Flutter app the call-graph answer was an error that cost a step and taught nothing. The real entry points are the app's main() library, the platform-channel calls the overview maps, and the manifest's exported components, so the answer names those files instead. The search is bounded to the two places a main library can be.
        """
        mains = sorted(self._rel(p) for p in self.root.glob("asm/*/main.dart"))
        mains += sorted(self._rel(p) for p in self.root.glob("dart_source/lib/main.dart"))
        lines = ["Flutter app - the Dart code is not in the DEX, so there is no method call "
                 "graph. Its entry points are:"]
        if mains:
            lines.append("  main() and the first screen: " + ", ".join(mains[:4]))
        lines.append("  platform channels: see the 'Flutter scan overview' at the top of your "
                     "context (each Dart call site and the Java file answering it)")
        if (self.root / "platform/resources/AndroidManifest.xml").is_file():
            lines.append("  exported components and deep links: "
                         "platform/resources/AndroidManifest.xml (read it, or search it for "
                         "'exported' / 'intent-filter')")
        lines.append("Move between Dart functions by the call annotations "
                     "('; [package:...] Class::method') rather than callers/callees.")
        return "\n".join(lines)

    def _react_native_entry_points(self) -> str:
        """
        Purpose:
            Answer an entry-point request for a React Native app, whose JavaScript has no DEX call graph.

        Returns:
            Where a React Native app is entered: its entry module and root component, its native modules, and its exported components.

        Implementation notes:
            The same reasoning as for Flutter: the useful answer names files rather than reporting that a graph is missing. Native modules are listed through the overview because any JavaScript in the app can call them, which makes them entry points for an attacker who gets JavaScript to run.
        """
        lines = ["React Native app - the JavaScript is not in the DEX, so there is no method call "
                 "graph. Its entry points are:"]
        entry = sorted(self._rel(p) for p in self.root.glob("app_modules/0*.js"))
        if entry:
            lines.append("  the entry module (AppRegistry -> root component): " + ", ".join(entry[:2]))
        lines.append("  native modules: see 'Native modules' in the React Native scan overview - every "
                     "@ReactMethod there is callable by any JS that runs in the app")
        if (self.root / "platform/resources/AndroidManifest.xml").is_file():
            lines.append("  exported components and deep links: platform/resources/AndroidManifest.xml")
        lines.append("Follow each module's '// Dependencies: [...]' header and its require/import ids "
                     "between app_modules files.")
        return "\n".join(lines)

    def file_tree(self) -> str:
        """
        Purpose:
            Show the shape of the decompiled source.

        Returns:
            The tree.

        Implementation notes:
            Given to the agent up front so it can orient itself before spending steps listing directories. Framework paths are excluded and the depth is bounded, since a full tree would not fit and would be mostly library code.
        """
        app_entries, fw_entries = [], []
        for file_path in self._iter_source_files(self.root, include_resources=True):
            rel = self._rel(file_path)
            try:
                size = file_path.stat().st_size
            except OSError:
                size = 0
            line = f"{rel} ({size}b)"
            (fw_entries if self._is_framework(rel) else app_entries).append(line)

        entries = app_entries
        if len(entries) < MAX_TREE_ENTRIES:
            entries = entries + fw_entries[: MAX_TREE_ENTRIES - len(entries)]
        truncated = (len(app_entries) + len(fw_entries)) - len(entries)
        out = entries[:MAX_TREE_ENTRIES]
        if truncated > 0:
            out.append(f"... (+{truncated} more files not shown; use list_files/search_code)")

        natives = self._native_library_summary()
        if natives:
            out = out + ["", "## Native libraries (inspect_native to list symbols)"] + natives
        return "\n".join(out) if out else "(no source files found)"

    def _native_library_summary(self) -> List[str]:
        """
        Purpose:
            Summarise the native libraries present.

        Returns:
            The summary lines.

        Implementation notes:
            Included in the agent's opening context so it knows native code exists and can inspect it, rather than concluding from the Java alone that it has seen the whole app.
        """
        seen = {}
        for so_path in sorted(self.root.rglob("*.so")):
            name = so_path.name
            if name not in seen:
                seen[name] = so_path
        lines = []
        for name, so_path in sorted(seen.items()):
            try:
                size = so_path.stat().st_size
            except OSError:
                size = 0
            lines.append(f"{self._rel(so_path)} ({size}b)")
        return lines

    def app_source_files(self) -> List[str]:
        """
        Purpose:
            List the application's own source files.

        Returns:
            The file paths.

        Implementation notes:
            Filtered to the profile's source extensions and excluding framework paths, so this is the set of files actually worth analysing.
        """
        out: List[str] = []
        for fp in self._iter_source_files(self.root):
            rel = self._rel(fp)
            if self._is_framework(rel):
                continue
            stem = Path(rel).stem
            if stem in self.profile.generated_stems:
                continue
            if any(stem.startswith(p) for p in self.profile.generated_stem_prefixes):
                continue
            out.append(rel)
        return sorted(out)

    def app_resource_files(self) -> List[str]:
        """
        Purpose:
            List the application's own resource files.

        Returns:
            The file paths.

        Implementation notes:
            Kept separate from the sources because resources are analysed differently -- they hold strings and configuration rather than logic -- and because the configuration variants have to be filtered out first.
        """
        out: List[str] = []
        for rel_glob in self.profile.resource_globs:
            candidate = self.root / rel_glob
            if candidate.is_dir():
                for f in sorted(candidate.iterdir()):
                    if f.is_file():
                        try:
                            out.append(f"{self._rel(f)} ({f.stat().st_size}b)")
                        except OSError:
                            out.append(self._rel(f))
            elif candidate.is_file():
                try:
                    out.append(f"{self._rel(candidate)} ({candidate.stat().st_size}b)")
                except OSError:
                    out.append(self._rel(candidate))
        if len(out) > MAX_RESOURCE_ENTRIES:
            truncated = len(out) - MAX_RESOURCE_ENTRIES
            out = out[:MAX_RESOURCE_ENTRIES]
            out.append(f"... (+{truncated} more resource files not shown; use list_files)")
        return out

    def manifest_summary(self) -> str:
        """
        Purpose:
            Summarise the manifest for the agent's opening context.

        Returns:
            The summary.

        Implementation notes:
            Provided up front because nearly every reachability question starts with what the app exports, and having the agent discover that by reading the manifest would cost it steps at the beginning of every region.
        """
        for rel in self.profile.summary_candidates:
            candidate = self.root / rel
            if candidate.is_file():
                return self.read_file(self._rel(candidate))
        return self.profile.summary_missing

    def _iter_source_files(self, base: Path, include_resources: bool = False):
        """
        Purpose:
            Walk the tree yielding the files worth analysing.

        Parameters:
            base: Where to start.
            include_resources: Whether to include resource files.

        Returns:
            The matching files.

        Implementation notes:
            One traversal shared by the listing helpers, so the noise filtering and extension rules are applied identically wherever files are enumerated.
        """
        exts = set(self.profile.source_exts)
        if include_resources:
            exts |= set(self.profile.resource_exts)
        if base.is_file():
            if base.suffix in exts:
                yield base
            return
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                if Path(name).suffix in exts:
                    yield Path(dirpath) / name
