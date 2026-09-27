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

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...utils.verbose import plural
from ...utils.xml_utils import is_framework_layout_file
from .patterns import find_endpoints, find_secrets
from .profiles import JAVA_KOTLIN, SourceProfile

MAX_READ_CHARS = 12000
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
        total_lines = len(lines)
        key = str(target)
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
                f"read_file again on this path to continue from line {last_line + 1}, "
                f"or pass start_line to jump elsewhere)"
            )
        return numbered

    def inspect_native(self, path: str) -> str:
        """
        Purpose:
            Summarise a native library: its symbols and strings.

        Parameters:
            path: The library.

        Returns:
            The summary, or an error.

        Implementation notes:
            Native code cannot be decompiled here, but its exported symbols and string constants still reveal what it does and what it embeds -- which is often where a Java-side finding's other half lives. The symbol dump needs objdump; the string scan and the signals derived from it (risky imports, the JNI surface, endpoints, credential candidates) are pure Python, so they are produced even where objdump is absent rather than failing the whole inspection. Bounded everywhere, since a library holds far more strings than the agent can use, and the signals are leads for the native library and evidence skills to weigh rather than scored findings.
        """
        try:
            target = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists() or not target.is_file():
            return f"ERROR: not a file: {path}"
        if target.suffix != ".so":
            return f"ERROR: not a native library (.so): {path}"

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

        signals = _native_signal_summary(symbols, strings)
        output = header + ("\n" + signals if signals else "")
        if len(output) > MAX_READ_CHARS:
            output = output[:MAX_READ_CHARS] + f"\n... [truncated at {MAX_READ_CHARS} chars]"
        return output

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
            This is how the agent navigates: it searches for a sink or an API and then reads around the hits, rather than reading files in order. Framework files are excluded and results are bounded, so a common term returns a usable sample rather than thousands of hits from bundled libraries.
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
        for file_path in self._iter_source_files(base):
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
            return self._NO_GRAPH
        nodes = self.call_graph.entry_points()
        if not nodes:
            return "No entry-point methods were identified in the app's own code."
        return "\n".join(
            [f"{plural(len(nodes), 'entry point')} - attacker-reachable, "
             "start here:"]
            + [f"  {n.key}   ({n.file})" for n in nodes])

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
