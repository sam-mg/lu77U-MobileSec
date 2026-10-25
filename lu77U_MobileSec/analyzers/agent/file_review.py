#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.file_review

Purpose:
    Give every flagged app-owned file one focused, single-request security review after the agent's investigation, so a finding no longer depends on the agent having chosen to open the file.

Responsibilities:
    Choose and order the files to review, render each as numbered lines (Blutter disassembly as a digest of its declarations, strings and calls), pack small files together and split large ones, ask the model for findings per part in parallel, and tag what comes back with its provenance.

Dependencies:
    concurrent.futures, contextvars, pathlib, the agent loop's parsing helpers, the skills loader, the Flutter disassembly digest, the response schema and parser.

Implementation notes:
    The investigating agent decides what to read and when to stop, and a smaller model routinely stops after a handful of files with the rest of the flagged code unread, or reads a file and never reports what was in it. Benchmark scans showed exactly that: a Flutter app whose agent read three of six screens and reported two of ten known issues. This pass is the counterweight: bounded, predictable, one request per part, with no tools to wander off with. It does not replace the agent, which is what follows data across files; it guarantees that every flagged file was looked at once with nothing else competing for attention. Its findings go through the same validation as the agent's, so a weak or wrong one is refuted or downgraded there rather than trusted here.

Security considerations:
    File contents are untrusted APK-derived text placed into a prompt. The reply is parsed as data and nothing in it is executed; cited paths are resolved later by the same confined resolver as every other finding.
"""

import contextvars
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .agent_loop import _FORCED_REPORT_MAX_TOKENS, _norm_path, _salvage_findings, _strip_thinking_tokens, context_file
from .native_loading import manifest_package
from .skills_loader import CORE_SKILL, CORE_SKILLS, load_skills
from .tools import AgentTools
from ..flutter.recovered import PoolEntry, digest_disassembly, parse_object_dump, parse_object_pool
from ..layout import PLATFORM_DIR
from ...ai.schema import VULNERABILITY_SCHEMA
from ...utils.cancellation import ScanCancelled
from ...utils.response_parser import ResponseParser
from ...utils.verbose import plural, verbose_print

ORIGIN = "file_review"
REGION_KEY = "file-review"
PART_CHARS = 32000
MAX_LINE_CHARS = 800
CONTEXT_CHARS = 4000
REVIEW_WORKERS = 4
MAX_NATIVE_CHARS = 60000
REVIEW_SKILLS = ("finding_quality", "vulnerability_classes", "business_logic_abuse", "storage_crypto_review",
                 "deeplink_endpoint_analysis")

_REVIEW_SYSTEM = """You are a mobile application security reviewer. You are shown one or more \
files from a decompiled Android app, each line prefixed with its real line number. Review \
them for security vulnerabilities and output a JSON array of findings.

Check the app's own logic for:
- secrets, keys, tokens, passwords, PINs or flags written into the code - including ones \
hidden by encoding and decoded at runtime (an XOR with a constant, shifted char codes, an \
integer array turned into a string, base64) and ones held in a const object's fields: \
obfuscation is not protection, report the secret and where it is decoded
- credentials, tokens, account or personal data stored unencrypted (shared preferences, \
AsyncStorage, SQLite, files, temporary files, external storage) or written to logs
- SQL, shell commands, file paths or URLs built from input by concatenation or interpolation
- WebViews that load attacker-influenced URLs, allow file or universal access, or expose a \
JavaScript bridge or message handler that trusts any page
- exported components, deep links and Intent extras that perform a sensitive action or \
reveal data without checking the caller or asking the user to confirm - including a link \
handler that reads parameters (amount, recipient, URL, target) and opens a screen which \
then acts on them by itself, in initState, a post-frame callback or useEffect, before the \
user presses anything
- authorization decided on the device: premium, VIP, admin or unlock state read from local \
storage or settled by a client-side comparison
- local authentication that can be guessed or bypassed: a short PIN with no attempt limit, a \
hardcoded or default PIN or password
- plain HTTP endpoints carrying credentials or account data; TLS certificate or hostname \
validation switched off; certificate pinning that falls back to an unpinned client
- weak or misused cryptography: ECB mode, a static or hardcoded key or IV, broken hashes \
protecting secrets, predictable randomness
- dynamic code execution: eval, new Function, code loaded from storage or the network
- hidden debug or developer screens that expose secrets or privileged actions
- unsafe native memory handling (strcpy, sprintf, unchecked lengths) on data from outside
- screens showing sensitive data with no screenshot protection (Informational or Low)
- client-side protections - root, emulator or debugger detection, integrity or tamper \
checks, certificate pinning: report each once at Informational (vuln_class BUILD-04), \
naming what it checks and the single call a hook would flip, since a check the device \
decides is context for the other findings rather than a boundary

Rules:
- The files in one request belong to the same app: follow calls between them. A link \
handler in one file and the screen it opens in another are one flow; read what that screen \
does when it starts (initState, a post-frame callback, useEffect) before deciding the link \
only fills in a form.
- Report only what the code shown demonstrates. Set "file" to the path exactly as written in \
the file's header and "line" to the real line number of the vulnerable line.
- One finding per distinct issue. Do not report the same issue again at another line.
- Ignore third-party library internals, layout code and harmless display strings.
- Score "cvss_vector" from the attacker's real position: remote (AV:N), another app on the \
same device (AV:L, PR:N), or someone holding the unlocked device or with root on it \
(AV:P or AV:L with PR:H). Severity is computed from the vector.
- Set "vuln_class" to the catalogue code that fits.
- If nothing in these files is a vulnerability, output [].
Output ONLY the JSON array - no prose, no code fences."""

_NATIVE_NOTE = ("native library, shown as the decompiled view the agent's inspect_native tool gives: "
                "Ghidra pseudo-C with JNI entry points first, then the symbols; line numbers are the view's")

_DIGEST_NOTE = ("compiled Dart, shown as a digest: only declarations, string loads, booleans, "
                "constants and resolved calls are listed, at their real line numbers. "
                "Instance_X {\"...\"} shows the strings inside a const object; "
                "\"int array\" is a constant array (with its characters when printable); "
                "\"xor with\" is an XOR by a constant; \"closure ->\" names the function a closure runs "
                "and what it calls; \"return\" and \"catch:\" mark where a function returns and "
                "where an exception handler begins")


def review_targets(code_graph, tools: AgentTools, leads: Optional[Sequence[Any]] = None) -> List[str]:
    """
    Purpose:
        Choose the files the review pass covers, most important first.

    Parameters:
        code_graph: The code graph, or None when no graph was built.
        tools: The tool surface, for the profile's extensions, framework filter and the app's file list.
        leads: The rule engine's leads.

    Returns:
        Relative paths, lead files first, then exported or role-bearing classes, then the remaining flagged files.

    Implementation notes:
        The set is the same one the agent is steered towards - the graph's flagged files plus every lead file - so the review checks the agent's assignment rather than inventing a new one. Ordering matters because the part budget can cut the list: a file the rule engine already found something in, or an entry point reachable from outside the app, is worth more than an internal helper. Native libraries are excluded since they have their own inspection path, and framework files are excluded by the profile's own noise filter. For a Flutter or React Native app the Java/Kotlin platform layer is reviewed only under the app's own package: the rest is plugin code, usually R8-obfuscated beyond recognition, which a channel name alone flags and which would spend most of the budget producing findings about libraries rather than the app.
    """
    root = Path(tools.root)
    exts = set(tools.profile.source_exts)
    native = {_norm_path(lib.path) for lib in getattr(code_graph, "native_libs", None) or []}
    lead_files = [_norm_path(lead.file) for lead in leads or [] if getattr(lead, "file", "")]
    entry_files: List[str] = []
    other_files: List[str] = []
    if code_graph is not None and getattr(code_graph, "nodes", None):
        for node in code_graph.nodes.values():
            if not (node.flagged and node.source_available and node.file):
                continue
            bucket = entry_files if node.role != "class" else other_files
            bucket.append(_norm_path(node.file))
    else:
        other_files = [_norm_path(rel) for rel in tools.app_source_files()]

    platform_prefix = f"{PLATFORM_DIR}/sources/"
    package = manifest_package(root) if tools.profile.key != "java_kotlin" else ""
    app_platform = platform_prefix + package.replace(".", "/") + "/" if package else ""

    ordered: List[str] = []
    seen = set()
    for rel in [*lead_files, *sorted(entry_files), *sorted(other_files)]:
        if not rel or rel in seen or rel in native:
            continue
        seen.add(rel)
        if PurePosixPath(rel).suffix not in exts or tools.is_framework_path(rel):
            continue
        if tools.profile.key != "java_kotlin" and rel.startswith(platform_prefix) and not (
                app_platform and rel.startswith(app_platform)):
            continue
        if (root / rel).is_file():
            ordered.append(rel)
    return ordered


def native_review_targets(code_graph) -> List[str]:
    """
    Purpose:
        List the native libraries the review pass covers.

    Parameters:
        code_graph: The code graph, or None.

    Returns:
        The graph's native libraries - the ones the app's own code loads - as relative paths.

    Implementation notes:
        These were left to the agent alone, and two benchmark scans lost every native finding when the agent stopped early or reported without opening the library. Only libraries the app loads are in the graph, so a framework runtime is never reviewed.
    """
    return [_norm_path(lib.path) for lib in getattr(code_graph, "native_libs", None) or [] if getattr(lib, "path", "")]


def render_native(tools: AgentTools, rel: str) -> str:
    """
    Purpose:
        Render a native library the way the agent's inspect_native tool shows it.

    Parameters:
        tools: The tool surface, which builds and caches the view.
        rel: The library's relative path.

    Returns:
        The numbered decompiled view, or the tool's summary page when no decompilation is available; "" when neither can be built.

    Side effects:
        May run Ghidra and objdump through the tool surface, which caches the result for the agent and for enrichment.

    Implementation notes:
        The numbering is the view's own, so a line the reviewer cites resolves through the same native-context step as an agent's citation. The view is bounded, keeping the JNI entry points that come first in it.
    """
    lines = tools.native_view(rel)
    if lines:
        numbered = "\n".join(f"{index}: {line[:MAX_LINE_CHARS]}" for index, line in enumerate(lines, 1))
        return numbered[:MAX_NATIVE_CHARS]
    summary = tools.inspect_native(rel)
    return "" if summary.startswith("ERROR") else summary[:MAX_NATIVE_CHARS]


def render_for_review(rel: str, text: str,
                      objects: Optional[Dict[str, List[str]]] = None,
                      pool: Optional[Dict[str, PoolEntry]] = None) -> Tuple[str, bool]:
    """
    Purpose:
        Turn one file into the numbered text the reviewer reads.

    Parameters:
        rel: The file's relative path.
        text: Its contents.
        objects: Blutter's object dump index, so a digest can show what const objects hold.
        pool: Blutter's object pool index, so a const list's slot can be followed to its objects.

    Returns:
        The rendered text, and whether it is a disassembly digest.

    Implementation notes:
        Blutter disassembly is recognised by its per-function address comments and digested, since raw it is an order of magnitude longer than what it says. Everything else is shown line for line with each line's number, because the reviewer has to cite real lines. A very long line, usually a minified literal, is cut so one line cannot take a whole part.
    """
    if rel.endswith(".dart") and "// ** addr:" in text:
        return digest_disassembly(text, objects, pool), True
    lines = text.splitlines()
    return "\n".join(f"{index}: {line[:MAX_LINE_CHARS]}" for index, line in enumerate(lines, 1)), False


def _load_objects(root: Path) -> Dict[str, List[str]]:
    """
    Purpose:
        Read Blutter's object dump once for the whole pass.

    Parameters:
        root: The analysis root.

    Returns:
        The object index, or an empty one when the app is not a Flutter release build or the dump cannot be read.
    """
    dump = root / "objs.txt"
    if not dump.is_file():
        return {}
    try:
        return parse_object_dump(dump.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {}


def _load_pool(root: Path) -> Dict[str, PoolEntry]:
    """
    Purpose:
        Read Blutter's object pool once for the whole pass.

    Parameters:
        root: The analysis root.

    Returns:
        The pool index, or an empty one when the app is not a Flutter release build or the pool cannot be read.
    """
    dump = root / "pp.txt"
    if not dump.is_file():
        return {}
    try:
        return parse_object_pool(dump.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {}


def _split(rendered: str, limit: int) -> List[str]:
    """
    Purpose:
        Cut one rendered file into slices that each fit a part.

    Parameters:
        rendered: The numbered text.
        limit: The largest slice, in characters.

    Returns:
        The slices, in order; a single slice when the file already fits.

    Implementation notes:
        Cuts fall on line boundaries, so every slice still carries real line numbers and the reviewer can cite into any of them.
    """
    if len(rendered) <= limit:
        return [rendered]
    slices: List[str] = []
    current: List[str] = []
    size = 0
    for line in rendered.split("\n"):
        if current and size + len(line) + 1 > limit:
            slices.append("\n".join(current))
            current, size = [], 0
        current.append(line)
        size += len(line) + 1
    if current:
        slices.append("\n".join(current))
    return slices


def build_parts(entries: Sequence[Tuple[str, str, bool]], limit: int = PART_CHARS) -> List[List[Tuple[str, str, bool]]]:
    """
    Purpose:
        Pack rendered files into review requests of bounded size.

    Parameters:
        entries: (path, rendered text, is digest) for each file, in priority order.
        limit: The most text one request carries.

    Returns:
        The parts, each a list of (path, text, is digest) slices, in priority order.

    Implementation notes:
        Small files share a request and large files are split across several, so request count tracks the amount of code rather than the number of files. A React Native app's own code is often thirty modules of a few hundred bytes each, and one request apiece would spend thirty calls where three suffice. Packing is greedy and preserves order, so the part budget still cuts from the end of the priority list.
    """
    parts: List[List[Tuple[str, str, bool]]] = []
    current: List[Tuple[str, str, bool]] = []
    size = 0
    for rel, rendered, digest in entries:
        for piece in _split(rendered, limit):
            if current and size + len(piece) > limit:
                parts.append(current)
                current, size = [], 0
            current.append((rel, piece, digest))
            size += len(piece)
    if current:
        parts.append(current)
    return parts


def _render_part(part: Sequence[Tuple[str, str, bool]], index: int, total: int, context: str) -> str:
    """
    Purpose:
        Build the request text for one part.

    Parameters:
        part: The (path, text, is digest) slices it carries.
        index: Its 1-based position.
        total: How many parts there are.
        context: The app context shown above the code.

    Returns:
        The prompt.
    """
    blocks = [context, f"## Files under review (part {index} of {total})"]
    for rel, text, digest in part:
        note = f" - {_DIGEST_NOTE}" if digest else ""
        if rel.endswith(".so"):
            note = f" - {_NATIVE_NOTE}"
        blocks.append(f"### {rel}{note}\n```\n{text}\n```")
    blocks.append("Report the vulnerabilities in these files as a JSON array, or [] if there are none.")
    return "\n\n".join(blocks)


def _attach_file(finding: Dict[str, Any], part_files: Sequence[str]) -> bool:
    """
    Purpose:
        Pin a finding's cited file to one of the files the request actually showed.

    Parameters:
        finding: The finding, updated in place.
        part_files: The paths shown in the request.

    Returns:
        Whether the cited file is one of them.

    Implementation notes:
        A model shown one file often omits the path or writes only its basename. Filling the shown path in, or mapping a basename that matches exactly one shown file, keeps the finding resolvable; a path that matches nothing shown is left as written and recorded as not read, which the evidence gate caps.
    """
    cited = _norm_path(str(finding.get("file") or ""))
    if not cited and len(part_files) == 1:
        finding["file"] = part_files[0]
        return True
    if cited in part_files:
        return True
    name = PurePosixPath(cited).name
    matches = [rel for rel in part_files if PurePosixPath(rel).name == name or rel.endswith("/" + cited)]
    if name and len(matches) == 1:
        finding["file"] = matches[0]
        return True
    return False


def _review_part(provider, system: str, prompt: str, part_files: Sequence[str],
                 parser: ResponseParser, profile=None) -> Optional[List[Dict[str, Any]]]:
    """
    Purpose:
        Send one part for review and return its findings, tagged.

    Parameters:
        provider: The AI provider.
        system: The system prompt.
        prompt: The request text.
        part_files: The paths the request showed.
        parser: The response parser.
        profile: The framework profile, whose summary file every request shows; None treats no file that way.

    Returns:
        The findings, or None when the request failed.

    Side effects:
        Makes one provider request.

    Implementation notes:
        Findings carry the agent's provenance fields so the evidence gates treat them like any other AI finding: the origin names this pass, the region's files-read count is what the request showed, and a finding citing a file the request did not show is marked unread. A malformed reply falls back to salvage, as the forced report does, because losing a part's findings to a stray brace costs more than an imprecise recovery.
    """
    result = provider.analyze(prompt, system_message=system, schema=VULNERABILITY_SCHEMA,
                              max_tokens=_FORCED_REPORT_MAX_TOKENS)
    if not isinstance(result, dict) or "error" in result:
        return None
    raw = _strip_thinking_tokens(result.get("response", "") or "")
    findings = parser.parse_json_response(raw) or _salvage_findings(raw)
    out: List[Dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or finding.get("vulnerability_type") or "").strip()
        if not title:
            continue
        finding.setdefault("title", title)
        finding.setdefault("vulnerability_type", title)
        finding.setdefault("source", "agent")
        finding["agent_origin"] = ORIGIN
        finding.setdefault("region_key", REGION_KEY)
        finding.setdefault("region_steps", 1)
        finding.setdefault("region_files_read", len(part_files))
        finding.setdefault("region_searches", 0)
        shown = _attach_file(finding, part_files)
        finding["cited_file_read"] = shown or (profile is not None and context_file(str(finding.get("file") or ""), profile))
        out.append(finding)
    return out


def run_file_review(provider, source_root, profile, code_graph, framework_label: str,
                    leads: Optional[Sequence[Any]] = None, max_parts: int = 0,
                    is_cancelled: Optional[Callable[[], bool]] = None,
                    verbose: bool = False,
                    telemetry: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Purpose:
        Review every flagged app-owned file once and return what the reviews found.

    Parameters:
        provider: The AI provider.
        source_root: Root of the decompiled source.
        profile: The framework profile.
        code_graph: The code graph, or None.
        framework_label: Framework name for the context block.
        leads: The rule engine's leads, whose files are reviewed first.
        max_parts: Most review requests to make; 0 means no limit.
        is_cancelled: Polled before each request.
        verbose: Traces the pass.
        telemetry: Populated with what was reviewed.

    Returns:
        The findings, untrusted until validation.

    Raises:
        ScanCancelled: When the user stops the scan during the pass.

    Side effects:
        Makes one provider request per part, several at once, on threads named after the pass.

    Implementation notes:
        The native libraries the app loads are reviewed first, as the decompiled view the agent's inspect_native tool gives, so a stopped or hurried agent no longer costs the native findings; the native skill is added only when a library is in the pass. Each request carries the framework's overview or manifest summary, cut short, because whether a screen is reachable from a deep link or a flag is ever sent to a server is stated there and not in the file. The system prompt is assembled once and shared, so every part sees identical guidance. Workers are capped low and the provider's own concurrency gate still applies, so this pass never floods a rate-limited provider. A failed part is counted and skipped rather than retried here, since the provider already retries transient failures, and an unexpected error in one part costs that part only. Context variables are copied into each worker, as the fan-out does, so per-scan logging keeps attributing requests to this scan.
    """
    is_cancelled = is_cancelled or (lambda: False)
    stats = telemetry if telemetry is not None else {}
    tools = AgentTools(source_root, profile=profile)
    files = review_targets(code_graph, tools, leads)
    objects = _load_objects(Path(source_root))
    pool = _load_pool(Path(source_root))
    entries: List[Tuple[str, str, bool]] = []
    for rel in native_review_targets(code_graph):
        if is_cancelled():
            raise ScanCancelled()
        rendered = render_native(tools, rel)
        if rendered.strip():
            entries.append((rel, rendered, False))
    for rel in files:
        try:
            text = (Path(source_root) / rel).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            verbose_print(f"File review: could not read {rel} ({exc}); skipped", verbose)
            continue
        rendered, digest = render_for_review(rel, text, objects, pool)
        if rendered.strip():
            entries.append((rel, rendered, digest))
    parts = build_parts(entries, PART_CHARS)
    skipped = 0
    if max_parts and len(parts) > max_parts:
        skipped = len(parts) - max_parts
        parts = parts[:max_parts]
    stats.update({"files": len(entries), "parts": len(parts), "parts_skipped": skipped,
                  "parts_failed": 0, "findings": 0})
    if not parts:
        return []

    verbose_print(
        f"File review: {plural(len(entries), 'file')} in {plural(len(parts), 'request')}"
        + (f" ({plural(skipped, 'part')} over the budget left out)" if skipped else ""), verbose)
    core = CORE_SKILLS.get(profile.key, CORE_SKILL)
    skills = REVIEW_SKILLS + (("native_library_analysis",) if any(rel.endswith(".so") for rel, _t, _d in entries) else ())
    system = _REVIEW_SYSTEM + "\n\n# Reference skills\n\n" + load_skills(skills, verbose, core=core)
    summary = tools.manifest_summary()
    if len(summary) > CONTEXT_CHARS:
        summary = summary[:CONTEXT_CHARS].rsplit("\n", 1)[0] + "\n... (truncated)"
    context = f"## App context\nFramework: {framework_label}\n{tools.profile.summary_label}:\n{summary}"
    parser = ResponseParser(verbose=verbose)

    def review(index: int, part: List[Tuple[str, str, bool]]) -> Optional[List[Dict[str, Any]]]:
        """
        Purpose:
            Review one part, unless the scan has been stopped.

        Parameters:
            index: The part's 1-based position.
            part: Its slices.

        Returns:
            The part's findings, or None when its request failed.

        Raises:
            ScanCancelled: When the user stopped the scan before this part started.
        """
        if is_cancelled():
            raise ScanCancelled()
        part_files = sorted({rel for rel, _text, _digest in part})
        return _review_part(provider, system, _render_part(part, index, len(parts), context),
                            part_files, parser, profile)

    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=REVIEW_WORKERS, thread_name_prefix=REGION_KEY) as pool:
        futures = [pool.submit(contextvars.copy_context().run, review, index, part)
                   for index, part in enumerate(parts, 1)]
        for future in futures:
            try:
                found = future.result()
            except ScanCancelled:
                raise
            except Exception as exc:
                verbose_print(f"File review: a request failed ({exc}); keeping the others", verbose)
                found = None
            if found is None:
                stats["parts_failed"] += 1
                continue
            findings.extend(found)
    stats["findings"] = len(findings)
    verbose_print(
        f"File review: {plural(len(findings), 'finding')} from {plural(len(parts), 'request')}"
        + (f", {plural(stats['parts_failed'], 'request')} failed" if stats["parts_failed"] else ""),
        verbose)
    return findings
