#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.agent_loop

Purpose:
    The agentic analysis loop: give a model a bounded set of tools over the decompiled code, let it navigate and read, steer it when it stalls, and collect the findings it reports.

Responsibilities:
    Build the opening context, parse each action, execute it through the tool surface, manage the transcript within the context window, enforce the step and time budgets, checkpoint progress, and salvage findings from imperfect output.

Dependencies:
    The tool surface, the skills loader, the code graph, the AI provider layer.

Implementation notes:
    Letting the model navigate is the point. An app is far larger than any context window, so the alternative -- sending source and asking for findings -- systematically under-reports anything but a small app. Here the model searches, reads what looks relevant and follows calls, which is how a person would do it. Most of this module is the machinery that makes that reliable: transcripts compacted so a long investigation still fits, actions parsed out of output that is frequently not clean JSON, repetition detected and steered away from, findings salvaged from a truncated report, and a forced report when the budget runs out with findings unrecorded. Findings are accumulated as they are reported rather than only at the end, so a region that runs out of budget or fails mid-investigation still contributes what it established.

Security considerations:
    Every tool call goes through the bounded read-only surface, which confines paths to the decompiled tree. The model chooses what to look at; it cannot reach outside the tree or write anything.
"""

import json
import re
import time
from pathlib import Path
from itertools import count
from typing import Any, Dict, List, Optional, Tuple

from .leads import render_leads
from ...validation import finding_identity, finding_richness
from .profiles import JAVA_KOTLIN, SourceProfile
from .tools import AgentTools, MAX_READ_CHARS
from .skills_loader import CORE_SKILL, CORE_SKILLS, PROFILE_SKILLS, load_skills
from ...ai.schema import VULNERABILITY_ITEM_SCHEMA, VULNERABILITY_SCHEMA
from ...config.prompts import VulnerabilityPrompts
from ...utils.cancellation import ScanCancelled
from ...utils.json_utils import loads_richest
from ...utils.response_parser import ResponseParser
from ...utils.verbose import plural, verbose_print

DEFAULT_MAX_STEPS = 30
_MAX_OBS_CHARS = MAX_READ_CHARS + 3000
_MAX_TRANSCRIPT_CHARS = 60000
_MAX_BATCH_FILES = 8
_MAX_BATCH_CHARS = 28000
_ADD_FINDING_NUDGE_AFTER = 6

_THOUGHT_MAX = 120

_AGENT_TURN_MAX_TOKENS = 4000
_MAX_FAILED_TURNS = 2
_FORCED_REPORT_MAX_TOKENS = 6000

NEXT_ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "maxLength": _THOUGHT_MAX,
                    "description": "Brief reasoning for this step - at most one short "
                                   "sentence, not a plan."},
        "action": {
            "type": "string",
            "enum": ["list_files", "read_file", "search_code", "inspect_native",
                     "find_method", "callers", "callees", "call_path",
                     "entry_points", "add_finding", "report"],
            "description": (
                "The next tool to use. Use 'add_finding' to record a confirmed "
                "vulnerability the MOMENT you've proven it (keeps investigating), "
                "and 'report' to finish. Findings recorded with 'add_finding' are "
                "saved even if the session is later cut short.\n"
                "Use text search to LOCATE code and the call graph to UNDERSTAND "
                "it: 'find_method' resolves a name to app methods, 'callers'/"
                "'callees' walk one hop back/forward, 'call_path' proves whether "
                "a sink is reachable from an entry point, and 'entry_points' "
                "lists the attacker-reachable methods to start from. A shared "
                "helper can have 100+ callers - search returns all of them, "
                "'call_path' returns the one route that reaches it from the code "
                "you are actually reviewing."
            ),
        },
        "path": {"type": "string", "description": "Path for list_files/read_file/search_code/inspect_native"},
        "method": {
            "type": "string",
            "description": (
                "Method for find_method/callers/callees, and the SOURCE for "
                "call_path. A bare name ('validateUser'), a qualified one "
                "('UserService.login'), or a full key "
                "('Lcom/x/Foo;->bar(I)V') when a name is ambiguous."
            ),
        },
        "target": {
            "type": "string",
            "description": "For call_path only: the method to reach FROM 'method'.",
        },
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "For read_file only: read SEVERAL files in one step (faster than "
                "one at a time). Prefer this to batch-read the flagged files."
            ),
        },
        "pattern": {"type": "string", "description": "Regex/substring for search_code"},
        "start_line": {
            "type": "integer",
            "description": (
                "Optional, for read_file and inspect_native: 1-based line to start "
                "from. Omit to auto-continue where the last read of this same path "
                "left off (or start at line 1 on the first read) - omitting never "
                "repeats content already shown."
            ),
        },
        "vulnerabilities": {
            "type": "array",
            "items": VULNERABILITY_ITEM_SCHEMA,
            "description": (
                "Findings to submit - with action 'add_finding' (record one or "
                "more confirmed vulns now, then keep going) or 'report' (finish)."
            ),
        },
    },
    "required": ["action"],
}

def _truncate(text: str, limit: int) -> str:
    """
    Purpose:
        Bound text to a length.

    Parameters:
        text: The text.
        limit: Maximum length.

    Returns:
        The bounded text.
    """
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated]"

_MIN_TRANSCRIPT_CHARS = 35000

def _compact_transcript(entries: List[str], start: int, high_water: int,
                        low_water: int) -> Tuple[str, int]:
    """
    Purpose:
        Render the investigation so far, dropping the oldest turns until it fits the context budget.

    Parameters:
        entries: The turns.
        start: The first turn currently retained.
        high_water: Length above which compaction is triggered.
        low_water: Length to compact down to.

    Returns:
        The rendered transcript and the new starting turn.

    Implementation notes:
        Two thresholds rather than one, so compaction happens in a chunk rather than dropping a single turn on every step -- which would recompute the transcript constantly and keep it permanently at the limit. The oldest turns go first, because the recent ones carry what the agent has just learned and is acting on. A note records that turns were dropped, so the agent knows its history is partial rather than believing it started there. The starting index is returned and carried forward, so compaction is not redone from scratch each turn.
    """
    if not entries:
        return "", start
    start = min(start, len(entries) - 1)

    def _render(i: int) -> str:
        """
        Purpose:
            Render the transcript from a given starting turn, noting how many were dropped.

        Parameters:
            i: The first turn to include.

        Returns:
            The rendered text.

        Implementation notes:
            The dropped-turn note is included in the rendered text rather than added afterwards, so the length the caller measures against the budget is the length the agent will actually receive.
        """
        body = "\n\n".join(entries[i:])
        return f"... [{i} earlier turns dropped]\n\n{body}" if i > 0 else body

    text = _render(start)
    if len(text) <= high_water:
        return text, start
    while start < len(entries) - 1 and len(_render(start)) > low_water:
        start += 1
    return _render(start), start

def _strip_thinking_tokens(text: str) -> str:
    """
    Purpose:
        Remove reasoning-trace markup before parsing.

    Parameters:
        text: The raw response.

    Returns:
        The response without thinking blocks.

    Implementation notes:
        The trace routinely contains a draft action or a draft finding in braces, which the extractor would find before the real one. It has to go first.
    """
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    lower = text.lower()
    if "</think>" in lower:
        text = text[lower.rindex("</think>") + len("</think>"):]
    text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE)
    return text.strip()

def _extract_first_json_object(text: str):
    """
    Purpose:
        Find the first complete JSON object in a response, tracking string and escape state.

    Parameters:
        text: The response.

    Returns:
        The object's text, or None.

    Complexity:
        O(n) in the text length.

    Implementation notes:
        Brace counting alone breaks on a brace inside a string, and these actions carry search patterns and code excerpts that contain them routinely.
    """
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return text[start : i + 1]
    return None

def _iter_json_objects(text: str):
    """
    Purpose:
        Yield every top-level JSON object in a response.

    Parameters:
        text: The response.

    Returns:
        The object texts.

    Implementation notes:
        Used by salvage, where the response is a list of findings that did not parse as a whole -- typically because it was truncated. Iterating the objects recovers the complete ones and discards only the partial last.
    """
    stack: List[int] = []
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            start = stack.pop()
            yield text[start:i + 1]

_SALVAGE_FIELDS = ("title", "cvss_vector", "severity", "file", "line", "description",
                   "recommendation", "impact", "cwe", "owasp_mobile", "exploitation")

def _salvage_findings(raw: str) -> List[Dict[str, Any]]:
    """
    Purpose:
        Recover findings from a report that would not parse as JSON.

    Parameters:
        raw: The response.

    Returns:
        The recovered findings.

    Implementation notes:
        This runs after a long and expensive investigation, where the alternative to salvage is losing everything the agent found because its final message was truncated or malformed. That makes a permissive recovery worth the imprecision. Fields are extracted per object by pattern, with a quoted form tried first and an unquoted fallback, since a truncated response has inconsistent quoting. Objects containing more than one title are skipped, because that means the object boundaries were misjudged and the fields would be mixed between findings. A recovered finding needs a title and either a file or a severity, so prose that happens to look object-shaped does not become a finding.
    """
    def field(obj: str, key: str) -> str:
        """
        Purpose:
            Extract one field from an object's text.

        Parameters:
            obj: The object text.
            key: The field name.

        Returns:
            The value, or an empty string.

        Implementation notes:
            The quoted form is tried first and unescaped properly; the unquoted fallback covers numbers and the malformed quoting that truncation produces.
        """
        m = re.search(r'"%s"\s*:\s*"((?:[^"\\]|\\.)*)"' % key, obj)
        if m:
            try:
                return json.loads('"' + m.group(1) + '"')
            except Exception:
                return m.group(1)
        m = re.search(r'"%s"\s*:\s*([^",}\n][^,}\n]*)' % key, obj)
        return m.group(1).strip() if m else ""

    out: List[Dict[str, Any]] = []
    for obj in _iter_json_objects(raw):
        if obj.count('"title"') != 1:
            continue
        f = {k: field(obj, k) for k in _SALVAGE_FIELDS}
        if f["title"] and (f["file"] or f["severity"]):
            out.append({k: v for k, v in f.items() if v})
    return out

def _coerce_report(obj):
    """
    Purpose:
        Recognise a report the model sent without the expected wrapper.

    Parameters:
        obj: The parsed response.

    Returns:
        The response as a report action, or unchanged.

    Implementation notes:
        Models finishing an investigation frequently send the findings array directly, or an object with the findings under a plausible key and no action field. Both plainly mean "report", and rejecting them would discard a complete set of findings over a formatting detail.
    """
    if isinstance(obj, list):
        return {"action": "report", "vulnerabilities": obj}
    if isinstance(obj, dict):
        action = (obj.get("action") or "").strip().lower()
        if not action:
            for key in ("vulnerabilities", "findings", "results"):
                if isinstance(obj.get(key), list):
                    return {"action": "report", "vulnerabilities": obj[key]}
    return obj

def _deadline_expired(deadline) -> bool:
    """
    Purpose:
        Report whether the time budget has run out.

    Parameters:
        deadline: A deadline object or a monotonic timestamp.

    Returns:
        True when expired; False when there is no deadline.

    Implementation notes:
        Accepts either form, so the loop works both under the fan-out's shared credited deadline and standalone with a plain timestamp.
    """
    if deadline is None:
        return False
    expired = getattr(deadline, "expired", None)
    if callable(expired):
        return bool(expired())
    return time.monotonic() >= float(deadline)


def _parse_action(raw: str) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Parse one agent response into an action.

    Parameters:
        raw: The response.

    Returns:
        The action, or None when nothing usable was found.

    Implementation notes:
        Handles the shapes models actually produce: a fenced code block, a reasoning trace around the object, an object embedded in prose, and a bare findings array meaning a report. None means the turn produced nothing actionable, and the loop tells the model so rather than guessing at an action.
    """
    if not raw:
        return None
    raw = _strip_thinking_tokens(raw)
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    try:
        obj = loads_richest(raw)
    except Exception:
        candidate = _extract_first_json_object(raw)
        if candidate is None:
            return None
        try:
            obj = loads_richest(candidate)
        except Exception:
            return None
    obj = _coerce_report(obj)
    return obj if isinstance(obj, dict) else None

_VALID_ACTIONS = frozenset(NEXT_ACTION_SCHEMA["properties"]["action"]["enum"])

def _parse_action_from_thinking(thinking: str) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Recover an action from the reasoning trace when the response itself had none.

    Parameters:
        thinking: The reasoning trace.

    Returns:
        The action, or None.

    Implementation notes:
        A model that reasons its way to an action and then emits an empty or prose-only response has still decided what to do. Recovering it from the trace saves a step out of a tight budget, and the step it would otherwise waste is one where the model is told it produced nothing.
    """
    if not thinking:
        return None
    for candidate in reversed(list(_iter_json_objects(thinking))):
        try:
            obj = loads_richest(candidate)
        except Exception:
            continue
        obj = _coerce_report(obj)
        if isinstance(obj, dict) and (obj.get("action") or "").strip() in _VALID_ACTIONS:
            return obj
    return None

def _build_initial_context(tools: AgentTools, static_signals: Dict[str, Any],
                           code_graph=None) -> str:
    """
    Purpose:
        Build the opening context: the app's structure, the manifest summary, the leads and the file tree.

    Parameters:
        tools: The tool surface, consulted for the file tree and manifest summary.
        static_signals: What the deterministic passes established, including the leads.
        code_graph: The region's code graph, used for the structure summary; None falls back to the tool surface alone.

    Returns:
        The context text.

    Implementation notes:
        Front-loaded deliberately. The agent's budget is steps, and anything it would otherwise spend three or four discovering -- what the app exports, what the tree looks like, what the scanners already found -- is cheaper to state once.
    """
    framework = static_signals.get("framework", "unknown")
    summary = _truncate(tools.manifest_summary(), 6000)
    fence = "xml" if tools.profile.key == "java_kotlin" else ""
    parts = [
        f"## Static signals\nDetected framework: {framework}\n",
    ]
    objective = (static_signals.get("objective") or "").strip()
    leads = list(static_signals.get("leads") or [])
    if objective:
        surface = static_signals.get("surface_label") or "your assigned surface"
        mission_intro = (
            f"Confirm or refute the {plural(len(leads), 'concrete lead')} below, "
            "then explore the rest of your map for more.\n\n" if leads else "")
        exhaustive_line = (
            "Leads first, exploration second: a refuted lead is as valuable as "
            "a confirmed one, and both beat a new guess." if leads else
            "Within your surface, be exhaustive: read every file in your map "
            "that could plausibly carry the issue you are looking for.")
        parts.append(
            f"## Your assigned objective - {surface}\n{mission_intro}{objective}\n\n"
            "You are ONE of several agents auditing this app in parallel. The code "
            "map below has been filtered to your surface; other agents hold the "
            "rest. Do not try to audit the whole app, and do not report findings "
            "outside your objective - they are being covered elsewhere and "
            f"duplicate work costs you the depth your own surface needs. {exhaustive_line}\n")
    if leads:
        leads_total = static_signals.get("leads_total", len(leads))
        parts.append(_truncate(render_leads(leads, leads_total), 6000))
    parts.append(f"## {tools.profile.summary_label}\n```{fence}\n{summary}\n```\n")
    if code_graph is not None:
        parts.append(code_graph.render() + "\n")
        resources = tools.app_resource_files()
        res_block = ("\n".join(resources) if resources
                     else "(none of note)")
        parts.append(
            "## App resources (not in the code map above)\n"
            f"{res_block}\n"
            "Use `list_files` to browse any other directory (layouts, "
            "framework resources, etc.) if you need it.\n"
            "The manifest is NOT a readable path - everything it declares is "
            "already summarised for you above. Do not `read_file` it.\n")
    else:
        parts.append("## Decompiled file tree (paths + sizes only)\n"
                     + tools.file_tree() + "\n")
    return "\n".join(parts)

def _describe_request(action: str, path: str, paths: List[str], pattern: str,
                      start_line: Optional[int], method: str = "",
                      target: str = "") -> str:
    """
    Purpose:
        Render an action into the transcript line describing what was asked.

    Parameters:
        action: The action name.
        path: The single path involved, for a read or a listing.
        paths: Several paths, for a batch read.
        pattern: The search pattern, for a search.
        start_line: Where a read was asked to start, when specified.
        method: The method named, for a call-graph query.
        target: The target method, for a path query.

    Returns:
        The description.

    Implementation notes:
        Kept short, because the transcript is context the agent re-reads every turn and a verbose history crowds out the code.
    """
    if action == "list_files":
        where = f"`{path}`" if path else "the source root"
        return f"The LLM is requesting to list all the files in {where} directory."
    if action == "read_file":
        if paths:
            listed = ", ".join(f"`{p}`" for p in paths[:3])
            more = f" and {plural(len(paths) - 3, 'other file')}" if len(paths) > 3 else ""
            return f"The LLM is requesting to read {listed}{more}."
        at = f" from line {start_line}" if start_line is not None else ""
        return f"The LLM is requesting to read `{path}`{at}."
    if action == "search_code":
        where = f" under `{path}`" if path else ""
        return f"The LLM is requesting to search the code for `{pattern}`{where}."
    if action == "inspect_native":
        return f"The LLM is requesting to inspect the native library `{path}`."
    if action == "find_method":
        return f"The LLM is looking up `{method}` in the app's call graph."
    if action == "callers":
        return f"The LLM is asking what calls `{method}`."
    if action == "callees":
        return f"The LLM is asking what `{method}` calls."
    if action == "call_path":
        return f"The LLM is tracing a call path from `{method}` to `{target}`."
    if action == "entry_points":
        return "The LLM is requesting the app's externally reachable entry points."
    if action == "add_finding":
        return "The LLM is recording a confirmed finding."
    if action == "report":
        return "The LLM is submitting its final report."
    return f"The LLM requested an unknown action: {action!r}."


_TOOL_ERROR_REASONS = (
    "path escapes sandbox", "not a native library", "not a file", "not found",
    "could not read", "empty pattern", "no call graph is available",
    "no app method matches",
)


def _describe_response(action: str, path: str, paths: List[str],
                       observation: str) -> str:
    """
    Purpose:
        Render a tool result into the transcript line describing what came back.

    Parameters:
        action: The action name.
        path: The single path involved.
        paths: Several paths, for a batch read.
        observation: The tool's output.

    Returns:
        The description.

    Security considerations:
        No branch copies the tool's output into the line, including the error branch, which names the failure from _TOOL_ERROR_REASONS and adds only the path the model asked for. The same variable carries native signal summaries with credential candidates, model-chosen search terms and exception text holding the analyst's absolute paths, and this line reaches the terminal and the shareable dashboard feed, so echoing even the head of an error would put tool-produced text there. An error outside the list is reported generically rather than quoted.
    """
    if observation.startswith("ERROR"):
        reason = next((r for r in _TOOL_ERROR_REASONS if observation.startswith(f"ERROR: {r}")),
                      "the tool reported an error")
        target = ", ".join(paths[:3]) if paths else path
        return f"Could not satisfy that request: {reason}" + (f": {target}" if target else "")
    if observation.startswith("NOTE: already read to the end"):
        target = (", ".join(f"`{p}`" for p in paths[:3]) if paths else f"`{path}`")
        return f"{target}: nothing new (already fully read)."
    lines = observation.count("\n") + 1
    if action == "list_files":
        return f"Listing returned to the LLM ({plural(lines, 'entry', 'entries')})."
    if action == "read_file":
        target = (", ".join(f"`{p}`" for p in paths[:3]) if paths else f"`{path}`")
        return f"Giving read access to {target} ({plural(lines, 'line')} sent to the LLM)."
    if action == "search_code":
        return f"Search results returned to the LLM ({plural(lines, 'match', 'matches')})."
    if action == "inspect_native":
        return f"Giving the native analysis of `{path}` to the LLM ({plural(lines, 'line')})."
    if action in ("find_method", "callers", "callees", "call_path", "entry_points"):
        return f"Call-graph answer returned to the LLM ({plural(lines, 'line')})."
    return "Response returned to the LLM."


_ALWAYS_LOADED = ("vulnerability_classes", "finding_quality")


def _planned_skills(static_signals: Dict[str, Any]) -> List[str]:
    """
    Purpose:
        Choose the skills to load for a region, from what the deterministic passes found there.

    Parameters:
        static_signals: What the scanners established.

    Returns:
        The skill names.

    Implementation notes:
        Selected rather than loading everything, because skills are prompt text and the full set would consume the budget the agent needs for code. A region touching WebViews gets the WebView guidance; one touching storage does not.
    """
    planned: List[str] = []
    for name in _ALWAYS_LOADED:
        if name not in planned:
            planned.append(name)
    for name in (static_signals.get("skills") or []):
        if isinstance(name, str) and name not in planned:
            planned.append(name)
    return planned


def _contextual_skills(action: str, path: str, pattern: str) -> List[str]:
    """
    Purpose:
        Add skills mid-investigation when the agent looks at something the opening selection did not anticipate.

    Parameters:
        action: The action being taken.
        path: The path involved.
        pattern: The search pattern.

    Returns:
        The additional skill names.

    Implementation notes:
        The initial selection is based on what the scanners found, which is not everything. An agent that searches for a crypto API in a region with no crypto findings gets the crypto guidance at that point rather than proceeding without it.
    """
    extra = []
    blob = f"{path} {pattern}".lower()
    if "androidmanifest" in path.lower() or "manifest" in blob:
        extra.append("manifest_review")
        extra.append("android_analysis")
    if any(k in blob for k in ("exported", "intent-filter", "provider", "receiver",
                               "getintent", "deeplink", "deep link", "scheme",
                               "javascriptinterface", "addjavascriptinterface",
                               "pendingintent", "rawquery", "execsql")):
        extra.append("vulnerability_classes")
        extra.append("chain_building")
    if any(k in blob for k in ("buildconfig", "version_name", "sdk", "gradle",
                               "google-services", "firebase", "flipper", "stetho")):
        extra.append("sdk_analysis")
    if any(k in blob for k in ("dexclassloader", "class.forName", "getdeclaredmethod",
                               "obfuscat", "proguard", "decrypt", "smali")) \
            or re.search(r"/[a-z]{1,2}/[A-Za-z]?\d*[a-z]?\.java", path):
        extra.append("reading_obfuscated_code")
    if re.search(r"\b(?:ssl|tls|trust|https?|cert|hostname|network|socket|pinning)\b", blob):
        extra.append("network_security")
    if action == "inspect_native" or any(k in blob for k in (".so", "jni", "native")):
        extra.append("offensive_android")
        extra.append("native_library_analysis")
    if any(k in blob for k in ("jiagu", "stubapp", "dexhelper", "secneo", "nesec",
                               "stubshell", "libshell", "apkwrapper", "packer",
                               "loadlibrary", "attachbasecontext")):
        extra.append("packed_app_triage")
    if any(k in blob for k in ("cipher", "secretkeyspec", "messagedigest", "mac",
                               "frida", "hook", "sharedpreferences", "okhttp")):
        extra.append("frida_hook_recipes")
    if any(k in blob for k in ("objection", "sslpinning", "keystore", "sqlite",
                               "shared_preferences", "root detection", "rootbeer",
                               "isrooted", "run-as", "keygenparameterspec")):
        extra.append("objection_runtime_toolkit")
    if any(k in blob for k in ("dart", "ffi", "pubspec", "platform channel", "methodchannel", ".asm")):
        extra.append("flutter_dart_security")
    if any(k in blob for k in ("blutter", "libapp", "libflutter", "kernel_blob", "pp.txt",
                               "invokemethod", "awaitstub", "returnasync", "flutter")):
        extra.append("flutter_reverse_engineering")
    if any(k in blob for k in ("hermes", "app_modules", "nativemodules", "reactmethod", "turbomodule",
                               "index.android.bundle", "react-native", "asyncstorage")):
        extra.append("react_native_reverse_engineering")
    if any(k in blob for k in ("hermes", "bundle", "asyncstorage", "webview",
                               "requirenativecomponent", "react-native")):
        extra.append("react_native_security")
    if any(k in blob for k in ("cordova", "config.xml", "inappbrowser", "phonegap",
                               "www/", "innerhtml", "deviceready")):
        extra.append("cordova_hybrid_security")
    if action in ("inspect_native",) or any(k in blob for k in (
            "am start", "am broadcast", "am startservice", "content://", "adb",
            "reachab", "exploitab", "proof", "osv", "sbom", "cyclonedx", "purl",
            "advisory", "verified")):
        extra.append("evidence_discipline")
    if action in ("inspect_native",) or any(k in blob for k in (
            "objection", "frida", "mitmproxy", "burp", "repackag", "apktool",
            "logcat", "sslpinning", "authoriz", "in scope", "in-scope",
            "out of scope", "out-of-scope")):
        extra.append("authorized_dynamic_testing")
    if any(k in blob for k in (
            "exported", "md5", "sha1", "sha-1", "getinstance",
            "addjavascriptinterface", "javascriptinterface", "dexclassloader",
            "class.forname", "buildconfig", "allowbackup", "usescleartext",
            "granturipermissions", "placeholder", "client_id", "client id",
            "api_key", "apikey", "false positive")):
        extra.append("false_positive_patterns")
    if any(k in blob for k in (
            "getintent", "getstringextra", "getparcelableextra", "getserializableextra",
            "getdata", "getqueryparameter", "rawquery", "execsql", "loadurl",
            "loaddata", "evaluatejavascript", "runtime.exec", "processbuilder",
            "startactivity", "readobject", "taint", "source to sink",
            "source-to-sink", "dataflow", "data flow")):
        extra.append("taint_source_to_sink")
    if any(k in blob for k in (
            "oauth", "pkce", "redirect_uri", "response_type", "code_challenge", "grant_type",
            "id_token", "appauth", "openid", "authorization code")):
        extra.append("oauth_oidc_mobile")
    if any(k in blob for k in (
            "clipboard", "setprimaryclip", "getprimaryclip", "newplaintext", "deep link",
            "deeplink", "getqueryparameter", "linking.", "app_links", "uni_links",
            "autoverify", "browsable")):
        extra.append("deeplink_clipboard_trust")
    if any(k in blob for k in (
            "deep link", "deeplink", "getqueryparameter", "intent://", "uri_intent_scheme",
            "browser_fallback_url", "router", "evaluatejavascript", "shouldoverrideurlloading",
            "onnewintent")):
        extra.append("deeplink_endpoint_analysis")
    if any(k in blob for k in (
            "premium", "subscription", "entitlement", "purchase", "billing", "receipt",
            "coupon", "promo", "referral", "redeem", "wallet", "isadmin", "ispro")):
        extra.append("business_logic_abuse")
    if any(k in blob for k in (
            "secretkeyspec", "ivparameterspec", "pbekeyspec", "cipher.getinstance",
            "keygenparameterspec", "encryptedsharedpreferences", "asyncstorage", "mmkv",
            "sqlcipher", "flag_secure")):
        extra.append("storage_crypto_review")
    if any(k in blob for k in (
            "pendingintent", "getparcelableextra", "parseuri", "zipentry", "objectinputstream",
            "taskaffinity", "filtertoucheswhenobscured", "preferenceactivity",
            "isvalidfragment", "biometricprompt", "bindservice", "sendbroadcast")):
        extra.append("android_ipc_ui_attacks")
    return extra

def context_file(path: str, profile: SourceProfile) -> bool:
    """
    Purpose:
        Tell whether a cited file is one the model was given whole in its opening context rather than had to open.

    Parameters:
        path: The cited file.
        profile: The framework profile, which names its summary files.

    Returns:
        True for the manifest and the profile's summary or overview file.

    Implementation notes:
        The manifest is summarised into every opening context and the agent is told not to read it, so a finding citing it was always marked as citing an unread file and capped at Medium - a benchmark scan's exported-provider finding lost its High that way. The same holds for a framework's overview file.
    """
    name = Path(_norm_path(path)).name.lower()
    names = {Path(candidate).name.lower() for candidate in profile.summary_candidates}
    return bool(name) and (name == "androidmanifest.xml" or name in names)


def _norm_path(p: str) -> str:
    """
    Purpose:
        Normalise a path for coverage comparison.

    Parameters:
        p: The path.

    Returns:
        The normalised path.

    Implementation notes:
        Paths reach coverage tracking from the graph, the tools and the leads, each spelled slightly differently; without normalising, a file read would not match the target it satisfied and would look unread forever.
    """
    return (p or "").strip().lstrip("./").replace("\\", "/")

def _coverage_targets(code_graph, tools: AgentTools, leads=None):
    """
    Purpose:
        Work out which files the agent ought to examine.

    Parameters:
        code_graph: The code graph.
        tools: The tool surface.
        leads: The rule engine's leads.

    Returns:
        The source and native targets.

    Implementation notes:
        Taken from the graph's flagged files where a graph exists, since those are the ones carrying a signal, and from the app's source list otherwise. Lead files are added unconditionally: the scanners already found something there, so it is worth the agent's time regardless of whether the graph flagged it.
    """
    native_targets = set()
    if code_graph is not None:
        native_targets = {_norm_path(l.path) for l in code_graph.native_libs}
        source_targets = {_norm_path(f) for f in code_graph.flagged_files()} - native_targets
    else:
        source_targets = {_norm_path(f) for f in tools.app_source_files()}
    if leads:
        source_targets |= {_norm_path(lead.file) for lead in leads if lead.file}
    return source_targets, native_targets

def _unread(source_targets, native_targets, read_files, inspected_native):
    """
    Purpose:
        Work out what the agent has not yet examined.

    Parameters:
        source_targets: Source files worth examining.
        native_targets: Native libraries worth inspecting.
        read_files: What has been read.
        inspected_native: What has been inspected.

    Returns:
        The unread source and native targets.

    Implementation notes:
        Drives the steering messages and the coverage record, which is what lets the report say how much of the flagged code the AI actually looked at.
    """
    unread_src = sorted(source_targets - read_files)
    unread_nat = sorted(native_targets - inspected_native)
    return unread_src, unread_nat

_COVERAGE_NOTE_CHARS = 1500

def _coverage_note(examined, unread_src, unread_nat) -> str:
    """
    Purpose:
        Tell the agent what it has already examined and which flagged files are left, for a turn whose history has lost that record to compaction.

    Parameters:
        examined: The files read and native libraries inspected so far.
        unread_src: Flagged source files not yet read.
        unread_nat: Flagged native libraries not yet inspected.

    Returns:
        The note, ending in a blank line so it sits apart from the turn instructions.

    Implementation notes:
        Compaction drops the oldest turns, and with them the only record the agent has of which files it opened. A real scan on a mid-size model dropped 221 turns and then re-read the same handful of files for over a hundred steps, never reporting because it never knew it was done. The loop already tracks coverage exactly, so stating it costs a few hundred characters and replaces the memory compaction took. Both lists are bounded with a count of the rest, so a large app cannot crowd the history out of the prompt.
    """
    lines = ["## Coverage (your earlier turns were dropped above; this is the full record)"]
    if examined:
        lines.append(f"Already examined ({len(examined)}): "
                     f"{_truncate(', '.join(sorted(examined)), _COVERAGE_NOTE_CHARS)}. Their contents "
                     "are no longer above - re-read one only to check a specific line for a finding.")
    remaining = list(unread_src) + list(unread_nat)
    if remaining:
        lines.append(f"Flagged and not yet examined ({len(remaining)}): "
                     f"{_truncate(', '.join(remaining), _COVERAGE_NOTE_CHARS)}.")
    else:
        lines.append("Every flagged file has been examined. Record anything confirmed with "
                     "'add_finding', then submit 'report'.")
    return "\n".join(lines) + "\n\n"

def _read_batch(tools: AgentTools, paths: List[str]):
    """
    Purpose:
        Read several files in one step, within a size budget.

    Parameters:
        tools: The tool surface.
        paths: The files to read.

    Returns:
        The combined text and the paths successfully read.

    Implementation notes:
        Batching matters because the step budget is tight and reading one file per step spends most of it on round trips rather than analysis. Bounded by both a file count and a total size, and the response says how many were left unread so the agent asks for them next turn rather than assuming it has seen everything. Only genuinely read files count toward coverage, so an error or an already-read marker does not mark a target satisfied.
    """
    chunks: List[str] = []
    ok: List[str] = []
    used = 0
    for p in paths[:_MAX_BATCH_FILES]:
        body = tools.read_file(p)
        chunks.append(f"=== {p} ===\n{body}")
        if not body.startswith("ERROR") and not body.startswith("(already read"):
            ok.append(p)
        used += len(body)
        if used >= _MAX_BATCH_CHARS:
            remaining = len(paths) - len(chunks)
            if remaining > 0:
                chunks.append(f"... (batch budget reached; {plural(remaining, 'more path')} "
                              "not read - request them next turn)")
            break
    return "\n\n".join(chunks), ok

def _steer_message(unread_src, unread_nat, *, repeated: bool, recorded: int = 0) -> str:
    """
    Purpose:
        Nudge the agent when it repeats itself, resends findings, or has files left to examine.

    Parameters:
        unread_src: Source files not yet read.
        unread_nat: Native libraries not yet inspected.
        repeated: Whether the last action repeated an earlier one.
        recorded: How many findings are already saved.

    Returns:
        The nudge text.

    Implementation notes:
        The three failure modes this addresses are the ones that actually waste budget. An agent that repeats an action is stuck and will keep repeating it. One that resends its findings is spending steps re-reporting what is already saved. One that has stopped exploring needs to be told what is left. Unread files are listed concretely with an example of the batch syntax, because a general instruction to keep looking produces another general response, while a list of paths produces a read. The list is truncated with a count, so the nudge stays small relative to the context it shares.
    """
    lines = []
    if repeated:
        lines.append("That repeated a previous action and produced no new "
                     "information - do NOT repeat it.")
    if recorded:
        lines.append(
            f"Your {plural(recorded, 'recorded finding')} are already saved - "
            "do NOT resend them. Keep examining, then submit 'report' again "
            "(with a \"vulnerabilities\" array only if you found something new).")
    if unread_src or unread_nat:
        lines.append("Files still worth examining before you finish "
                     "(read them together in one step with \"paths\"):")
        for f in unread_src[:12]:
            lines.append(f"  - {f}")
        for f in unread_nat[:4]:
            lines.append(f"  - inspect_native {f}")
        if len(unread_src) > 12:
            lines.append(f"  … and {len(unread_src) - 12} more")
        lines.append('e.g. {"action":"read_file","paths":[' +
                     ", ".join('"%s"' % f for f in unread_src[:4]) + "]}")
        lines.append("Examine them, or submit 'report' to finish.")
    else:
        lines.append("You have examined the flagged files. Submit 'report' with "
                     "your findings when ready.")
    return "SYSTEM NUDGE: " + "\n".join(lines)

def run_agent_analysis(
    provider,
    jadx_output_dir,
    static_signals: Optional[Dict[str, Any]] = None,
    code_graph=None,
    profile: SourceProfile = JAVA_KOTLIN,
    max_steps: Optional[int] = None,
    is_cancelled=None,
    verbose: bool = False,
    deadline: Optional[float] = None,
    telemetry: Optional[Dict[str, Any]] = None,
    resume_state: Optional[Dict[str, Any]] = None,
    on_checkpoint=None,
) -> Tuple[List[Dict[str, Any]], bool, str]:
    """
    Purpose:
        Run the agent over a region: give it the tools, let it investigate, and return what it found.

    Parameters:
        provider: The AI provider.
        jadx_output_dir: The decompiled tree the tool surface reads from.
        static_signals: What the deterministic passes established, including the leads to start from.
        code_graph: The region's code graph; None runs without structural context.
        profile: The framework profile, selecting extensions, prompts and noise filters.
        max_steps: Step ceiling for this region; None means unbounded.
        is_cancelled: Polled each turn so a user stop takes effect promptly.
        verbose: Traces each action and result.
        deadline: Shared time budget across the fan-out.
        telemetry: Populated with this region's coverage and exploration statistics.
        resume_state: Prior state from a checkpoint, so an interrupted region continues rather than restarting.
        on_checkpoint: Called with the region's state as it progresses, to persist it.

    Returns:
        The findings, whether the region completed, and the transcript.

    Side effects:
        Makes many provider requests, reads the decompiled tree, and invokes the checkpoint callback.

    Implementation notes:
        Findings are merged as they are reported rather than collected at the end, so a region that exhausts its budget, fails, or is cancelled still contributes what it established. A step whose request fails while the provider is still available - typically a reply the model reasoned past its output cap - costs that step, not the region: the loop notes the loss, asks for one short action, and carries on, and only a second consecutive failure or an unavailable provider ends the region. A benchmark scan lost its only region at step 3 to one such reply. The loop ends on an explicit report, on the step ceiling, or on the deadline. In the last two cases a final report is forced if nothing has been recorded, because an investigation that read the code and never got to report would otherwise be a total loss. Checkpointing is a callback rather than a direct write, so this module stays independent of where the state is stored. A region resumed with steps already spent counts as having driven the loop, so a provider failure on its first new turn ends it with its restored findings rather than reporting that the model could not drive the loop at all - which once discarded a resumed scan's whole analysis when the machine was offline. A malformed resume state is applied as far as it parses and the failure is logged, so a region that resumes with partial coverage state leaves a trace instead of silently re-reading files. Coverage is written into the telemetry mapping and returned, so the report can state what this region actually examined.

    Security considerations:
        Every tool call is confined to the decompiled tree by the tool surface. The model chooses the actions; it cannot reach outside or write.
    """
    static_signals = static_signals or {}
    is_cancelled = is_cancelled or (lambda: False)
    tools = AgentTools(jadx_output_dir, profile=profile,
                       call_graph=getattr(code_graph, "call_graph", None))
    parser = ResponseParser(verbose=verbose)
    agent_system = VulnerabilityPrompts.get_agent_system(profile.key)
    core_skill = CORE_SKILLS.get(profile.key, CORE_SKILL)

    initial_context = _build_initial_context(tools, static_signals, code_graph)

    skill_names: List[str] = _planned_skills(static_signals)
    for name in PROFILE_SKILLS.get(profile.key, ()):
        if name not in skill_names:
            skill_names.append(name)
    system = agent_system + "\n\n# Reference skills\n\n" + load_skills(
        skill_names, verbose, core=core_skill)
    verbose_print(
        f"Agent context: system prompt fixed at {len(system):,} chars "
        f"({plural(len(skill_names) + 1, 'skill')} loaded up front)", verbose)

    transcript: List[str] = []
    history_start = 0
    progressed = False

    source_targets, native_targets = _coverage_targets(
        code_graph, tools, leads=static_signals.get("leads"))
    read_files: set = set()
    inspected_native: set = set()
    region_searches = 0
    last_sig: Optional[tuple] = None
    no_progress = 0
    coverage_nudged = False
    exploratory_actions = 0
    add_finding_nudged = False

    accumulated: List[Dict[str, Any]] = []
    seen_keys: set = set()
    seen_keys_index: Dict[Tuple[str, str, str], int] = {}
    seen_identity: Dict[Tuple[str, str, str], int] = {}

    base_steps = 0
    region_key = static_signals.get("surface_label") or "single"

    if resume_state:
        try:
            base_steps = int(resume_state.get("steps_taken", 0) or 0)
            for v in resume_state.get("accumulated", []) or []:
                if isinstance(v, dict):
                    accumulated.append(v)
            for k in resume_state.get("seen_keys", []) or []:
                if isinstance(k, (list, tuple)) and len(k) == 3:
                    seen_keys.add(tuple(str(x) for x in k))
            for idx, v in enumerate(accumulated):
                title = (v.get("title") or v.get("vulnerability_type") or "").strip().lower()
                ekey = (title, str(v.get("file", "")).strip(), str(v.get("line", "")).strip())
                seen_keys.add(ekey)
                seen_keys_index[ekey] = idx
                identity = finding_identity(v)
                if identity is not None:
                    seen_identity[identity] = idx
            transcript.extend(str(t) for t in (resume_state.get("transcript", []) or []))
            verbose_print(
                f"Resuming region {region_key!r} from checkpoint: "
                f"{plural(len(accumulated), 'finding')} recorded, "
                f"{plural(base_steps, 'step')} already spent, "
                f"{plural(len(transcript), 'transcript entry', 'transcript entries')}",
                verbose)
        except Exception as exc:
            verbose_print(f"Checkpoint restore failed ({exc}); running region {region_key!r} fresh",
                          verbose)
            base_steps, accumulated[:], seen_keys = 0, [], set()
            seen_keys_index.clear()
            seen_identity.clear()

    _PROVIDER_STOP_REASONS = ("provider_unavailable", "provider_error")

    def _snapshot(done_reason=None, done_ok=None) -> Dict[str, Any]:
        """
        Purpose:
            Capture the region's state for the checkpoint.

        Parameters:
            done_reason: Why the region finished, when it has.
            done_ok: Whether it completed successfully.

        Returns:
            The state.

        Implementation notes:
            Carries the accumulated findings and the coverage as well as the position, so a resumed region continues rather than re-deriving what it already established.
        """
        snap = {
            "region_key": region_key,
            "steps_taken": steps_taken,
            "accumulated": accumulated,
            "seen_keys": [list(k) for k in seen_keys],
            "transcript": transcript,
            "read_files": sorted(read_files),
            "inspected_native": sorted(inspected_native),
            "coverage_nudged": coverage_nudged,
            "add_finding_nudged": add_finding_nudged,
            "exploratory_actions": exploratory_actions,
            "done": done_reason is not None,
        }
        if done_reason is not None:
            snap["stop_reason"] = done_reason
            snap["completed_ok"] = bool(done_ok)
            snap["resumable"] = done_reason in _PROVIDER_STOP_REASONS
        return snap

    def _checkpoint(done_reason=None, done_ok=None) -> None:
        """
        Purpose:
            Persist the region's state.

        Parameters:
            done_reason: Why the region finished, when it has.
            done_ok: Whether it completed successfully.

        Side effects:
            Writes the region checkpoint.

        Implementation notes:
            Written as the region progresses rather than only at the end, since the expensive thing to lose is the provider calls already made. A failed save is logged and otherwise ignored: it costs the ability to resume this region, never the region's work, so the investigation carries on with its findings intact.
        """
        if on_checkpoint is None:
            return
        try:
            on_checkpoint(_snapshot(done_reason, done_ok))
        except Exception as exc:
            verbose_print(f"Region checkpoint could not be saved: {exc}", verbose)

    if resume_state:
        try:
            read_files |= {_norm_path(p) for p in (resume_state.get("read_files", []) or [])}
            inspected_native |= {_norm_path(p) for p in (resume_state.get("inspected_native", []) or [])}
            coverage_nudged = bool(resume_state.get("coverage_nudged", coverage_nudged))
            add_finding_nudged = bool(resume_state.get("add_finding_nudged", add_finding_nudged))
            exploratory_actions = int(resume_state.get("exploratory_actions", 0) or 0)
            if accumulated or base_steps > 0:
                progressed = True
        except Exception as exc:
            verbose_print(f"Resume state could not be fully restored: {exc}", verbose)

    def _merge_findings(raw_vulns, origin: str = "report") -> int:
        """
        Purpose:
            Add newly reported findings to the region's accumulated set.

        Parameters:
            raw_vulns: The reported findings.
            origin: Where they came from, for provenance.

        Returns:
            How many were new.

        Implementation notes:
            Deduplicated on the way in, because an agent frequently resends findings it has already reported -- which the steering message also addresses, but the merge is what makes a resend harmless rather than a duplicate in the report. The count of new findings is returned so the loop can tell the agent when a report added nothing, which is a strong signal it has finished. Provenance is recorded because a finding salvaged from a truncated report or produced by the forced final report is weaker evidence than one the agent reported deliberately, and the gates weigh that. A native library counts as read once it has been inspected, since inspect_native is the only way to open one.
        """
        if not raw_vulns:
            return 0
        parsed = parser.parse_json_response(json.dumps(raw_vulns))
        added = 0
        for v in parsed:
            if "title" in v and "vulnerability_type" not in v:
                v["vulnerability_type"] = v["title"]
            title = (v.get("title") or v.get("vulnerability_type") or "").strip().lower()
            if not title:
                continue
            v.setdefault("source", "agent")
            v.setdefault("agent_origin", origin)
            v.setdefault("region_key", region_key)
            v.setdefault("region_steps", steps_taken)
            v.setdefault("region_files_read", len(read_files) + len(inspected_native))
            v.setdefault("region_searches", region_searches)
            cited = _norm_path(str(v.get("file", "")))
            v.setdefault("cited_file_read", bool(cited) and (cited in read_files or cited in inspected_native
                                                             or context_file(cited, profile)))

            key = (title, str(v.get("file", "")).strip(), str(v.get("line", "")).strip())
            identity = finding_identity(v)
            idx = seen_keys_index.get(key)
            if idx is None and identity is not None:
                idx = seen_identity.get(identity)
            if idx is None:
                seen_keys.add(key)
                seen_keys_index[key] = len(accumulated)
                if identity is not None:
                    seen_identity[identity] = len(accumulated)
                accumulated.append(v)
                added += 1
                continue
            seen_keys.add(key)
            seen_keys_index[key] = idx
            if identity is not None:
                seen_identity[identity] = idx
            if finding_richness(v) > finding_richness(accumulated[idx]):
                accumulated[idx] = v
        return added

    stop_reason = "provider_error"
    steps_taken = 0

    def _finish(reason: str, ok: bool):
        """
        Purpose:
            End the region and record why.

        Parameters:
            reason: Why it ended.
            ok: Whether it completed successfully.

        Returns:
            The findings, the completion flag and the transcript.

        Implementation notes:
            Every exit goes through here, so the checkpoint and the coverage record are written on the success, budget-exhausted and failure paths alike. A region that ended without recording why would appear in the report's coverage as simply absent.
        """
        if telemetry is not None:
            telemetry["stop_reason"] = reason
            telemetry["steps"] = steps_taken
            telemetry["findings"] = len(accumulated)
            telemetry["files_read"] = len(read_files) + len(inspected_native)
            telemetry["searches"] = region_searches
        _checkpoint(done_reason=reason, done_ok=ok)
        if reason not in _PROVIDER_STOP_REASONS:
            close_session = getattr(provider, "close_session", None)
            if close_session:
                close_session(region_key)
        return accumulated, ok, "\n\n".join(transcript)

    if resume_state and resume_state.get("done") and not resume_state.get("resumable"):
        verbose_print(
            f"Region {region_key!r} already completed before the interruption; "
            f"reusing {plural(len(accumulated), 'finding')}, no model calls", verbose)
        return _finish(str(resume_state.get("stop_reason") or "reported"),
                       bool(resume_state.get("completed_ok", True)))

    failed_turns = 0
    for step in count():
        steps_taken = base_steps + step
        _checkpoint()
        if max_steps is not None and steps_taken >= max_steps:
            verbose_print(
                f"Agent step budget reached ({max_steps} steps); writing up what "
                "was found", verbose)
            stop_reason = "budget_steps"
            break
        if _deadline_expired(deadline):
            verbose_print(
                f"Agent time budget reached at step {steps_taken}; writing up what "
                "was found", verbose)
            stop_reason = "budget_time"
            break
        if is_cancelled():
            if telemetry is not None:
                telemetry["stop_reason"] = "cancelled"
                telemetry["steps"] = steps_taken
                telemetry["findings"] = len(accumulated)
            raise ScanCancelled()
        budget_line = (
            f"You have {plural(max(0, max_steps - steps_taken), 'step')} left. " if max_steps is not None else "")
        if accumulated:
            recorded_items = "; ".join(
                f"{v.get('title') or v.get('vulnerability_type') or '?'} "
                f"({v.get('file', '?')}:{v.get('line', '?')})"
                for v in accumulated)
            recorded_line = (
                f"You have already recorded {plural(len(accumulated), 'finding')} - "
                f"{_truncate(recorded_items, 1500)}. Do NOT resend these in "
                "'report'; it takes no \"vulnerabilities\" array unless you found "
                "something new. ")
        else:
            recorded_line = ""
        tail = (
            f"{recorded_line}{budget_line}Respond with the next action JSON. The "
            "moment you CONFIRM a vulnerability, record it right away with "
            "'add_finding' (then keep examining the remaining flagged files) - do "
            "not save it up for the end. Submit 'report' only once you've examined "
            "everything worth examining."
        )
        on_session = bool(getattr(provider, "has_session", None)
                          and provider.has_session(region_key))
        if on_session:
            prompt = f"{transcript[-1]}\n\n{tail}" if transcript else tail
        else:
            history, history_start = _compact_transcript(
                transcript, history_start, _MAX_TRANSCRIPT_CHARS, _MIN_TRANSCRIPT_CHARS)
            coverage = ""
            if history_start > 0:
                coverage = _coverage_note(
                    read_files | inspected_native,
                    *_unread(source_targets, native_targets, read_files, inspected_native))
            prompt = (
                f"{initial_context}\n\n## Investigation so far\n"
                f"{history or '(nothing yet)'}\n\n{coverage}{tail}"
            )

        result = provider.analyze(prompt, system_message=system, schema=NEXT_ACTION_SCHEMA,
                                  max_tokens=_AGENT_TURN_MAX_TOKENS, session_key=region_key)
        if not isinstance(result, dict) or "error" in result:
            verbose_print(f"Agent step {steps_taken + 1}: provider error: {result}", verbose)
            if not getattr(provider, "unavailable", None) and failed_turns < _MAX_FAILED_TURNS:
                failed_turns += 1
                detail = result.get("error") if isinstance(result, dict) else result
                transcript.append(
                    f"[Step {steps_taken + 1}] SYSTEM NOTE: your reply to this step was lost "
                    f"({_truncate(str(detail), 200)}). Reply with ONE short action JSON and keep "
                    "your reasoning brief.")
                continue
            stop_reason = ("provider_unavailable"
                           if getattr(provider, "unavailable", None)
                           else "provider_error")
            if not progressed:
                if telemetry is not None:
                    telemetry["stop_reason"] = stop_reason
                    telemetry["steps"] = steps_taken
                    telemetry["findings"] = 0
                return [], False, ""
            break

        failed_turns = 0
        action_obj = _parse_action(result.get("response", ""))
        if action_obj is None and not result.get("response") and result.get("thinking"):
            action_obj = _parse_action_from_thinking(result["thinking"])
            if action_obj is not None:
                verbose_print(
                    f"Agent step {steps_taken + 1}: recovered an action from an "
                    "unterminated reasoning trace (content was empty)", verbose)
        if action_obj is None:
            if hasattr(provider, "record_unparseable"):
                provider.record_unparseable()
            verbose_print(
                f"Agent step {steps_taken + 1}: could not parse action. Raw response: "
                f"{(result.get('response') or '')[:300]!r}. Retrying once "
                "before burning the step.", verbose)
            retry_result = provider.analyze(prompt, system_message=system,
                                            schema=NEXT_ACTION_SCHEMA,
                                            max_tokens=_AGENT_TURN_MAX_TOKENS)
            if isinstance(retry_result, dict) and "error" not in retry_result:
                result = retry_result
                action_obj = _parse_action(result.get("response", ""))
                if (action_obj is None and not result.get("response")
                        and result.get("thinking")):
                    action_obj = _parse_action_from_thinking(result["thinking"])

        if action_obj is None:
            raw_resp = _strip_thinking_tokens(result.get("response", "") or "")
            if '"vulnerabilities"' in raw_resp or raw_resp.count('"severity"') >= 2:
                salvaged = parser.parse_json_response(raw_resp) or _salvage_findings(raw_resp)
                if salvaged:
                    verbose_print(
                        f"Agent step {steps_taken + 1}: salvaged {plural(len(salvaged), 'finding')} "
                        "from an unparseable report response", verbose)
                    _merge_findings(salvaged, origin="salvage")
                    return _finish("reported", True)
            verbose_print(f"Agent step {steps_taken + 1}: still unparseable after a retry", verbose)
            transcript.append("ASSISTANT: (unparseable) -> reminder: reply with one JSON object having an 'action'.")
            if not progressed and step >= 2:
                if telemetry is not None:
                    telemetry["stop_reason"] = "unparseable"
                    telemetry["steps"] = steps_taken
                    telemetry["findings"] = 0
                return [], False, ""
            continue

        progressed = True
        action = (action_obj.get("action") or "").strip()
        path = action_obj.get("path", "") or ""
        pattern = action_obj.get("pattern", "") or ""
        method = str(action_obj.get("method", "") or "").strip()
        target = str(action_obj.get("target", "") or "").strip()
        thought = action_obj.get("thought", "")
        start_line_raw = action_obj.get("start_line")
        try:
            start_line = int(start_line_raw) if start_line_raw is not None else None
        except (TypeError, ValueError):
            start_line = None
        raw_paths = action_obj.get("paths")
        paths = [str(p).strip() for p in raw_paths if str(p).strip()] \
            if isinstance(raw_paths, list) else []

        if action == "add_finding":
            exploratory_actions = 0
            added = _merge_findings(action_obj.get("vulnerabilities"), origin="add_finding")
            verbose_print(
                f"Agent step {steps_taken + 1}: recorded {plural(added, 'new finding')} "
                f"({len(accumulated)} total so far)", verbose)
            transcript.append(
                f"ASSISTANT: {thought}\n"
                f"TOOL add_finding -> recorded {plural(added, 'new finding')}; "
                f"{len(accumulated)} saved so far. Keep investigating the remaining "
                "flagged files, then submit 'report' to finish.")
            _checkpoint()
            continue

        if action == "report":
            _merge_findings(action_obj.get("vulnerabilities"), origin="report")
            unread_src, unread_nat = _unread(source_targets, native_targets, read_files, inspected_native)
            if code_graph is not None and (unread_src or unread_nat) and not coverage_nudged:
                coverage_nudged = True
                verbose_print(
                    f"Coverage nudge at step {steps_taken + 1}: {len(unread_src)} source + "
                    f"{plural(len(unread_nat), 'native file')} unexamined", verbose)
                transcript.append("ASSISTANT: (attempted report)\n"
                                  + _steer_message(unread_src, unread_nat, repeated=False,
                                                   recorded=len(accumulated)))
                continue
            verbose_print(
                f"Agent finished at step {steps_taken + 1} with "
                f"{plural(len(accumulated), 'finding')}", verbose)
            return _finish("reported", True)

        batched = action == "read_file" and paths
        verbose_print(_describe_request(action, path, paths, pattern, start_line,
                                        method, target), verbose)
        if action == "list_files":
            observation = tools.list_files(path)
        elif batched:
            observation, ok_paths = _read_batch(tools, paths)
        elif action == "read_file":
            observation = tools.read_file(path, start_line=start_line)
        elif action == "search_code":
            observation = tools.search_code(pattern, path)
            if not observation.startswith("ERROR"):
                region_searches += 1
        elif action == "inspect_native":
            observation = tools.inspect_native(path, start_line=start_line)
        elif action == "find_method":
            observation = tools.find_method(method)
        elif action == "callers":
            observation = tools.callers(method)
        elif action == "callees":
            observation = tools.callees(method)
        elif action == "call_path":
            observation = tools.call_path(method, target)
        elif action == "entry_points":
            observation = tools.entry_points()
        else:
            observation = (
                "Unknown action '{}'. Use list_files, read_file, search_code, "
                "inspect_native, find_method, callers, callees, call_path, "
                "entry_points, add_finding, or report.".format(action))

        verbose_print(_describe_response(action, path, paths, observation), verbose)

        if batched:
            read_files.update(_norm_path(p) for p in ok_paths)
        elif action == "read_file" and not observation.startswith("ERROR"):
            read_files.add(_norm_path(path))
        elif action == "inspect_native" and not observation.startswith("ERROR"):
            inspected_native.add(_norm_path(path))

        sig = (action, _norm_path(path), tuple(_norm_path(p) for p in paths),
               pattern.strip(), start_line, method, target)
        stalled = (sig == last_sig) or observation.startswith("NOTE: already read to the end")
        no_progress = no_progress + 1 if stalled else 0
        last_sig = sig

        label = (
            f"{action}("
            f"{'paths=' + repr(paths) if batched else 'path=' + repr(path)}"
            f"{(', pattern=' + repr(pattern)) if pattern else ''}"
            f"{(', start_line=' + repr(start_line)) if start_line is not None else ''})"
        )
        entry = f"ASSISTANT: {thought}\nTOOL {label} ->\n{_truncate(observation, _MAX_OBS_CHARS)}"

        if no_progress >= 2:
            unread_src, unread_nat = _unread(source_targets, native_targets, read_files, inspected_native)
            entry += "\n" + _steer_message(unread_src, unread_nat, repeated=True)
            no_progress = 0

        exploratory_actions += 1
        if (not add_finding_nudged and not accumulated
                and exploratory_actions >= _ADD_FINDING_NUDGE_AFTER):
            add_finding_nudged = True
            verbose_print(
                f"Add-finding nudge at step {steps_taken + 1}: {exploratory_actions} "
                "exploratory turns with nothing recorded yet", verbose)
            entry += (
                "\nSYSTEM NUDGE: You have investigated several files and not called "
                "'add_finding' even once. The moment you CONFIRM something is a real "
                "vulnerability, record it right away with 'add_finding' - do not wait "
                "until the end. A long investigation risks losing an early confirmed "
                "finding if it is never recorded along the way. If nothing is "
                "confirmed yet, keep investigating.")
        transcript.append(entry)

    if getattr(provider, "unavailable", None):
        verbose_print(
            "Agent loop ended with the provider unavailable; keeping the "
            f"{plural(len(accumulated), 'finding')} already recorded", verbose)
        return _finish(stop_reason, True)

    if accumulated:
        verbose_print(
            f"Agent loop ended without a report; keeping the "
            f"{plural(len(accumulated), 'finding')} already recorded rather than "
            "forcing a blind rewrite", verbose)
        return _finish(stop_reason, True)

    verbose_print("Agent loop ended without a report; forcing a final report", verbose)
    forced = _force_final_report(
        provider, initial_context, transcript, parser, skill_names, verbose, core=core_skill)
    _merge_findings(forced, origin="forced_report")
    return _finish(stop_reason, True)

_REPORT_SYSTEM = """You are a security analyst summarising a mobile app code audit.
You have already finished reading the source files.  Your ONLY task now is to
output a JSON array of vulnerability objects - no tool calls, no prose, no
markdown.  Each object must have at minimum:
  "title", "cvss_vector", "file", "line", "description", "recommendation"
where "line" is the 1-based line number (e.g. "8") or an inclusive range (e.g.
"6-7") of the vulnerable line(s), and "cvss_vector" is the CVSS v3.1 base
vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") scored from what the code
actually does - AV/AC/PR/UI/S/C/I/A per
https://www.first.org/cvss/calculator/3.1. Severity is COMPUTED from this
score; do not pick a severity word instead (only include "severity" as a
fallback if you truly cannot score a valid vector).  Do NOT include code
snippets - the code is extracted automatically from the file at the line(s)
you cite.
If you found nothing, output an empty array: []
Output ONLY valid JSON.  Do NOT wrap it in ```code fences```.  Do NOT include
any <think> blocks or reasoning text."""

def _force_final_report(provider, initial_context, transcript, parser, skill_names, verbose,
                        core: str = CORE_SKILL):
    """
    Purpose:
        Ask for a final report when the agent ran out of budget without producing one.

    Parameters:
        provider: The AI provider.
        initial_context: The opening context.
        transcript: The investigation so far.
        parser: The response parser.
        skill_names: Skills to load for the report.
        verbose: Traces progress.
        core: The core skill.

    Returns:
        The findings.

    Side effects:
        Makes one provider request.

    Implementation notes:
        This recovers an investigation that read the code and never got to report it -- the commonest way a region wastes its whole budget. The prompt asks for findings only, with no actions, so the model cannot spend the last request on another tool call. The quality and taxonomy skills are added for this request specifically, since the model is now writing findings rather than exploring and those are the guidance that matters. The response goes through the normal parser and falls back to salvage, because a forced report is produced under pressure and is exactly the case most likely to be truncated. Titles are copied into the type field, since findings recovered this way often carry only one of the two and downstream code reads either.
    """
    skill_names = [*skill_names, "finding_quality", "vulnerability_classes"]
    skills_text = load_skills(skill_names, verbose, core=core)
    report_system = _REPORT_SYSTEM + (("\n\n# Skills reference\n\n" + skills_text) if skills_text else "")
    history, _ = _compact_transcript(transcript, 0, _MAX_TRANSCRIPT_CHARS, _MIN_TRANSCRIPT_CHARS)
    prompt = (
        f"{initial_context}\n\n## Investigation so far\n{history}\n\n"
        "You have finished exploring the code.  Output ONLY a JSON array of "
        "vulnerability findings based on what you read above.  No actions, no "
        "prose - just the JSON array."
    )
    result = provider.analyze(prompt, system_message=report_system, schema=VULNERABILITY_SCHEMA,
                              max_tokens=_FORCED_REPORT_MAX_TOKENS)
    if not isinstance(result, dict) or "error" in result:
        return []
    raw = _strip_thinking_tokens(result.get("response", "") or "")
    vulns = parser.parse_json_response(raw) or _salvage_findings(raw)
    for v in vulns:
        if "title" in v and "vulnerability_type" not in v:
            v["vulnerability_type"] = v["title"]
    return vulns
