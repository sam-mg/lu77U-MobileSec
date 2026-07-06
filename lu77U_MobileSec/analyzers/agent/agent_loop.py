"""Provider-agnostic, bounded tool-calling loop."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .tools import AgentTools, MAX_READ_CHARS
from .skills_loader import load_skills
from ...ai.schema import VULNERABILITY_ITEM_SCHEMA, VULNERABILITY_SCHEMA
from ...config.prompts import VulnerabilityPrompts
from ...utils.response_parser import ResponseParser
from ...utils.verbose import verbose_print

DEFAULT_MAX_STEPS = 30
_MAX_OBS_CHARS = MAX_READ_CHARS + 3000
_MAX_TRANSCRIPT_CHARS = 60000    # total rolling transcript cap (oldest dropped first)
_MAX_BATCH_FILES = 8
_MAX_BATCH_CHARS = 28000

NEXT_ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "description": "Brief reasoning for this step"},
        "action": {
            "type": "string",
            "enum": ["list_files", "read_file", "search_code", "inspect_native", "report"],
            "description": "The next tool to use, or 'report' to finish",
        },
        "path": {"type": "string", "description": "Path for list_files/read_file/search_code/inspect_native"},
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
                "Optional, for read_file only: 1-based line to start from. Omit to "
                "auto-continue where the last read of this same path left off (or "
                "start at line 1 on the first read) — omitting never repeats "
                "content already shown."
            ),
        },
        "vulnerabilities": {
            "type": "array",
            "items": VULNERABILITY_ITEM_SCHEMA,
            "description": "Findings to submit (only when action is 'report')",
        },
    },
    "required": ["action"],
}

AGENT_SYSTEM = VulnerabilityPrompts.get_static_agent_system()

def _truncate(text: str, limit: int) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated]"

def _truncate_tail(text: str, limit: int) -> str:
    """Like ``_truncate``, but keeps the most RECENT ``limit`` characters
    (dropping the oldest) instead of the earliest. Used for the rolling
    investigation transcript, where what the model did a few turns ago
    matters more than what it did first — the initial manifest/file-tree
    context is passed separately and unaffected by this window regardless."""
    if text is None:
        return ""
    return text if len(text) <= limit else "... [earlier turns truncated]\n" + text[-limit:]

def _strip_thinking_tokens(text: str) -> str:
    """Isolate a thinking model's actual answer from its chain-of-thought.

    Thinking models (nemotron-3-super, DeepSeek-R1, QwQ, …) wrap reasoning in
    ``<think>…</think>``. Two cases matter:

    - Paired blocks are removed outright.
    - A *lone* ``</think>`` (the opening tag lost to streaming/truncation) means
      everything before it was reasoning and the real answer follows it — so we
      keep only what comes after the LAST ``</think>``. This is what fixed a
      real failure where the model emitted a draft ``{"action":"read_file"}``
      inside its thinking, then ``</think>``, then its actual ``report``; the
      old code kept the draft and ran a stray read instead of reporting.
    """
    import re
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    lower = text.lower()
    if "</think>" in lower:
        text = text[lower.rindex("</think>") + len("</think>"):]
    # Drop any stray opening tags left over.
    text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE)
    return text.strip()

def _extract_first_json_object(text: str):
    """Return the substring of the first complete top-level {...} using brace counting.

    Unlike find+rfind this is not fooled by duplicate JSON objects separated by
    stray text (e.g. a </think> tag between two copies of the same object).
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
    """Yield every balanced ``{...}`` substring at any nesting depth, string-aware
    (a brace inside a JSON string doesn't count). Used to pull individual finding
    objects out of a report even when the surrounding JSON is malformed."""
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
    """Last-resort recovery of a findings report whose JSON is too malformed for
    any real parser — extract each finding object by brace matching, then pull
    its fields with regex, tolerating arbitrary intra-object errors (models
    routinely emit an unquoted ``"line": 76-80 (manifest export)`` or a stray
    ``"line": "12", 22-23`` that breaks strict parsing). Recovers the valid
    findings instead of discarding the whole report. Confirmed to recover all 13
    findings from a real run's malformed 14 KB response."""
    def field(obj: str, key: str) -> str:
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
        if obj.count('"title"') != 1:   # skip the outer wrapper + non-finding objects
            continue
        f = {k: field(obj, k) for k in _SALVAGE_FIELDS}
        if f["title"] and (f["file"] or f["severity"]):
            out.append({k: v for k, v in f.items() if v})
    return out

def _coerce_report(obj):
    """Normalize a parsed object that is *really* a finish/report into the
    canonical ``{"action": "report", "vulnerabilities": [...]}`` shape.

    Weaker models often emit their findings as a bare JSON array, or a dict
    that carries ``vulnerabilities``/``findings`` without an ``action`` — both
    clearly mean "I'm done, here are the findings". Recognizing that avoids
    discarding a valid report just because it didn't wear the exact envelope.
    Returns ``obj`` unchanged when it's a normal action dict."""
    if isinstance(obj, list):
        return {"action": "report", "vulnerabilities": obj}
    if isinstance(obj, dict):
        action = (obj.get("action") or "").strip().lower()
        if not action:
            for key in ("vulnerabilities", "findings", "results"):
                if isinstance(obj.get(key), list):
                    return {"action": "report", "vulnerabilities": obj[key]}
    return obj

def _parse_action(raw: str) -> Optional[Dict[str, Any]]:
    """Parse the model's next-action JSON, tolerating fenced/loose/thinking output."""
    if not raw:
        return None
    raw = _strip_thinking_tokens(raw)
    # strip ```json fences if present
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    try:
        obj = json.loads(raw)
    except Exception:
        candidate = _extract_first_json_object(raw)
        if candidate is None:
            return None
        try:
            obj = json.loads(candidate)
        except Exception:
            return None
    obj = _coerce_report(obj)
    return obj if isinstance(obj, dict) else None

def _build_initial_context(tools: AgentTools, static_signals: Dict[str, Any],
                           code_graph=None) -> str:
    """First-turn context (re-sent every turn, never transcript-truncated).

    When a ``code_graph`` is available it becomes the model's primary map — a
    security-annotated view of the app's own classes — and the full ~23 KB file
    tree is dropped (it's re-sent every turn and is mostly framework/resource
    noise the graph already subsumes). In its place goes a short list of the
    security-relevant app resources the graph *doesn't* cover (network config,
    raw assets, strings) plus a pointer to ``list_files`` for anything else.
    Without a graph, the flat tree is the map, as before.
    """
    framework = static_signals.get("framework", "unknown")
    manifest = _truncate(tools.manifest_summary(), 6000)
    parts = [
        f"## Static signals\nDetected framework: {framework}\n",
        f"## AndroidManifest.xml\n```xml\n{manifest}\n```\n",
    ]
    if code_graph is not None:
        parts.append(code_graph.render() + "\n")
        resources = tools.app_resource_files()
        res_block = ("\n".join(resources) if resources
                     else "(none of note)")
        parts.append(
            "## App resources (not in the code map above)\n"
            f"{res_block}\n"
            "Use `list_files` to browse any other directory (layouts, "
            "framework resources, etc.) if you need it.\n")
    else:
        parts.append("## Decompiled file tree (paths + sizes only)\n"
                     + tools.file_tree() + "\n")
    return "\n".join(parts)

def _contextual_skills(action: str, path: str, pattern: str) -> List[str]:
    extra = []
    blob = f"{path} {pattern}".lower()
    if "androidmanifest" in path.lower() or "manifest" in blob:
        extra.append("manifest_review")
    if any(k in blob for k in ("ssl", "trust", "http", "cert", "hostname", "network", "socket")):
        extra.append("network_security")
    if action == "inspect_native" or any(k in blob for k in (".so", "jni", "native")):
        extra.append("offensive_android")
    return extra

def _norm_path(p: str) -> str:
    return (p or "").strip().lstrip("./").replace("\\", "/")

def _coverage_targets(code_graph, tools: AgentTools):
    """Return ``(source_targets, native_targets)`` the agent should examine
    before finishing: the graph's flagged files when a graph exists, else every
    app source file. Native libs are tracked separately (examined via
    ``inspect_native``, not ``read_file``)."""
    native_targets = set()
    if code_graph is not None:
        native_targets = {_norm_path(l.path) for l in code_graph.native_libs}
        source_targets = {_norm_path(f) for f in code_graph.flagged_files()} - native_targets
    else:
        source_targets = {_norm_path(f) for f in tools.app_source_files()}
    return source_targets, native_targets

def _unread(source_targets, native_targets, read_files, inspected_native):
    unread_src = sorted(source_targets - read_files)
    unread_nat = sorted(native_targets - inspected_native)
    return unread_src, unread_nat

def _read_batch(tools: AgentTools, paths: List[str]):
    """Read several files in one turn (bounded by count + total chars), returning
    ``(observation, ok_paths)``. Cutting per-file round-trips is the biggest
    wall-clock lever since each model call costs ~15 s."""
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
                chunks.append(f"... (batch budget reached; {remaining} more path(s) "
                              "not read — request them next turn)")
            break
    return "\n\n".join(chunks), ok

def _steer_message(unread_src, unread_nat, *, repeated: bool) -> str:
    lines = []
    if repeated:
        lines.append("That repeated a previous action and produced no new "
                     "information — do NOT repeat it.")
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
    max_steps: int = DEFAULT_MAX_STEPS,
    verbose: bool = False,
) -> Tuple[List[Dict[str, Any]], bool, str]:
    """Run the bounded agent loop.

    ``code_graph`` (optional :class:`~lu77U_MobileSec.analyzers.agent.code_graph.CodeGraph`)
    becomes the model's map and drives coverage tracking; when ``None`` the loop
    degrades to the flat file tree with no behavior change beyond the anti-loop
    guard. Returns ``(vulnerabilities, completed_ok, transcript)``. ``completed_ok``
    is False only when the provider could not drive the loop at all (caller then
    falls back to the non-agentic full-dump path).
    """
    static_signals = static_signals or {}
    tools = AgentTools(jadx_output_dir)
    parser = ResponseParser(verbose=verbose)

    initial_context = _build_initial_context(tools, static_signals, code_graph)
    transcript: List[str] = []
    skill_names: List[str] = []
    progressed = False  # did the provider produce at least one valid action?

    # Coverage + anti-loop state.
    source_targets, native_targets = _coverage_targets(code_graph, tools)
    read_files: set = set()
    inspected_native: set = set()
    last_sig: Optional[tuple] = None
    no_progress = 0
    coverage_nudged = False

    def _finalize_report(action_obj, step):
        vulns_raw = action_obj.get("vulnerabilities") or []
        verbose_print(f"Agent finished at step {step} with {len(vulns_raw)} finding(s)", verbose)
        vulns = parser.parse_json_response(json.dumps(vulns_raw))
        for v in vulns:
            if "title" in v and "vulnerability_type" not in v:
                v["vulnerability_type"] = v["title"]
        return vulns

    for step in range(max_steps):
        remaining = max_steps - step
        system = AGENT_SYSTEM + "\n\n# Reference skills\n\n" + load_skills(skill_names, verbose)
        history = _truncate_tail("\n\n".join(transcript), _MAX_TRANSCRIPT_CHARS)
        prompt = (
            f"{initial_context}\n\n## Investigation so far\n"
            f"{history or '(nothing yet)'}\n\n"
            f"You have {remaining} step(s) left. Respond with the next action JSON."
        )

        result = provider.analyze(prompt, system_message=system, schema=NEXT_ACTION_SCHEMA)
        if not isinstance(result, dict) or "error" in result:
            verbose_print(f"Agent step {step}: provider error: {result}", verbose)
            if not progressed:
                return [], False, ""  # provider can't drive the loop → fall back
            break

        action_obj = _parse_action(result.get("response", ""))
        if action_obj is None:
            raw_resp = _strip_thinking_tokens(result.get("response", "") or "")
            if '"vulnerabilities"' in raw_resp or raw_resp.count('"severity"') >= 2:
                salvaged = parser.parse_json_response(raw_resp) or _salvage_findings(raw_resp)
                if salvaged:
                    verbose_print(
                        f"Agent step {step}: salvaged {len(salvaged)} finding(s) "
                        "from an unparseable report response", verbose)
                    for v in salvaged:
                        if "title" in v and "vulnerability_type" not in v:
                            v["vulnerability_type"] = v["title"]
                    return salvaged, True, "\n\n".join(transcript)
            verbose_print(f"Agent step {step}: could not parse action", verbose)
            transcript.append("ASSISTANT: (unparseable) -> reminder: reply with one JSON object having an 'action'.")
            if not progressed and step >= 2:
                return [], False, ""  # provider keeps emitting junk → fall back
            continue

        progressed = True
        action = (action_obj.get("action") or "").strip()
        path = action_obj.get("path", "") or ""
        pattern = action_obj.get("pattern", "") or ""
        thought = action_obj.get("thought", "")
        start_line_raw = action_obj.get("start_line")
        try:
            start_line = int(start_line_raw) if start_line_raw is not None else None
        except (TypeError, ValueError):
            start_line = None
        raw_paths = action_obj.get("paths")
        paths = [str(p).strip() for p in raw_paths if str(p).strip()] \
            if isinstance(raw_paths, list) else []

        if action == "report":
            unread_src, unread_nat = _unread(source_targets, native_targets, read_files, inspected_native)
            if code_graph is not None and (unread_src or unread_nat) and not coverage_nudged:
                coverage_nudged = True
                verbose_print(
                    f"Coverage nudge at step {step}: {len(unread_src)} source + "
                    f"{len(unread_nat)} native file(s) unexamined", verbose)
                transcript.append("ASSISTANT: (attempted report)\n"
                                  + _steer_message(unread_src, unread_nat, repeated=False))
                continue
            return _finalize_report(action_obj, step), True, "\n\n".join(transcript)

        batched = action == "read_file" and paths
        if action == "list_files":
            observation = tools.list_files(path)
        elif batched:
            observation, ok_paths = _read_batch(tools, paths)
        elif action == "read_file":
            observation = tools.read_file(path, start_line=start_line)
        elif action == "search_code":
            observation = tools.search_code(pattern, path)
        elif action == "inspect_native":
            observation = tools.inspect_native(path)
        else:
            observation = (
                "Unknown action '{}'. Use list_files, read_file, search_code, "
                "inspect_native, or report.".format(action))

        if batched:
            read_files.update(_norm_path(p) for p in ok_paths)
        elif action == "read_file" and not observation.startswith("ERROR"):
            read_files.add(_norm_path(path))
        elif action == "inspect_native" and not observation.startswith("ERROR"):
            inspected_native.add(_norm_path(path))

        sig = (action, _norm_path(path), tuple(_norm_path(p) for p in paths),
               pattern.strip(), start_line)
        stalled = (sig == last_sig) or observation.startswith("(already read to the end")
        no_progress = no_progress + 1 if stalled else 0
        last_sig = sig

        for name in _contextual_skills(action, path + " " + " ".join(paths), pattern):
            if name not in skill_names:
                skill_names.append(name)

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
        transcript.append(entry)

    # Step budget exhausted without a 'report' → force a final answer.
    verbose_print("Agent step budget exhausted; forcing a final report", verbose)
    vulns = _force_final_report(provider, initial_context, transcript, parser, skill_names, verbose)
    return vulns, True, "\n\n".join(transcript)

_REPORT_SYSTEM = """You are a security analyst summarising an Android code audit.
You have already finished reading the source files.  Your ONLY task now is to
output a JSON array of vulnerability objects — no tool calls, no prose, no
markdown.  Each object must have at minimum:
  "title", "cvss_vector", "file", "line", "description", "recommendation"
where "line" is the 1-based line number (e.g. "8") or an inclusive range (e.g.
"6-7") of the vulnerable line(s), and "cvss_vector" is the CVSS v3.1 base
vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") scored from what the code
actually does — AV/AC/PR/UI/S/C/I/A per
https://www.first.org/cvss/calculator/3.1. Severity is COMPUTED from this
score; do not pick a severity word instead (only include "severity" as a
fallback if you truly cannot score a valid vector).  Do NOT include code
snippets — the code is extracted automatically from the file at the line(s)
you cite.
If you found nothing, output an empty array: []
Output ONLY valid JSON.  Do NOT wrap it in ```code fences```.  Do NOT include
any <think> blocks or reasoning text."""

def _force_final_report(provider, initial_context, transcript, parser, skill_names, verbose):
    skills_text = load_skills(skill_names, verbose)
    report_system = _REPORT_SYSTEM + (("\n\n# Skills reference\n\n" + skills_text) if skills_text else "")
    history = _truncate_tail("\n\n".join(transcript), _MAX_TRANSCRIPT_CHARS)
    prompt = (
        f"{initial_context}\n\n## Investigation so far\n{history}\n\n"
        "You have finished exploring the code.  Output ONLY a JSON array of "
        "vulnerability findings based on what you read above.  No actions, no "
        "prose — just the JSON array."
    )
    result = provider.analyze(prompt, system_message=report_system, schema=VULNERABILITY_SCHEMA)
    if not isinstance(result, dict) or "error" in result:
        return []
    raw = _strip_thinking_tokens(result.get("response", "") or "")
    vulns = parser.parse_json_response(raw) or _salvage_findings(raw)
    for v in vulns:
        if "title" in v and "vulnerability_type" not in v:
            v["vulnerability_type"] = v["title"]
    return vulns