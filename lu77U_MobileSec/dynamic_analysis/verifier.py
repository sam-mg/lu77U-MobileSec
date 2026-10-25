#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.verifier

Purpose:
    Take static findings to a live device and settle them: let an agent read the source, run permitted device commands and inject instrumentation until it can say whether each finding actually holds on the running app.

Responsibilities:
    Triage which findings are worth verifying, run the agent loop against the bounded tool surface, parse its actions, record verdicts, and attach the outcome to each finding.

Dependencies:
    The AI provider layer, the bounded device tool surface, the code graph.

Implementation notes:
    Static analysis cannot see what is reachable at runtime, and a verdict from the device is worth far more than another opinion about the code. This phase is where a finding stops being a claim. The agent is given a step budget scaled to the number of findings rather than a fixed one, so a small result set finishes quickly and a large one gets proportionate room. Findings the agent never reaches are marked not verified with a reason, never silently dropped: an unverified finding stays in the report as a lead.

Security considerations:
    Every device operation goes through the bounded tool surface, which scopes access to the app under test. The agent chooses what to run; the tool surface decides what is allowed.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..analyzers.agent.skills_loader import load_skill
from ..analyzers.agent.tools import MAX_READ_CHARS
from ..config.prompts import VulnerabilityPrompts
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import plural, verbose_print
from .adb_manager import ADBManager
from .frida_manager import FridaManager
from .verify_tools import VerifyTools

DEFAULT_MAX_STEPS = 20
_MAX_REPEATED_TOOL_ERRORS = 3
_MAX_STEPS_CEILING = 60


def _default_max_steps(num_findings: int) -> int:
    """
    Purpose:
        Scale the agent's step budget to how many findings it has to settle.

    Parameters:
        num_findings: Number of findings to verify.

    Returns:
        The step ceiling.

    Implementation notes:
        Roughly two steps per finding plus a margin, floored at a useful minimum and capped so a large result set cannot make the phase unbounded. Two steps is about what a verdict costs -- one to look, one to decide -- and the margin covers setup and the ones that need more.
    """
    return max(DEFAULT_MAX_STEPS, min(_MAX_STEPS_CEILING, 2 * num_findings + 6))
_MAX_OBS_CHARS = MAX_READ_CHARS + 3000
_MAX_TRANSCRIPT_CHARS = 50000


def _truncate(text: Optional[str], limit: int) -> str:
    """
    Purpose:
        Bound text to a length, marking it when cut.

    Parameters:
        text: The text.
        limit: Maximum length.

    Returns:
        The bounded text.
    """
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def _truncate_tail(text: Optional[str], limit: int) -> str:
    """
    Purpose:
        Bound text by keeping its end rather than its beginning.

    Parameters:
        text: The text.
        limit: Maximum length.

    Returns:
        The bounded text, marked when earlier content was dropped.

    Implementation notes:
        Used for the conversation transcript, where the recent turns matter and the early ones can go. Truncating from the front instead would leave the agent with its opening context and none of what it has just learned.
    """
    if text is None:
        return ""
    return text if len(text) <= limit else "... [earlier turns truncated]\n" + text[-limit:]


def _strip_thinking_tokens(text: str) -> str:
    """
    Purpose:
        Remove reasoning-trace markup before parsing an action.

    Parameters:
        text: The raw response.

    Returns:
        The response with thinking blocks removed.

    Implementation notes:
        The trace often contains a draft action in braces, which the JSON extractor would find first. It has to go before extraction, not after.
    """
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _extract_first_json_object(text: str) -> Optional[str]:
    """
    Purpose:
        Find the first complete JSON object in a response, tracking string and escape state.

    Parameters:
        text: The response text.

    Returns:
        The object's text, or None.

    Complexity:
        O(n) in the text length.

    Implementation notes:
        Brace counting alone would break on a brace inside a string value -- and these actions carry Frida scripts and shell commands, which contain braces routinely. Tracking string and escape state is what makes the extraction correct for exactly the payloads this agent sends.
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
                return text[start:i + 1]
    return None


def _parse_action(raw: str) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Parse one agent response into an action object.

    Parameters:
        raw: The response text.

    Returns:
        The action, or None when nothing parseable was found.

    Implementation notes:
        Three shapes are handled in order: a Markdown code fence is unwrapped, a reasoning trace is stripped, and a bare object is extracted from surrounding prose. Models produce all three despite being asked for raw JSON. None means the turn produced nothing usable, and the caller tells the agent so rather than guessing at an action.
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
        obj = json.loads(raw)
    except Exception:
        candidate = _extract_first_json_object(raw)
        if candidate is None:
            return None
        try:
            obj = json.loads(candidate)
        except Exception:
            return None
    return obj if isinstance(obj, dict) else None


_THOUGHT_MAX = 120
_COMMAND_MAX = 300
_SCRIPT_MAX = 2000
_NOTE_TEXT_MAX = 400
_EVIDENCE_MAX = 400
_VERDICT_REASON_MAX = 240
_STEP_MAX_TOKENS = 3000
_TRIAGE_MAX_TOKENS = 300

NEXT_ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "maxLength": _THOUGHT_MAX,
                    "description": "Brief reasoning for this step - at most one short "
                                   "sentence, not a plan."},
        "action": {
            "type": "string",
            "enum": ["read_source", "adb", "frida", "note", "verdict"],
            "description": "The next tool to use",
        },
        "path": {"type": "string", "description": "Path for read_source (one file)"},
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "For read_source: several file paths to read in one step.",
        },
        "start_line": {
            "type": "integer",
            "description": (
                "Optional, for read_source only: 1-based line to start from. Omit "
                "to auto-continue where the last read of this same path left off "
                "(or start at line 1 on the first read)."
            ),
        },
        "command": {"type": "string", "maxLength": _COMMAND_MAX,
                    "description": "Command for adb (scoped to the target app)"},
        "script": {"type": "string", "maxLength": _SCRIPT_MAX,
                   "description": "Frida JS source for frida - the minimal hook, not a "
                                  "general-purpose instrumentation script"},
        "trigger": {"type": "string", "maxLength": _COMMAND_MAX,
                    "description": "For frida, optional: an adb command (same rules as the "
                                   "adb action) run once the hooks are installed, so the code "
                                   "they watch runs while they listen - e.g. the am start that "
                                   "opens the hooked screen"},
        "text": {"type": "string", "maxLength": _NOTE_TEXT_MAX,
                 "description": "Free-text observation for note"},
        "finding_id": {"type": "string", "description": "Which finding this verdict concludes"},
        "finding_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "For a batched verdict: several finding ids that the SAME evidence "
                "proves at once (e.g. one dumpsys proving F1,F2,F3). They share the "
                "given status + evidence/reason. Use instead of finding_id. Label each "
                "id's proof in the evidence ('F1: ... F2: ...'): each finding is shown "
                "only the part labelled with its own id."
            ),
        },
        "status": {"type": "string", "enum": ["verified", "refuted", "not_verified"]},
        "evidence": {"type": "string", "maxLength": _EVIDENCE_MAX,
                     "description": "Proof, when status is verified - the command/hook and "
                                    "what it showed, not a transcript"},
        "reason": {"type": "string", "maxLength": _VERDICT_REASON_MAX,
                   "description": "Why it couldn't be proven, when not_verified"},
    },
    "required": ["action"],
}


_ID_LABEL_RE = re.compile(r"\bF(\d+)\s*:")
_ID_LIST_RE = re.compile(r"\s*\((?:[a-z]+ )?F\d+(?:(?:, | and | & |,)F\d+)*\)")
_ID_MENTION_RE = re.compile(r"\bF(\d+)\b")
_ITEM_START_RE = re.compile(r"(?:^|(?<=\s))\d{1,2}\. (?=\S)")
_SENTENCE_END_RE = re.compile(r"(?<=[.!?]) (?=\S)")
_TRAILING_ITEM_RE = re.compile(r" \d{1,2}\.(?: [A-Z][a-z]{0,12})?$")


def _clean_ids(text: str) -> str:
    """
    Purpose:
        Remove the agent's internal finding identifiers from text a reader will see.

    Parameters:
        text: Evidence or a reason, as the agent wrote it.

    Returns:
        The text without parenthesised identifier lists such as "(F3, F5, F7)" and without leftover segment labels.

    Implementation notes:
        The identifiers are positional within one verification session and mean nothing in a report; a published reason read "preventing the proof of SQL injections (F1, F8, F9, F23)".
    """
    text = _ID_LIST_RE.sub("", text or "")
    text = _ID_LABEL_RE.sub("", text)
    text = re.sub(r"\s{2,}", " ", text).strip()
    text = _TRAILING_ITEM_RE.sub("", text)
    return _ITEM_START_RE.sub("", text, count=1) if _ITEM_START_RE.match(text) else text


def _evidence_for(fid: str, evidence: str) -> Optional[str]:
    """
    Purpose:
        Pick out the part of a batched verdict's evidence that concerns one finding.

    Parameters:
        fid: The finding's identifier.
        evidence: The verdict's evidence text.

    Returns:
        The finding's own evidence, cleaned for a reader; the whole text, cleaned, when it carries no per-finding labels; None when it is labelled per finding and none of the labels is this one.

    Implementation notes:
        A batched verdict shares one evidence text across its findings, and the agent writes it as labelled segments ("F24: dumpsys showed ... F27: ..."). Attaching the whole text to every finding in the batch once marked a missing-FLAG_SECURE note verified by evidence about an exported content provider. Unlabelled evidence is taken to cover the whole batch, as the verdict states.
    """
    labels = list(_ID_LABEL_RE.finditer(evidence or ""))
    if not labels:
        return _mentioned_part(fid, evidence or "")
    parts = []
    for i, match in enumerate(labels):
        end = labels[i + 1].start() if i + 1 < len(labels) else len(evidence)
        if f"F{match.group(1)}" == fid:
            parts.append(evidence[match.end():end].strip())
    return _clean_ids(" ".join(parts)) or None if parts else None


def _mentioned_part(fid: str, evidence: str) -> Optional[str]:
    """
    Purpose:
        Pick out the items of unlabelled evidence that name one finding.

    Parameters:
        fid: The finding's identifier.
        evidence: Evidence with no "F1:" style labels.

    Returns:
        The items that mention fid or no identifier at all, cleaned; the whole text, cleaned, when it is a single item or names fewer than two findings; None when every item names other findings.

    Implementation notes:
        An agent asked for labels sometimes writes a numbered list instead and names the findings inside it: "1. dumpsys confirms APICreds2Activity is exported (proving F35). 2. am start ... bypasses the PIN check (proving F6 and F27)". The text is split at its list numbers, or at sentence ends when it has none, and each item goes to the findings it names; an item naming none is shared. A single item, or text naming only one finding, is shared by the whole batch as before, since one sentence often covers several findings while naming one. Taking the whole list for every finding in the batch once showed a plaintext temp-file finding as verified by an activity launch.
    """
    starts = [m.start() for m in _ITEM_START_RE.finditer(evidence)]
    if len(starts) >= 2:
        bounds = ([0] if starts[0] > 0 else []) + starts + [len(evidence)]
        items = [evidence[a:b] for a, b in zip(bounds, bounds[1:])]
    else:
        items = _SENTENCE_END_RE.split(evidence)
    named = [(item, {f"F{n}" for n in _ID_MENTION_RE.findall(item)}) for item in items]
    if len(items) < 2 or len(set().union(*(ids for _, ids in named))) < 2:
        return _clean_ids(evidence) or None
    own = [item for item, ids in named if fid in ids or not ids]
    return _clean_ids(" ".join(own)) or None if own else None


_DEVICE_ACTION_RE = re.compile(
    r"\b(?:adb|dumpsys|am start|screencap|logcat|run-as|frida|content (?:query|read|insert|call)"
    r"|pm (?:list|path|dump)|getprop|uiautomator|input (?:tap|text|swipe)|mitm\w*|intercepted"
    r"|hooked|cmd package)\b", re.IGNORECASE)

_VERSION_LIMIT_RE = re.compile(r"\bAndroid (\d+)(?:\.\d+)? (?:and|or) (?:lower|below|earlier)\b", re.IGNORECASE)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


_STATUSES = ("verified", "refuted", "not_verified")
_CONFIGURATION_CLASSES = frozenset(("NETWORK-03", "STORAGE-04", "PLATFORM-12"))


def configuration_finding(finding: Dict[str, Any]) -> bool:
    """
    Purpose:
        Tell whether a finding states how the app is built or configured, which the device cannot add to.

    Parameters:
        finding: The finding.

    Returns:
        True for a build-configuration class (every BUILD class) and for the configuration notes: no network security config, backup enabled, no FLAG_SECURE.

    Implementation notes:
        Triage is told these are settled by the manifest, but a model still picked "targetSdkVersion 27 allows implicit component export" in two Ghera runs and spent device steps reading targetSdk out of dumpsys while the clipboard leak the benchmark plants went unreached. Leaving them out mechanically keeps the steps for findings a device can decide.
    """
    code = str(finding.get("vuln_class") or "").strip().upper()
    return code.startswith("BUILD-") or code in _CONFIGURATION_CLASSES


def version_limited(finding: Dict[str, Any], release: Optional[str]) -> Optional[str]:
    """
    Purpose:
        Say why a finding cannot be reproduced on a device whose Android version is past the one it is limited to.

    Parameters:
        finding: The finding.
        release: The device's Android version, such as "11"; None when unknown.

    Returns:
        The reason to record, or None when the finding is not limited to an older version or the device runs one it covers.

    Implementation notes:
        Findings about an attack the platform closed say so in their own words ("possible on Android 10 and lower"), so the limit is read from the title and description. On a newer device such a finding cannot be shown, and a verdict saying it was would be wrong: a run on Android 11 recorded task hijacking as verified because dumpsys showed the app's minSdkVersion. Device steps are not spent on it.
    """
    major = re.match(r"\d+", str(release or ""))
    if not major:
        return None
    text = f"{finding.get('title') or ''} {finding.get('description') or ''}"
    limits = [int(m.group(1)) for m in _VERSION_LIMIT_RE.finditer(text)]
    if not limits or int(major.group(0)) <= max(limits):
        return None
    return (f"The finding applies to Android {max(limits)} and lower; this device runs Android "
            f"{release}, where the platform closes it, so it cannot be reproduced here.")


STATIC_ONLY_REASON = ("Only the decompiled source was read again for this finding; nothing was shown on "
                      "the device.")


def shown_on_device(evidence: str) -> bool:
    """
    Purpose:
        Tell whether verification evidence describes something done on the device.

    Parameters:
        evidence: A finding's own verification evidence.

    Returns:
        True when the evidence names a device action: an adb or shell command, a Frida hook, logcat, an intercepted request or a UI action.

    Implementation notes:
        The verifier's read_source tool reads the same decompiled tree phase 1 read, and a verdict resting on it alone was published as verified: "read_source of 503_PREMIUM_API_KEY.js confirms the hardcoded premium API key". Re-reading the code proves nothing phase 1 did not, so such a verdict is recorded as not verified, with STATIC_ONLY_REASON.
    """
    return bool(_DEVICE_ACTION_RE.search(evidence or ""))


_OLD_ABORT_RE = re.compile(
    r"Dynamic verification aborted after a device tool failed identically (\d+) times in a row "
    r"\((.*?)\)\. The runtime environment appears broken \(e\.g\. the Frida Java bridge is unavailable "
    r"on this Frida version\), so further steps could not make progress\.")


def abort_reason(error_line: str, count: int) -> str:
    """
    Purpose:
        Say why device verification stopped early, for every finding it had not reached.

    Parameters:
        error_line: The first line of the tool's repeated error.
        count: How many times in a row it failed.

    Returns:
        The reason a reader sees.

    Implementation notes:
        The tool's own error is the cause, so it is quoted as the reason rather than guessed at: the earlier wording read "(ERROR: frida-server is not running on the device.). The runtime environment appears broken (e.g. the Frida Java bridge is unavailable on this Frida version)" when the error had already said what was wrong.
    """
    message = re.sub(r"^\s*ERROR:\s*", "", error_line or "").strip().rstrip(".")
    return (f"Device verification stopped after one device tool failed the same way {count} times "
            f"in a row: {message}. The findings it had not reached could not be checked on the device.")


def reword_abort_reason(reason: str) -> str:
    """
    Purpose:
        Rewrite a stored abort reason in the earlier wording into the current one.

    Parameters:
        reason: A stored not-verified reason.

    Returns:
        The reason in abort_reason's wording when it was an abort reason in the earlier wording, otherwise the reason unchanged.
    """
    match = _OLD_ABORT_RE.fullmatch((reason or "").strip())
    return abort_reason(match.group(2), int(match.group(1))) if match else reason


def _finding_id(index: int) -> str:
    """
    Purpose:
        Build the short identifier the agent uses to refer to a finding.

    Parameters:
        index: Position in the finding list.

    Returns:
        The identifier.

    Implementation notes:
        Short and positional, because the agent has to echo it back accurately and a long identifier invites transcription errors that would attach a verdict to the wrong finding.
    """
    return f"F{index + 1}"


def _record_verdict(action_obj: Dict[str, Any], valid_ids: set,
                    verdicts: Dict[str, Dict[str, Any]]) -> str:
    """
    Purpose:
        Record the agent's verdict for one or more findings.

    Parameters:
        action_obj: The action carrying the verdict.
        valid_ids: Identifiers the agent is allowed to rule on.
        verdicts: Accumulated verdicts, updated in place.

    Returns:
        A message for the agent describing what was recorded or rejected.

    Implementation notes:
        Both the single and plural spellings are accepted, since a model settling several related findings at once naturally writes a list. Identifiers are checked against the valid set, so a hallucinated or mistyped identifier is rejected with a message rather than silently creating a verdict for a finding that does not exist. Only the three defined statuses are accepted; anything else is refused, which keeps an ambiguous verdict from being recorded as a definite one. A refutation, like a verification, carries evidence: it is a claim about what the device did.
    """
    raw_ids = action_obj.get("finding_ids")
    if isinstance(raw_ids, list) and raw_ids:
        ids = [s for s in (str(x).strip() for x in raw_ids) if s]
    else:
        one = (action_obj.get("finding_id") or "").strip()
        ids = [one] if one else []
    status = (action_obj.get("status") or "").strip()
    if not ids or status not in _STATUSES:
        return f"ERROR: invalid verdict (finding_ids={ids!r}, status={status!r})"
    record = {
        "status": status,
        "evidence": action_obj.get("evidence") if status in ("verified", "refuted") else None,
        "reason": action_obj.get("reason") if status == "not_verified" else None,
    }
    recorded, unknown = [], []
    for fid in ids:
        if fid in valid_ids:
            verdicts[fid] = dict(record)
            recorded.append(fid)
        else:
            unknown.append(fid)
    if not recorded:
        return f"ERROR: invalid verdict (unknown finding ids={unknown!r}, status={status!r})"
    msg = f"Recorded verdict for {', '.join(recorded)}: {status}"
    if unknown:
        msg += f" (ignored unknown ids: {', '.join(unknown)})"
    return msg


_DEDUP_ADB_PREFIXES = ("dumpsys", "run-as", "getprop", "pm", "logcat", "cat", "ls")

_MAX_BATCH_READS = 6


def _dedup_key(action: str, action_obj: Dict[str, Any]) -> Optional[Tuple[Any, ...]]:
    """
    Purpose:
        Build a key identifying a repeated action, so the agent can be told it is looping.

    Parameters:
        action: The action name.
        action_obj: The action arguments.

    Returns:
        A key, or None when the action is not one worth deduplicating. Keys differ in length by action (three parts for a read, two for a command); they are only compared for equality, and the leading action name keeps the two shapes from colliding.

    Implementation notes:
        Only the read and command actions are keyed. An agent that reads the same file or runs the same command twice has stalled, and telling it so is what breaks the loop -- whereas repeating an instrumentation script can be legitimate, since the app's state changes between runs.
    """
    if action == "read_source":
        path = action_obj.get("path")
        if not isinstance(path, str):
            return None
        return ("read_source", path.strip(), action_obj.get("start_line"))
    if action == "adb":
        cmd = action_obj.get("command")
        if not isinstance(cmd, str):
            return None
        cmd = cmd.strip()
        core = cmd[6:].lstrip() if cmd.startswith("shell ") else cmd
        if any(core == p or core.startswith(p + " ") for p in _DEDUP_ADB_PREFIXES):
            return ("adb", cmd)
    return None


def _read_sources(tools, action_obj: Dict[str, Any]) -> str:
    """
    Purpose:
        Read one or several source files for the agent.

    Parameters:
        tools: The bounded tool surface.
        action_obj: The action carrying the path or paths.

    Returns:
        The concatenated source.

    Implementation notes:
        Both the single and plural spellings are accepted, and a string is normalised to a one-element list, because models mix the two freely. Allowing several per turn saves steps out of a budget that is deliberately tight.

    Security considerations:
        Path containment is enforced by the tool surface, not here.
    """
    raw = action_obj.get("paths")
    if raw is None:
        raw = action_obj.get("path")
    if isinstance(raw, str):
        paths = [raw.strip()] if raw.strip() else []
    elif isinstance(raw, list):
        paths = [str(p).strip() for p in raw if str(p).strip()]
    else:
        paths = []
    if not paths:
        return ("ERROR: read_source needs a 'path' - a file path string, or a list "
                "of paths to read several at once.")
    if len(paths) == 1:
        start_line_raw = action_obj.get("start_line")
        try:
            start_line = int(start_line_raw) if start_line_raw is not None else None
        except (TypeError, ValueError):
            start_line = None
        return tools.read_source(paths[0], start_line=start_line)
    parts = [f"===== {p} =====\n{tools.read_source(p)}" for p in paths[:_MAX_BATCH_READS]]
    if len(paths) > _MAX_BATCH_READS:
        parts.append(f"(+{plural(len(paths) - _MAX_BATCH_READS, 'more path')} not shown - "
                     "read them in a later step)")
    return "\n\n".join(parts)


_MAX_MEMORY_CHARS = 8000


def _finding_structure_hint(f: Dict[str, Any], code_graph) -> str:
    """
    Purpose:
        Annotate a finding with what the code graph knows about its file.

    Parameters:
        f: The finding.
        code_graph: The code graph, or None.

    Returns:
        A short annotation, or an empty string.

    Implementation notes:
        The role and the sinks in the file tell the agent whether the finding sits somewhere reachable, which is the question it is trying to answer. Supplying it up front saves the agent spending steps rediscovering it. Returns empty rather than failing when there is no graph, so verification works without one.
    """
    if code_graph is None:
        return ""
    node = code_graph.node_for_file(f.get("file", ""))
    if node is None:
        return ""
    bits = [node.role]
    if node.signals:
        bits.append("sinks: " + ",".join(node.signals))
    return f"  [{'; '.join(bits)}]"


def _build_initial_context(package: str, findings: List[Dict[str, Any]],
                           static_transcript: str = "", code_graph=None,
                           release: Optional[str] = None) -> str:
    """
    Purpose:
        Build the opening context: the findings to settle, with their locations and any structural hints.

    Parameters:
        package: Package under test.
        findings: Findings to verify.
        static_transcript: The static phase's reasoning, for continuity.
        code_graph: Code graph for structural hints.
        release: The device's Android version, stated so the agent knows which platform protections apply; None to leave it out.

    Returns:
        The context text.

    Implementation notes:
        Each finding is listed with its identifier, severity, location and hint, so the agent can plan an order rather than working through them blindly. The list is in severity order, most severe first, because the agent works down it: a run spent its steps on an Informational note while a High SQL injection a single provider query proves went unreached. The static transcript is included so the agent knows what the static phase already established and does not repeat its reasoning on the device, where each step is far more expensive.
    """
    lines = []
    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity") or "").lower(), 4))
    for f in ordered:
        title = f.get("title") or f.get("vulnerability_type") or "Untitled finding"
        line_ref = f.get("line") or f.get("line_number") or "?"
        hint = _finding_structure_hint(f, code_graph)
        lines.append(
            f"- id={f['_verify_id']} severity={f.get('severity', '?')} "
            f"file={f.get('file', '?')} line={line_ref}{hint}\n"
            f"  {title}: {(f.get('description') or '')[:300]}"
        )
    findings_block = "\n".join(lines) if lines else "(no static findings)"
    device_block = f"## Device\nAndroid {release}\n\n" if release else ""
    context = (
        f"## Target app\n{package}\n\n"
        f"{device_block}"
        f"## Static findings to verify ({len(findings)}, most severe first)\n{findings_block}\n"
    )
    if code_graph is not None:
        structure = code_graph.structure_summary()
        if structure:
            context += (
                "\n## App structure (for planning runtime proofs)\n"
                f"{structure}\n"
            )
    if static_transcript:
        context += (
            "\n## Phase 1 investigation notes (memory, for reference only - "
            "does not need to be re-derived)\n"
            f"{_truncate(static_transcript, _MAX_MEMORY_CHARS)}\n"
        )
    return context


def _mark_all(findings: List[Dict[str, Any]], reason: str) -> None:
    """
    Purpose:
        Mark every finding as not verified with a shared reason.

    Parameters:
        findings: The findings.
        reason: Why verification did not happen.

    Side effects:
        Mutates each finding and removes its temporary identifier.

    Implementation notes:
        Used when the phase cannot run at all -- no device, no provider, cancelled. Marking explicitly is what stops an unverified finding looking the same as one the agent examined and could not confirm. The temporary identifier is removed so it does not reach the report.
    """
    for f in findings:
        f.pop("_verify_id", None)
        f["dynamic_verification"] = {"status": "not_verified", "reason": reason}


_PROOF_BATCH = 8
_PROOF_MAX_TOKENS = 1200
_PROOF_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "reviews": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "holds": {"type": "boolean"},
                    "reason": {"type": "string", "description": "One sentence; required when holds is false."},
                },
                "required": ["id", "holds"],
            },
        },
    },
    "required": ["reviews"],
}
_PROOF_REVIEW_SYSTEM = """You check the evidence a device-verification agent gave for its verdicts on \
an Android app's security findings. You do not judge the findings; you judge whether the evidence \
shows what the verdict says. A verdict holds only when all of these are true:

1. The evidence shows the claim itself, not a neighbouring fact. An injection claim needs crafted \
input changing what the query does (rows it should not return, a UNION's values); a provider that \
returns or deletes every row for a plain selection such as 1=1 shows missing access control, not \
injection. A data-leak claim needs the app itself leaking the data.
2. The app was driven the way the finding's attacker would drive it: another app through am or \
content commands carrying its own input, or the device's user through the screen. A Frida script \
that calls the app's methods or a platform API itself (for example calling Log.e, or invoking a \
method with arguments it chose) or rewrites return values shows what the script did, not what the \
app does. Frida hooks that only watch are fine.
3. Package metadata (dumpsys package, pm, getprop) settles only claims about configuration.
4. For "refuted": a real attempt that would have succeeded were the finding true, and the observed \
absence of the claimed effect.

Return {"reviews": [{"id": ..., "holds": true|false, "reason": ...}]}, one entry per verdict. When \
holds is false, the reason says in one sentence what the evidence does not show."""


def review_proofs(provider, findings: List[Dict[str, Any]], verbose: bool = False) -> Dict[str, int]:
    """
    Purpose:
        Check each device verdict's evidence against the proof rules, and set aside the ones it does not support.

    Parameters:
        provider: AI provider for the review.
        findings: The findings that went to the device, with their verdicts; mutated in place.
        verbose: Traces the review.

    Returns:
        How many verdicts were reviewed and how many were set aside.

    Side effects:
        Makes one provider request per batch; a verdict the review rejects becomes not verified, its reason saying why, its evidence kept beside it.

    Implementation notes:
        The agent is told the proof rules and still breaks them: a run "proved" a credit-card log leak with a Frida script that called Log.e itself, and a provider SQL injection with `content delete --where "1=1"`, which is an ordinary selection. Rules in the agent's prompt compete with everything else it is doing; a separate request that only reads verdict and evidence applies them reliably, as the review pass does for static findings. A batch whose answer cannot be read keeps its verdicts, so a failed review never discards a good proof. An entry's id is read however the label is echoed back - "P3", "[P3]" or "3" - because one answer wrote "[P0]" for every entry and the whole batch went unreviewed.
    """
    claims = [f for f in findings if (f.get("dynamic_verification") or {}).get("status") in ("verified", "refuted")]
    reviewed = rejected = 0
    for start in range(0, len(claims), _PROOF_BATCH):
        batch = claims[start:start + _PROOF_BATCH]
        lines = []
        for i, f in enumerate(batch):
            verdict = f["dynamic_verification"]
            lines.append(f"[P{i}] {verdict['status'].upper()} - {f.get('title') or 'Finding'}: "
                         f"{_truncate(f.get('description') or '', 300)}\n    Evidence: "
                         f"{_truncate(verdict.get('evidence') or '', 900)}")
        try:
            result = provider.analyze(
                "Verdicts to check:\n\n" + "\n\n".join(lines), system_message=_PROOF_REVIEW_SYSTEM,
                schema=_PROOF_REVIEW_SCHEMA, max_tokens=_PROOF_MAX_TOKENS)
            if not isinstance(result, dict) or "error" in result:
                raise ValueError(str(result))
            obj = _parse_action(result.get("response", "")) or {}
            entries = obj.get("reviews")
            lists = [v for v in obj.values() if isinstance(v, list)]
            if not isinstance(entries, list) and len(lists) == 1:
                entries = lists[0]
            if not isinstance(entries, list):
                raise ValueError("no review list in response")
        except Exception as exc:
            verbose_print(f"Proof review failed ({exc}); verdicts kept as given", verbose)
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            index = re.fullmatch(r"\[?\s*P?\s*(\d+)\s*\]?", str(entry.get("id", "")).strip(), re.IGNORECASE)
            if not index or int(index.group(1)) >= len(batch):
                continue
            reviewed += 1
            if entry.get("holds") is False:
                f = batch[int(index.group(1))]
                old = f["dynamic_verification"]
                why = " ".join(str(entry.get("reason") or "it does not meet the proof rules").split())
                f["dynamic_verification"] = {
                    "status": "not_verified",
                    "reason": f"The device evidence was set aside on review: {why}",
                    "rejected_evidence": old.get("evidence") or "",
                    "rejected_status": old.get("status"),
                }
                rejected += 1
    if claims:
        verbose_print(f"Proof review: {rejected} of {reviewed} device verdicts set aside", verbose)
    return {"reviewed": reviewed, "rejected": rejected}


_NEEDS_SCHEMA = {
    "type": "object",
    "properties": {
        "need_runtime_verification": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The ids of findings that genuinely need runtime proof.",
        },
    },
    "required": ["need_runtime_verification"],
}


def _classify_needs_verification(provider, findings: List[Dict[str, Any]],
                                 verbose: bool) -> set:
    """
    Purpose:
        Decide which findings are worth taking to the device.

    Parameters:
        provider: AI provider.
        findings: Candidate findings.
        verbose: Traces the triage.

    Returns:
        The identifiers selected for verification.

    Side effects:
        Makes one provider request.

    Implementation notes:
        Device steps are the scarcest resource in the pipeline, so spending them on findings that runtime cannot settle is waste. A hardcoded string is as true on the device as in the source; an exported component's reachability is not. Triage runs as its own cheap request rather than being folded into the agent loop, so the expensive loop starts already knowing what to work on. The prompt names the key, and an object whose only list sits under another name is read as the answer: the schema is not enforced on every provider, and a model left to name the field itself answered {"runtime_verification_needed": [...]}, which was read as no answer, so every finding went to the device and the exported activity that needed the steps was not reached.
    """
    all_ids = {f["_verify_id"] for f in findings}
    lines = []
    for f in findings:
        title = f.get("title") or f.get("vulnerability_type") or "Finding"
        lines.append(f'{f["_verify_id"]}: {title} - {(f.get("description") or "")[:180]}')
    prompt = (
        "You are triaging static Android security findings before a runtime "
        "(dynamic) verification phase on a live device. Decide which findings "
        "genuinely NEED runtime proof and which are already conclusively "
        "established by the static code/manifest alone.\n\n"
        "NEEDS runtime proof (only potential until exercised): SQL injection, "
        "exported component / IPC / deep-link exploitation, WebView JavaScript "
        "bridge, native/JNI memory-safety bugs, TLS / certificate-validation "
        "bypass, insecure data storage or logging that only happens at runtime.\n"
        "Does NOT need runtime proof (already proven statically): hardcoded "
        "strings / secrets / API keys, android:debuggable, android:allowBackup, "
        "cleartext-traffic / network-security-config, and other manifest flags.\n\n"
        "Findings:\n" + "\n".join(lines) +
        "\n\nReturn JSON of the form "
        '{"need_runtime_verification": ["F1", ...]} listing the ids that NEED '
        "runtime verification."
    )
    try:
        result = provider.analyze(
            prompt, system_message="Return only the requested JSON object.",
            schema=_NEEDS_SCHEMA, max_tokens=_TRIAGE_MAX_TOKENS)
        if not isinstance(result, dict) or "error" in result:
            raise ValueError(str(result))
        obj = _parse_action(result.get("response", "")) or {}
        ids = obj.get("need_runtime_verification")
        lists = [v for v in obj.values() if isinstance(v, list)]
        if not isinstance(ids, list) and len(lists) == 1:
            ids = lists[0]
        if not isinstance(ids, list):
            raise ValueError("no id list in response")
        needed = {str(x).strip() for x in ids if str(x).strip() in all_ids}
        verbose_print(
            f"Verification triage: {len(needed)}/{len(all_ids)} findings need "
            f"runtime proof ({', '.join(sorted(needed)) or 'none'})", verbose)
        return needed
    except Exception as exc:
        verbose_print(f"Verification triage failed ({exc}); verifying all findings",
                      verbose)
        return all_ids


def run_dynamic_verification(
    provider,
    device: str,
    package: str,
    apk_path: str,
    source_root=None,
    findings: List[Dict[str, Any]] = None,
    static_transcript: str = "",
    code_graph=None,
    progress=None,
    is_cancelled=None,
    max_steps: Optional[int] = None,
    verbose: bool = False,
    jadx_output_dir=None,
    adb: Optional[ADBManager] = None,
    frida: Optional[FridaManager] = None,
    triage_provider=None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Purpose:
        Run the verification phase: triage the findings, drive the agent against the device, and attach a verdict to each finding.

    Parameters:
        provider: AI provider for the verification agent.
        device: Device serial.
        package: Package under test.
        apk_path: Local APK path, installed if the app is not already present.
        source_root: Root of the decompiled source the agent reads.
        findings: Findings to verify, mutated in place with their verdicts.
        static_transcript: The static phase's reasoning, for continuity.
        code_graph: Code graph for structural hints.
        progress: Reports progress to the dashboard.
        is_cancelled: Polled between agent steps so a user stop takes effect promptly.
        max_steps: Step ceiling; derived from the finding count when omitted.
        verbose: Traces the session.
        jadx_output_dir: The decompiled tree backing the agent's source reads.
        adb: Device manager, constructed if not supplied.
        frida: Instrumentation manager, constructed if not supplied.
        triage_provider: Cheaper provider for the triage pass; the main one when omitted.

    Returns:
        The verified findings and the session record.

    Raises:
        ScanCancelled: When the user stopped the scan.

    Side effects:
        Installs and drives the app on the device, runs instrumentation, and mutates the findings.

    Implementation notes:
        The loop is bounded in two ways: a step budget scaled to the finding count, and duplicate-action detection that tells the agent when it is repeating itself. Without both, an agent that cannot settle a finding will keep looking at it until the budget is gone and nothing else gets verified. The managers are injectable so a caller that already deployed instrumentation for an earlier phase can pass it in rather than repeating the deployment. Triage runs on a separate cheaper provider where one is configured, since deciding which findings are worth device time is a much easier judgement than making it. Every finding ends with a verdict, including the ones never reached, which are marked not verified with a reason. A silently missing verdict would read as an absence of a problem.

    Security considerations:
        All device access goes through the bounded tool surface. The agent's requests are untrusted and are validated there, not here.
    """
    source_root = source_root or jadx_output_dir
    findings = findings if findings is not None else []
    progress = progress or (lambda *_unused_args, **_unused_kwargs: None)
    is_cancelled = is_cancelled or (lambda: False)

    def _raise_if_cancelled():
        """
        Purpose:
            Stop the verification loop if the user has cancelled.

        Raises:
            ScanCancelled: When cancellation has been requested.

        Implementation notes:
            Checked between agent steps rather than during one, so a stop lands between device operations instead of interrupting one partway.
        """
        if is_cancelled():
            raise ScanCancelled()

    session: Dict[str, Any] = {
        "device": device, "package": package,
        "install": {"ok": False, "message": ""},
        "frida": {"ok": False, "message": ""},
        "total_count": len(findings), "verified_count": 0,
    }

    if not findings:
        session["skipped_reason"] = "No static findings to verify."
        return findings, session

    for i, f in enumerate(findings):
        f["_verify_id"] = _finding_id(i)
    candidates = [f for f in findings if not configuration_finding(f)]
    _triage_prov = triage_provider or provider
    _triage_before = getattr(_triage_prov, "usage", {}).get("completion_tokens", 0)
    needed_ids = _classify_needs_verification(_triage_prov, candidates, verbose) if candidates else set()
    _triage_after = getattr(_triage_prov, "usage", {}).get("completion_tokens", 0)
    if _triage_after > _triage_before:
        verbose_print(
            f"Triage output: {_triage_after - _triage_before} completion tokens", verbose)
    to_verify = [f for f in findings if f["_verify_id"] in needed_ids]
    for f in findings:
        if f["_verify_id"] not in needed_ids:
            f.pop("_verify_id", None)

    session["total_count"] = len(to_verify)
    if not to_verify:
        session["skipped_reason"] = "No findings required runtime verification."
        return findings, session

    if max_steps is None:
        max_steps = _default_max_steps(len(to_verify))
    verbose_print(f"Dynamic verification budget: {max_steps} steps for "
                  f"{plural(len(to_verify), 'finding')} needing runtime proof", verbose)

    adb = adb or ADBManager(verbose=verbose)
    frida = frida or FridaManager(verbose=verbose)

    progress("installing", 65, f"Checking {package} on the device and installing it if this build is not there…")
    install_ok, install_msg = adb.install_apk(device, apk_path, package=package)
    session["install"] = {"ok": install_ok, "message": install_msg}
    if not install_ok:
        verbose_print(f"Install failed: {install_msg}; skipping dynamic verification", verbose)
        _mark_all(to_verify, f"Could not install the app on the device: {install_msg}")
        session["skipped_reason"] = f"Install failed: {install_msg}"
        return findings, session
    _raise_if_cancelled()

    has_root = adb.check_root(device)
    frida_ok, frida_msg = frida.setup_and_verify(adb, device, has_root)
    session["frida"] = {"ok": frida_ok, "message": frida_msg}
    if not frida_ok:
        verbose_print(f"Frida unavailable ({frida_msg}); verification continues adb-only", verbose)
    _raise_if_cancelled()

    adb.launch_app(device, package)
    release = adb.get_android_release(device)
    session["android_version"] = release
    for f in list(to_verify):
        reason = version_limited(f, release)
        if reason:
            f.pop("_verify_id", None)
            f["dynamic_verification"] = {"status": "not_verified", "reason": reason}
            to_verify.remove(f)
    if not to_verify:
        session["skipped_reason"] = "Every finding needing runtime proof is closed on this device's Android version."
        return findings, session

    _loop_before = getattr(provider, "usage", {}).get("completion_tokens", 0)

    try:
        tools = VerifyTools(adb, frida, device, package, source_root, verbose=verbose)
    except ValueError as exc:
        _mark_all(to_verify, f"Could not start dynamic verification: {exc}")
        session["skipped_reason"] = str(exc)
        return findings, session

    system = VulnerabilityPrompts.get_dynamic_verification_system(package)
    offensive_skill = load_skill("offensive_android", verbose)
    if offensive_skill:
        system += "\n\n# Reference: proving findings at runtime\n\n" + offensive_skill
    initial_context = _build_initial_context(package, to_verify, static_transcript, code_graph, release)
    transcript: List[str] = []
    verdicts: Dict[str, Dict[str, Any]] = {}
    progressed = False
    aborted_reason: Optional[str] = None
    repeated_error: Optional[str] = None
    repeated_error_count = 0
    tool_cache: Dict[Any, str] = {}

    progress("dynamic_verify", 70, "Dynamic verification - AI is proving findings at runtime…")

    try:
        for step in range(max_steps):
            _raise_if_cancelled()
            remaining = max_steps - step
            pending = [f["_verify_id"] for f in to_verify if f["_verify_id"] not in verdicts]
            if not pending:
                break
            history = _truncate_tail("\n\n".join(transcript), _MAX_TRANSCRIPT_CHARS)
            prompt = (
                f"{initial_context}\n\n## Investigation so far\n{history or '(nothing yet)'}\n\n"
                f"## Verdicts so far\n"
                f"{_truncate(json.dumps(verdicts, indent=2), 3000) if verdicts else '(none yet)'}\n\n"
                f"## Still pending: {', '.join(pending)}\n\n"
                f"You have {plural(remaining, 'step')} left. Respond with the next action JSON."
            )

            result = provider.analyze(prompt, system_message=system, schema=NEXT_ACTION_SCHEMA,
                                      max_tokens=_STEP_MAX_TOKENS)
            if not isinstance(result, dict) or "error" in result:
                verbose_print(f"Verify step {step}: provider error: {result}", verbose)
                aborted_reason = "The AI provider could not complete dynamic verification."
                break

            action_obj = _parse_action(result.get("response", ""))
            if action_obj is None:
                verbose_print(f"Verify step {step}: could not parse action", verbose)
                transcript.append(
                    "ASSISTANT: (unparseable) -> reminder: reply with one JSON "
                    "object having an 'action'.")
                if not progressed and step >= 2:
                    aborted_reason = "The AI provider did not produce usable verification actions."
                    break
                continue

            progressed = True
            action = (action_obj.get("action") or "").strip()
            thought = action_obj.get("thought", "")

            try:
                if action == "verdict":
                    observation = _record_verdict(
                        action_obj, {f["_verify_id"] for f in to_verify}, verdicts)
                elif action == "note":
                    observation = "Noted."
                elif action in ("read_source", "adb", "frida"):
                    key = _dedup_key(action, action_obj)
                    if key is not None and key in tool_cache:
                        observation = (
                            "(identical to an earlier step - you already have this "
                            "result. Record verdicts with finding_ids for everything "
                            "it proves, or move to a still-pending finding instead of "
                            "repeating it.)\n" + tool_cache[key])
                    else:
                        if action == "read_source":
                            observation = _read_sources(tools, action_obj)
                        elif action == "adb":
                            observation = tools.adb_command(action_obj.get("command", ""))
                        else:
                            observation = tools.frida_script(action_obj.get("script", ""),
                                                             action_obj.get("trigger") or "")
                        if key is not None:
                            tool_cache[key] = observation
                elif action == "inspect_native":
                    observation = (
                        "inspect_native is a Phase-1 static tool and isn't available in "
                        "verification. The native symbol table was already captured in "
                        "Phase 1 - to prove a native finding at runtime use 'frida' to "
                        "Interceptor.attach the exported Java_<pkg>_<Class>_<method> "
                        "symbol (or a flagged libc import) and observe it being hit.")
                else:
                    observation = (
                        f"Unknown action '{action}'. Use read_source, adb, frida, note, "
                        "or verdict.")
            except ScanCancelled:
                raise
            except Exception as exc:
                observation = (
                    f"ERROR: the '{action}' action could not run ({exc}). Check your "
                    "arguments - path/command/script must be plain strings (use a list "
                    "of paths only for read_source), and use finding_ids for a batched "
                    "verdict - then try a different step.")
                verbose_print(f"Verify step {step}: action {action!r} raised: {exc}", verbose)

            label = "".join(
                f" {k}={v!r}" for k, v in action_obj.items()
                if k in ("path", "command", "script", "trigger", "finding_id", "finding_ids", "status") and v
            )
            transcript.append(
                f"ASSISTANT: {thought}\nTOOL {action}{label} ->\n"
                f"{_truncate(observation, _MAX_OBS_CHARS)}"
            )

            if action in ("frida", "adb", "read_source"):
                first_line = next((ln for ln in observation.splitlines() if ln.strip()), "")
                if first_line.strip()[:5].upper() == "ERROR":
                    if first_line == repeated_error:
                        repeated_error_count += 1
                    else:
                        repeated_error, repeated_error_count = first_line, 1
                    if repeated_error_count >= _MAX_REPEATED_TOOL_ERRORS:
                        aborted_reason = abort_reason(first_line, repeated_error_count)
                        verbose_print(f"Verify: aborting early - {aborted_reason}", verbose)
                        break
                else:
                    repeated_error, repeated_error_count = None, 0
            elif action == "verdict" and observation.startswith("Recorded verdict"):
                repeated_error, repeated_error_count = None, 0
    except ScanCancelled:
        raise
    except Exception as exc:
        aborted_reason = aborted_reason or (
            f"Dynamic verification stopped early after an internal error: {exc}")
        verbose_print(f"Dynamic verification loop error: {exc}", verbose)
    finally:
        try:
            frida.stop_server(adb, device)
        except Exception as exc:
            verbose_print(f"Error stopping frida-server: {exc}", verbose)

    for f in to_verify:
        fid = f.pop("_verify_id", None)
        v = verdicts.get(fid)
        if v is None:
            f["dynamic_verification"] = {
                "status": "not_verified",
                "reason": aborted_reason or "Not reached within the dynamic-verification step budget.",
            }
        elif v["status"] in ("verified", "refuted"):
            own = _evidence_for(fid, v.get("evidence") or "")
            f["dynamic_verification"] = (
                {"status": v["status"], "evidence": own} if own and shown_on_device(own)
                else {"status": "not_verified", "reason": STATIC_ONLY_REASON} if own
                else {"status": "not_verified",
                      "reason": "Recorded as verified together with other findings, but the evidence "
                                "given did not cover this one."})
        else:
            f["dynamic_verification"] = {
                "status": "not_verified",
                "reason": _clean_ids(v.get("reason") or "") or "Could not be verified on this device.",
            }

    session["proof_review"] = review_proofs(triage_provider or provider, to_verify, verbose)
    session["verified_count"] = sum(
        1 for f in to_verify if f.get("dynamic_verification", {}).get("status") == "verified")
    session["refuted_count"] = sum(
        1 for f in to_verify if f.get("dynamic_verification", {}).get("status") == "refuted")
    _loop_after = getattr(provider, "usage", {}).get("completion_tokens", 0)
    if _loop_after > _loop_before:
        verbose_print(
            f"Dynamic verification loop output: {_loop_after - _loop_before} "
            f"completion tokens for {plural(len(to_verify), 'finding')}", verbose)
    return findings, session
