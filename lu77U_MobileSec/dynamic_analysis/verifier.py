"""Bounded, tool-using agent loop for Phase 2 — dynamic verification."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..analyzers.agent.skills_loader import load_skill
from ..analyzers.agent.tools import MAX_READ_CHARS
from ..config.prompts import VulnerabilityPrompts
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import verbose_print
from .adb_manager import ADBManager
from .frida_manager import FridaManager
from .verify_tools import VerifyTools

DEFAULT_MAX_STEPS = 20
_MAX_REPEATED_TOOL_ERRORS = 3
_MAX_STEPS_CEILING = 60


def _default_max_steps(num_findings: int) -> int:
    """Scale the Phase-2 step budget to the workload.

    Each finding needs at least a verdict turn, and most need a proof turn or two
    on top — so a flat ``DEFAULT_MAX_STEPS`` can't reach a verdict for every
    finding once there are more than a handful (the 19-finding DIVA run hit the
    cap having concluded only 4). Floor at ``DEFAULT_MAX_STEPS``, ceiling at
    ``_MAX_STEPS_CEILING``. Batched verdicts (one turn closing several findings)
    keep the actual turn count well under this in practice.
    """
    return max(DEFAULT_MAX_STEPS, min(_MAX_STEPS_CEILING, 2 * num_findings + 6))
_MAX_OBS_CHARS = MAX_READ_CHARS + 3000
_MAX_TRANSCRIPT_CHARS = 50000    # total rolling transcript cap (oldest dropped first)


def _truncate(text: Optional[str], limit: int) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def _truncate_tail(text: Optional[str], limit: int) -> str:
    """Like ``_truncate``, but keeps the most RECENT ``limit`` characters
    (dropping the oldest) instead of the earliest — used for the rolling
    investigation transcript, where recent turns matter more than the first."""
    if text is None:
        return ""
    return text if len(text) <= limit else "... [earlier turns truncated]\n" + text[-limit:]


def _strip_thinking_tokens(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _extract_first_json_object(text: str) -> Optional[str]:
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


NEXT_ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "description": "Brief reasoning for this step"},
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
        "command": {"type": "string", "description": "Command for adb (scoped to the target app)"},
        "script": {"type": "string", "description": "Frida JS source for frida"},
        "text": {"type": "string", "description": "Free-text observation for note"},
        "finding_id": {"type": "string", "description": "Which finding this verdict concludes"},
        "finding_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "For a batched verdict: several finding ids that the SAME evidence "
                "proves at once (e.g. one dumpsys proving F1,F2,F3). They share the "
                "given status + evidence/reason. Use instead of finding_id."
            ),
        },
        "status": {"type": "string", "enum": ["verified", "not_verified"]},
        "evidence": {"type": "string", "description": "Proof, when status is verified"},
        "reason": {"type": "string", "description": "Why it couldn't be proven, when not_verified"},
    },
    "required": ["action"],
}


def _finding_id(index: int) -> str:
    return f"F{index + 1}"


def _record_verdict(action_obj: Dict[str, Any], valid_ids: set,
                    verdicts: Dict[str, Dict[str, Any]]) -> str:
    """Record one or several findings' verdicts from a single ``verdict`` action.

    Supports ``finding_ids`` (a list, for batching — one observation that proves
    multiple findings) as well as the original single ``finding_id``. Every id in
    a batch shares the action's ``status`` and ``evidence``/``reason``. Returns a
    human-readable observation string (an ``ERROR: …`` when nothing valid was
    recorded)."""
    raw_ids = action_obj.get("finding_ids")
    if isinstance(raw_ids, list) and raw_ids:
        ids = [s for s in (str(x).strip() for x in raw_ids) if s]
    else:
        one = (action_obj.get("finding_id") or "").strip()
        ids = [one] if one else []
    status = (action_obj.get("status") or "").strip()
    if not ids or status not in ("verified", "not_verified"):
        return f"ERROR: invalid verdict (finding_ids={ids!r}, status={status!r})"
    record = {
        "status": status,
        "evidence": action_obj.get("evidence") if status == "verified" else None,
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
        return f"ERROR: invalid verdict (unknown finding_id(s)={unknown!r}, status={status!r})"
    msg = f"Recorded verdict for {', '.join(recorded)}: {status}"
    if unknown:
        msg += f" (ignored unknown id(s): {', '.join(unknown)})"
    return msg


_DEDUP_ADB_PREFIXES = ("dumpsys", "run-as", "getprop", "pm", "logcat", "cat", "ls")

_MAX_BATCH_READS = 6


def _dedup_key(action: str, action_obj: Dict[str, Any]):
    """A cache key for a read-only tool call whose result won't change on a
    repeat, or ``None`` for side-effecting / nondeterministic calls (``am start``,
    ``input``, ``frida`` hooks that may capture fresh runtime data) which can
    legitimately be issued again. Returns ``None`` for non-string fields (e.g. a
    batched read whose ``path`` is a list) rather than assuming a type."""
    if action == "read_source":
        path = action_obj.get("path")
        if not isinstance(path, str):        # list / omitted → not dedup-able here
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
    """Read one source file, or several when the model batches them as a list in
    ``path``/``paths`` (a habit carried over from Phase 1 — and a budget saver).

    Accepts ``path`` as a string or a list, plus an optional ``paths`` list.
    ``start_line`` only applies to a single-file read; it's ignored for a batch.
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
        return ("ERROR: read_source needs a 'path' — a file path string, or a list "
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
        parts.append(f"(+{len(paths) - _MAX_BATCH_READS} more path(s) not shown — "
                     "read them in a later step)")
    return "\n\n".join(parts)


_MAX_MEMORY_CHARS = 8000


def _finding_structure_hint(f: Dict[str, Any], code_graph) -> str:
    """Per-finding hint from the code graph: the class's role + sink families,
    which point at the right runtime proof (exported → adb-invoke; native-call
    → Frida-hook the native method; sql/prefs/storage → run-as / content query)."""
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
                           static_transcript: str = "", code_graph=None) -> str:
    lines = []
    for i, f in enumerate(findings):
        title = f.get("title") or f.get("vulnerability_type") or "Untitled finding"
        line_ref = f.get("line") or f.get("line_number") or "?"
        hint = _finding_structure_hint(f, code_graph)
        lines.append(
            f"- id={f['_verify_id']} severity={f.get('severity', '?')} "
            f"file={f.get('file', '?')} line={line_ref}{hint}\n"
            f"  {title}: {(f.get('description') or '')[:300]}"
        )
    findings_block = "\n".join(lines) if lines else "(no static findings)"
    context = (
        f"## Target app\n{package}\n\n"
        f"## Static findings to verify ({len(findings)})\n{findings_block}\n"
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
            "\n## Phase 1 investigation notes (memory, for reference only — "
            "does not need to be re-derived)\n"
            f"{_truncate(static_transcript, _MAX_MEMORY_CHARS)}\n"
        )
    return context


def _mark_all(findings: List[Dict[str, Any]], reason: str) -> None:
    for f in findings:
        f.pop("_verify_id", None)
        f["dynamic_verification"] = {"status": "not_verified", "reason": reason}


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
    """Ask the model which findings actually need runtime (dynamic) verification.

    Some findings are already conclusively proven by the static code/manifest
    (hardcoded strings/secrets, ``android:debuggable``, ``android:allowBackup``,
    cleartext-traffic config, other manifest flags) — running the device loop on
    them just wastes tokens and device time. Others are only *potential* until
    exercised (SQL injection, exported-component/IPC abuse, WebView JS bridge,
    native/JNI memory bugs, TLS/cert-validation bypass, insecure runtime storage/
    logging) and genuinely benefit from a runtime proof.

    Returns the set of ``_verify_id``s that need verification. On any parse/
    provider failure it falls back to "verify everything" (safe default).
    """
    all_ids = {f["_verify_id"] for f in findings}
    lines = []
    for f in findings:
        title = f.get("title") or f.get("vulnerability_type") or "Finding"
        lines.append(f'{f["_verify_id"]}: {title} — {(f.get("description") or "")[:180]}')
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
        "\n\nReturn JSON with the ids that NEED runtime verification."
    )
    try:
        result = provider.analyze(
            prompt, system_message="Return only the requested JSON object.",
            schema=_NEEDS_SCHEMA)
        if not isinstance(result, dict) or "error" in result:
            raise ValueError(str(result))
        obj = _parse_action(result.get("response", "")) or {}
        ids = obj.get("need_runtime_verification")
        if not isinstance(ids, list):
            raise ValueError("no id list in response")
        needed = {str(x).strip() for x in ids if str(x).strip() in all_ids}
        verbose_print(
            f"Verification triage: {len(needed)}/{len(all_ids)} finding(s) need "
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
    jadx_output_dir,
    findings: List[Dict[str, Any]],
    static_transcript: str = "",
    code_graph=None,
    progress=None,
    is_cancelled=None,
    max_steps: Optional[int] = None,
    verbose: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run Phase 2 against a device with the target app installed.

    ``findings`` is mutated in place: each item gains a ``dynamic_verification``
    key (``{"status": "verified", "evidence": ...}`` or
    ``{"status": "not_verified", "reason": ...}``). Returns
    ``(findings, session)`` where ``session`` summarizes the device session
    (install/frida status, verified/total counts) for the report.

    ``static_transcript`` is Phase 1's investigation transcript (from
    ``run_agent_analysis``); pass it (the caller gates this on the
    ``agent_memory`` setting) to give this phase extra "memory" of how each
    finding was originally discovered. Pass ``""`` to omit it.
    """
    progress = progress or (lambda *a, **k: None)
    is_cancelled = is_cancelled or (lambda: False)

    def _raise_if_cancelled():
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
    needed_ids = _classify_needs_verification(provider, findings, verbose)
    to_verify = [f for f in findings if f["_verify_id"] in needed_ids]
    for f in findings:
        if f["_verify_id"] not in needed_ids:
            f.pop("_verify_id", None)   # statically conclusive → no badge

    session["total_count"] = len(to_verify)
    if not to_verify:
        session["skipped_reason"] = "No findings required runtime verification."
        return findings, session

    if max_steps is None:
        max_steps = _default_max_steps(len(to_verify))
    verbose_print(f"Dynamic verification budget: {max_steps} steps for "
                  f"{len(to_verify)} finding(s) needing runtime proof", verbose)

    adb = ADBManager(verbose=verbose)
    frida = FridaManager(verbose=verbose)

    progress("installing", 65, f"Installing {package} for dynamic verification…")
    install_ok, install_msg = adb.install_apk(device, apk_path)
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

    try:
        tools = VerifyTools(adb, frida, device, package, jadx_output_dir, verbose=verbose)
    except ValueError as exc:
        _mark_all(to_verify, f"Could not start dynamic verification: {exc}")
        session["skipped_reason"] = str(exc)
        return findings, session

    system = VulnerabilityPrompts.get_dynamic_verification_system(package)
    offensive_skill = load_skill("offensive_android", verbose)
    if offensive_skill:
        system += "\n\n# Reference: proving findings at runtime\n\n" + offensive_skill
    initial_context = _build_initial_context(package, to_verify, static_transcript, code_graph)
    transcript: List[str] = []
    verdicts: Dict[str, Dict[str, Any]] = {}
    progressed = False
    aborted_reason: Optional[str] = None
    repeated_error: Optional[str] = None    # last identical tool-error signature
    repeated_error_count = 0
    tool_cache: Dict[Any, str] = {}         # dedup exact read-only tool repeats

    progress("dynamic_verify", 70, "Dynamic verification — AI is proving findings at runtime…")

    try:
        for step in range(max_steps):
            _raise_if_cancelled()
            remaining = max_steps - step
            pending = [f["_verify_id"] for f in to_verify if f["_verify_id"] not in verdicts]
            if not pending:
                break
            history = _truncate_tail("\n\n".join(transcript), _MAX_TRANSCRIPT_CHARS)
            prompt = (
                f"{initial_context}\n\n## Verdicts so far\n"
                f"{_truncate(json.dumps(verdicts, indent=2), 3000) if verdicts else '(none yet)'}\n\n"
                f"## Still pending: {', '.join(pending)}\n\n"
                f"## Investigation so far\n{history or '(nothing yet)'}\n\n"
                f"You have {remaining} step(s) left. Respond with the next action JSON."
            )

            result = provider.analyze(prompt, system_message=system, schema=NEXT_ACTION_SCHEMA)
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
                            "(identical to an earlier step — you already have this "
                            "result. Record verdicts with finding_ids for everything "
                            "it proves, or move to a still-pending finding instead of "
                            "repeating it.)\n" + tool_cache[key])
                    else:
                        if action == "read_source":
                            observation = _read_sources(tools, action_obj)
                        elif action == "adb":
                            observation = tools.adb_command(action_obj.get("command", ""))
                        else:  # frida
                            observation = tools.frida_script(action_obj.get("script", ""))
                        if key is not None:
                            tool_cache[key] = observation
                elif action == "inspect_native":
                    observation = (
                        "inspect_native is a Phase-1 static tool and isn't available in "
                        "verification. The native symbol table was already captured in "
                        "Phase 1 — to prove a native finding at runtime use 'frida' to "
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
                    "arguments — path/command/script must be plain strings (use a list "
                    "of paths only for read_source), and use finding_ids for a batched "
                    "verdict — then try a different step.")
                verbose_print(f"Verify step {step}: action {action!r} raised: {exc}", verbose)

            label = "".join(
                f" {k}={v!r}" for k, v in action_obj.items()
                if k in ("path", "command", "script", "finding_id", "finding_ids", "status") and v
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
                        aborted_reason = (
                            f"Dynamic verification aborted after a device tool failed "
                            f"identically {repeated_error_count} times in a row "
                            f"({first_line.strip()}). The runtime environment appears "
                            f"broken (e.g. the Frida Java bridge is unavailable on this "
                            f"Frida version), so further steps could not make progress."
                        )
                        verbose_print(f"Verify: aborting early — {aborted_reason}", verbose)
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
        elif v["status"] == "verified":
            f["dynamic_verification"] = {
                "status": "verified",
                "evidence": v.get("evidence") or "(no evidence text provided)",
            }
        else:
            f["dynamic_verification"] = {
                "status": "not_verified",
                "reason": v.get("reason") or "Could not be verified on this device.",
            }

    session["verified_count"] = sum(
        1 for f in to_verify if f.get("dynamic_verification", {}).get("status") == "verified")
    return findings, session