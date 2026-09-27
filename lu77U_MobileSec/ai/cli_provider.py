#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.cli_provider

Purpose:
    Drive vendor coding CLIs -- Claude Code, GitHub Copilot, Kimi, Codex and Antigravity -- as analysis providers, so that a user with a subscription can run scans without also holding an API key.

Responsibilities:
    Describe each CLI declaratively as a CLISpec, run it as a subprocess in a scratch directory, extract the answer from its output format, manage conversation sessions, and synthesise one provider class per CLI.

Dependencies:
    subprocess, tempfile, threading, the shared base provider.

Implementation notes:
    Each CLI differs in nearly every detail -- whether the prompt goes on stdin or in an argument, whether schemas are native or must be described in prose, how the answer is framed, how a session is identified, whether the exit code means anything. Those differences are data in CLI_SPECS with small per-CLI callables, and the execution, session and error handling around them is written once. Adding a CLI is a spec entry, not a new provider. Every invocation runs with its working directory set to a scratch directory. These tools are coding agents that read and write the directory they are launched in; running them in the user's project would let a model-chosen action touch real files.

Security considerations:
    This module executes local binaries. Argument vectors are always lists and never shell strings, so prompt content -- which includes decompiled application source -- cannot be interpreted as a command. Each CLI is constrained as far as its flags allow: tools disabled or denied, sandboxes set to read-only, permission prompts suppressed rather than auto-approved, and builtin integrations disabled. The prompt still contains untrusted decompiled source, so a prompt-injection payload inside an APK is attempting to steer an agent that has file-system tools. The scratch working directory plus these flags are what bound that, and any new CLI added here must be constrained the same way. Prompts are sent to the vendor behind whichever CLI is selected, exactly as an API provider would.
"""

import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .base_provider import BaseAIProvider
from .errors import ErrorClass
from ..utils.verbose import verbose_print

_CALL_TIMEOUT_S = 300.0

_PROBE_TIMEOUT_S = 45.0


class CLIProcessError(Exception):
    """
    Purpose:
        Raised when a CLI invocation fails in a way specific to running a subprocess: the binary is missing, it timed out, it exited non-zero, or it reported an error inside its own output.

    Invariants:
        Carries a message naming the CLI and the failure, which the shared error classifier then inspects to decide whether the cause was authentication, quota or something transient.

    Thread-safety:
        Stateless; safe to raise from any thread.
    """


@dataclass(frozen=True)
class CLISpec:
    """
    Purpose:
        Declarative description of one vendor CLI: how to invoke it, how to read its answer, and what it supports.

    Attributes:
        key: Provider identifier.
        binary: Executable name looked up on PATH.
        display: Human-readable name for messages.
        signin_hint: Instructions shown when the CLI is missing or not signed in.
        build_argv: Builds the argument vector for a fresh call.
        extract: Pulls the answer out of the completed process.
        native_schema: Whether the CLI enforces a JSON schema itself, rather than needing one described in the prompt.
        models: Selectable model names; empty means the CLI decides.
        usage_from_json: Whether token usage can be parsed from stdout.
        requires_additional_properties_false: Whether every object in the schema must forbid extra properties.
        prompt_via_stdin: Whether the prompt goes on stdin rather than in an argument.
        supports_conversation: Whether multi-turn sessions are supported.
        resume_argv: Builds the argument vector that continues a session.
        session_id_from: Extracts a session identifier from stdout.
        assign_session_id: Whether the caller may choose the session identifier instead of reading one back.

    Invariants:
        Frozen, so a spec cannot be mutated at runtime and every provider instance sharing it sees the same configuration. A spec with supports_conversation set must supply resume_argv, and must supply either assign_session_id or session_id_from -- otherwise a session can be opened but never continued.

    Thread-safety:
        Immutable and safe to share across threads.
    """
    key: str
    binary: str
    display: str
    signin_hint: str
    build_argv: Callable[
        ["CLIBackedProvider", str, str, Optional[Path], Optional[Path],
         Optional[str]], List[str]]
    extract: Callable[[subprocess.CompletedProcess, Optional[Path]], str]
    native_schema: bool
    models: List[str]
    usage_from_json: bool = True
    requires_additional_properties_false: bool = False
    prompt_via_stdin: bool = True
    supports_conversation: bool = False
    resume_argv: Optional[Callable[
        ["CLIBackedProvider", str, Optional[Path], Optional[Path], str], List[str]]] = None
    session_id_from: Optional[Callable[[str], Optional[str]]] = None
    assign_session_id: bool = False


def _prompt_payload(system_message: str, prompt: str) -> str:
    """
    Purpose:
        Combine a system message and a prompt into one payload, for CLIs that accept no separate system-prompt flag.

    Parameters:
        system_message: The system prompt, possibly empty.
        prompt: The user prompt.

    Returns:
        The combined text, or the prompt alone when there is no system message.

    Implementation notes:
        Separated by a blank line so the CLI's own prompt handling sees two paragraphs rather than one run-on instruction.

    Security considerations:
        Concatenation means the system message loses whatever privileged framing the CLI might give a real system prompt, so on these CLIs the instructions and the untrusted source sit at the same level.
    """
    return prompt if not system_message else f"{system_message}\n\n{prompt}"


def _with_additional_properties_false(schema: Any) -> Any:
    """
    Purpose:
        Recursively set additionalProperties to false on every object in a schema.

    Parameters:
        schema: A JSON-schema fragment.

    Returns:
        A new fragment with the constraint applied. The input is not mutated.

    Complexity:
        O(n) in the number of schema nodes.

    Implementation notes:
        Required by CLIs whose structured-output mode is strict and rejects a schema that does not say so explicitly. An existing value is respected rather than overwritten, so a schema that deliberately permits extra properties keeps that.
    """
    if isinstance(schema, dict):
        out = {k: _with_additional_properties_false(v) for k, v in schema.items()}
        if out.get("type") == "object" and "additionalProperties" not in out:
            out["additionalProperties"] = False
        return out
    if isinstance(schema, list):
        return [_with_additional_properties_false(v) for v in schema]
    return schema


def _claude_argv(p: "CLIBackedProvider", system_message: str, stdin_payload: str,
                  schema_path: Optional[Path], output_path: Optional[Path],
                  session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector for a fresh Claude Code invocation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        system_message: System prompt, where this CLI takes one as a flag.
        stdin_payload: The prompt text, for CLIs that take it as an argument rather than on stdin.
        schema_path: Path to the schema file, where this CLI supports native schemas.
        output_path: Path the CLI should write structured output to, where it supports that.
        session_id: Identifier for a new conversation, where this CLI accepts a caller-assigned one.

    Returns:
        The argument vector.

    Security considerations:
        Returned as a list and executed without a shell, so prompt text containing shell metacharacters is passed as data.

    Implementation notes:
        Tools are disabled outright, safe mode is on, setting sources are cleared and permission prompts are answered without asking. Together these keep the CLI from reading the user's global configuration or taking file-system actions on behalf of a prompt that contains untrusted source. Session persistence is disabled when no session is in use, so a one-off analysis leaves nothing behind in the user's session history. The schema is passed as the file's contents rather than its path, which is what this CLI expects. stdin_payload is unused here because Claude Code takes the prompt on stdin, which the caller supplies separately.
    """
    del stdin_payload
    argv = [
        p.resolved_binary, "-p",
        "--output-format", "json",
        "--tools", "",
        "--safe-mode",
        "--setting-sources", "",
        "--permission-mode", "dontAsk",
    ]
    if session_id:
        argv += ["--session-id", session_id]
    else:
        argv += ["--no-session-persistence"]
    if p.model:
        argv += ["--model", p.model]
    if system_message:
        argv += ["--system-prompt", system_message]
    if schema_path is not None:
        argv += ["--json-schema", schema_path.read_text(encoding="utf-8")]
    return argv


def _claude_resume_argv(p: "CLIBackedProvider", stdin_payload: str,
                        schema_path: Optional[Path], output_path: Optional[Path],
                        session_id: str) -> List[str]:
    """
    Purpose:
        Build the argument vector that continues an existing Claude Code conversation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        stdin_payload: The prompt text, for CLIs that take it as an argument.
        schema_path: Path to the schema file, where supported.
        output_path: Path for structured output, where supported.
        session_id: The conversation to resume.

    Returns:
        The argument vector.

    Implementation notes:
        The same hardening flags as a fresh call are repeated, because they are per-invocation rather than remembered with the session. The schema is re-sent on resume, since the CLI does not carry it across turns.
    """
    del stdin_payload
    argv = [
        p.resolved_binary, "-p",
        "--output-format", "json",
        "--tools", "",
        "--safe-mode",
        "--setting-sources", "",
        "--permission-mode", "dontAsk",
        "--resume", session_id,
    ]
    if p.model:
        argv += ["--model", p.model]
    if schema_path is not None:
        argv += ["--json-schema", schema_path.read_text(encoding="utf-8")]
    return argv


def _claude_extract(proc: subprocess.CompletedProcess, output_path: Optional[Path]) -> str:
    """
    Purpose:
        Pull the answer out of Claude Code's JSON output.

    Parameters:
        proc: The completed process.
        output_path: Unused; this CLI reports on stdout.

    Returns:
        The structured output as JSON text when present, otherwise the plain result text.

    Raises:
        CLIProcessError: When the payload reports an error, carrying the API status and message.
        json.JSONDecodeError: When stdout is not the expected JSON.

    Implementation notes:
        This CLI reports failures inside a successful process exit, which is why its key is listed as having an unreliable exit code and why the error flag is checked explicitly here. Trusting the exit status alone would turn an authentication failure into an empty analysis.
    """
    data = json.loads(proc.stdout)
    if data.get("is_error"):
        raise CLIProcessError(
            f"claude exited with an error (status {data.get('api_error_status')}): "
            f"{data.get('result', proc.stderr)}")
    structured = data.get("structured_output")
    if structured is not None:
        return json.dumps(structured)
    return str(data.get("result", ""))


_COPILOT_DENIED_TOOLS = (
    "bash", "apply_patch", "write", "write_agent", "session_store_sql", "sql")


def _copilot_argv(p: "CLIBackedProvider", system_message: str, stdin_payload: str,
                  schema_path: Optional[Path], output_path: Optional[Path],
                  session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector for a fresh GitHub Copilot invocation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        system_message: System prompt, where this CLI takes one as a flag.
        stdin_payload: The prompt text, for CLIs that take it as an argument rather than on stdin.
        schema_path: Path to the schema file, where this CLI supports native schemas.
        output_path: Path the CLI should write structured output to, where it supports that.
        session_id: Identifier for a new conversation, where this CLI accepts a caller-assigned one.

    Returns:
        The argument vector.

    Security considerations:
        Returned as a list and executed without a shell, so prompt text containing shell metacharacters is passed as data.

    Implementation notes:
        The prompt is passed as an argument because this CLI does not read stdin. Every tool that could modify the machine is denied by name -- shell execution, patch application, file writes and SQL access -- since the prompt carries untrusted decompiled source and this CLI is otherwise willing to act on it. Builtin integrations are disabled for the same reason. Colour is disabled so the JSON event stream is not interleaved with escape sequences.
    """
    del session_id
    argv = [p.resolved_binary, "--prompt", stdin_payload,
            "--output-format", "json", "--no-color", "--disable-builtin-mcps"]
    for tool in _COPILOT_DENIED_TOOLS:
        argv += ["--deny-tool", tool]
    if p.model:
        argv += ["--model", p.model]
    return argv


def _copilot_resume_argv(p: "CLIBackedProvider", stdin_payload: str,
                         schema_path: Optional[Path], output_path: Optional[Path],
                         session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector that continues an existing GitHub Copilot conversation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        stdin_payload: The prompt text, for CLIs that take it as an argument.
        schema_path: Path to the schema file, where supported.
        output_path: Path for structured output, where supported.
        session_id: The conversation to resume.

    Returns:
        The argument vector.

    Implementation notes:
        Continuation uses the CLI's own most-recent-conversation flag rather than an explicit identifier, so the session id is read back only for bookkeeping. The tool denials are repeated, because they apply per invocation.
    """
    del session_id
    argv = [p.resolved_binary, "--prompt", stdin_payload, "--continue",
            "--output-format", "json", "--no-color", "--disable-builtin-mcps"]
    for tool in _COPILOT_DENIED_TOOLS:
        argv += ["--deny-tool", tool]
    if p.model:
        argv += ["--model", p.model]
    return argv


def _copilot_extract(proc: subprocess.CompletedProcess, output_path: Optional[Path]) -> str:
    """
    Purpose:
        Pull the assistant's answer out of Copilot's line-delimited JSON event stream.

    Parameters:
        proc: The completed process.
        output_path: Unused.

    Returns:
        The content of the last assistant message, or the raw stdout when no such event was found.

    Complexity:
        O(n) in the number of output lines.

    Implementation notes:
        The stream carries many event types and the answer is whichever assistant message came last, so every line is scanned and the last match wins rather than returning the first. Unparseable lines are skipped rather than failing the extraction, because the CLI interleaves non-JSON diagnostics into the stream. Falling back to raw stdout keeps a response recoverable by the downstream parser when the event shape changes.
    """
    answer = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(event, dict) and event.get("type") == "assistant.message":
            content = (event.get("data") or {}).get("content")
            if isinstance(content, str):
                answer = content
    return answer if answer is not None else proc.stdout.strip()


def _copilot_session_id(stdout: str) -> Optional[str]:
    """
    Purpose:
        Read the conversation identifier out of Copilot's event stream.

    Parameters:
        stdout: The CLI's raw output.

    Returns:
        The session identifier, or None when absent or not a string.

    Implementation notes:
        Returns on the first result event rather than scanning to the end, since there is exactly one per invocation. A missing identifier is not an error -- resumption falls back to the CLI's own continue flag.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(event, dict) and event.get("type") == "result":
            sid = event.get("sessionId")
            return sid if isinstance(sid, str) else None
    return None


def _kimi_argv(p: "CLIBackedProvider", system_message: str, stdin_payload: str,
              schema_path: Optional[Path], output_path: Optional[Path],
              session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector for a fresh Kimi invocation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        system_message: System prompt, where this CLI takes one as a flag.
        stdin_payload: The prompt text, for CLIs that take it as an argument rather than on stdin.
        schema_path: Path to the schema file, where this CLI supports native schemas.
        output_path: Path the CLI should write structured output to, where it supports that.
        session_id: Identifier for a new conversation, where this CLI accepts a caller-assigned one.

    Returns:
        The argument vector.

    Security considerations:
        Returned as a list and executed without a shell, so prompt text containing shell metacharacters is passed as data.

    Implementation notes:
        The prompt is passed as an argument, and text output is requested rather than JSON because this CLI has no native schema support. The schema is instead described in the prompt by the caller.
    """
    del session_id
    argv = [p.resolved_binary, "-p", stdin_payload, "--output-format", "text"]
    if p.model:
        argv += ["--model", p.model]
    return argv


def _kimi_resume_argv(p: "CLIBackedProvider", stdin_payload: str,
                      schema_path: Optional[Path], output_path: Optional[Path],
                      session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector that continues an existing Kimi conversation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        stdin_payload: The prompt text, for CLIs that take it as an argument.
        schema_path: Path to the schema file, where supported.
        output_path: Path for structured output, where supported.
        session_id: The conversation to resume.

    Returns:
        The argument vector.

    Implementation notes:
        Continuation uses the CLI's own continue flag, so no identifier is tracked for this provider at all.
    """
    del session_id
    argv = [p.resolved_binary, "-p", stdin_payload, "-c", "--output-format", "text"]
    if p.model:
        argv += ["--model", p.model]
    return argv


_KIMI_VERSION_BANNER_RE = re.compile(r"^kimi version \S+\s*\n", re.IGNORECASE)


def _kimi_extract(proc: subprocess.CompletedProcess, output_path: Optional[Path]) -> str:
    """
    Purpose:
        Return Kimi's answer with its version banner removed.

    Parameters:
        proc: The completed process.
        output_path: Unused.

    Returns:
        The answer text.

    Implementation notes:
        The CLI prints a version banner as its first line even in non-interactive use. It is stripped with a count of one so that an identical line legitimately appearing inside the answer is preserved.
    """
    text = proc.stdout
    text = _KIMI_VERSION_BANNER_RE.sub("", text, count=1)
    return text.strip()


def _codex_argv(p: "CLIBackedProvider", system_message: str, stdin_payload: str,
                schema_path: Optional[Path], output_path: Optional[Path],
                session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector for a fresh Codex invocation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        system_message: System prompt, where this CLI takes one as a flag.
        stdin_payload: The prompt text, for CLIs that take it as an argument rather than on stdin.
        schema_path: Path to the schema file, where this CLI supports native schemas.
        output_path: Path the CLI should write structured output to, where it supports that.
        session_id: Identifier for a new conversation, where this CLI accepts a caller-assigned one.

    Returns:
        The argument vector.

    Security considerations:
        Returned as a list and executed without a shell, so prompt text containing shell metacharacters is passed as data.

    Implementation notes:
        Invoked in exec mode with a bare dash, which makes it read the prompt from stdin. The sandbox is set to read-only, which is this CLI's own containment rather than something imposed here. The git repository check is skipped because the working directory is a scratch directory and is deliberately not a repository. Ephemeral mode is used for one-off calls so no thread is persisted. Structured output goes to a file rather than stdout, which is why both a schema path and an output path are required before the flags are added. system_message and stdin_payload are unused: the system message is folded into the stdin payload by the caller, and the payload itself is written to the process rather than passed as an argument.
    """
    del system_message, stdin_payload
    argv = [
        p.resolved_binary, "exec", "-",
        "--json",
        "--sandbox", "read-only",
        "--skip-git-repo-check",
    ]
    if not session_id:
        argv.append("--ephemeral")
    if schema_path is not None and output_path is not None:
        argv += ["--output-schema", str(schema_path), "-o", str(output_path)]
    if p.model:
        argv += ["--model", p.model]
    return argv


def _codex_resume_argv(p: "CLIBackedProvider", stdin_payload: str,
                       schema_path: Optional[Path], output_path: Optional[Path],
                       session_id: str) -> List[str]:
    """
    Purpose:
        Build the argument vector that continues an existing Codex conversation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        stdin_payload: The prompt text, for CLIs that take it as an argument.
        schema_path: Path to the schema file, where supported.
        output_path: Path for structured output, where supported.
        session_id: The conversation to resume.

    Returns:
        The argument vector.

    Implementation notes:
        Resume takes the thread identifier positionally, followed by a bare dash so the new turn is still read from stdin. The sandbox flag is absent because it is fixed by the thread being resumed.
    """
    del stdin_payload
    argv = [
        p.resolved_binary, "exec", "resume", session_id, "-",
        "--json",
        "--skip-git-repo-check",
    ]
    if schema_path is not None and output_path is not None:
        argv += ["--output-schema", str(schema_path), "-o", str(output_path)]
    if p.model:
        argv += ["--model", p.model]
    return argv


def _codex_extract(proc: subprocess.CompletedProcess, output_path: Optional[Path]) -> str:
    """
    Purpose:
        Read Codex's answer from its structured output file, falling back to stdout.

    Parameters:
        proc: The completed process.
        output_path: Path the CLI was asked to write structured output to.

    Returns:
        The file contents when it exists, otherwise trimmed stdout.

    Implementation notes:
        The file is preferred because stdout carries the whole event stream, of which the answer is only a part. The fallback covers an invocation made without a schema, where no file was requested.
    """
    if output_path is not None and output_path.exists():
        return output_path.read_text(encoding="utf-8")
    return proc.stdout.strip()


def _codex_session_id(stdout: str) -> Optional[str]:
    """
    Purpose:
        Read the thread identifier out of Codex's event stream.

    Parameters:
        stdout: The CLI's raw output.

    Returns:
        The thread identifier, or None when absent.

    Implementation notes:
        Taken from the thread-started event, which this CLI emits first. Scanning stops at the first match.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(event, dict) and event.get("type") == "thread.started":
            tid = event.get("thread_id")
            return tid if isinstance(tid, str) else None
    return None


def _antigravity_argv(p: "CLIBackedProvider", system_message: str, stdin_payload: str,
                      schema_path: Optional[Path], output_path: Optional[Path],
                      session_id: Optional[str] = None) -> List[str]:
    """
    Purpose:
        Build the argument vector for a fresh Antigravity invocation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        system_message: System prompt, where this CLI takes one as a flag.
        stdin_payload: The prompt text, for CLIs that take it as an argument rather than on stdin.
        schema_path: Path to the schema file, where this CLI supports native schemas.
        output_path: Path the CLI should write structured output to, where it supports that.
        session_id: Identifier for a new conversation, where this CLI accepts a caller-assigned one.

    Returns:
        The argument vector.

    Security considerations:
        Returned as a list and executed without a shell, so prompt text containing shell metacharacters is passed as data.

    Implementation notes:
        The prompt is passed as an argument, and the schema is passed by path rather than by contents -- the opposite of Claude Code, which is precisely the kind of difference the spec table exists to absorb.
    """
    del session_id
    argv = [p.resolved_binary, "-p", stdin_payload, "--output-format", "json"]
    if p.model:
        argv += ["--model", p.model]
    if schema_path is not None:
        argv += ["--json-schema", str(schema_path)]
    return argv


def _antigravity_resume_argv(p: "CLIBackedProvider", stdin_payload: str,
                             schema_path: Optional[Path], output_path: Optional[Path],
                             session_id: str) -> List[str]:
    """
    Purpose:
        Build the argument vector that continues an existing Antigravity conversation.

    Parameters:
        p: The provider, consulted for the resolved binary and the model.
        stdin_payload: The prompt text, for CLIs that take it as an argument.
        schema_path: Path to the schema file, where supported.
        output_path: Path for structured output, where supported.
        session_id: The conversation to resume.

    Returns:
        The argument vector.

    Implementation notes:
        Continuation takes an explicit conversation identifier, so the session id read back from the first call is load-bearing here. The schema is re-sent, since it is not retained across turns.
    """
    argv = [p.resolved_binary, "-p", stdin_payload, "--output-format", "json",
            "--conversation", session_id]
    if p.model:
        argv += ["--model", p.model]
    if schema_path is not None:
        argv += ["--json-schema", str(schema_path)]
    return argv


def _antigravity_extract(proc: subprocess.CompletedProcess, output_path: Optional[Path]) -> str:
    """
    Purpose:
        Pull the answer out of Antigravity's JSON response.

    Parameters:
        proc: The completed process.
        output_path: Unused.

    Returns:
        The result or response field as text, or the raw stdout when neither is present or the output is not JSON.

    Implementation notes:
        Two field names are tried because the CLI has used both. A non-string value is re-serialised rather than stringified, so a structured answer stays valid JSON for the response parser. Every unexpected shape degrades to raw stdout instead of raising, leaving recovery to the response parser.
    """
    text = proc.stdout.strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    if not isinstance(data, dict):
        return text
    value = data.get("result")
    if value is None:
        value = data.get("response")
    if value is None:
        return text
    return value if isinstance(value, str) else json.dumps(value)


def _antigravity_session_id(stdout: str) -> Optional[str]:
    """
    Purpose:
        Read the conversation identifier from Antigravity's JSON response.

    Parameters:
        stdout: The CLI's raw output.

    Returns:
        The conversation identifier, or None when absent.

    Implementation notes:
        Parses the whole of stdout as one JSON document, unlike the line-delimited streams of the other CLIs.
    """
    try:
        data = json.loads(stdout.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    cid = data.get("conversation_id")
    return cid if isinstance(cid, str) else None


CLI_SPECS: Dict[str, CLISpec] = {
    "claude_cli": CLISpec(
        key="claude_cli", binary="claude",
        display="Claude Code CLI (Claude Pro/Max subscription)",
        signin_hint="Run `claude` once in a terminal and complete the browser sign-in.",
        build_argv=_claude_argv, extract=_claude_extract,
        native_schema=True,
        models=["opus", "sonnet", "fable", "haiku"],
        supports_conversation=True, resume_argv=_claude_resume_argv,
        assign_session_id=True,
    ),
    "copilot_cli": CLISpec(
        key="copilot_cli", binary="copilot",
        display="GitHub Copilot CLI (Copilot Pro subscription)",
        signin_hint="Run `copilot` once and sign in with your GitHub account.",
        build_argv=_copilot_argv, extract=_copilot_extract,
        native_schema=False, prompt_via_stdin=False,
        models=[], usage_from_json=False,
        supports_conversation=True, resume_argv=_copilot_resume_argv,
        session_id_from=_copilot_session_id,
    ),
    "kimi_cli": CLISpec(
        key="kimi_cli", binary="kimi",
        display="Kimi CLI (Kimi Plus/Pro/Max/Ultra subscription)",
        signin_hint=(
            "Run `kimi` once and complete the Moonshot AI sign-in. If it's "
            "installed but not found, it may not be on PATH - set "
            "binary_path in Settings to its full path "
            "(commonly ~/.kimi-code/bin/kimi)."),
        build_argv=_kimi_argv, extract=_kimi_extract,
        native_schema=False, prompt_via_stdin=False,
        models=[], usage_from_json=False,
        supports_conversation=True, resume_argv=_kimi_resume_argv,
    ),
    "codex_cli": CLISpec(
        key="codex_cli", binary="codex",
        display="Codex CLI (ChatGPT Plus/Pro subscription)",
        signin_hint="Run `codex` once and choose \"Sign in with ChatGPT\".",
        build_argv=_codex_argv, extract=_codex_extract,
        native_schema=True,
        models=[], usage_from_json=False,
        supports_conversation=True, resume_argv=_codex_resume_argv,
        session_id_from=_codex_session_id,
        requires_additional_properties_false=True,
    ),
    "antigravity_cli": CLISpec(
        key="antigravity_cli", binary="agy",
        display="Antigravity CLI (Google AI Pro/Ultra subscription)",
        signin_hint="Run `agy` once and sign in with your Google account.",
        build_argv=_antigravity_argv, extract=_antigravity_extract,
        native_schema=True, prompt_via_stdin=False,
        models=[],
        supports_conversation=True, resume_argv=_antigravity_resume_argv,
        session_id_from=_antigravity_session_id,
    ),
}

_EXIT_CODE_UNRELIABLE = {"claude_cli"}


class CLIBackedProvider(BaseAIProvider):
    """
    Purpose:
        Shared provider implementation for every CLI-backed vendor, parameterised by a CLISpec.

    Attributes:
        spec: The CLI description; set on each synthesised subclass, never on this base.

    Invariants:
        Every invocation runs with its working directory inside a scratch directory, never the user's own. A session's scratch directory outlives a single call and is removed when the session is closed.

    Thread-safety:
        Session state is guarded by a lock. Concurrency is bounded by the base provider's request gate, which for these providers defaults to one in flight, since a coding CLI is a heavyweight local process.

    Security considerations:
        Executes local binaries with argument vectors, never through a shell. The scratch working directory is the main containment: these CLIs are agents that act on the directory they run in, and the prompt they are given contains untrusted decompiled source.
    """
    spec: CLISpec = None

    def __init__(self, *args, **kwargs):
        """
        Purpose:
            Initialise session tracking for this provider.

        Parameters:
            args: Forwarded to the base provider.
            kwargs: Forwarded to the base provider.

        Postconditions:
            No sessions and no scratch directories exist yet.
        """
        super().__init__(*args, **kwargs)
        self._session_lock = threading.Lock()
        self._sessions: Dict[str, Optional[str]] = {}
        self._session_dirs: Dict[str, Path] = {}

    def has_session(self, session_key: str) -> bool:
        """
        Purpose:
            Report whether a conversation is open under the given key.

        Parameters:
            session_key: Caller-chosen session identifier.

        Returns:
            True when a session exists, even if its CLI-side identifier is None -- a session continued through a "most recent conversation" flag has no identifier but is still open.

        Thread-safety:
            Read under the session lock.
        """
        with self._session_lock:
            return session_key in self._sessions

    def close_session(self, session_key: str) -> None:
        """
        Purpose:
            End a conversation and remove its scratch directory.

        Parameters:
            session_key: Caller-chosen session identifier.

        Side effects:
            Deletes the session's scratch directory from disk.

        Postconditions:
            The session is absent; closing an unknown session is a no-op.

        Implementation notes:
            The state is removed under the lock and the directory is deleted outside it, so a slow recursive delete does not block other workers. Deletion ignores errors: a CLI may still hold a file open, and failing to clean up a temporary directory must not fail the scan.
        """
        with self._session_lock:
            self._sessions.pop(session_key, None)
            cwd = self._session_dirs.pop(session_key, None)
        if cwd is not None:
            shutil.rmtree(cwd, ignore_errors=True)

    def default_model(self) -> str:
        """
        Purpose:
            The model used when the user has configured none.

        Returns:
            The first model the spec lists, or an empty string when the CLI chooses for itself.
        """
        return self.spec.models[0] if self.spec.models else ""

    def supports_vision(self) -> bool:
        """
        Purpose:
            Report that CLI providers do not accept image input.

        Returns:
            False.

        Implementation notes:
            Uniformly false: these CLIs take a text prompt, and there is no portable way to attach an image across all five.
        """
        return False

    @property
    def resolved_binary(self) -> str:
        """
        Purpose:
            Resolve the executable to invoke.

        Returns:
            The configured override, the PATH lookup, or the bare binary name as a last resort.

        Implementation notes:
            Returning the bare name when the lookup fails lets the invocation proceed and fail with the CLI's own error, which names the tool -- more useful than a generic resolution failure.

        Security considerations:
            The override is operator-supplied through settings and is executed. That is an intended capability, and it is the documented fix for a CLI installed outside PATH.
        """
        override = (self.config or {}).get("binary_path")
        if override:
            return override
        return shutil.which(self.spec.binary) or self.spec.binary

    def _binary_available(self) -> bool:
        """
        Purpose:
            Check whether the CLI can be invoked at all.

        Returns:
            True when the override points at an existing file, or the binary is on PATH.

        Implementation notes:
            An override is checked as a file rather than looked up on PATH, since the point of an override is to name a binary PATH does not know about.
        """
        override = (self.config or {}).get("binary_path")
        if override:
            return Path(override).is_file()
        return shutil.which(self.spec.binary) is not None

    def _run(self, argv: List[str], stdin_payload: str, timeout: float,
             cwd: Path) -> subprocess.CompletedProcess:
        """
        Purpose:
            Execute the CLI and capture its output, converting process-level failures into CLIProcessError.

        Parameters:
            argv: The argument vector.
            stdin_payload: Text written to the process's stdin.
            timeout: Seconds to wait before giving up.
            cwd: Scratch working directory for the process.

        Returns:
            The completed process.

        Raises:
            CLIProcessError: When the binary is missing or the timeout expires.

        Side effects:
            Spawns a subprocess and blocks until it exits.

        Implementation notes:
            A non-zero exit is not raised here; the caller decides, because one CLI reports success in its exit code while reporting an error in its payload. The timeout matters: these are interactive tools that can wait indefinitely on a prompt, and without it a scan would hang rather than fail.

        Security considerations:
            The vector is passed as a list with no shell, and the working directory is always a scratch directory supplied by the caller.
        """
        try:
            return subprocess.run(
                argv, input=stdin_payload, capture_output=True, text=True,
                timeout=timeout, cwd=str(cwd),
            )
        except FileNotFoundError as e:
            raise CLIProcessError(
                f"{self.spec.binary} is not installed or not on PATH: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise CLIProcessError(
                f"{self.spec.binary} did not respond within {timeout:.0f}s") from e

    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
        max_tokens: Optional[int] = None,
        session_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Purpose:
            Run an analysis through the configured CLI, handling schema delivery, session reuse and scratch-directory lifetime.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the shared default applies when None.
            schema: Response schema; the vulnerability schema applies when None.
            images: Ignored; no CLI here supports vision.
            max_tokens: Ignored; these CLIs expose no output cap.
            session_key: Enables conversation reuse where the CLI supports it.

        Returns:
            A result dict carrying "response" on success, or "error" on failure, with "fatal" when the circuit tripped. Never raises.

        Side effects:
            Creates a scratch directory, spawns the CLI, updates counters, writes a transcript, and may open or close a session.

        Implementation notes:
            A missing binary trips the circuit as an authentication failure rather than returning a retryable error, because no amount of retrying installs a CLI. The message carries the spec's sign-in hint so the user is told how to fix it. Scratch directory lifetime follows the session. A conversational call keeps its directory across turns, since the CLI may store session state inside it; a one-off call uses a TemporaryDirectory that is cleaned up in the finally block. Only the one-off case owns a cleanup object, which is what makes the finally block safe for both. Schema delivery splits on native support. A CLI that enforces schemas gets a schema file; one that does not gets the schema appended to the prompt as an instruction -- and only on the first turn, since repeating it on resume wastes context on something already established. An array schema is wrapped in an object for native-schema CLIs and unwrapped from the answer afterwards, because structured-output modes generally require an object at the top level. Claude Code is special-cased to receive the system message as a flag; the others have it folded into the payload, because they expose no equivalent. Session identifiers are obtained one of two ways: assigned by this code before the call for CLIs that accept one, or read back from the output afterwards. The provisional identifier is only committed to the session map after the call succeeds, so a failed first turn does not register a session that was never created. Any failure closes the session. A CLI that errored mid-conversation cannot be assumed resumable, and attempting to resume a broken session would fail every subsequent turn in that region.

        Security considerations:
            The prompt contains decompiled application source and is passed to a local agent CLI, which forwards it to that vendor. The process runs in a scratch directory with the spec's hardening flags applied.
        """
        del max_tokens
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"{self.spec.display} circuit open ({self._fatal}); skipping call",
                self.verbose)
            return tripped

        if not self._binary_available():
            return self._trip(
                ErrorClass.FATAL_AUTH,
                f"{self.spec.binary} is not installed or not on PATH. {self.spec.signin_hint}")

        schema = schema or self.schema

        conversational = bool(session_key) and self.spec.supports_conversation
        with self._session_lock:
            resuming = conversational and session_key in self._sessions
            stored_id = self._sessions.get(session_key) if conversational else None
            session_cwd = self._session_dirs.get(session_key) if conversational else None

        owns_tmp_object: Optional[tempfile.TemporaryDirectory] = None
        if session_cwd is not None:
            tmp_path = session_cwd
            cwd = session_cwd
        elif conversational:
            tmp_path = Path(tempfile.mkdtemp(prefix="lu77u-cli-session-"))
            cwd = tmp_path
            with self._session_lock:
                self._session_dirs[session_key] = tmp_path
        else:
            owns_tmp_object = tempfile.TemporaryDirectory(prefix="lu77u-cli-")
            tmp_path = Path(owns_tmp_object.name) / "cwd"
            tmp_path.mkdir()
            cwd = tmp_path

        with self._request_gate:
            started = time.monotonic()
            try:
                schema_path: Optional[Path] = None
                output_path: Optional[Path] = None
                user_prompt = prompt
                argv_system = system_message or self.default_system_message
                stdin_payload = prompt

                wrap_array = self.spec.native_schema and schema.get("type") == "array"
                schema_for_cli = (
                    {"type": "object",
                     "properties": {"vulnerabilities": schema},
                     "required": ["vulnerabilities"]}
                    if wrap_array else schema)
                if self.spec.requires_additional_properties_false:
                    schema_for_cli = _with_additional_properties_false(schema_for_cli)

                if self.spec.native_schema:
                    schema_path = tmp_path / "schema.json"
                    schema_path.write_text(json.dumps(schema_for_cli), encoding="utf-8")
                    output_path = tmp_path / "output.json"
                elif not resuming:
                    user_prompt = (
                        f"{prompt}\n\nRespond with ONLY JSON matching this "
                        f"JSON Schema, no prose, no markdown fences:\n"
                        f"{json.dumps(schema)}"
                    )

                if self.spec.key == "claude_cli":
                    stdin_payload = user_prompt
                    argv_system = system_message or self.default_system_message
                else:
                    stdin_payload = (
                        user_prompt if resuming
                        else _prompt_payload(argv_system, user_prompt))
                    argv_system = ""

                provisional_id: Optional[str] = None
                if resuming:
                    if self.spec.resume_argv is None:
                        resuming = False
                    else:
                        argv = self.spec.resume_argv(
                            self, stdin_payload, schema_path, output_path, stored_id)
                if not resuming:
                    provisional_id = str(uuid.uuid4()) if conversational else None
                    argv = self.spec.build_argv(
                        self, argv_system, stdin_payload, schema_path, output_path,
                        provisional_id)

                stdin_for_process = stdin_payload if self.spec.prompt_via_stdin else ""
                proc = self._run(argv, stdin_for_process, _CALL_TIMEOUT_S, cwd)

                if proc.returncode != 0 and self.spec.key not in _EXIT_CODE_UNRELIABLE:
                    raise CLIProcessError(
                        f"{self.spec.binary} exited {proc.returncode}: "
                        f"{proc.stderr or proc.stdout}")

                raw = self.spec.extract(proc, output_path)
                response_text = self._unwrap(raw, wrap_array)
                metrics = self._usage_from_stdout(proc.stdout) if self.spec.usage_from_json else {}
                elapsed = time.monotonic() - started
                self.record_usage(elapsed, metrics, ok=True)
                self.log_exchange(
                    argv_system, stdin_payload, response_text,
                    elapsed=elapsed, metrics=metrics,
                    session_key=session_key, resumed=resuming)

                if conversational and not resuming:
                    new_id = (provisional_id if self.spec.assign_session_id
                             else self.spec.session_id_from(proc.stdout)
                             if self.spec.session_id_from else None)
                    with self._session_lock:
                        self._sessions[session_key] = new_id
                return {"response": response_text}
            except Exception as e:
                elapsed = time.monotonic() - started
                verbose_print(f"{self.spec.display} analysis failed: {e}", self.verbose)
                self.record_usage(elapsed, ok=False)
                self.log_exchange(
                    argv_system, stdin_payload, "", elapsed=elapsed,
                    error=str(e), session_key=session_key, resumed=resuming)
                if conversational:
                    self.close_session(session_key)
                fatal = self._handle_exception(e)
                if fatal:
                    return fatal
                return {"error": f"{self.spec.display} request failed: {e}"}
            finally:
                if owns_tmp_object is not None:
                    owns_tmp_object.cleanup()


    def _unwrap(self, raw: str, wrapped: bool) -> str:
        """
        Purpose:
            Recover the plain findings array from an answer wrapped in the schema envelope.

        Parameters:
            raw: The extracted answer.
            wrapped: Whether the request actually used the wrapped schema.

        Returns:
            The unwrapped array as JSON text, or the input unchanged.

        Implementation notes:
            Returns the input untouched when the request was not wrapped, when it will not parse, or when the key is absent, leaving those cases to the response parser.
        """
        if not wrapped:
            return raw
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError, TypeError):
            return raw
        if isinstance(parsed, dict) and "vulnerabilities" in parsed:
            return json.dumps(parsed["vulnerabilities"])
        return raw

    def _usage_from_stdout(self, stdout: str) -> Dict[str, Any]:
        """
        Purpose:
            Extract token usage and cost from a CLI's JSON output, where it reports them.

        Parameters:
            stdout: The CLI's raw output.

        Returns:
            A metrics dict in the shared shape, or an empty dict when usage was absent or unparseable.

        Implementation notes:
            Each counter is read under two possible names, because these CLIs mirror the naming of whichever API they wrap -- some use the Anthropic spelling, others the OpenAI one. Cost is included only when the CLI reports it and it is numeric. For subscription-backed CLIs it is usually absent, which is correct: those calls are not billed per token. Every failure yields an empty dict, so missing usage never fails a successful analysis.
        """
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}
        usage = data.get("usage") if isinstance(data, dict) else None
        if not isinstance(usage, dict):
            return {}
        metrics: Dict[str, Any] = {
            "prompt_eval_count": usage.get("input_tokens") or usage.get("prompt_tokens"),
            "eval_count": usage.get("output_tokens") or usage.get("completion_tokens"),
            "cache_read_tokens": (
                usage.get("cache_read_tokens")
                or usage.get("cache_read_input_tokens") or 0),
            "cache_creation_tokens": (
                usage.get("cache_creation_tokens")
                or usage.get("cache_creation_input_tokens") or 0),
        }
        cost = data.get("total_cost_usd")
        if isinstance(cost, (int, float)):
            metrics["cost_usd"] = cost
        return metrics

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the models this CLI offers.

        Returns:
            A copy of the spec's list, empty when the CLI chooses its own model.

        Implementation notes:
            A copy, so a caller sorting or filtering it cannot mutate the shared frozen spec's list.
        """
        return list(self.spec.models)

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that the CLI is installed and signed in, by running a minimal probe.

        Returns:
            True when the probe succeeds.

        Side effects:
            Spawns the CLI in a throwaway directory with a short timeout.

        Implementation notes:
            There is no way to ask these tools whether they are authenticated, so the probe is a real one-word request. It uses a trivial schema and a much shorter timeout than an analysis, so a missing sign-in fails quickly rather than after the full call budget. Success is read from the payload rather than the exit code for CLIs whose exit code is unreliable. The whole body is guarded and returns False, because this runs while rendering the settings page.

        Security considerations:
            The probe prompt contains no analysis content.
        """
        if not self._binary_available():
            return False
        try:
            with tempfile.TemporaryDirectory(prefix="lu77u-cli-probe-") as tmp:
                tmp_path = Path(tmp)
                cwd = tmp_path / "cwd"
                cwd.mkdir()
                schema_path: Optional[Path] = None
                output_path: Optional[Path] = None
                if self.spec.native_schema:
                    schema_path = tmp_path / "schema.json"
                    schema_path.write_text(
                        json.dumps({"type": "object",
                                    "properties": {"ok": {"type": "boolean"}},
                                    "required": ["ok"]}), encoding="utf-8")
                    output_path = tmp_path / "output.json"
                probe_prompt = "Reply with the single word: ok"
                if self.spec.key == "claude_cli":
                    stdin_payload = probe_prompt
                    argv_system = ""
                else:
                    stdin_payload = _prompt_payload("", probe_prompt)
                    argv_system = ""
                argv = self.spec.build_argv(
                    self, argv_system, stdin_payload, schema_path, output_path, None)
                stdin_for_process = stdin_payload if self.spec.prompt_via_stdin else ""
                proc = self._run(argv, stdin_for_process, _PROBE_TIMEOUT_S, cwd)
                if self.spec.key in _EXIT_CODE_UNRELIABLE:
                    data = json.loads(proc.stdout)
                    return not data.get("is_error")
                return proc.returncode == 0
        except Exception as e:
            verbose_print(f"{self.spec.display} credential validation failed: {e}", self.verbose)
            return False


def _make_provider_class(spec: CLISpec) -> type:
    """
    Purpose:
        Synthesise a provider class for one CLI spec.

    Parameters:
        spec: The CLI description.

    Returns:
        A new subclass of CLIBackedProvider bound to that spec.

    Implementation notes:
        Generated with type() rather than written out five times, so the shared behaviour genuinely cannot drift between CLIs. Each class carries only its name and its spec. The class name is derived from the spec key so that tracebacks and repr output name the specific CLI rather than the shared base.
    """
    class_name = "".join(part.title() for part in spec.key.split("_")) + "Provider"
    return type(class_name, (CLIBackedProvider,), {"name": spec.key, "spec": spec})


ClaudeCliProvider = _make_provider_class(CLI_SPECS["claude_cli"])
CopilotCliProvider = _make_provider_class(CLI_SPECS["copilot_cli"])
KimiCliProvider = _make_provider_class(CLI_SPECS["kimi_cli"])
CodexCliProvider = _make_provider_class(CLI_SPECS["codex_cli"])
AntigravityCliProvider = _make_provider_class(CLI_SPECS["antigravity_cli"])
