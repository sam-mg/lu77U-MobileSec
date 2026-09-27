#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.verbose

Purpose:
    Single tracing channel for the whole tool. Every component logs through verbose_print, which redacts secrets, optionally prints to the terminal, and forwards the interesting subset to the dashboard.

Responsibilities:
    Redact credential-shaped substrings, maintain the sink registry that the web UI attaches to, classify a message as milestone or noise, and emit.

Dependencies:
    re, ..ui.colors for the terminal colour codes.

Implementation notes:
    Two audiences want different volumes from the same call sites. An operator running with -V wants everything; the dashboard's progress feed wants the couple of dozen lines that mark real progress, or it becomes an unreadable scroll. Rather than make every call site choose, one function serves both and _MILESTONE_PATTERNS decides what is worth surfacing. The pattern list is anchored and specific by design. A loose filter would leak thousands of lines into the UI; an allowlist keeps the feed curated, at the cost of needing an entry when a new milestone message is introduced.

Thread-safety:
    _SINKS is a plain list with no lock. Registration is expected to happen at startup, before analysis threads exist. verbose_print iterates over a snapshot, so a concurrent registration cannot corrupt an in-progress emit, but two concurrent registrations can still race.

Security considerations:
    Redaction happens before anything is printed or forwarded, so no sink can receive an unredacted message. The patterns are best-effort heuristics over known credential shapes, not a guarantee: a secret in an unrecognised format will pass through. Never log a credential on the assumption that this module will catch it.
"""

import re
from typing import Callable, List, Optional

from ..ui.colors import Colors

_SINKS: List[Callable[[str], None]] = []

_SECRET_PATTERNS = [
    re.compile(r"(?i)([?&](?:key|api[-_]?key|access[-_]?token|token|password)=)[^\s&\"'>]+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)([\"']?\b(?:api[-_]?key|secret|token|password)\b[\"']?\s*[:=]\s*[\"']?)[^\s,\"'}]+"),
]

def redact(message: str) -> str:
    """
    Purpose:
        Mask credential-shaped substrings before a message is printed or forwarded anywhere.

    Parameters:
        message: Any object; coerced with str so that a caller passing an exception or a dict cannot bypass redaction by not passing a string.

    Returns:
        The message with each recognised secret replaced by its label and "***", preserving enough context for the line to stay readable.

    Complexity:
        O(n) in message length, times the fixed number of patterns.

    Implementation notes:
        Three shapes are covered: a credential in a URL query string, an Authorization bearer token, and a key/value assignment in JSON, YAML or a config dump. Each pattern captures its label in group 1 and substitutes only the value, so "api_key=abc123" becomes "api_key=***" rather than vanishing -- the reader still learns that a key was present.

    Security considerations:
        Best-effort only. Coverage is limited to these three shapes; a bare token with no surrounding label, or a secret split across lines, is not matched. This is a safety net, not a licence to log secrets.
    """
    text = str(message)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1***", text)
    return text

def register_sink(sink: Callable[[str], None]) -> None:
    """
    Purpose:
        Attach an additional destination for milestone messages, used by the web dashboard to stream progress into a running job.

    Parameters:
        sink: A callable taking one already-redacted string.

    Postconditions:
        The sink is present exactly once; registering the same callable twice is a no-op rather than a duplicate.

    Side effects:
        Mutates module-global state for the lifetime of the process.

    Thread-safety:
        Not synchronised. Register before starting analysis threads.

    Implementation notes:
        Idempotence matters because a dashboard reconnect would otherwise double every line in the feed. Identity is by equality, so a bound method registered twice from the same instance deduplicates, but two equivalent lambdas do not.
    """
    if sink not in _SINKS:
        _SINKS.append(sink)

def unregister_sink(sink: Callable[[str], None]) -> None:
    """
    Purpose:
        Detach a previously registered sink, typically when a job finishes or a dashboard client disconnects.

    Parameters:
        sink: The callable passed to register_sink.

    Postconditions:
        The sink is absent. Removing one that was never registered is a no-op.

    Side effects:
        Mutates module-global state.

    Implementation notes:
        The ValueError is swallowed because cleanup runs on paths that may execute twice -- a finally block plus an error handler -- and a failed unregister must never mask the error being handled.
    """
    try:
        _SINKS.remove(sink)
    except ValueError:
        pass

def plural(count: int, singular: str, plural_form: Optional[str] = None) -> str:
    """
    Purpose:
        Format a count with a correctly pluralised noun, so that progress lines do not read "1 files".

    Parameters:
        count: The number to render.
        singular: The singular noun.
        plural_form: Explicit plural for irregular nouns; defaults to the singular with "s" appended.

    Returns:
        A string of the form "<count> <noun>".

    Complexity:
        O(1).

    Implementation notes:
        Only a count of exactly 1 takes the singular, so zero and negative counts pluralise -- "0 files" reads correctly, "0 file" does not.
    """
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{count} {word}"


_MILESTONE_PATTERNS = tuple(re.compile(p) for p in (
    r"^(BasicInfoExtractor|ManifestParser|OutputManager|ResponseParser|"
    r"ADBManager|JSONExporter|JavaKotlinDecompiler) (initializing|initialized)$",
    r"^Androguard available:",
    r"^FrameworkDetectionResult created with",
    r"^\w[\w/ ]* APK detected with",
    r"^\w+Detector indicators:",
    r"^\w+ detection confirmed$",
    r"^Found \d+ native librar",
    r"^Found native architectures:",
    r"^Loading APK with androguard$",
    r"^APK loaded successfully$",
    r"^Package name:",
    r"^Resolved app name:",
    r"^Version: ",
    r"^SDK versions",
    r"^Extracting application components$",
    r"^Found \d+ (activit|service|receiver|provider)",
    r"^Primary framework \(",
    r"^(JADX|Blutter|ilspycmd) path configured as:",
    r"^Listing ADB devices$",
    r"^Running: adb ",
    r"^adb (rc=|stdout=)",
    r"^Total devices:",
    r"^Initializing \w+Provider ",
    r"^Starting .* Analysis\.\.\.$",
    r"^Creating output directory structure for:",
    r"^Generated timestamp:",
    r"^APK name:",
    r"^(Decompiling APK|Recovering \.NET assemblies)",
    r"^Extracting (application components|the app's web assets)",
    r"^Decompiled output directory:",
    r"^Decompiled to \d+",
    r"^(Code graph|Cordova graph|Flutter graph|RN graph|Xamarin graph) built:",
    r"^Partition(ing|ed) ",
    r"^Wrote \d+ assembly string sidecar",
    r"^Recovered \d+ \.NET assembl",
    r"^Running agentic",
    r"^Fan-out",
    r"^Agent context:",
    r"^Starting \w+ analysis",
    r"^The LLM is ",
    r"^(Giving|Listing|Search results|Response) .* to the LLM",
    r"^Could not satisfy that request:",
    r"^Processing response text",
    r"^Successfully parsed as direct JSON$",
    r"^Parsed JSON is a list with",
    r"^Validating vulnerability keys:",
    r"^Normalizing vulnerability result",
    r"^Agent (step \d+: recorded|finished at step)",
    r"^Agentic analysis produced",
    r"^Coverage nudge at step",
    r"^SAST[: ]",
    r"^Semgrep: \d+ hit",
    r"^Deterministic scanners produced",
    r"^Gates: ",
    r"^(Verifying rule findings|Reviewing findings):",
    r"^Chains: ",
    r"^Verification triage:",
    r"^On-device session complete",
    r"^\d+ findings? verified",
    r"^Starting JSON export$",
    r"^JSON Saved in",
    r"^(HTML|PDF) (report )?saved",
    r"^Total time taken:",
    r"^No vulnerabilities found!$",
))

_ALWAYS_KEEP = re.compile(
    r"(?i)\b(error|failed|failure|could not|cannot|unable|timed out|timeout|"
    r"refused|denied|invalid|missing|not found|not configured|skipping|"
    r"warning|unsupported|cancelled|stopped|no output|gave up)\b")


def is_milestone(message: str) -> bool:
    """
    Purpose:
        Decide whether a message is worth showing in the dashboard's progress feed, as opposed to the full verbose stream.

    Parameters:
        message: The already-redacted message text.

    Returns:
        True when the message should reach registered sinks.

    Complexity:
        O(n) in message length, times the pattern count. Runs on every verbose call, which is why the cheap always-keep check is tried first.

    Implementation notes:
        _ALWAYS_KEEP is evaluated before the milestone list and matches anywhere in the line. Anything that reports a failure, a skip or a timeout reaches the user regardless of which component produced it: a curated allowlist that silently drops errors would be worse than no filter at all. Milestone patterns are anchored at the start, because they identify a known message shape rather than searching for a topic. Empty and whitespace-only messages are rejected outright so that spacing lines in the terminal stream do not punctuate the UI feed.
    """
    text = str(message or "").strip()
    if not text:
        return False
    if _ALWAYS_KEEP.search(text):
        return True
    return any(pattern.search(text) for pattern in _MILESTONE_PATTERNS)


def verbose_print(message: str, verbose: bool = False):
    """
    Purpose:
        The tracing entry point used throughout the codebase: redact, print when asked, and forward milestones to the dashboard.

    Parameters:
        message: Text to trace; coerced to str during redaction.
        verbose: Controls terminal output only. Sink forwarding is independent, so the dashboard receives milestones even on a quiet run.

    Side effects:
        Writes to stdout when verbose is set, and calls every registered sink for a milestone message.

    Complexity:
        O(n) in message length, plus the milestone classification.

    Implementation notes:
        The terminal and sink paths are deliberately decoupled. A dashboard user starts no terminal and passes no -V, but still needs progress; tying the feed to the verbose flag would leave the UI silent. Sinks are iterated over a copy, so a sink that registers or unregisters during the call cannot mutate the list mid-iteration. Every sink call is individually wrapped: a dashboard client that disconnected mid-scan raises on write, and that must not propagate into the analysis that happened to emit the line.

    Security considerations:
        Redaction runs first, so both the terminal and every sink see only the masked text.
    """
    safe = redact(message)
    if verbose:
        print(f"{Colors.YELLOW}[VERBOSE] {safe}{Colors.RESET}")
    if _SINKS and is_milestone(safe):
        for sink in list(_SINKS):
            try:
                sink(safe)
            except Exception:
                pass
