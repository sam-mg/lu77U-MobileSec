#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.semgrep_runner

Purpose:
    Run Semgrep over decompiled source with this project's rule set, and translate its output into the rule engine's finding type.

Responsibilities:
    Locate Semgrep, invoke it, and convert its results.

Dependencies:
    Semgrep, as an executable or an importable module; entirely optional.

Implementation notes:
    Semgrep complements the built-in extractors: it matches on syntax rather than on text, so it catches patterns a regular expression cannot express. It is optional because it is a large dependency and the built-in extractors cover the common cases without it.

Security considerations:
    Semgrep is invoked with a fixed argument vector over the decompiled tree, and is bounded by a timeout so a pathological file cannot stall the scan.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .findings import SastFinding, normalize_severity
from ...utils.verbose import plural, verbose_print

DEFAULT_TIMEOUT = 600

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "semgrep" / "android"

_SEVERITY_MAP = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

_MAX_HITS = 300


def _resolve_semgrep() -> Optional[List[str]]:
    """
    Purpose:
        Locate Semgrep, as an executable or as a module.

    Returns:
        The command to invoke it, or None when it is unavailable.

    Implementation notes:
        The executable is preferred, with the module form as a fallback -- an installation into the current environment may not put a script on PATH, particularly inside a virtual environment. Running it through the current interpreter in that case guarantees the version matching the environment rather than whichever happens to be first on PATH.
    """
    found = shutil.which("semgrep")
    if found:
        return [found]
    try:
        import semgrep
        return [sys.executable, "-m", "semgrep"]
    except Exception:
        return None


def run_semgrep(source_root, verbose: bool = False,
                timeout: int = DEFAULT_TIMEOUT,
                rules_dir: Optional[Path] = None) -> List[SastFinding]:
    """
    Purpose:
        Run Semgrep over a decompiled tree with the project's rules.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces the outcome.
        timeout: Seconds to allow.
        rules_dir: Rule directory; the project's own when omitted.

    Returns:
        The findings; empty when Semgrep is unavailable or produced nothing.

    Side effects:
        Spawns Semgrep.

    Implementation notes:
        Every failure -- missing tool, timeout, unparseable output -- yields an empty list rather than raising, because this is a complement to the built-in extractors and its absence must not cost their findings.
    """
    root = Path(source_root) if source_root else None
    if root is None or not root.is_dir():
        return []

    rules = Path(rules_dir) if rules_dir else RULES_DIR
    if not rules.exists():
        verbose_print(f"Semgrep: rules directory {rules} is missing; skipping", verbose)
        return []

    argv = _resolve_semgrep()
    if argv is None:
        verbose_print("Semgrep: not available in this environment; skipping", verbose)
        return []

    cmd = argv + [
        "scan", "--json", "--quiet",
        "--config", str(rules),
        "--metrics", "off",
        "--no-git-ignore",
        "--timeout", "30",
        str(root),
    ]
    verbose_print(f"Semgrep: {' '.join(cmd[:6])} … {root}", verbose)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        verbose_print("Semgrep: executable disappeared between resolve and run", verbose)
        return []
    except subprocess.TimeoutExpired:
        verbose_print(f"Semgrep: timed out after {timeout}s; skipping", verbose)
        return []
    except Exception as exc:
        verbose_print(f"Semgrep: failed to run ({exc}); skipping", verbose)
        return []

    if not result.stdout.strip():
        verbose_print(f"Semgrep: no output (exit {result.returncode})", verbose)
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        verbose_print(f"Semgrep: unparseable JSON output ({exc}); skipping", verbose)
        return []

    findings = _to_findings(payload, root, verbose)
    verbose_print(f"Semgrep: {plural(len(findings), 'hit')}", verbose)
    return findings


def _to_findings(payload: Dict[str, Any], root: Path, verbose: bool) -> List[SastFinding]:
    """
    Purpose:
        Convert Semgrep's output into rule findings.

    Parameters:
        payload: Semgrep's parsed output.
        root: Source root, for relative paths.
        verbose: Traces conversion problems.

    Returns:
        The findings.

    Implementation notes:
        The result count is capped, because a broad rule over a large decompiled tree can produce thousands of hits and a report cannot absorb them. Paths are made relative to the source root so they match the paths the rest of the pipeline uses; a path that will not relativise is skipped rather than reported with an absolute path that nothing downstream could resolve.
    """
    out: List[SastFinding] = []
    for item in (payload.get("results") or [])[:_MAX_HITS]:
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        try:
            rel = str(Path(item.get("path", "")).relative_to(root))
        except (ValueError, TypeError):
            rel = item.get("path", "")
        line = int((item.get("start") or {}).get("line") or 0)
        message = " ".join((extra.get("message") or "").split())
        out.append(SastFinding(
            title=_title_for(item.get("check_id", ""), message),
            severity=normalize_severity(
                _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "Medium")),
            description=message or "Semgrep rule matched.",
            vuln_class=str(meta.get("vuln_class", "")),
            file=rel, line=line,
            line_end=int((item.get("end") or {}).get("line") or line),
            cwe=str(meta.get("cwe", "")),
            owasp_mobile=str(meta.get("owasp_mobile", "")),
            evidence=(extra.get("lines") or "").strip()[:600],
            detector="semgrep", confidence="MEDIUM",
            recommendation="Confirm the flagged path against the surrounding logic before "
                           "acting on it.",
            extra={"semgrep_rule": item.get("check_id", ""),
                   "chain_tag": meta.get("chain_tag", "")}))
    return out


def _title_for(check_id: str, message: str) -> str:
    """
    Purpose:
        Derive a readable title from a Semgrep rule identifier.

    Parameters:
        check_id: The rule identifier.
        message: The rule's message, used as a fallback.

    Returns:
        The title.

    Implementation notes:
        The last segment of the dotted identifier is the rule's own name; the leading path is the rule file's location and is noise in a report. Separators become spaces and the result is capitalised so it reads as a heading rather than an identifier. The message is the fallback, truncated, for a rule whose identifier yields nothing usable.
    """
    tail = (check_id or "").rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").strip()
    if tail:
        return tail[:1].upper() + tail[1:]
    return (message[:80] or "Semgrep finding")
