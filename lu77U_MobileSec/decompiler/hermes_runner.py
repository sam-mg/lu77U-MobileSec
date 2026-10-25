#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.hermes_runner

Purpose:
    Run hermes-decomp over a Hermes-compiled React Native bundle to recover JavaScript, plus the module list and string constants it can extract.

Responsibilities:
    Resolve the configured path, decompile the bundle, and gather the supplementary outputs.

Dependencies:
    subprocess, ..config.user_settings.

Security considerations:
    Invoked as an argument vector with no shell. The bundle is attacker-controlled input to the tool, which runs in its own process.
"""

import subprocess
from pathlib import Path
from typing import Optional

from ..config import user_settings
from ..utils.verbose import verbose_print

DEFAULT_TIMEOUT = 300

def _resolve_hermes_decomp_path() -> str:
    """
    Purpose:
        Read the configured path to hermes-decomp.

    Returns:
        The configured path, empty when the user has not set one.

    Side effects:
        Loads user settings on first call.

    Implementation notes:
        Wrapped in its own function so the caller reads it once per invocation rather than at import, which means a path changed in Settings takes effect without a restart.
    """
    return user_settings.get_hermes_decomp_path()

def decompile_hbc(bundle_path, out_dir, verbose: bool = False,
                  timeout: int = DEFAULT_TIMEOUT) -> Optional[Path]:
    """
    Purpose:
        Decompile a Hermes bytecode bundle to JavaScript.

    Parameters:
        bundle_path: Path to the Hermes bundle.
        out_dir: Directory to write results into; created if missing.
        verbose: Traces the command and the outcome.
        timeout: Seconds to allow before giving up.

    Returns:
        The path to the decompiled JavaScript, or None on any failure.

    Side effects:
        Creates the output directory, spawns the decompiler, and writes the supplementary files.

    Implementation notes:
        Success is judged by the output file existing and being non-empty rather than by the return code, since the tool can exit zero having written nothing. The supplementary extractions run only after the main decompilation succeeded, so a failed run does not spend time on extras. Every failure returns None, leaving the React Native analysis to proceed on whatever else it has.
    """
    hermes_path = _resolve_hermes_decomp_path()
    if not hermes_path:
        verbose_print("hermes-decomp path is not configured", verbose)
        return None

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "bundle.js"

    cmd = [hermes_path, "decompile", str(bundle_path), "-o", str(out_file)]
    verbose_print(f"Command: {' '.join(cmd)}", verbose)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        verbose_print(f"hermes-decomp executable not found at {hermes_path!r}: {exc}", verbose)
        return None
    except subprocess.TimeoutExpired:
        verbose_print(f"hermes-decomp timed out after {timeout}s", verbose)
        return None
    except Exception as exc:
        verbose_print(f"hermes-decomp invocation failed: {exc}", verbose)
        return None

    verbose_print(f"hermes-decomp return code: {result.returncode}", verbose)
    if not out_file.is_file() or out_file.stat().st_size == 0:
        verbose_print(
            f"hermes-decomp produced no output file. stderr (first 500 chars): "
            f"{(result.stderr or '')[:500]}", verbose)
        return None

    _extract_extras(hermes_path, bundle_path, out_dir, verbose)
    verbose_print(f"hermes-decomp output: {out_file}", verbose)
    return out_file

def _extract_extras(hermes_path: str, bundle_path, out_dir: Path, verbose: bool) -> None:
    """
    Purpose:
        Run the decompiler's auxiliary subcommands to capture the bundle's module list and candidate secrets.

    Parameters:
        hermes_path: Path to the decompiler.
        bundle_path: Path to the bundle.
        out_dir: Directory to write the extra files into.
        verbose: Traces each extraction.

    Side effects:
        Spawns one process per subcommand and may write two files.

    Implementation notes:
        Both subcommands are entirely optional: each is individually guarded and a failure is traced and skipped. Older builds of the tool do not have them, and their absence must not fail a decompilation that already succeeded. A shorter timeout is used than for the main decompilation, since these are cheap operations and a hang here would be pure delay. Empty output is not written, so an absent file means the subcommand found nothing rather than that it was not run.

    Security considerations:
        The secrets output is exactly what its name suggests -- candidate credentials recovered from the bundle -- and is written in plaintext beside the other scan artifacts.
    """
    for subcommand, filename in (("modules", "modules.txt"), ("secrets", "secrets.txt")):
        try:
            result = subprocess.run(
                [hermes_path, subcommand, str(bundle_path)],
                capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                (out_dir / filename).write_text(result.stdout, encoding="utf-8")
                verbose_print(f"hermes-decomp {subcommand} -> {filename}", verbose)
        except Exception as exc:
            verbose_print(f"hermes-decomp {subcommand} unavailable ({exc}); skipping", verbose)


def extract_hbc_modules(bundle_path, out_dir, verbose: bool = False,
                        timeout: int = DEFAULT_TIMEOUT) -> Optional[Path]:
    """
    Purpose:
        Extract every Metro module of a Hermes bundle to its own decompiled file.

    Parameters:
        bundle_path: Path to the Hermes bundle.
        out_dir: Directory to write the per-module files into; created if missing.
        verbose: Traces the command and the outcome.
        timeout: Seconds to allow before giving up.

    Returns:
        The directory holding the module files, or None when hermes-decomp is unconfigured, lacks the extract command, or wrote nothing.

    Side effects:
        Creates the output directory and spawns the decompiler, then runs the module-list and secrets extractions beside it.

    Implementation notes:
        Preferred over a whole-bundle decompile because a module is the unit the app is built from: per-module files carry the module's id, recovered name and dependencies in a header, which is what lets the app be told apart from the framework. Success is judged by at least one module file being written, not by the exit status. The extras are written to the parent of the module directory, so they sit beside the analysis rather than among the modules.
    """
    hermes_path = _resolve_hermes_decomp_path()
    if not hermes_path:
        verbose_print("hermes-decomp path is not configured", verbose)
        return None
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [hermes_path, "extract", str(bundle_path), "-o", str(out_dir)]
    verbose_print(f"Command: {' '.join(cmd)}", verbose)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        verbose_print(f"hermes-decomp executable not found at {hermes_path!r}: {exc}", verbose)
        return None
    except subprocess.TimeoutExpired:
        verbose_print(f"hermes-decomp extract timed out after {timeout}s", verbose)
        return None
    except Exception as exc:
        verbose_print(f"hermes-decomp extract failed: {exc}", verbose)
        return None
    written = sum(1 for _ in out_dir.glob("*.js"))
    verbose_print(f"hermes-decomp extract return code {result.returncode}, {written} module files", verbose)
    if not written:
        verbose_print(f"hermes-decomp extract wrote nothing. stderr (first 500 chars): "
                      f"{(result.stderr or '')[:500]}", verbose)
        return None
    _extract_extras(hermes_path, bundle_path, out_dir.parent, verbose)
    return out_dir
