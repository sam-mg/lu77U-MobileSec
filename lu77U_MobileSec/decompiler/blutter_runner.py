#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.blutter_runner

Purpose:
    Run Blutter over a Flutter app's native libraries to recover Dart structure from the AOT snapshot.

Responsibilities:
    Resolve the configured path, invoke Blutter, and decide whether it actually produced usable output.

Dependencies:
    subprocess, ..config.user_settings.

Implementation notes:
    The default timeout is far longer than the other decompilers' because Blutter compiles a Dart SDK matching the app's Dart version on its first run against that version. A first Flutter scan legitimately takes minutes, and a short timeout would make Flutter support appear broken.

Security considerations:
    Blutter is invoked as an argument vector with no shell, and the paths it receives are ones this tool constructed rather than values taken from the APK.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from ..config import user_settings
from ..utils.verbose import verbose_print

DEFAULT_TIMEOUT = 1800

def _resolve_blutter_path() -> str:
    """
    Purpose:
        Read the configured path to Blutter.

    Returns:
        The configured path, empty when the user has not set one.

    Side effects:
        Loads user settings on first call.

    Implementation notes:
        Wrapped in its own function so the caller reads it once per invocation rather than at import, which means a path changed in Settings takes effect without a restart.
    """
    return user_settings.get_blutter_path()

def run_blutter(lib_dir, out_dir, verbose: bool = False,
                timeout: int = DEFAULT_TIMEOUT) -> Optional[Path]:
    """
    Purpose:
        Decompile a Flutter app's Dart snapshot with Blutter.

    Parameters:
        lib_dir: Directory holding the extracted native libraries.
        out_dir: Directory to write results into; created if missing.
        verbose: Traces the command and the outcome.
        timeout: Seconds to allow before giving up.

    Returns:
        The output directory, or None when Blutter is unconfigured, failed, or produced nothing usable.

    Side effects:
        Creates the output directory and spawns Blutter.

    Implementation notes:
        Blutter is a Python script rather than an executable, so it is run through the current interpreter. That also guarantees it runs under the same Python this tool is using rather than whatever is first on PATH. The return code is not trusted on its own. Success is decided by inspecting the output: Blutter can exit zero having produced nothing useful, and treating that as success would send an empty directory to the analyzer. The check looks for either of the two artifacts a real run produces. Every failure mode returns None rather than raising, so a Flutter app whose snapshot cannot be recovered still completes the rest of its scan. The long-first-run behaviour is traced explicitly, so a user watching a slow scan can tell it is compiling rather than hung.
    """
    blutter_path = _resolve_blutter_path()
    if not blutter_path:
        verbose_print("Blutter path is not configured", verbose)
        return None

    lib_dir = Path(lib_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, blutter_path, str(lib_dir), str(out_dir)]
    verbose_print(f"Command: {' '.join(cmd)}", verbose)
    verbose_print(
        "Blutter may compile the Dart SDK on its first run against a new "
        "Dart version - this can take several minutes.", verbose)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        verbose_print(f"Blutter executable not found at {blutter_path!r}: {exc}", verbose)
        return None
    except subprocess.TimeoutExpired:
        verbose_print(f"Blutter timed out after {timeout}s", verbose)
        return None
    except Exception as exc:
        verbose_print(f"Blutter invocation failed: {exc}", verbose)
        return None

    verbose_print(f"Blutter return code: {result.returncode}", verbose)
    if result.returncode != 0:
        verbose_print(f"Blutter stderr (first 500 chars): {(result.stderr or '')[:500]}", verbose)

    pp_txt = out_dir / "pp.txt"
    asm_dir = out_dir / "asm"
    produced_output = pp_txt.is_file() or (asm_dir.is_dir() and any(asm_dir.iterdir()))
    if not produced_output:
        verbose_print(
            "Blutter produced no recognizable output (no pp.txt, empty asm/) "
            "- treating as failed", verbose)
        return None

    verbose_print(f"Blutter output directory: {out_dir}", verbose)
    return out_dir
