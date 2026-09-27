#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.rn_bundle_decompiler

Purpose:
    Run react-native-decompiler over a plain-JavaScript React Native bundle to split it back into per-module source files.

Responsibilities:
    Resolve the configured path, invoke the tool, and confirm it produced output.

Dependencies:
    subprocess, ..config.user_settings.

Implementation notes:
    This is the counterpart to the Hermes runner: which one applies is decided by the bundle's magic bytes, not by configuration.

Security considerations:
    Invoked as an argument vector with no shell.
"""

import subprocess
from pathlib import Path
from typing import Optional

from ..config import user_settings
from ..utils.verbose import verbose_print

DEFAULT_TIMEOUT = 300

def _resolve_rn_decompiler_path() -> str:
    """
    Purpose:
        Read the configured path to react-native-decompiler.

    Returns:
        The configured path, empty when the user has not set one.

    Side effects:
        Loads user settings on first call.

    Implementation notes:
        Wrapped in its own function so the caller reads it once per invocation rather than at import, which means a path changed in Settings takes effect without a restart.
    """
    return user_settings.get_rn_decompiler_path()

def decompile_js_bundle(bundle_path, out_dir, verbose: bool = False,
                        timeout: int = DEFAULT_TIMEOUT) -> Optional[Path]:
    """
    Purpose:
        Unbundle a plain-JavaScript React Native bundle into per-module sources.

    Parameters:
        bundle_path: Path to the bundle.
        out_dir: Directory to write results into; created if missing.
        verbose: Traces the command and the outcome.
        timeout: Seconds to allow before giving up.

    Returns:
        The output directory, or None on any failure.

    Side effects:
        Creates the output directory and spawns the decompiler.

    Implementation notes:
        Linting is disabled in the invocation. The tool runs ESLint over its output by default, which is slow on a large bundle and irrelevant here -- the output is being read by an analyzer, not by a developer. Success is judged by output files existing rather than by the return code. The failure message names the two bundle formats this tool cannot handle, Hermes bytecode and Webpack v5, because those are the common causes and the tool's own error does not say so.
    """
    decompiler_path = _resolve_rn_decompiler_path()
    if not decompiler_path:
        verbose_print("RN decompiler path is not configured", verbose)
        return None

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [decompiler_path, "-i", str(bundle_path), "-o", str(out_dir), "--noEslint"]
    verbose_print(f"Command: {' '.join(cmd)}", verbose)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        verbose_print(f"RN decompiler executable not found at {decompiler_path!r}: {exc}", verbose)
        return None
    except subprocess.TimeoutExpired:
        verbose_print(f"RN decompiler timed out after {timeout}s", verbose)
        return None
    except Exception as exc:
        verbose_print(f"RN decompiler invocation failed: {exc}", verbose)
        return None

    verbose_print(f"RN decompiler return code: {result.returncode}", verbose)
    produced_output = out_dir.is_dir() and any(out_dir.rglob("*.*"))
    if not produced_output:
        verbose_print(
            f"RN decompiler produced no output files (bundle may be Hermes-"
            f"compiled or a Webpack v5 bundle, neither supported by this "
            f"tool). stderr (first 500 chars): {(result.stderr or '')[:500]}", verbose)
        return None

    verbose_print(f"RN decompiler output directory: {out_dir}", verbose)
    return out_dir
