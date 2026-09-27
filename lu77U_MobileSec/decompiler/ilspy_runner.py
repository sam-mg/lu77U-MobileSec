#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.ilspy_runner

Purpose:
    Run ilspycmd over a Xamarin or MAUI app's managed assemblies to recover C#, and decide which assemblies are the app's own.

Responsibilities:
    Resolve the tool, filter out framework assemblies, and decompile the rest.

Dependencies:
    subprocess, shutil, ..config.user_settings.

Implementation notes:
    Filtering matters as much as decompiling here. A Xamarin APK bundles the entire .NET base class library plus the Xamarin framework, which is tens of megabytes of assemblies that are identical in every such app. Decompiling them would take far longer than the app's own code and bury it in framework source.

Security considerations:
    Assemblies are attacker-controlled executable content. They are passed to a decompiler as file paths and are never loaded or executed by this process.
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from ..config import user_settings
from ..utils.verbose import plural, verbose_print

DEFAULT_TIMEOUT = 180

_SKIP_PREFIXES = (
    "System.", "Microsoft.", "Mono.", "Xamarin.", "netstandard", "mscorlib",
    "Java.Interop", "FSharp.", "Newtonsoft.Json", "SQLitePCLRaw",
)


def resolve_ilspy() -> Optional[str]:
    """
    Purpose:
        Locate the .NET decompiler.

    Returns:
        The configured path when it exists, the PATH lookup otherwise, or None.

    Implementation notes:
        The configured path is checked for existence before being preferred, so a stale setting falls through to PATH rather than causing a failure that looks like a missing tool.
    """
    configured = user_settings.get_xamarin_decompiler_path()
    if configured and Path(configured).exists():
        return configured
    return shutil.which("ilspycmd")


def decompile_assemblies(source_root, out_dir, verbose: bool = False,
                         timeout: int = DEFAULT_TIMEOUT,
                         is_cancelled=None) -> Optional[Path]:
    """
    Purpose:
        Decompile an app's own assemblies to C#.

    Parameters:
        source_root: Directory holding the recovered assemblies.
        out_dir: Directory to write C# into; created if missing.
        verbose: Traces progress and failures.
        timeout: Seconds allowed per assembly.
        is_cancelled: Polled between assemblies so a user stop takes effect promptly.

    Returns:
        The output directory, or None when the tool is unavailable, there is nothing to decompile, or nothing was produced.

    Raises:
        ScanCancelled: When the user stopped the scan.

    Side effects:
        Creates the output directory and spawns one process per assembly.

    Implementation notes:
        The timeout is per assembly rather than for the whole batch, so one pathological assembly is skipped while the rest still decompile. Failure handling distinguishes two cases deliberately: a timeout or a non-zero exit on one assembly is traced and the loop continues, while a failure to start the process at all aborts, because that means the tool is broken rather than the input. An absent tool is not an error. The Xamarin analysis can proceed on assembly strings alone, and the message says so and names the setting that would enable full decompilation. Cancellation is checked between assemblies, so a stop is honoured within one assembly's decompilation rather than after the whole batch.
    """
    from ..utils.cancellation import ScanCancelled

    is_cancelled = is_cancelled or (lambda: False)
    ilspy = resolve_ilspy()
    if not ilspy:
        verbose_print(
            "ilspycmd is not configured or on PATH; continuing on assembly "
            "strings alone (set xamarin_decompiler_path in Settings for C#)",
            verbose)
        return None

    root, out = Path(source_root), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    targets = app_assemblies(root)
    if not targets:
        verbose_print("No app assemblies to decompile", verbose)
        return None

    verbose_print(f"Decompiling {plural(len(targets), 'assembly', 'assemblies')} with {ilspy}", verbose)
    for assembly in targets:
        if is_cancelled():
            raise ScanCancelled()
        cmd = [ilspy, str(assembly), "-o", str(out)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            verbose_print(f"ilspycmd timed out on {assembly.name}; skipping", verbose)
            continue
        except (OSError, ValueError) as exc:
            verbose_print(f"ilspycmd failed to start ({exc}); giving up", verbose)
            return None
        if result.returncode != 0:
            verbose_print(
                f"ilspycmd exited {result.returncode} on {assembly.name}: "
                f"{(result.stderr or '').strip()[:200]}", verbose)

    produced = sum(1 for _ in out.rglob("*.cs"))
    if produced == 0:
        verbose_print("ilspycmd produced no C# output", verbose)
        return None
    verbose_print(f"Decompiled to {plural(produced, 'C# file')}", verbose)
    return out


def app_assemblies(source_root) -> List[Path]:
    """
    Purpose:
        Select the assemblies that belong to the app rather than to the framework.

    Parameters:
        source_root: Directory holding the recovered assemblies.

    Returns:
        Assembly paths, sorted; empty when the directory does not exist.

    Implementation notes:
        Filtering is by a prefix list covering the .NET base class library, the Mono and Xamarin runtimes, and the handful of ubiquitous third-party libraries that appear in essentially every Xamarin app. Prefix matching rather than exact names, because these ship as many individually-named assemblies under a shared namespace and listing them all would go stale with every framework release. Sorted so that decompilation order, and therefore the output, is deterministic between runs.

    Known limitations:
        An app whose own assembly name starts with one of these prefixes is skipped and never decompiled. The prefixes are distinctive enough that this is unlikely, and the alternative -- decompiling the whole base class library -- is far worse.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []
    return sorted(
        p for p in root.glob("*.dll")
        if not any(p.name.startswith(prefix) for prefix in _SKIP_PREFIXES))
