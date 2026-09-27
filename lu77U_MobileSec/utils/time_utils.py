#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.time_utils

Purpose:
    Format elapsed durations for humans reading scan progress, where the interesting range spans sub-millisecond tool probes and multi-hour decompilations.

Responsibilities:
    Turn a float of seconds into a compact string.

Dependencies:
    .verbose.
"""

from .verbose import verbose_print

def format_duration(seconds: float, verbose: bool = False) -> str:
    """
    Purpose:
        Render a duration as a compact human-readable string such as "1h 5m 3s", "42.5s" or "12.3ms".

    Parameters:
        seconds: Elapsed time. Negative values are clamped rather than rejected.
        verbose: Emits a step-by-step trace of the breakdown.

    Returns:
        A non-empty string. "0s" for any negative input.

    Postconditions:
        Precision adapts to magnitude: milliseconds below one second, one decimal place below one minute, whole seconds above it. This keeps a long-running stage from displaying meaningless fractional precision while still distinguishing two fast tool probes.

    Complexity:
        O(1).

    Implementation notes:
        Hours and minutes are appended only when non-zero, so a short duration reads as "3.2s" rather than "0h 0m 3.2s". The seconds component is always appended, which is what keeps the result non-empty for an input of exactly zero. A negative input returns early instead of producing a negative component, because durations are computed from clock deltas and a negative one means the clock moved, not that time ran backwards.
    """
    verbose_print(f"Formatting duration: {seconds} seconds", verbose)
    
    if seconds < 0:
        verbose_print("Negative duration detected, returning '0s'", verbose)
        return "0s"
    
    total_seconds = seconds
    verbose_print(f"Total seconds to format: {total_seconds}", verbose)
    
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    remaining_seconds = total_seconds % 60
    
    verbose_print(f"Time breakdown - Hours: {hours}, Minutes: {minutes}, Seconds: {remaining_seconds:.1f}", verbose)
    
    parts = []
    
    if hours > 0:
        parts.append(f"{hours}h")
        verbose_print(f"Added hours component: {hours}h", verbose)
    if minutes > 0:
        parts.append(f"{minutes}m")
        verbose_print(f"Added minutes component: {minutes}m", verbose)
    
    if total_seconds < 1:
        ms_value = remaining_seconds * 1000
        parts.append(f"{ms_value:.1f}ms")
        verbose_print(f"Added milliseconds component: {ms_value:.1f}ms", verbose)
    elif total_seconds < 60:
        parts.append(f"{remaining_seconds:.1f}s")
        verbose_print(f"Added precise seconds component: {remaining_seconds:.1f}s", verbose)
    else:
        parts.append(f"{remaining_seconds:.0f}s")
        verbose_print(f"Added rounded seconds component: {remaining_seconds:.0f}s", verbose)
    
    result = " ".join(parts)
    verbose_print(f"Final formatted duration: '{result}'", verbose)
    return result
