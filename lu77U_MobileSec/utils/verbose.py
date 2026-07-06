"""Verbose utilities for lu77U-MobileSec."""

from typing import Callable, List

from ..ui.colors import Colors

_SINKS: List[Callable[[str], None]] = []

def register_sink(sink: Callable[[str], None]) -> None:
    """Register a callback invoked with every verbose message."""
    if sink not in _SINKS:
        _SINKS.append(sink)

def unregister_sink(sink: Callable[[str], None]) -> None:
    """Remove a previously registered sink (no-op if absent)."""
    try:
        _SINKS.remove(sink)
    except ValueError:
        pass

def verbose_print(message: str, verbose: bool = False):
    """Echo to the terminal when ``verbose``; always forward to registered sinks."""
    if verbose:
        print(f"{Colors.YELLOW}[VERBOSE] {message}{Colors.RESET}")
    if _SINKS:
        for sink in list(_SINKS):
            try:
                sink(str(message))
            except Exception:
                pass