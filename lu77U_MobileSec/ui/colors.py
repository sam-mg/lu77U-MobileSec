#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ui.colors

Purpose:
    Provide the ANSI colour codes used across terminal output, and make them work on Windows consoles that do not interpret ANSI by default.

Responsibilities:
    Initialise colorama where available, and expose the codes and their semantic aliases.

Dependencies:
    contextlib, platform, colorama when installed.

Implementation notes:
    colorama is initialised at import, with different settings per platform. On Windows it translates ANSI sequences into console API calls, which is the only way colour works in the older console host. On POSIX it is initialised without autoreset, because the codes here are emitted and reset explicitly and autoreset would insert a reset after every write. colorama is optional: its absence is tolerated silently, with the ImportError suppressed rather than caught and discarded by hand. On POSIX the escape sequences work without it; on Windows they degrade to visible escape characters, which is ugly but does not stop the tool running. This module is imported by the verbose logger, so it must stay dependency-free beyond colorama -- a heavier import here would be paid by every module that traces anything. Colors is a namedtuple instance rather than a class: every call site still reads it as Colors.NAME, and the codes are still plain string constants safe to read from any thread, but the module no longer defines a class with no methods for the sake of a namespace. WARNING maps to purple rather than yellow because yellow is reserved for verbose tracing, which would otherwise be indistinguishable from a warning in a scrolling log; the semantic names alias onto the colours below so the palette can be changed in one place without hunting for every red string in the codebase.
"""

import collections
import contextlib
import platform

if platform.system() == "Windows":
    with contextlib.suppress(ImportError):
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
else:
    with contextlib.suppress(ImportError):
        import colorama
        colorama.init(autoreset=False)

_CODES = {
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "PURPLE": '\033[95m',
    "CYAN": '\033[96m',
    "WHITE": '\033[97m',
    "MAGENTA": '\033[35m',
    "BOLD": '\033[1m',
    "UNDERLINE": '\033[4m',
    "RESET": '\033[0m',
}
_CODES.update(
    SUCCESS=_CODES["GREEN"],
    ERROR=_CODES["RED"],
    WARNING=_CODES["PURPLE"],
    INFO=_CODES["CYAN"],
    HEADER=_CODES["PURPLE"],
    VERBOSE=_CODES["YELLOW"],
)

Colors = collections.namedtuple("Colors", _CODES.keys())(**_CODES)
