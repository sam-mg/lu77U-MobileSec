#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ui.colors

Purpose:
    Provide the ANSI colour codes used across terminal output, and make them work on Windows consoles that do not interpret ANSI by default.

Responsibilities:
    Initialise colorama where available, and expose the codes and their semantic aliases.

Dependencies:
    platform, colorama when installed.

Implementation notes:
    colorama is initialised at import, with different settings per platform. On Windows it translates ANSI sequences into console API calls, which is the only way colour works in the older console host. On POSIX it is initialised without autoreset, because the codes here are emitted and reset explicitly and autoreset would insert a reset after every write. Its absence is tolerated silently. On POSIX the escape sequences work without it; on Windows they degrade to visible escape characters, which is ugly but does not stop the tool running. This module is imported by the verbose logger, so it must stay dependency-free beyond colorama -- a heavier import here would be paid by every module that traces anything.
"""

import platform

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
    except ImportError:
        pass
else:
    try:
        import colorama
        colorama.init(autoreset=False)
    except ImportError:
        pass

class Colors:
    """
    Purpose:
        Namespace of ANSI escape codes, plus semantic aliases that name what a colour is for rather than what it looks like.

    Attributes:
        RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, WHITE, MAGENTA: Foreground colour codes.
        BOLD, UNDERLINE: Text attribute codes.
        RESET: Returns the terminal to its default state.
        SUCCESS, ERROR, WARNING, INFO, HEADER, VERBOSE: Semantic aliases onto the colours above.

    Invariants:
        Every sequence is a plain string constant, so they can be concatenated into f-strings anywhere without a function call.

    Thread-safety:
        Class-level constants only; safe to read from any thread.

    Implementation notes:
        Call sites use the semantic names, so the palette can be changed in one place without hunting for every red string in the codebase. WARNING maps to purple rather than yellow because yellow is reserved for verbose tracing, which would otherwise be indistinguishable from a warning in a scrolling log.
    """
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[35m'
    
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = PURPLE  
    INFO = CYAN
    HEADER = PURPLE
    VERBOSE = YELLOW
