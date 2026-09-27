#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.cli.main

Purpose:
    Terminal entry point. The CLI itself does no analysis; its only job is to parse flags and hand control to the local web dashboard, so that the terminal and browser front ends never drift apart in behaviour.

Responsibilities:
    Parse argv, enable ANSI colour on Windows, start the web server, and convert every exit path into a deliberate process exit code.

Dependencies:
    argparse (via .parser), ..web.server for the dashboard, colorama on Windows only, ..utils.verbose for opt-in tracing.

Security considerations:
    The dashboard is bound by ..web.server, not here; this module never widens that binding. Tracebacks are printed only under --verbose so that filesystem paths are not leaked to a casual terminal observer.
"""

import sys
import platform

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init(autoreset=True, convert=True, strip=False, wrap=True)
    except ImportError:
        pass

from .parser import parse_args
from .._metadata import NAME
from ..utils.verbose import verbose_print

def main(args=None):
    """
    Purpose:
        Run the CLI: parse arguments, then block inside the web server until the user interrupts it.

    Parameters:
        args: Argument vector to parse. None means read sys.argv, which is the normal console-script path; tests pass an explicit list.

    Returns:
        None on a path that cannot happen in practice -- every branch either blocks in serve() or exits the process.

    Raises:
        SystemExit: 0 after a KeyboardInterrupt, 1 after any other exception. Raised rather than returned so the shell sees a real exit code.

    Side effects:
        Initialises colorama on Windows, binds the dashboard's TCP port, and may launch the user's default browser unless --no-browser was given.

    Security considerations:
        The traceback is emitted only when --verbose is set. Argument parsing happens before anything else, so a parse failure exits before any port is bound or any browser is opened.

    Implementation notes:
        parsed_args is seeded to None before the try block because parsing can itself fail; the handler falls back to non-verbose in that case rather than raising a second error while reporting the first. The web.server import is deferred into the function so that --version and --help stay fast and do not pay for the server's import graph.
    """
    parsed_args = None
    try:
        parsed_args = parse_args(args)
        verbose_print(f"Starting {NAME}", parsed_args.verbose)
        verbose_print(f"Python version: {sys.version}", parsed_args.verbose)
        verbose_print(f"Platform: {platform.platform()}", parsed_args.verbose)

        from ..web.server import serve
        serve(
            verbose=parsed_args.verbose,
            port=parsed_args.port,
            open_browser=not parsed_args.no_browser,
        )

    except KeyboardInterrupt:
        print(f"\n\nExiting {NAME}...")
        sys.exit(0)
    except Exception as e:
        verbose_value = parsed_args.verbose if parsed_args is not None else False
        if verbose_value:
            import traceback
            traceback.print_exc()
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
