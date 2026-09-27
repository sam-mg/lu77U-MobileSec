#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.core.app

Purpose:
    The application object embedders use. It is the one public entry point the package facade exports, so that using this tool as a library does not mean importing from its CLI or web internals.

Responsibilities:
    Hold the run-wide verbosity setting and start the dashboard.

Dependencies:
    ..web.server, imported lazily.

Implementation notes:
    Deliberately thin. Orchestration lives in the web service layer, and duplicating any of it here would give the library and the dashboard two code paths that could diverge.
"""

class MobileSecApp:
    """
    Purpose:
        Entry point for running lu77U-MobileSec from Python rather than from the command line.

    Attributes:
        verbose: Whether analysis activity is traced.

    Invariants:
        Holds no scan state. One instance can start the dashboard once; concurrent scans are managed by the web layer's job registry, not here.

    Thread-safety:
        The object itself is trivially safe; run blocks its calling thread for the lifetime of the server.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Create the application object.

        Parameters:
            verbose: Enables tracing for everything this instance starts.
        """
        self.verbose = verbose

    def run(self, port=None, open_browser: bool = True):
        """
        Purpose:
            Start the local dashboard and block until it stops.

        Parameters:
            port: Port to bind; None lets the server choose.
            open_browser: Whether to open the user's browser at the dashboard.

        Side effects:
            Binds a TCP port and may launch a browser. Blocks the calling thread.

        Implementation notes:
            The server import is deferred into the method so that importing lu77U_MobileSec -- which the package facade does eagerly -- does not pull in the HTTP stack for a caller that only wants the version metadata.

        Security considerations:
            The bind address and port policy belong to the server; this method only forwards the caller's choices and never widens them.
        """
        from ..web.server import serve
        serve(verbose=self.verbose, port=port, open_browser=open_browser)
