#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.server

Purpose:
    Start the local dashboard: choose a port, build the application, quieten the polling noise in the access log, and run the server.

Responsibilities:
    Port selection, access-log filtering and server startup.

Dependencies:
    uvicorn, imported at call time.

Security considerations:
    The server binds to the loopback address only. This is a local analysis tool that exposes scan results and settings without authentication, so binding to any other interface would publish an unauthenticated control surface on the network.
"""

import logging
import socket
from typing import Optional

from .._metadata import NAME

DEFAULT_PORT = 8000

class _PollingAccessLogFilter(logging.Filter):
    """
    Purpose:
        Suppress access-log entries for the endpoint the dashboard polls continuously.

    Attributes:
        NOISY_PATHS: Paths whose successful reads are not logged.

    Implementation notes:
        The dashboard polls for status every second or so, which fills the log and buries the requests worth seeing. Only reads of those specific paths are dropped; writes and other paths are logged normally.

    Thread-safety:
        Stateless; safe to install on a shared logger.
    """
    NOISY_PATHS = ("/api/status",)

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Purpose:
            Decide whether one access-log record should be emitted.

        Parameters:
            record: The log record.

        Returns:
            False for a polling read, True otherwise.

        Implementation notes:
            The structured arguments are inspected first, and the formatted message only when they are not in the expected shape. Uvicorn's record layout has changed across versions, and the fallback keeps the filter working rather than silently passing everything through. Query strings are stripped before comparison, so a polling request with parameters is still recognised.
        """
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3:
            method, path = str(args[1]), str(args[2]).split("?", 1)[0]
            return not (method == "GET" and path in self.NOISY_PATHS)
        msg = record.getMessage()
        return not any(f'"GET {p} HTTP' in msg or f'"GET {p}?' in msg
                       for p in self.NOISY_PATHS)

def _find_free_port(preferred: int = DEFAULT_PORT) -> int:
    """
    Purpose:
        Find a port the dashboard can bind to.

    Parameters:
        preferred: The port to try first.

    Returns:
        A usable port number.

    Implementation notes:
        The preferred port is tried first so the dashboard keeps a stable URL between runs, then two alternatives, then an ephemeral port as a guarantee. Without the fallbacks, a second instance or an unrelated service on the port would stop the tool starting. Each probe binds to loopback specifically, matching where the server will actually bind -- a port free on one interface is not necessarily free on another.

    Known limitations:
        There is a window between the probe closing its socket and the server binding, in which another process could take the port.
    """
    for candidate in (preferred, 8765, 8123, 0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", candidate))
            return sock.getsockname()[1]
        except OSError:
            continue
        finally:
            sock.close()
    return preferred

def serve(verbose: bool = False, port: Optional[int] = None,
          open_browser: bool = True) -> None:
    """
    Purpose:
        Start the dashboard and block until it stops.

    Parameters:
        verbose: Enables request logging and verbose analysis output.
        port: Port to bind; one is chosen when omitted.
        open_browser: Whether to open the dashboard in the browser.

    Side effects:
        Binds a port, may open a browser, and runs the server until interrupted.

    Implementation notes:
        uvicorn and the application are imported inside the function, so a caller that only wants the version metadata does not pay for the web stack. The URL is printed before the server starts, so it is visible even when the browser does not open. Logging verbosity follows the verbose flag: quiet by default, because a user running a scan wants progress rather than request logs.

    Security considerations:
        Binds to loopback only, and that address is not configurable here.
    """
    import uvicorn

    from .app import create_app

    chosen_port = port or _find_free_port(DEFAULT_PORT)
    url = f"http://127.0.0.1:{chosen_port}"
    app = create_app(verbose=verbose)

    if open_browser:
        app.state.browser_url = url

    print(f"\n  {NAME} is running at {url}")
    print("  Press Ctrl+C to stop.\n")

    logging.getLogger("uvicorn.access").addFilter(_PollingAccessLogFilter())

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=chosen_port,
        log_level="info" if verbose else "warning",
        access_log=verbose,
        timeout_graceful_shutdown=3,
    )
