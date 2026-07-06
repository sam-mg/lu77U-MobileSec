"""Local server launcher."""

import logging
import socket
import threading
import webbrowser
from typing import Optional

DEFAULT_PORT = 8000

class _PollingAccessLogFilter(logging.Filter):
    """Drop uvicorn access-log lines for the browser's periodic polling
    endpoints so they don't bury the logs that matter.

    The dashboard polls ``/api/status`` every few seconds; each poll is a 200 OK
    that carries no signal, and in verbose mode (the only mode where access logs
    are on) they flood the terminal. Everything else — scans, uploads, settings,
    non-200s — still logs normally. Extend ``NOISY_PATHS`` to silence more.
    """

    NOISY_PATHS = ("/api/status",)

    def filter(self, record: logging.LogRecord) -> bool:
        # uvicorn access record args: (client_addr, method, path, http_ver, status)
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3:
            method, path = str(args[1]), str(args[2]).split("?", 1)[0]
            return not (method == "GET" and path in self.NOISY_PATHS)
        # Fallback if uvicorn's record shape ever changes: match the request line.
        msg = record.getMessage()
        return not any(f'"GET {p} HTTP' in msg or f'"GET {p}?' in msg
                       for p in self.NOISY_PATHS)

def _find_free_port(preferred: int = DEFAULT_PORT) -> int:
    """Return ``preferred`` if free, else an OS-assigned ephemeral port."""
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
    import uvicorn

    from .app import create_app

    chosen_port = port or _find_free_port(DEFAULT_PORT)
    url = f"http://127.0.0.1:{chosen_port}"
    app = create_app(verbose=verbose)

    if open_browser:
        @app.on_event("startup")
        async def _open_browser():  # pragma: no cover - side effect only
            threading.Timer(0.9, lambda: webbrowser.open(url)).start()

    print(f"\n  lu77U-MobileSec is running at {url}")
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