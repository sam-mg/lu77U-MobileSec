#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.app

Purpose:
    Build the dashboard application: its routes, its job manager, the log bridge that routes analysis output to the right scan, and the single-page app it serves.

Responsibilities:
    Construct the application, manage startup and shutdown, and serve the built frontend safely.

Dependencies:
    FastAPI, the job manager, the verbose logging module.

Security considerations:
    Static file serving is the security-sensitive part. Requested paths are resolved segment by segment against real directory entries rather than joined, and symlinks are refused, so a crafted path cannot read outside the build directory.
"""

import asyncio
import contextlib
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .._metadata import NAME, VERSION
from ..config.branding import FAVICON_LINK_TAG
from ..utils import verbose as verbose_mod
from .events import current_scan_id
from .jobs import JobManager
from .routes import dynamic, scans, settings, system

STATIC_DIR = Path(__file__).parent / "static"

_QUOTA_RESUME_CHECK_INTERVAL_S = 300

@asynccontextmanager
async def _lifespan(app: FastAPI):
    """
    Purpose:
        Run the application's startup and shutdown: attach the log bridge, start the quota-resume task, optionally open the browser, and tear all of it down.

    Parameters:
        app: The application.

    Returns:
        An async context manager. Startup runs on entry, shutdown on exit.

    Side effects:
        Registers a log sink, starts a background task, may open a browser, and on shutdown cancels running scans.

    Implementation notes:
        Startup reconciliation of scans interrupted by a previous shutdown is attempted but never fatal: a failure is logged and the server still starts, because a dashboard that refuses to come up is worse than one showing a stale scan as running. The browser is opened on a short delay rather than immediately, so the server is accepting connections by the time the page loads and the user does not meet a connection error. Shutdown cancels the background task and waits for it through asyncio.gather, then cancels active scans and unregisters the log sink. Leaving the sink registered would keep a reference to a dead application and route later log lines into it.
    """
    app.state.jobs.bind_loop(asyncio.get_running_loop())

    try:
        app.state.jobs.reconcile_orphans()
        app.state.jobs.auto_resume_interrupted()
    except Exception as exc:
        verbose_mod.verbose_print(f"Startup reconciliation of interrupted scans failed: {exc}", app.state.jobs.verbose)

    async def _quota_resume_loop():
        """
        Purpose:
            Periodically resume scans that were paused because a provider's quota was exhausted.

        Side effects:
            Wakes on an interval and asks the job manager to resume eligible scans.

        Implementation notes:
            A quota pause is expected to clear on its own when the provider's window rolls over, so a scan that hit one is paused rather than failed and this loop restarts it. Without that, a long scan would be lost to a limit that resolved itself minutes later. Every Exception is suppressed, because a failure in one resume attempt must not end the loop and leave every later pause stranded. Cancellation still stops the task at shutdown: asyncio.CancelledError derives from BaseException, not Exception, so it passes straight through the suppress.
        """
        while True:
            with contextlib.suppress(Exception):
                await asyncio.sleep(_QUOTA_RESUME_CHECK_INTERVAL_S)
                app.state.jobs.resume_expired_quota_pauses()

    quota_resume_task = asyncio.create_task(_quota_resume_loop())

    def _sink(message: str) -> None:
        """
        Purpose:
            Route a verbose log line to the scan that produced it.

        Parameters:
            message: The already-redacted log line.

        Side effects:
            Emits the line to that scan's log stream.

        Implementation notes:
            The scan is identified from the context variable rather than passed in, which is what lets analysis code deep in the call stack log without knowing about the web layer. A line emitted outside any scan is dropped rather than broadcast, since it belongs to no job's stream.

        Security considerations:
            The message has already passed through the verbose module's redaction before reaching any sink.
        """
        scan_id = current_scan_id.get()
        if scan_id:
            app.state.jobs.emit_log(scan_id, message)

    app.state._log_sink = _sink
    verbose_mod.register_sink(_sink)

    browser_url = getattr(app.state, "browser_url", None)
    if browser_url:
        import threading
        import webbrowser
        threading.Timer(0.9, lambda: webbrowser.open(browser_url)).start()

    yield

    quota_resume_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.gather(quota_resume_task)
    app.state.jobs.cancel_all_active()
    sink = getattr(app.state, "_log_sink", None)
    if sink is not None:
        verbose_mod.unregister_sink(sink)

def create_app(verbose: bool = False) -> FastAPI:
    """
    Purpose:
        Build the dashboard application.

    Parameters:
        verbose: Enables verbose analysis output.

    Returns:
        The configured application.

    Implementation notes:
        The job manager is attached to application state rather than being a module global, so tests can build independent applications and a second instance in one process does not share job state.
    """
    app = FastAPI(
        title=NAME,
        version=VERSION,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=_lifespan,
    )
    app.state.verbose = verbose
    app.state.jobs = JobManager(verbose=verbose)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost",
            "http://localhost:5173",
            "http://localhost:8000",
            "http://127.0.0.1",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(system.router)
    app.include_router(scans.router)
    app.include_router(dynamic.router)
    app.include_router(settings.router)

    _mount_spa(app)
    return app

def _mount_spa(app: FastAPI) -> None:
    """
    Purpose:
        Serve the built single-page frontend, falling back to a message when it has not been built.

    Parameters:
        app: The application.

    Implementation notes:
        The catch-all route is registered last so it cannot shadow the API routes, and unmatched paths fall through to the app's own router rather than returning a not-found -- which is what makes client-side routing work on a page reload. A missing build returns instructions rather than an error, since running from a source checkout without building the frontend is a normal state.
    """
    index = STATIC_DIR / "index.html"
    assets = STATIC_DIR / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """
        Purpose:
            Serve the single-page app, or a specific static file when the path names one.

        Parameters:
            full_path: The requested path.

        Returns:
            The file response, or the app shell.

        Implementation notes:
            An unmatched path returns the app shell rather than a not-found, so client-side routes survive a page reload.

        Security considerations:
            Path resolution goes through the segment-by-segment resolver, which refuses traversal and symlinks.
        """
        if not index.exists():
            missing = STATIC_DIR / "_missing.html"
            return FileResponse(missing) if missing.exists() else _no_build_response()
        target = _static_file(full_path)
        if target is not None:
            return FileResponse(target)
        return FileResponse(index, headers={"Cache-Control": "no-store"})

def _static_file(request_path: str) -> Optional[Path]:
    """
    Purpose:
        Resolve a requested path to a file inside the build directory, or refuse it.

    Parameters:
        request_path: The requested path.

    Returns:
        The file path, or None when it does not resolve to a permitted file.

    Security considerations:
        This is the path-traversal control for static serving. Each segment is matched against the real entries of the current directory rather than being joined onto a base path, so a traversal segment simply finds no matching entry and the resolution fails. Symlinked entries are refused, so a link inside the build directory cannot point outside it. Both checks are needed: resolving-then-comparing would be vulnerable to a symlink, and refusing symlinks alone would not stop traversal.
    """
    segments = [seg for seg in request_path.split("/") if seg]
    if not segments:
        return None
    current = STATIC_DIR
    for segment in segments:
        try:
            entry = {child.name: child for child in current.iterdir()}.get(segment)
        except OSError:
            return None
        if entry is None or entry.is_symlink():
            return None
        current = entry
    return current if current.is_file() else None

def _no_build_response():
    """
    Purpose:
        Return a page explaining that the frontend has not been built, with the commands to build it.

    Returns:
        The response.

    Implementation notes:
        Returns a success status rather than an error, because the server is working correctly and the API is live -- only the interface is absent. An error status would suggest a fault to fix rather than a build step to run. The favicon is inlined as a data URI because this page is served exactly when the static build -- and therefore any icon file to link to -- is missing.
    """
    from fastapi.responses import HTMLResponse

    return HTMLResponse(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{NAME}</title>{FAVICON_LINK_TAG}</head>"
        "<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;"
        f"padding:3rem'><h1>{NAME}</h1><p>The web UI has not been built yet."
        "</p><p>Run <code>scripts/build_frontend.sh</code> (or "
        "<code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code>) to build it. "
        "The API is live at <code>/api</code>.</p></body></html>",
        status_code=200,
    )
