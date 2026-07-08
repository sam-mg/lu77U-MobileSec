"""FastAPI application factory."""

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..utils import verbose as verbose_mod
from .events import current_scan_id
from .jobs import JobManager
from .routes import dynamic, scans, settings, system

STATIC_DIR = Path(__file__).parent / "static"

def create_app(verbose: bool = False) -> FastAPI:
    app = FastAPI(
        title="lu77U-MobileSec",
        version="1.0.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.verbose = verbose
    app.state.jobs = JobManager(verbose=verbose)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost",
            "http://localhost:5173",    # Vite dev server
            "http://localhost:8000",    # default FastAPI dev port
            "http://127.0.0.1",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    async def _on_startup():
        app.state.jobs.bind_loop(asyncio.get_running_loop())

        def _sink(message: str) -> None:
            scan_id = current_scan_id.get()
            if scan_id:
                app.state.jobs.emit_log(scan_id, message)

        app.state._log_sink = _sink
        verbose_mod.register_sink(_sink)

    @app.on_event("shutdown")
    async def _on_shutdown():
        app.state.jobs.cancel_all_active()
        sink = getattr(app.state, "_log_sink", None)
        if sink is not None:
            verbose_mod.unregister_sink(sink)

    app.include_router(system.router)
    app.include_router(scans.router)
    app.include_router(dynamic.router)
    app.include_router(settings.router)

    _mount_spa(app)
    return app

def _mount_spa(app: FastAPI) -> None:
    """Serve the built SPA; fall back to index.html for client-side routes."""
    index = STATIC_DIR / "index.html"
    assets = STATIC_DIR / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if not index.exists():
            return FileResponse(STATIC_DIR / "_missing.html") if (STATIC_DIR / "_missing.html").exists() else _no_build_response()
        candidate = (STATIC_DIR / full_path).resolve()
        if full_path and candidate.is_file() and str(candidate).startswith(str(STATIC_DIR.resolve())):
            return FileResponse(candidate)
        return FileResponse(index, headers={"Cache-Control": "no-store"})

def _no_build_response():
    from fastapi.responses import HTMLResponse

    return HTMLResponse(
        "<html><body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;"
        "padding:3rem'><h1>lu77U-MobileSec</h1><p>The web UI has not been built yet."
        "</p><p>Run <code>scripts/build_frontend.sh</code> (or "
        "<code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code>) to build it. "
        "The API is live at <code>/api</code>.</p></body></html>",
        status_code=200,
    )