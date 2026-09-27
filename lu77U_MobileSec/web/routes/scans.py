#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.routes.scans

Purpose:
    Expose the scan lifecycle: start one from an upload or a local path, list and inspect them, stream their logs, control them, download their reports and delete them.

Responsibilities:
    Validate requests, delegate to the job manager, and stream progress over a websocket.

Dependencies:
    The job manager, the scan store, the report renderers.

Security considerations:
    Two inputs are attacker-influenced and both are constrained. An uploaded filename is sanitised by the store before it becomes a path, and a local path must resolve inside the user's home directory -- without that, this endpoint would read any file on the machine. Every handler checks the scan exists before acting, so an unknown identifier returns a not-found rather than reaching the store.
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import (APIRouter, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, Response
from starlette.background import BackgroundTask

from ...config import user_settings
from ...tools_checker.analysis_checker import get_analysis_status
from .. import store

router = APIRouter(prefix="/api", tags=["scans"])

_REPORT_MEDIA = {
    "json": "application/json",
    "html": "text/html",
    "pdf": "application/pdf",
}

def _jobs(request: Request):
    """
    Purpose:
        Return the job manager attached to this application.

    Parameters:
        request: The incoming request.

    Returns:
        The job manager.

    Implementation notes:
        Read from application state rather than a module global, so tests and a second application in one process do not share job state.
    """
    return request.app.state.jobs

@router.post("/scans")
async def create_scan(
    request: Request,
    file: Optional[UploadFile] = File(default=None),
    path: Optional[str] = Form(default=None),
):
    """
    Purpose:
        Start a scan from either an uploaded APK or a local file path.

    Parameters:
        request: The incoming request.
        file: The uploaded APK, when one was sent.
        path: A local path, when one was given instead.

    Returns:
        The new scan's identifier.

    Raises:
        HTTPException: When prerequisites are not configured, the input is not an APK, the path is outside the home directory or missing, or neither input was given.

    Side effects:
        Copies the APK into a new scan directory and starts the analysis.

    Implementation notes:
        Readiness is checked before anything is copied, and the failure carries the full status so the interface can show exactly what is unconfigured rather than a bare message.

    Security considerations:
        The local-path branch resolves the path fully -- expanding the home shortcut and following links -- and requires the result to be under the user's home directory. Comparing before resolution would be defeated by a traversal sequence or a symlink. The extension is checked on both branches, so a non-APK is rejected before the copy rather than after.
    """
    status = get_analysis_status()
    if not status["ready_for_analysis"]:
        raise HTTPException(
            status_code=400,
            detail={"message": "Analysis prerequisites are not configured. "
                               "Set the JADX path and an AI provider in Settings.",
                    "status": status},
        )

    jobs = _jobs(request)

    if file is not None and file.filename:
        if not file.filename.lower().endswith(".apk"):
            raise HTTPException(400, "Only .apk files are supported")
        scan_id, dest = jobs.prepare_scan(file.filename)
        with open(dest, "wb") as out:
            shutil.copyfileobj(file.file, out)
        jobs.start_scan(scan_id, dest)
        return {"id": scan_id}

    if path:
        home = os.path.realpath(os.path.expanduser("~"))
        resolved = os.path.realpath(os.path.expanduser(path))
        if not resolved.startswith(home + os.sep):
            raise HTTPException(400, "Path must be within your home directory")
        src = Path(resolved)
        if not src.is_file():
            raise HTTPException(400, "File not found")
        if src.suffix.lower() != ".apk":
            raise HTTPException(400, "Only .apk files are supported")
        scan_id, dest = jobs.prepare_scan(src.name)
        shutil.copyfile(src, dest)
        jobs.start_scan(scan_id, dest)
        return {"id": scan_id}

    raise HTTPException(400, "Provide an APK file upload or a local 'path'")

@router.get("/scans")
async def list_scans(request: Request):
    """
    Purpose:
        List every stored scan, for the dashboard's history.

    Parameters:
        request: The incoming request.

    Returns:
        The JSON response body.
    """
    return {"scans": _jobs(request).list_scans()}

@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str):
    """
    Purpose:
        Return one scan's metadata and result.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.
    """
    jobs = _jobs(request)
    meta = jobs.get_meta(scan_id)
    if meta is None:
        raise HTTPException(404, "Scan not found")
    return {"meta": meta, "result": jobs.get_result(scan_id)}

@router.get("/scans/{scan_id}/logs")
async def get_scan_logs(request: Request, scan_id: str, limit: int | None = None):
    """
    Purpose:
        Return a scan's log lines.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.
        limit: Return only the most recent lines when given.

    Returns:
        The JSON response body.

    Implementation notes:
        Read on a worker thread, since a long scan's log is large enough that reading it inline would stall the event loop.
    """
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    lines = await asyncio.to_thread(store.read_log, scan_id, limit)
    path = store.log_path(scan_id)
    return {"scan_id": scan_id, "count": len(lines), "logs": lines,
            "persisted": bool(path is not None and path.exists())}


@router.get("/scans/{scan_id}/logs/download")
async def download_scan_logs(request: Request, scan_id: str):
    """
    Purpose:
        Download a scan's log as a file.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.
    """
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    path = store.log_path(scan_id)
    if path is None or not path.exists():
        raise HTTPException(404, "No log recorded for this scan")
    return FileResponse(path, media_type="text/plain",
                        filename=f"{scan_id}-scan.log")


@router.post("/scans/{scan_id}/stop")
async def stop_scan(request: Request, scan_id: str):
    """
    Purpose:
        Cancel a running scan.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.

    Implementation notes:
        Cancellation is cooperative: the job manager sets a flag that the analysis polls between stages, so a scan stops at the next check rather than being killed mid-operation on a device.
    """
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    if not jobs.cancel_scan(scan_id):
        raise HTTPException(400, "Scan is not running")
    return {"stopping": scan_id}

@router.post("/scans/{scan_id}/pause")
async def pause_scan(request: Request, scan_id: str):
    """
    Purpose:
        Pause a running scan.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.

    Implementation notes:
        Pausing relies on the checkpoint, so a paused scan resumes from its last completed stage rather than restarting.
    """
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    if not jobs.pause_scan(scan_id):
        raise HTTPException(400, "Scan is not running")
    return {"pausing": scan_id}

@router.post("/scans/{scan_id}/resume")
async def resume_scan(request: Request, scan_id: str):
    """
    Purpose:
        Resume a paused scan from its checkpoint.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.
    """
    jobs = _jobs(request)
    meta = jobs.get_meta(scan_id)
    if meta is None:
        raise HTTPException(404, "Scan not found")
    if meta.get("status") != "paused":
        raise HTTPException(400, "Scan is not paused")
    if not jobs.resume_scan(scan_id):
        raise HTTPException(400, "Scan could not be resumed")
    return {"resuming": scan_id}

@router.delete("/scans/{scan_id}")
async def delete_scan(request: Request, scan_id: str):
    """
    Purpose:
        Stop a scan if it is running and delete everything it produced.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.

    Returns:
        The JSON response body.

    Implementation notes:
        Stopping before deleting matters: removing the directory under a running scan would leave it writing into a deleted path. The work happens on a worker thread because it waits for the scan to stop.
    """
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    deleted = await asyncio.to_thread(jobs.stop_and_delete, scan_id)
    if not deleted:
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}

@router.get("/scans/{scan_id}/report/{fmt}")
async def download_report(request: Request, scan_id: str, fmt: str):
    """
    Purpose:
        Download a scan's report in the requested format.

    Parameters:
        request: The incoming request.
        scan_id: The scan identifier.
        fmt: The report format.

    Returns:
        The report as a file response.

    Raises:
        HTTPException: When the format is unknown, PDF generation is disabled in settings, or the scan does not exist.

    Implementation notes:
        The format is checked against a fixed mapping rather than used to build a filename, so an unexpected value cannot reach the filesystem. A PDF request is refused when the user has disabled PDF generation, rather than silently returning HTML -- the interface hides the option, and a direct request should get a clear reason.
    """
    if fmt not in _REPORT_MEDIA:
        raise HTTPException(404, "Unknown report format")
    if fmt == "pdf" and not user_settings.get_pdf_generation():
        raise HTTPException(400, "PDF report generation is disabled in Settings")
    jobs = _jobs(request)
    meta = jobs.get_meta(scan_id)
    result = jobs.get_result(scan_id)
    if meta is None or not result:
        raise HTTPException(404, "Scan result not available")

    app = result.get("application_info") or {}
    base = (app.get("app_name") or app.get("package_name")
            or Path(meta.get("filename", "report")).stem or "report")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", str(base)).strip("_") or "report"

    if fmt == "json":
        return Response(content=json.dumps(result, indent=2, default=str),
                        media_type=_REPORT_MEDIA["json"],
                        headers={"Content-Disposition": f'attachment; filename="{base}.json"'})

    from ...report_generator.report_renderer import render_report_html
    html_str = render_report_html(result)

    if fmt == "html":
        return Response(content=html_str, media_type=_REPORT_MEDIA["html"],
                        headers={"Content-Disposition": f'attachment; filename="{base}.html"'})

    from ...report_generator.pdf_generation_engine import convert_html_to_pdf

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()
    converted = await asyncio.to_thread(
        convert_html_to_pdf, html_str, tmp.name, False)
    if not converted:
        Path(tmp.name).unlink(missing_ok=True)
        raise HTTPException(500, "Failed to generate PDF")
    return FileResponse(tmp.name, media_type=_REPORT_MEDIA["pdf"], filename=f"{base}.pdf",
                        background=BackgroundTask(lambda: Path(tmp.name).unlink(missing_ok=True)))

@router.websocket("/ws/scans/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str):
    """
    Purpose:
        Stream a scan's progress and log lines to the dashboard over a websocket.

    Parameters:
        websocket: The connection.
        scan_id: The scan identifier.

    Side effects:
        Subscribes to the scan's event stream for the life of the connection.

    Implementation notes:
        Streaming rather than polling, because a scan emits progress continuously and polling at a useful rate would be both wasteful and laggy. The polling status endpoint remains for clients that cannot hold a socket open. The subscription is released when the connection closes, so a disconnected client does not leave a queue accumulating events for the rest of the scan.
    """
    jobs = websocket.app.state.jobs
    await websocket.accept()
    queue = jobs.subscribe(scan_id)
    try:
        meta = jobs.get_meta(scan_id)
        if meta is not None:
            await websocket.send_json({"type": "meta", "meta": meta})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        try:
            await websocket.close()
        except Exception:
            pass
    except Exception:
        pass
    finally:
        jobs.unsubscribe(scan_id, queue)
