"""Scan endpoints: create (upload or local path), list, detail, stop, delete,
report download, and the live progress/log WebSocket."""

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import (APIRouter, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, Response
from starlette.background import BackgroundTask

from ...tools_checker.analysis_checker import get_analysis_status

router = APIRouter(prefix="/api", tags=["scans"])

_REPORT_MEDIA = {
    "json": "application/json",
    "html": "text/html",
    "pdf": "application/pdf",
}

def _jobs(request: Request):
    return request.app.state.jobs

@router.post("/scans")
async def create_scan(
    request: Request,
    file: Optional[UploadFile] = File(default=None),
    path: Optional[str] = Form(default=None),
):
    """Start a scan from an uploaded APK (multipart ``file``) or a local ``path``."""
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
        src = Path(path).expanduser().resolve()
        home = Path.home().resolve()
        if not str(src).startswith(str(home)):
            raise HTTPException(400, "Path must be within your home directory")
        if not src.exists() or not src.is_file():
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
    return {"scans": _jobs(request).list_scans()}

@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str):
    jobs = _jobs(request)
    meta = jobs.get_meta(scan_id)
    if meta is None:
        raise HTTPException(404, "Scan not found")
    return {"meta": meta, "result": jobs.get_result(scan_id)}

@router.post("/scans/{scan_id}/stop")
async def stop_scan(request: Request, scan_id: str):
    """Signal a running/queued/waiting scan to stop without deleting it."""
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    if not jobs.cancel_scan(scan_id):
        raise HTTPException(400, "Scan is not running")
    return {"stopping": scan_id}

@router.delete("/scans/{scan_id}")
async def delete_scan(request: Request, scan_id: str):
    """Delete a scan. If it's currently running, stop it first (bounded wait)."""
    jobs = _jobs(request)
    if jobs.get_meta(scan_id) is None:
        raise HTTPException(404, "Scan not found")
    deleted = await asyncio.to_thread(jobs.stop_and_delete, scan_id)
    if not deleted:
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}

@router.get("/scans/{scan_id}/report/{fmt}")
async def download_report(request: Request, scan_id: str, fmt: str):
    """Generate the report on demand from the stored result and stream it as a
    download. Nothing is persisted server-side — JSON is the stored result as-is;
    HTML and PDF are rendered fresh from it each time."""
    if fmt not in _REPORT_MEDIA:
        raise HTTPException(404, "Unknown report format")
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

    # PDF: render HTML → PDF in a temp file, stream, delete.
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
    """Stream status + progress + log events for a scan (with backlog replay)."""
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