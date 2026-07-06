"""In-process scan job manager."""

import asyncio
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import store
from .events import current_scan_id
from .services.analysis_service import AnalysisService
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import verbose_print

_BACKLOG_LIMIT = 3000
_ACTIVE_STATUSES = ("queued", "running")
_STOP_WAIT_TIMEOUT = 10.0  # seconds delete() waits for a cancelled worker to unwind

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class _DaemonJobRunner:
    """Bounded-concurrency job runner using daemon worker threads.

    ``concurrent.futures.ThreadPoolExecutor`` registers each worker thread
    with a module-level ``atexit`` hook (``concurrent.futures.thread._python_exit``)
    that blocks interpreter shutdown until every worker finishes its *current*
    task — including one stuck in a long blocking adb/Frida/AI call mid-scan.
    That's what left Ctrl+C hanging (or needing a second, uglier interrupt)
    while a scan was in flight. Daemon threads are abandoned immediately on
    interpreter exit instead, so the process always exits promptly regardless
    of what a background scan is doing; ``JobManager`` still asks active scans
    to cancel on shutdown (see ``cancel_all_active``) so they get a chance to
    clean up first.
    """

    def __init__(self, max_workers: int):
        self._semaphore = threading.Semaphore(max_workers)

    def submit(self, fn, *args) -> None:
        def _run():
            with self._semaphore:
                fn(*args)
        threading.Thread(target=_run, daemon=True).start()

class JobManager:
    def __init__(self, verbose: bool = False, max_workers: int = 2):
        self.verbose = verbose
        self._executor = _DaemonJobRunner(max_workers=max_workers)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._backlog: Dict[str, List[dict]] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Record the server's event loop so worker threads can push events."""
        self._loop = loop

    def _publish(self, scan_id: Optional[str], event: Dict[str, Any]) -> None:
        if not scan_id:
            return
        event = {**event, "scan_id": scan_id, "ts": _now_iso()}
        with self._lock:
            backlog = self._backlog.setdefault(scan_id, [])
            backlog.append(event)
            if len(backlog) > _BACKLOG_LIMIT:
                del backlog[: len(backlog) - _BACKLOG_LIMIT]
            subs = list(self._subscribers.get(scan_id, ()))
        if self._loop is not None:
            for queue in subs:
                try:
                    self._loop.call_soon_threadsafe(queue.put_nowait, event)
                except Exception:
                    pass

    def emit_log(self, scan_id: Optional[str], message: str) -> None:
        self._publish(scan_id, {"type": "log", "message": message})

    def emit_progress(self, scan_id: str, phase: str, percent: int,
                      message: str = "") -> None:
        meta = store.load_meta(scan_id)
        if meta is not None:
            meta["phase"] = phase
            meta["progress"] = percent
            store.save_meta(meta)
        self._publish(scan_id, {"type": "progress", "phase": phase,
                                "percent": percent, "message": message})

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subscribers.setdefault(scan_id, set()).add(queue)
            backlog = list(self._backlog.get(scan_id, ()))
        for event in backlog:
            queue.put_nowait(event)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        with self._lock:
            subs = self._subscribers.get(scan_id)
            if subs:
                subs.discard(queue)

    def prepare_scan(self, filename: str) -> tuple[str, Path]:
        """Create a scan record + folder; return (scan_id, apk destination).

        The scan's dedicated (human-named) folder is created under the configured
        output directory and its path recorded in ``meta["dir"]``; the APK is
        copied into it by the caller.
        """
        scan_id = uuid.uuid4().hex[:12]
        safe_name = store.sanitize_filename(filename)
        folder = store.create_scan_folder(scan_id, safe_name)
        dest = folder / safe_name
        store.save_meta({
            "id": scan_id,
            "dir": str(folder),
            "kind": "static",
            "filename": safe_name,
            "status": "queued",
            "created_at": _now_iso(),
            "started_at": None,
            "finished_at": None,
            "duration": 0,
            "progress": 0,
            "phase": "queued",
            "error": None,
            "summary": {},
            "reports": {},
        })
        return scan_id, dest

    def start_scan(self, scan_id: str, apk_path: Path) -> None:
        self._executor.submit(self._run, scan_id, str(apk_path))

    def _get_cancel_event(self, scan_id: str) -> threading.Event:
        with self._lock:
            event = self._cancel_events.get(scan_id)
            if event is None:
                event = threading.Event()
                self._cancel_events[scan_id] = event
            return event

    def cancel_scan(self, scan_id: str) -> bool:
        """Signal a queued/running scan to stop. Returns True if signaled."""
        meta = store.load_meta(scan_id)
        if not meta or meta.get("status") not in _ACTIVE_STATUSES:
            return False
        self._get_cancel_event(scan_id).set()
        return True

    def cancel_all_active(self) -> None:
        """Signal every active scan to stop (best-effort, does not block).

        Called on server shutdown. Worker threads are daemons (see
        ``_DaemonJobRunner``), so the process exits promptly regardless — this
        just gives an in-flight scan a chance to notice at its next
        cancellation checkpoint and clean up (stop frida-server, close
        mitmproxy) instead of being abandoned mid-operation.
        """
        for meta in store.list_meta():
            if meta.get("status") in _ACTIVE_STATUSES:
                self.cancel_scan(meta["id"])

    def stop_and_delete(self, scan_id: str, timeout: float = _STOP_WAIT_TIMEOUT) -> bool:
        """Cancel a running scan (if any), wait briefly for it to unwind, then delete."""
        meta = store.load_meta(scan_id)
        if meta and meta.get("status") in _ACTIVE_STATUSES:
            self.cancel_scan(scan_id)
            deadline = time.time() + timeout
            while time.time() < deadline:
                meta = store.load_meta(scan_id)
                if not meta or meta.get("status") not in _ACTIVE_STATUSES:
                    break
                time.sleep(0.2)
        return store.delete_scan(scan_id)

    def _finish_meta(self, scan_id: str, updates: dict) -> bool:
        """Merge ``updates`` into the scan's persisted meta, unless the scan
        directory was deleted out from under this worker.

        ``stop_and_delete()`` only waits up to ``_STOP_WAIT_TIMEOUT`` before
        deleting the scan directory outright; several steps in both pipelines
        (JADX decompilation, Frida download/push, an AI request with up to a
        120s provider timeout) routinely run longer than that. If a worker
        finishes — successfully, cancelled, or failed — after its scan was
        already deleted, writing meta.json here would resurrect a scan the
        user already removed, so this is a no-op in that case.
        """
        existing = store.load_meta(scan_id)
        if existing is None:
            verbose_print(
                f"Scan {scan_id} was deleted while running; discarding its result",
                self.verbose)
            store.delete_scan(scan_id)
            return False
        existing.update(**updates)
        store.save_meta(existing)
        return True

    def _handle_cancelled(self, scan_id: str, started: float) -> None:
        self.emit_log(scan_id, "Scan stopped by user")
        saved = self._finish_meta(scan_id, dict(
            status="cancelled", finished_at=_now_iso(), error=None,
            phase="cancelled", duration=round(time.time() - started, 2)))
        if saved:
            self._publish(scan_id, {"type": "status", "status": "cancelled"})

    def _run(self, scan_id: str, apk_path: str) -> None:
        cancel_event = self._get_cancel_event(scan_id)
        if cancel_event.is_set() or store.load_meta(scan_id) is None:
            self._cancel_events.pop(scan_id, None)
            return
        token = current_scan_id.set(scan_id)
        started = time.time()
        self._finish_meta(scan_id, dict(
            status="running", started_at=_now_iso(), phase="starting", progress=3))
        self._publish(scan_id, {"type": "status", "status": "running"})

        def progress_cb(phase, percent, message=""):
            if cancel_event.is_set():
                raise ScanCancelled()
            self.emit_progress(scan_id, phase, percent, message)

        try:
            service = AnalysisService(verbose=self.verbose, progress=progress_cb,
                                      is_cancelled=cancel_event.is_set)
            result = service.run(apk_path)
            if store.load_meta(scan_id) is not None:
                store.save_result(scan_id, result)

            summary = result.get("summary", {}) or {}
            app_info = result.get("application_info", {}) or {}
            framework = result.get("framework_detection", {}) or {}
            saved = self._finish_meta(scan_id, dict(
                status="completed",
                finished_at=_now_iso(),
                progress=100,
                phase="done",
                duration=round(time.time() - started, 2),
                summary={
                    "primary_framework": framework.get("primary_framework"),
                    "total_vulnerabilities": summary.get("total_vulnerabilities", 0),
                    "critical": summary.get("critical_count", 0),
                    "high": summary.get("high_count", 0),
                    "medium": summary.get("medium_count", 0),
                    "low": summary.get("low_count", 0),
                    "security_score": summary.get("security_score"),
                    "package_name": app_info.get("package_name"),
                    "app_name": app_info.get("app_name"),
                    "analysis_supported": result.get("analysis", {}).get("supported", True),
                },
                reports=result.get("reports", {}),
            ))
            if saved:
                self.emit_progress(scan_id, "done", 100, "Scan complete")
                self._publish(scan_id, {"type": "status", "status": "completed"})
        except ScanCancelled:
            self._handle_cancelled(scan_id, started)
        except Exception as exc:
            err_id = uuid.uuid4().hex[:8]
            import logging as _logging
            _logging.getLogger(__name__).error(
                "Scan %s failed [err_id=%s]: %s\n%s",
                scan_id, err_id, exc, traceback.format_exc())
            public_msg = f"Scan failed (ref: {err_id})"
            self.emit_log(scan_id, f"ERROR: {public_msg}")
            saved = self._finish_meta(scan_id, dict(
                status="failed", finished_at=_now_iso(), error=public_msg,
                phase="failed", duration=round(time.time() - started, 2)))
            if saved:
                self._publish(scan_id, {"type": "status", "status": "failed",
                                        "error": public_msg})
        finally:
            self._cancel_events.pop(scan_id, None)
            current_scan_id.reset(token)

    def get_meta(self, scan_id: str) -> Optional[dict]:
        return store.load_meta(scan_id)

    def get_result(self, scan_id: str) -> Optional[dict]:
        return store.load_result(scan_id)

    def list_scans(self) -> List[dict]:
        return store.list_meta()

    def delete(self, scan_id: str) -> bool:
        return store.delete_scan(scan_id)