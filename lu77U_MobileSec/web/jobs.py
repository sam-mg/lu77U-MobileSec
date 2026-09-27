#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.jobs

Purpose:
    Own the lifecycle of every scan the dashboard runs: queue them, run them off the request path, stream their progress, let the user stop and resume them, and recover the ones a restart interrupted.

Responsibilities:
    Run scans on worker threads, publish events to websocket subscribers, maintain scan metadata, and reconcile state after a crash or restart.

Dependencies:
    The scan store, the checkpoint layer, the analysis service.

Implementation notes:
    Scans run on threads rather than in the event loop because the analysis is blocking throughout -- subprocesses, file I/O and synchronous provider calls. Events cross back into the loop through a thread-safe handoff. Cancellation and pausing are cooperative: the analysis polls a flag between stages. Killing a scan outright would leave a device with an interception CA installed and an instrumentation server running. Scan state lives on disk rather than in memory, so a restart can see what was running and decide what to do about it.

Thread-safety:
    Shared state is guarded by one lock. Event delivery takes a snapshot of subscribers under that lock and dispatches outside it, so a slow consumer cannot block a worker.
"""

import asyncio
import os
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import checkpoint as ckpt
from . import store
from .events import current_scan_id
from .services.analysis_service import AnalysisService, quota_exhausted
from ..config import user_settings
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import plural, verbose_print

_BACKLOG_LIMIT = 3000
_ACTIVE_STATUSES = ("queued", "running")
_STOP_WAIT_TIMEOUT = 10.0

_MAX_AUTO_RESUME = 2

_MAX_QUOTA_AUTO_RESUME = 20

_QUOTA_DEFAULT_RESUME_HOURS = 5

_BOOT_ID = uuid.uuid4().hex


def _pid_alive(pid: Any) -> bool:
    """
    Purpose:
        Check whether a process is still running.

    Parameters:
        pid: The process identifier.

    Returns:
        True when the process exists.

    Implementation notes:
        Uses the null signal, which checks existence without affecting the process. Used to tell a scan abandoned by a crashed server from one another live server still owns -- reclaiming the second would have two servers writing the same scan.
    """
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, TypeError, ValueError):
        return False

def _now_iso() -> str:
    """
    Purpose:
        Produce the timestamp used throughout scan metadata and events.

    Returns:
        The current time as an ISO string in UTC.

    Implementation notes:
        UTC with an explicit offset, so stored timestamps sort correctly as strings and do not shift across a timezone change or a daylight-saving boundary.
    """
    return datetime.now(timezone.utc).isoformat()


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _norm_sev(value: Any) -> str:
    """
    Purpose:
        Normalise a severity for the dashboard's counts.

    Parameters:
        value: Severity text.

    Returns:
        One of the known severity keys.

    Implementation notes:
        Matched on a prefix, which absorbs the spelling variations between the rule engine, model output and the taxonomy without a synonym table. An unrecognised value becomes informational rather than being dropped, so no finding vanishes from the counts.
    """
    v = str(value or "").strip().lower()
    for s in _SEVERITIES:
        if v.startswith(s[:4]):
            return s
    return "info"


def _partial_result(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Build a result document from the findings a scan produced before it stopped.

    Parameters:
        findings: Findings gathered so far.

    Returns:
        A result document in the normal shape.

    Implementation notes:
        A cancelled or interrupted scan has usually found something, and discarding it would waste the work. Emitting it in the same shape as a complete result means the dashboard renders it with no special case -- the metadata is what records that it is partial.
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {s: [] for s in _SEVERITIES}
    for v in findings:
        buckets[_norm_sev(v.get("severity"))].append(v)
    by_severity = {s: len(buckets[s]) for s in _SEVERITIES}
    return {
        "metadata": {"partial": True, "generated_at": _now_iso()},
        "summary": {
            "vulnerability_scan_complete": False,
            "total_vulnerabilities": len(findings),
            "security_score": None,
        },
        "vulnerability_analysis": {
            "analyzed": True,
            "total_vulnerabilities": len(findings),
            "by_severity": by_severity,
            "vulnerabilities": buckets,
        },
        "analysis": {
            "supported": True, "success": False, "files_analyzed": 0,
            "analysis_time": 0, "framework": "",
            "decompilation_status": "Stopped before completion",
        },
        "reports": {},
    }

class _DaemonJobRunner:
    """
    Purpose:
        Runs scans on daemon threads so that a scan in progress cannot keep the process alive at shutdown.

    Attributes:
        max_workers: How many scans may run concurrently.

    Implementation notes:
        Daemon threads are deliberate. A scan can be blocked for minutes inside a subprocess, and a non-daemon worker would make the server refuse to exit until it finished. Shutdown cancels active scans first, so the abrupt end is the fallback rather than the normal path.

    Thread-safety:
        Each submitted scan runs on its own thread; shared state lives in the manager.
    """
    def __init__(self, max_workers: int):
        """
        Purpose:
            Construct the runner.

        Parameters:
            max_workers: Concurrency limit.
        """
        self._semaphore = threading.Semaphore(max_workers)

    def submit(self, fn, *args) -> None:
        """
        Purpose:
            Run a scan on a daemon thread.

        Parameters:
            fn: The callable to run.
            args: Its arguments.

        Side effects:
            Starts a thread.
        """
        def _run():
            """
            Purpose:
                Thread body that invokes the submitted callable.

            Implementation notes:
                Wrapped so that an exception escaping the scan is contained in the worker rather than surfacing as an unhandled thread exception; the scan's own handler records the failure in its metadata.
            """
            with self._semaphore:
                fn(*args)
        threading.Thread(target=_run, daemon=True).start()

class JobManager:
    """
    Purpose:
        Runs and tracks every scan for one dashboard instance.

    Attributes:
        verbose: Whether job activity is traced and logs are persisted.

    Invariants:
        Scan metadata on disk is the record of truth; in-memory state is a cache of the running scans. A scan is only ever reclaimed by one server, decided by the recorded owner and boot identity.

    Thread-safety:
        Shared maps are guarded by a lock. Events are handed to the event loop through a thread-safe call, since they originate on worker threads.
    """
    def __init__(self, verbose: bool = False, max_workers: int = 2):
        """
        Purpose:
            Construct the manager and its worker pool.

        Parameters:
            verbose: Enables tracing and log persistence.
            max_workers: How many scans may run at once.

        Implementation notes:
            The concurrency default is low because a scan is heavy throughout -- decompilation, several model calls, sometimes a device -- and running many at once contends for all three.
        """
        self.verbose = verbose
        self._executor = _DaemonJobRunner(max_workers=max_workers)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._backlog: Dict[str, List[dict]] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._pause_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Purpose:
            Attach the event loop that worker threads publish events through.

        Parameters:
            loop: The running event loop.

        Implementation notes:
            Bound at startup rather than captured at construction, because the manager is built before the loop is running. Until it is bound, events are still recorded in the backlog and are delivered when a subscriber connects.
        """
        self._loop = loop

    def _publish(self, scan_id: Optional[str], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Purpose:
            Record an event and deliver it to that scan's subscribers.

        Parameters:
            scan_id: The scan the event belongs to.
            event: The event payload.

        Returns:
            The stamped event, or None when there was no scan to attribute it to.

        Side effects:
            Appends to the backlog and enqueues to each subscriber.

        Implementation notes:
            A bounded backlog is kept per scan so a client connecting mid-scan receives recent history rather than starting blank. The bound matters: a verbose scan emits thousands of lines, and an unbounded backlog would hold them all in memory for the life of the process. Subscribers are snapshotted under the lock and delivered to outside it, so a slow or stuck consumer cannot block the worker thread that produced the event. Delivery uses a thread-safe handoff into the loop, because this is called from worker threads. Failures are swallowed per subscriber, so a disconnected client cannot break delivery to the others.
        """
        if not scan_id:
            return None
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
        return event

    def emit_log(self, scan_id: Optional[str], message: str) -> None:
        """
        Purpose:
            Publish a log line for a scan, and persist it when verbose.

        Parameters:
            scan_id: The scan, or None for a line outside any scan.
            message: The already-redacted line.

        Side effects:
            Publishes the event and may append to the scan's log file.

        Implementation notes:
            Persisted only under verbose, since a full scan log is large and is a diagnostic rather than a product. The live stream is unaffected either way.

        Security considerations:
            The message has already passed through the verbose module's redaction.
        """
        event = self._publish(scan_id, {"type": "log", "message": message})
        if self.verbose and scan_id and event is not None:
            store.append_log(scan_id, event.get("ts", ""), message)

    def emit_progress(self, scan_id: str, phase: str, percent: int,
                      message: str = "") -> None:
        """
        Purpose:
            Publish a progress update and record it in the scan's metadata.

        Parameters:
            scan_id: The scan.
            phase: Current stage.
            percent: Overall completion.
            message: Human-readable description.

        Side effects:
            Publishes the event and updates stored metadata.

        Implementation notes:
            Written to metadata as well as streamed, so a client that reloads mid-scan sees the current phase rather than waiting for the next update.
        """
        meta = store.load_meta(scan_id)
        if meta is not None:
            meta["phase"] = phase
            meta["progress"] = percent
            store.save_meta(meta)
        self._publish(scan_id, {"type": "progress", "phase": phase,
                                "percent": percent, "message": message})

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """
        Purpose:
            Open an event stream for a scan, seeded with recent history.

        Parameters:
            scan_id: The scan.

        Returns:
            A queue receiving that scan's events.

        Implementation notes:
            The backlog is replayed into the new queue, so a client connecting mid-scan sees how it got here rather than an empty pane until the next event.
        """
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subscribers.setdefault(scan_id, set()).add(queue)
            backlog = list(self._backlog.get(scan_id, ()))
        for event in backlog:
            queue.put_nowait(event)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        """
        Purpose:
            Close an event stream.

        Parameters:
            scan_id: The scan.
            queue: The queue to remove.

        Implementation notes:
            Must be called when a websocket closes; otherwise the queue keeps accumulating events for the rest of the scan with nothing draining it.
        """
        with self._lock:
            subs = self._subscribers.get(scan_id)
            if subs:
                subs.discard(queue)

    def prepare_scan(self, filename: str) -> tuple[str, Path]:
        """
        Purpose:
            Create a scan: allocate its identifier, make its directory, and record its initial metadata.

        Parameters:
            filename: The uploaded filename.

        Returns:
            The scan identifier and the path the APK should be written to.

        Side effects:
            Creates the scan directory and writes metadata.

        Implementation notes:
            Metadata is written with every field present from the outset, including the ones only filled in later, so readers never meet a missing key and the shape does not change as a scan progresses. Preparing is separate from starting so the caller can write the APK into place before analysis begins.

        Security considerations:
            The filename is sanitised by the store before it becomes a path.
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
            "pause_reason": None,
            "resume_attempts": 0,
            "summary": {},
            "reports": {},
        })
        return scan_id, dest

    def start_scan(self, scan_id: str, apk_path: Path, resume: bool = False) -> None:
        """
        Purpose:
            Queue a scan for execution.

        Parameters:
            scan_id: The scan identifier.
            apk_path: Path to the APK.
            resume: Continue from the checkpoint rather than starting fresh.

        Side effects:
            Submits the scan to the worker pool.
        """
        self._executor.submit(self._run, scan_id, str(apk_path), resume)

    def _get_cancel_event(self, scan_id: str) -> threading.Event:
        """
        Purpose:
            Return the cancellation flag for a scan, creating it if needed.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            The event.

        Thread-safety:
            Created under the lock, so two threads asking at once get the same event rather than one of them getting a flag nobody sets.
        """
        with self._lock:
            event = self._cancel_events.get(scan_id)
            if event is None:
                event = threading.Event()
                self._cancel_events[scan_id] = event
            return event

    def _get_pause_event(self, scan_id: str) -> threading.Event:
        """
        Purpose:
            Return the pause flag for a scan, creating it if needed.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            The event.

        Implementation notes:
            Pausing and cancelling are separate flags because they lead to different outcomes -- a pause keeps the checkpoint for a later resume, a cancel finishes the scan.
        """
        with self._lock:
            event = self._pause_events.get(scan_id)
            if event is None:
                event = threading.Event()
                self._pause_events[scan_id] = event
            return event

    def cancel_scan(self, scan_id: str) -> bool:
        """
        Purpose:
            Ask a running scan to stop.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            True when a cancellable scan was signalled.

        Side effects:
            Sets the cancellation flag.

        Implementation notes:
            Cooperative: the analysis polls the flag between stages. Killing the thread would leave a device with an interception CA installed and an instrumentation server running, and the teardown that removes both is in the analysis path.
        """
        meta = store.load_meta(scan_id)
        if not meta or meta.get("status") not in _ACTIVE_STATUSES:
            return False
        self._get_cancel_event(scan_id).set()
        return True

    def pause_scan(self, scan_id: str) -> bool:
        """
        Purpose:
            Ask a running scan to pause at its next checkpoint.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            True when a pausable scan was signalled.

        Side effects:
            Sets the pause flag.
        """
        meta = store.load_meta(scan_id)
        if not meta or meta.get("status") not in _ACTIVE_STATUSES:
            return False
        self._get_pause_event(scan_id).set()
        return True

    def resume_scan(self, scan_id: str) -> bool:
        """
        Purpose:
            Restart a paused scan from its checkpoint.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            True when the scan was resubmitted.

        Side effects:
            Clears the pause state and queues the scan again.
        """
        meta = store.load_meta(scan_id)
        if not meta or meta.get("status") != "paused":
            return False
        apk_path = Path(meta.get("dir", "")) / meta.get("filename", "")
        if not apk_path.is_file():
            self._finish_meta(scan_id, dict(
                status="failed", phase="failed",
                error="Cannot resume - the uploaded APK is no longer on disk."))
            return False
        with self._lock:
            self._cancel_events.pop(scan_id, None)
            self._pause_events.pop(scan_id, None)
        self._finish_meta(scan_id, dict(
            status="queued", phase="queued", pause_reason=None, error=None,
            finished_at=None,
            resume_attempts=int(meta.get("resume_attempts", 0) or 0) + 1))
        self._publish(scan_id, {"type": "status", "status": "queued"})
        self.start_scan(scan_id, apk_path, resume=True)
        return True

    def reconcile_orphans(self) -> None:
        """
        Purpose:
            Decide what to do about scans that were running when the server last stopped.

        Side effects:
            Rewrites the metadata of interrupted scans.

        Implementation notes:
            Ownership is established before anything is touched: a scan recorded against a different boot identity and a process that is still alive belongs to another running server and is left alone. Without that check, two servers on one machine would each reclaim the other's scans. An orphan with a checkpoint becomes paused and resumable, since its work can be continued. One without becomes failed, because there is nothing to resume from -- and leaving it marked running would show a scan that will never progress.
        """
        for meta in store.list_meta():
            if meta.get("status") not in _ACTIVE_STATUSES:
                continue
            scan_id = meta.get("id")
            if not scan_id:
                continue
            owner = meta.get("owner_pid")
            if (meta.get("boot_id") not in (None, _BOOT_ID)
                    and owner not in (None, os.getpid())
                    and _pid_alive(owner)):
                verbose_print(
                    f"Scan {scan_id} is owned by a live server (pid {owner}); leaving it",
                    self.verbose)
                continue
            if ckpt.has_checkpoint(scan_id):
                self._finish_meta(scan_id, dict(
                    status="paused", pause_reason="interrupted",
                    phase=meta.get("phase") or "interrupted",
                    error=None, finished_at=None, resumable=True))
                verbose_print(f"Scan {scan_id}: interrupted, checkpoint found - marked paused",
                              self.verbose)
            else:
                self._finish_meta(scan_id, dict(
                    status="failed", phase="failed", finished_at=_now_iso(),
                    error="Interrupted before any progress was saved."))
                verbose_print(f"Scan {scan_id}: interrupted with no checkpoint - marked failed",
                              self.verbose)

    def auto_resume_interrupted(self) -> None:
        """
        Purpose:
            Restart scans that a previous run left interrupted, when the user has enabled it.

        Side effects:
            Queues eligible scans.

        Implementation notes:
            Attempts are counted and capped. A scan that is interrupted repeatedly is probably crashing the server, and retrying it forever would make the dashboard unusable -- so after the cap it is left paused for the user to decide.
        """
        if not user_settings.get_auto_resume():
            return
        for meta in store.list_meta():
            if meta.get("status") != "paused" or meta.get("pause_reason") != "interrupted":
                continue
            if int(meta.get("resume_attempts", 0) or 0) >= _MAX_AUTO_RESUME:
                verbose_print(
                    f"Scan {meta.get('id')}: interrupted {meta.get('resume_attempts')}x already "
                    "- leaving paused for the user", self.verbose)
                continue
            self.resume_scan(meta["id"])

    def resume_expired_quota_pauses(self) -> None:
        """
        Purpose:
            Restart scans paused for a provider quota, once the quota window has passed.

        Side effects:
            Queues eligible scans.

        Implementation notes:
            A quota pause records when it is worth retrying, and this skips anything still inside that window rather than retrying blindly into the same limit. Attempts are separately counted and capped, so a genuinely exhausted allowance does not produce an endless resume loop. The separate counter matters: a quota pause is a different failure from an interruption and deserves its own budget.
        """
        if not user_settings.get_auto_resume():
            return
        now = _now_iso()
        for meta in store.list_meta():
            if meta.get("status") != "paused" or meta.get("pause_reason") != "provider_quota":
                continue
            resume_after = meta.get("resume_after")
            if resume_after and str(resume_after) > now:
                continue
            attempts = int(meta.get("quota_resume_attempts", 0) or 0)
            if attempts >= _MAX_QUOTA_AUTO_RESUME:
                verbose_print(
                    f"Scan {meta.get('id')}: quota-paused {attempts}x already - "
                    "leaving paused for the user", self.verbose)
                continue
            scan_id = meta["id"]
            self._finish_meta(scan_id, dict(quota_resume_attempts=attempts + 1))
            self.resume_scan(scan_id)

    def cancel_all_active(self) -> None:
        """
        Purpose:
            Cancel every running scan, at shutdown.

        Side effects:
            Signals cancellation for each active scan.

        Implementation notes:
            Called during shutdown so scans stop cooperatively and run their teardown, rather than being cut off when the daemon threads die with the process.
        """
        for meta in store.list_meta():
            if meta.get("status") in _ACTIVE_STATUSES:
                self.cancel_scan(meta["id"])

    def stop_and_delete(self, scan_id: str, timeout: float = _STOP_WAIT_TIMEOUT) -> bool:
        """
        Purpose:
            Stop a scan and delete everything it produced.

        Parameters:
            scan_id: The scan identifier.
            timeout: How long to wait for the scan to stop.

        Returns:
            True when the scan was deleted.

        Side effects:
            Cancels the scan and removes its directory.

        Implementation notes:
            Waits for the scan to actually stop before deleting, with a timeout. Removing the directory under a running scan would leave it writing into a deleted path and could recreate parts of it after the delete.
        """
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
        """
        Purpose:
            Apply updates to a scan's stored metadata.

        Parameters:
            scan_id: The scan identifier.
            updates: Fields to change.

        Returns:
            True when the metadata was updated.

        Side effects:
            Rewrites the metadata file.
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

    def _handle_cancelled(self, scan_id: str, started: float,
                          checkpoint: Optional["ckpt.ScanCheckpoint"] = None) -> None:
        """
        Purpose:
            Record a cancelled scan, keeping whatever it managed to find.

        Parameters:
            scan_id: The scan identifier.
            started: When the scan began, for the recorded duration.
            checkpoint: The scan's checkpoint, read for the findings gathered before cancellation.

        Side effects:
            Writes a partial result and updates metadata.

        Implementation notes:
            A cancelled scan usually found something, and a user who stops a long run still wants what it had. The findings come from the checkpoint rather than from the aborted call stack, which is what makes them recoverable at all. The partial result is written in the normal shape so the dashboard renders it, with the metadata recording that it is incomplete.
        """
        self.emit_log(scan_id, "Scan stopped by user")
        partial = checkpoint.collected_findings() if checkpoint is not None else []
        summary_update: Dict[str, Any] = {}
        if partial and store.load_meta(scan_id) is not None:
            store.save_result(scan_id, _partial_result(partial))
            summary_update = {"summary": {"total_vulnerabilities": len(partial),
                                          "analysis_supported": True}}
            self.emit_log(scan_id, f"Kept {plural(len(partial), 'finding')} gathered before the stop")
        saved = self._finish_meta(scan_id, dict(
            status="cancelled", finished_at=_now_iso(), error=None,
            phase="cancelled", duration=round(time.time() - started, 2),
            **summary_update))
        if checkpoint is not None:
            checkpoint.clear()
        if saved:
            self._publish(scan_id, {"type": "status", "status": "cancelled"})

    def _handle_paused(self, scan_id: str, started: float) -> None:
        """
        Purpose:
            Record a paused scan so it can be resumed.

        Parameters:
            scan_id: The scan identifier.
            started: When the scan began.

        Side effects:
            Updates metadata to the paused state.

        Implementation notes:
            No finish time is recorded, since the scan has not finished -- a paused scan that reported one would show as complete in the history.
        """
        self.emit_log(scan_id, "Scan paused - resume to continue from here")
        meta = store.load_meta(scan_id) or {}
        reason = meta.get("pause_reason") or "user"
        saved = self._finish_meta(scan_id, dict(
            status="paused", pause_reason=reason, error=None,
            finished_at=None, duration=round(time.time() - started, 2),
            resumable=ckpt.has_checkpoint(scan_id)))
        if saved:
            self._publish(scan_id, {"type": "status", "status": "paused"})

    def _run(self, scan_id: str, apk_path: str, resume: bool = False) -> None:
        """
        Purpose:
            Run one scan to completion on a worker thread, handling cancellation, pausing, quota exhaustion and failure.

        Parameters:
            scan_id: The scan identifier.
            apk_path: Path to the APK.
            resume: Continue from the checkpoint rather than starting fresh.

        Side effects:
            Runs the full analysis, writes results and reports, and updates metadata throughout.

        Implementation notes:
            Ownership -- this server's boot identity and process id -- is recorded when the scan starts, which is what lets a later restart tell its own orphans from another server's live scans. The outcomes are distinguished deliberately: cancellation keeps partial findings, a pause keeps the checkpoint, a quota failure pauses with a retry time rather than failing, and anything else fails with the error recorded. Collapsing these would lose either the work or the ability to resume.

        Security considerations:
            The scan context is bound for the duration, so log lines emitted anywhere in the analysis are attributed to this scan and reach only its subscribers.
        """
        cancel_event = self._get_cancel_event(scan_id)
        pause_event = self._get_pause_event(scan_id)
        if cancel_event.is_set() or store.load_meta(scan_id) is None:
            with self._lock:
                self._cancel_events.pop(scan_id, None)
                self._pause_events.pop(scan_id, None)
            return
        token = current_scan_id.set(scan_id)
        started = time.time()
        checkpoint = (ckpt.ScanCheckpoint.load(scan_id) if resume
                      else ckpt.ScanCheckpoint.fresh(scan_id))
        if resume:
            self.emit_log(scan_id, "Resuming from checkpoint - earlier AI work is kept")
        self._finish_meta(scan_id, dict(
            status="running", started_at=_now_iso(), phase="starting", progress=3,
            pause_reason=None, boot_id=_BOOT_ID, owner_pid=os.getpid()))
        self._publish(scan_id, {"type": "status", "status": "running"})

        def stopping() -> bool:
            """
            Purpose:
                Report whether the scan has been asked to stop, for either reason.

            Returns:
                True when cancellation or pausing has been requested.

            Implementation notes:
                Both flags are collapsed into one predicate because the analysis treats them identically -- it stops at the next checkpoint. Which of them was set is what decides the outcome afterwards.
            """
            return cancel_event.is_set() or pause_event.is_set()

        def progress_cb(phase, percent, message=""):
            """
            Purpose:
                Report progress from inside the analysis, and turn a stop request into a cancellation.

            Parameters:
                phase: Current stage.
                percent: Overall completion.
                message: Human-readable description.

            Raises:
                ScanCancelled: When the scan has been asked to stop.

            Side effects:
                Publishes a progress event.

            Implementation notes:
                Raising from the progress callback is how cancellation reaches the analysis without every stage needing its own check. Progress is reported frequently, so the stop is honoured promptly.
            """
            if stopping():
                raise ScanCancelled()
            self.emit_progress(scan_id, phase, percent, message)

        try:
            service = AnalysisService(verbose=self.verbose, progress=progress_cb,
                                      is_cancelled=stopping, checkpoint=checkpoint)
            result = service.run(apk_path)

            if quota_exhausted(result):
                if store.load_meta(scan_id) is not None:
                    store.save_result(scan_id, result)
                resume_after = (
                    datetime.now(timezone.utc)
                    + timedelta(hours=_QUOTA_DEFAULT_RESUME_HOURS)).isoformat()
                self._finish_meta(scan_id, dict(
                    pause_reason="provider_quota", resume_after=resume_after))
                self.emit_log(
                    scan_id,
                    "Paused - the AI provider's subscription quota ran out. "
                    f"Retries automatically after about {_QUOTA_DEFAULT_RESUME_HOURS}h, "
                    "or resume any time.")
                self._handle_paused(scan_id, started)
                return
            checkpoint.clear()
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
            if pause_event.is_set() and not cancel_event.is_set():
                self._handle_paused(scan_id, started)
            else:
                self._handle_cancelled(scan_id, started, checkpoint)
        except Exception as exc:
            err_id = uuid.uuid4().hex[:8]
            import logging as _logging
            _logging.getLogger(__name__).error(
                "Scan %s failed [err_id=%s]: %s\n%s",
                scan_id, err_id, exc, traceback.format_exc())
            public_msg = f"Scan failed (ref: {err_id})"
            self.emit_log(scan_id, f"ERROR: {public_msg}")
            checkpoint.clear()
            saved = self._finish_meta(scan_id, dict(
                status="failed", finished_at=_now_iso(), error=public_msg,
                phase="failed", duration=round(time.time() - started, 2)))
            if saved:
                self._publish(scan_id, {"type": "status", "status": "failed",
                                        "error": public_msg})
        finally:
            with self._lock:
                self._cancel_events.pop(scan_id, None)
                self._pause_events.pop(scan_id, None)
            current_scan_id.reset(token)

    def get_meta(self, scan_id: str) -> Optional[dict]:
        """
        Purpose:
            Return a scan's metadata.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            The metadata, or None when the scan does not exist.
        """
        return store.load_meta(scan_id)

    def get_result(self, scan_id: str) -> Optional[dict]:
        """
        Purpose:
            Return a scan's stored result.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            The result, or None when unavailable.
        """
        return store.load_result(scan_id)

    def list_scans(self) -> List[dict]:
        """
        Purpose:
            List every stored scan for the dashboard's history.

        Returns:
            The metadata of each scan.
        """
        return store.list_meta()

    def delete(self, scan_id: str) -> bool:
        """
        Purpose:
            Delete a scan's stored data.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            True when it was deleted.

        Side effects:
            Removes the scan directory.

        Implementation notes:
            Deletes without stopping a running scan first; callers that might be deleting an active scan should use the stop-and-delete path instead.
        """
        return store.delete_scan(scan_id)
