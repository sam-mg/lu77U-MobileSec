#!/usr/bin/env python3
"""
Module: test_job_ownership

Purpose:
    Which server owns a scan, and what a server starting up does with scans it finds unfinished.

Responsibilities:
    Pin that a queued scan records its owner before it runs, that a server reconciling at startup leaves another live server's queued scan alone, that an abandoned queued scan becomes resumable rather than failed, that a worker does not run a scan whose status changed while it waited, and clears any earlier error when it does run one, and that a scan whose provider was unreachable pauses for a short retry instead of finishing, and that two scans take turns on one device.

Dependencies:
    pytest, the job manager and the scan store.

Implementation notes:
    The preflight's clean-install check starts a second dashboard on the same machine, and its startup reconciliation once failed two scans the user's dashboard had queued but not yet started, because a queued scan carried no owner. The store is redirected to a temporary directory and the worker pool is replaced, so no scan runs and the user's scan folder is never read.
"""

import os

import pytest

from lu77U_MobileSec.web import jobs as jobs_mod
from lu77U_MobileSec.web import store

SCAN_ID = "0123456789ab"


@pytest.fixture
def manager(monkeypatch, tmp_path):
    """
    Purpose:
        Build a job manager over an empty temporary scan store, with a worker pool that records instead of running.

    Parameters:
        monkeypatch: Redirects the store and replaces the pool.
        tmp_path: The temporary output base.

    Returns:
        The manager, with the submissions recorded on it as submitted.

    Security considerations:
        The user's real scan folder is never read or written.
    """
    monkeypatch.setattr(store, "get_output_base", lambda: tmp_path)
    monkeypatch.setattr(store, "_folder_cache", {})
    manager = jobs_mod.JobManager(verbose=False)
    manager.submitted = []
    monkeypatch.setattr(manager._executor, "submit", lambda *args: manager.submitted.append(args))
    return manager


def _queued(status="queued", **extra):
    """
    Purpose:
        Create a scan folder holding an APK and metadata in the given state.

    Parameters:
        status: The scan's status.
        extra: Further metadata to record, such as the owner or an earlier error.

    Returns:
        The APK path.
    """
    folder = store.create_scan_folder(SCAN_ID, "app.apk")
    apk = folder / "app.apk"
    apk.write_bytes(b"PK")
    store.save_meta(dict({"id": SCAN_ID, "dir": str(folder), "filename": "app.apk",
                          "status": status, "phase": status, "error": None}, **extra))
    return apk


def test_queueing_records_the_owner(manager):
    """
    Purpose:
        Pin that queueing a scan records this server as its owner before the scan runs.

    Parameters:
        manager: The job manager.
    """
    apk = _queued()
    manager.start_scan(SCAN_ID, apk)
    meta = store.load_meta(SCAN_ID)
    assert (meta["owner_pid"], meta["boot_id"]) == (os.getpid(), jobs_mod._BOOT_ID)
    assert len(manager.submitted) == 1


def test_another_live_servers_queued_scan_is_left_alone(manager):
    """
    Purpose:
        Pin that startup reconciliation leaves a queued scan alone when a different, live server owns it.

    Parameters:
        manager: The job manager.
    """
    _queued(boot_id="another-server", owner_pid=os.getppid())
    manager.reconcile_orphans()
    assert store.load_meta(SCAN_ID)["status"] == "queued"


def test_an_abandoned_queued_scan_becomes_resumable(manager):
    """
    Purpose:
        Pin that a queued scan with no live owner becomes paused and resumable, since it never started and its APK is still there.

    Parameters:
        manager: The job manager.
    """
    _queued()
    manager.reconcile_orphans()
    meta = store.load_meta(SCAN_ID)
    assert (meta["status"], meta["pause_reason"]) == ("paused", "interrupted")


def test_an_abandoned_running_scan_without_a_checkpoint_still_fails(manager):
    """
    Purpose:
        Pin that a running scan with no live owner and no checkpoint is still marked failed, since there is nothing to continue.

    Parameters:
        manager: The job manager.
    """
    _queued(status="running")
    manager.reconcile_orphans()
    assert store.load_meta(SCAN_ID)["status"] == "failed"


def test_a_scan_no_longer_queued_is_not_run(manager, monkeypatch):
    """
    Purpose:
        Pin that a worker whose scan was marked failed while it waited for a slot does not run it.

    Parameters:
        manager: The job manager.
        monkeypatch: Replaces the analysis so a run would be visible.
    """
    ran = []
    monkeypatch.setattr(jobs_mod, "AnalysisService", lambda **_: ran.append(True))
    apk = _queued(status="failed")
    manager._run(SCAN_ID, str(apk), False)
    assert ran == [] and store.load_meta(SCAN_ID)["status"] == "failed"


def test_starting_clears_an_earlier_error(manager, monkeypatch):
    """
    Purpose:
        Pin that a scan which starts no longer carries an error recorded before it ran.

    Parameters:
        manager: The job manager.
        monkeypatch: Makes the analysis stop the scan as soon as it starts.
    """
    seen = {}

    class _Stops:
        """
        Purpose:
            An analysis that records the metadata it starts under, then fails.
        """
        def __init__(self, **unused_kwargs):
            """
            Purpose:
                Accept the real constructor's arguments.

            Parameters:
                unused_kwargs: The real constructor's arguments, ignored.
            """

        def run(self, unused_apk_path):
            """
            Purpose:
                Record the metadata at start, then fail.

            Parameters:
                unused_apk_path: The APK, ignored.

            Raises:
                RuntimeError: Always, so the run ends quickly.
            """
            seen.update(store.load_meta(SCAN_ID))
            raise RuntimeError("stop here")

    monkeypatch.setattr(jobs_mod, "AnalysisService", _Stops)
    apk = _queued(error="Interrupted before any progress was saved.")
    manager._run(SCAN_ID, str(apk), False)
    assert seen["status"] == "running" and seen["error"] is None


def test_an_unreachable_provider_pauses_for_a_short_retry(manager, monkeypatch):
    """
    Purpose:
        Pin that a scan which stopped with its provider unreachable is paused with a retry minutes away, its result kept, and that auto-resume picks it up once that time passes.

    Parameters:
        manager: The job manager.
        monkeypatch: Replaces the analysis, the clock check and auto-resume setting.
    """
    from datetime import datetime, timezone

    class _Offline:
        """
        Purpose:
            An analysis that ends with the provider unreachable.
        """
        def __init__(self, **unused_kwargs):
            """
            Purpose:
                Accept the real constructor's arguments.

            Parameters:
                unused_kwargs: The real constructor's arguments, ignored.
            """

        def run(self, unused_apk_path):
            """
            Purpose:
                Return a result whose provider could not be reached.

            Parameters:
                unused_apk_path: The APK, ignored.

            Returns:
                The result.
            """
            return {"analyzer_details": {"llm_usage": {"unreachable": "nodename nor servname provided"}}}

    monkeypatch.setattr(jobs_mod, "AnalysisService", _Offline)
    apk = _queued()
    manager._run(SCAN_ID, str(apk), False)
    meta = store.load_meta(SCAN_ID)
    assert (meta["status"], meta["pause_reason"]) == ("paused", "provider_unreachable")
    wait = datetime.fromisoformat(meta["resume_after"]) - datetime.now(timezone.utc)
    assert 0 < wait.total_seconds() <= 15 * 60
    assert store.load_result(SCAN_ID) is not None

    monkeypatch.setattr(jobs_mod.user_settings, "get_auto_resume", lambda: True)
    store.save_meta(dict(store.load_meta(SCAN_ID), resume_after="2000-01-01T00:00:00+00:00"))
    manager.resume_expired_quota_pauses()
    assert store.load_meta(SCAN_ID)["status"] == "queued"


def test_two_scans_take_turns_on_one_device():
    """
    Purpose:
        Pin that a second scan waits for a device the first is using, says it is waiting, and can be stopped while it waits.
    """
    import threading
    from lu77U_MobileSec.utils.cancellation import ScanCancelled
    from lu77U_MobileSec.web.services.analysis_service import hold_device

    first = hold_device("emulator-test", lambda: False, lambda: None)
    told = []
    with pytest.raises(ScanCancelled):
        hold_device("emulator-test", lambda: bool(told), lambda: told.append(True))
    assert told == [True]
    got = []
    waiter = threading.Thread(target=lambda: got.append(hold_device("emulator-test", lambda: False, lambda: None)))
    waiter.start()
    waiter.join(timeout=0.5)
    assert waiter.is_alive() and not got
    first.release()
    waiter.join(timeout=5)
    assert got and got[0] is first
    got[0].release()
    other = hold_device("emulator-other", lambda: False, lambda: None)
    other.release()
