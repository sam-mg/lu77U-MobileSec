#!/usr/bin/env python3
"""
Module: test_scan_logs

Purpose:
    The per-scan log file: what is written, when it is written at all, and how it is read back.

Responsibilities:
    Pin that the file is a complete and ordered record, that its parsing survives awkward messages and torn writes, that writing never raises, and that persistence happens only in verbose mode while live streaming happens either way.

Dependencies:
    pytest, the scan store and the job manager.

Implementation notes:
    The interface shows a scan's whole log history, which the live socket alone cannot supply: its backlog is bounded and held in memory, so it has nothing at all for a scan that finished before the page was opened and only the tail of a long one. The file is the complete record. It is written only when the server runs verbose, because verbose output narrates every file the engine reads, which reaches hundreds of megabytes on a large application. Both halves of that are asserted here, that it is complete when enabled and that nothing at all is written when it is not.
"""

import pytest

from lu77U_MobileSec.web import store


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """
    Purpose:
        Create a scan folder inside a temporary output base and hand back its identifier.

    Parameters:
        tmp_path: The temporary output base.
        monkeypatch: Redirects the output base and clears the folder cache.

    Returns:
        The scan identifier.

    Side effects:
        Creates the scan folder.

    Security considerations:
        Redirecting the output base keeps the test run from writing into the user's real scan directory alongside their actual results.
    """
    monkeypatch.setattr(store, "get_output_base", lambda: tmp_path)
    monkeypatch.setattr(store, "_folder_cache", {})
    scan_id = "abc123def456"
    store.create_scan_folder(scan_id, "demo.apk")
    return scan_id


class TestLogFile:
    """
    Purpose:
        The log file itself: ordering, completeness, and parsing back what was written.
    """
    def test_lines_round_trip_in_order(self, scan):
        """
        Purpose:
            Pin that a long run of lines reads back complete and in the order written.

        Parameters:
            scan: The scan identifier.
        """
        for i in range(2000):
            store.append_log(scan, f"2026-01-01T00:00:{i % 60:02d}Z", f"line {i}")
        lines = store.read_log(scan)
        assert len(lines) == 2000
        assert lines[0]["message"] == "line 0"
        assert lines[-1]["message"] == "line 1999"

    def test_nothing_is_truncated(self, scan):
        """
        Purpose:
            Pin that the file keeps every line with no ceiling.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            The interface once kept 1500 lines and the socket backlog keeps 3000, so the file is the only thing that makes showing the whole log actually true rather than nearly true.
        """
        for i in range(5000):
            store.append_log(scan, "2026-01-01T00:00:00Z", f"line {i}")
        assert len(store.read_log(scan)) == 5000

    def test_limit_returns_the_newest(self, scan):
        """
        Purpose:
            Pin that a bounded read returns the most recent lines rather than the oldest.

        Parameters:
            scan: The scan identifier.
        """
        for i in range(100):
            store.append_log(scan, "t", f"line {i}")
        tail = store.read_log(scan, limit=10)
        assert len(tail) == 10
        assert tail[0]["message"] == "line 90"

    def test_the_timestamp_is_kept(self, scan):
        """
        Purpose:
            Pin that a line reads back with exactly the timestamp and message it was written with.

        Parameters:
            scan: The scan identifier.
        """
        store.append_log(scan, "2026-01-01T12:00:00+00:00", "hello")
        assert store.read_log(scan)[0] == {"ts": "2026-01-01T12:00:00+00:00",
                                           "message": "hello"}

    def test_a_message_containing_a_tab_keeps_its_tail(self, scan):
        """
        Purpose:
            Pin that a message containing tabs is not cut short when it is read back.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            The separator is the first tab only, because indented engine output contains tabs of its own and splitting on every one of them would silently drop the rest of those lines.
        """
        store.append_log(scan, "t", "col a\tcol b\tcol c")
        assert store.read_log(scan)[0]["message"] == "col a\tcol b\tcol c"

    def test_a_line_without_a_separator_is_still_returned(self, scan):
        """
        Purpose:
            Pin that a line with no separator is returned as a message and does not stop the rest of the file being read.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            A torn write happens when a scan is killed mid-line, and a reader that gave up there would hide every line written before the interruption as well.
        """
        store.log_path(scan).write_text("no separator here\nt\treal line\n")
        lines = store.read_log(scan)
        assert [l["message"] for l in lines] == ["no separator here", "real line"]

    def test_reading_a_scan_with_no_log_is_empty_not_an_error(self, scan):
        """
        Purpose:
            Pin that reading a scan that has written no log yields an empty list.

        Parameters:
            scan: The scan identifier.
        """
        assert store.read_log(scan) == []

    def test_writing_for_an_unknown_scan_is_a_noop(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that writing a line for a scan with no folder neither raises nor creates one.

        Parameters:
            tmp_path: The temporary output base.
            monkeypatch: Redirects the output base and clears the folder cache.

        Implementation notes:
            Logging must never raise, because a scan whose folder failed to be created should still run and still report what went wrong.
        """
        monkeypatch.setattr(store, "get_output_base", lambda: tmp_path)
        monkeypatch.setattr(store, "_folder_cache", {})
        store.append_log("ffffffffffff", "t", "orphan")
        assert store.read_log("ffffffffffff") == []


class _Jobs:
    """
    Purpose:
        The parts of the job manager these tests need, constructed without a server around it.

    Attributes:
        manager: The job manager under test.
    """
    def __init__(self, verbose):
        """
        Purpose:
            Build the job manager at the requested verbosity.

        Parameters:
            verbose: Whether the manager should persist log lines.
        """
        from lu77U_MobileSec.web.jobs import JobManager
        self.manager = JobManager(verbose=verbose)


class TestVerboseGating:
    """
    Purpose:
        What the verbose flag does and does not gate.
    """
    def test_verbose_writes_the_log(self, scan):
        """
        Purpose:
            Pin that a line emitted in verbose mode reaches the file.

        Parameters:
            scan: The scan identifier.
        """
        jobs = _Jobs(verbose=True).manager
        jobs.emit_log(scan, "something happened")
        assert [l["message"] for l in store.read_log(scan)] == ["something happened"]

    def test_normal_mode_writes_nothing(self, scan):
        """
        Purpose:
            Pin that in normal mode nothing is written and no file is created at all.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            The absence of the file is asserted as well as the absence of content, because an empty file left behind would still be served to the interface as a scan with no log rather than as a scan whose log was never kept.
        """
        jobs = _Jobs(verbose=False).manager
        jobs.emit_log(scan, "something happened")
        assert store.read_log(scan) == []
        assert not store.log_path(scan).exists()

    def test_live_streaming_happens_either_way(self, scan):
        """
        Purpose:
            Pin that the live backlog fills at both verbosity settings.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            Persistence is what the flag gates. The progress view shows output on every scan, so a flag that also silenced the stream would leave an ordinary scan looking frozen.
        """
        for verbose in (True, False):
            jobs = _Jobs(verbose=verbose).manager
            jobs.emit_log(scan, "streamed")
            backlog = jobs._backlog[scan]
            assert [e["message"] for e in backlog] == ["streamed"]

    def test_the_persisted_line_carries_the_streamed_timestamp(self, scan):
        """
        Purpose:
            Pin that a line's stored timestamp is the same one it was streamed with.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            The interface removes duplicates between the replayed backlog and the fetched history by comparing timestamp and message, so taking a second reading of the clock for the file would give one line two identities and show it twice.
        """
        jobs = _Jobs(verbose=True).manager
        jobs.emit_log(scan, "once")
        streamed = jobs._backlog[scan][0]
        assert store.read_log(scan)[0]["ts"] == streamed["ts"]

    def test_repeated_identical_messages_are_kept_separately(self, scan):
        """
        Purpose:
            Pin that the same message emitted several times is kept as several lines with distinct timestamps.

        Parameters:
            scan: The scan identifier.

        Implementation notes:
            Logs legitimately repeat, and sub-second timestamp resolution is what stops the interface's duplicate removal from collapsing a retry loop into one line.
        """
        jobs = _Jobs(verbose=True).manager
        for _ in range(3):
            jobs.emit_log(scan, "Retrying…")
        lines = store.read_log(scan)
        assert len(lines) == 3
        assert len({l["ts"] for l in lines}) == 3

    def test_emit_log_without_a_scan_id_is_a_noop(self):
        """
        Purpose:
            Pin that emitting a line with no scan attached does not raise.

        Implementation notes:
            Lines are emitted from code that runs before a scan exists and after it ends, so this path is reached in normal operation rather than only in error.
        """
        jobs = _Jobs(verbose=True).manager
        jobs.emit_log(None, "no scan")
