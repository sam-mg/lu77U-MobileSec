"""Cooperative cancellation signal for long-running background jobs."""

class ScanCancelled(Exception):
    """Raised to unwind out of a scan once the user has stopped/deleted it."""