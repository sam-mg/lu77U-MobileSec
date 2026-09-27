#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.events

Purpose:
    Carry the current scan's identity across the call stack, so that a log line emitted deep inside analysis can be attributed to the job that produced it without every function taking a scan id parameter.

Responsibilities:
    Declare the context variable.

Dependencies:
    contextvars only.

Implementation notes:
    A context variable rather than a thread-local, because scans run across both threads and async tasks and a context variable propagates correctly into both. A thread-local would lose the association the moment work moved onto an executor. The default of None means "not inside a scan", which the log sink uses to decide whether a message belongs to any job at all.
"""

import contextvars
from typing import Optional

current_scan_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_scan_id", default=None
)
