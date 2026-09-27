#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.budget

Purpose:
    Bound how long the agent phase may run, while allowing time lost to provider throttling to be credited back.

Responsibilities:
    Track the deadline, accept bounded credit for blocked time, and report what remains.

Dependencies:
    time, threading.

Implementation notes:
    A wall-clock budget alone is unfair to a scan that spent its time blocked on a rate-limited provider rather than working. Crediting that time back means throttling costs throughput rather than coverage. The credit is capped as a fraction of the original budget, so a provider that throttles continuously cannot extend the scan indefinitely -- which is what an uncapped credit would allow.

Thread-safety:
    Credit is applied under a lock, since workers block independently and would otherwise race when crediting.
"""

import threading
import time
from typing import Optional

MAX_CREDIT_FRACTION = 0.5


class Deadline:
    """
    Purpose:
        A wall-clock budget for the agent phase, with bounded credit for blocked time.

    Attributes:
        None public; the state is the deadline, the credit cap and how much has been credited.

    Invariants:
        Total credit never exceeds the cap. A deadline constructed with no limit never expires and accepts no credit.

    Thread-safety:
        Credit and closure are guarded by a lock; the remaining and expired checks are lock-free reads.
    """
    def __init__(self, seconds: Optional[float]) -> None:
        """
        Purpose:
            Construct the budget.

        Parameters:
            seconds: The budget in seconds; a falsy value means unlimited.

        Implementation notes:
            Unlimited is a supported configuration -- the settings allow zero to mean no limit -- and is represented by an absent deadline rather than a very large one, so the checks short-circuit rather than comparing against a sentinel. Measured on the monotonic clock, so a system time change during a long scan cannot shorten or extend it.
        """
        self._seconds = float(seconds) if seconds else None
        self._deadline = (time.monotonic() + self._seconds
                          if self._seconds is not None else None)
        self._max_credit = (self._seconds * MAX_CREDIT_FRACTION
                            if self._seconds is not None else None)
        self._credited = 0.0
        self._lock = threading.Lock()
        self._closed = False

    def expired(self) -> bool:
        """
        Purpose:
            Report whether the budget has run out.

        Returns:
            True when the deadline has passed; always False when unlimited.
        """
        if self._deadline is None:
            return False
        return time.monotonic() >= self._deadline

    def credit(self, seconds: float) -> None:
        """
        Purpose:
            Extend the deadline by time the agent spent blocked rather than working.

        Parameters:
            seconds: The blocked duration.

        Side effects:
            Moves the deadline, up to the cap.

        Thread-safety:
            Applied under the lock, so concurrent credits from several blocked workers cannot exceed the cap between them.

        Implementation notes:
            Capped as a fraction of the original budget. Without the cap, a provider throttling every request would credit back as fast as time passed and the phase would never end. Ignored once closed, so credit arriving from a worker that finished after the phase ended cannot revive it.
        """
        if self._deadline is None or seconds <= 0:
            return
        with self._lock:
            if self._closed:
                return
            room = (self._max_credit - self._credited
                   if self._max_credit is not None else seconds)
            grant = max(0.0, min(seconds, room))
            if grant <= 0:
                return
            self._credited += grant
            self._deadline += grant

    def close(self) -> None:
        """
        Purpose:
            Stop accepting credit.

        Side effects:
            Marks the budget closed.

        Implementation notes:
            Called when the phase ends, so a late credit from a straggling worker does not extend a deadline nothing is using any more.
        """
        with self._lock:
            self._closed = True

    @property
    def remaining(self) -> Optional[float]:
        """
        Purpose:
            Report how much of the budget is left.

        Returns:
            The remaining seconds, or None when unlimited. Never negative.

        Implementation notes:
            Clamped at zero so callers can use it as a timeout directly without guarding for an expired budget.
        """
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    @property
    def credited(self) -> float:
        """
        Purpose:
            Report how much blocked time has been credited back.

        Returns:
            The credited seconds.

        Implementation notes:
            Reported so a scan that ran long can show how much of that was throttling rather than analysis.
        """
        return self._credited
