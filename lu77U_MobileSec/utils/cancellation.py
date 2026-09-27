#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.cancellation

Purpose:
    Provide the single exception type used to unwind a scan that the user stopped, so that cancellation is distinguishable from failure at every layer it passes through.

Responsibilities:
    Declare ScanCancelled. Nothing else belongs here: the module is dependency-free so that any module in the codebase can import it without creating a cycle.

Dependencies:
    None.

Implementation notes:
    Cancellation is modelled as an exception rather than a return value because a scan is a deep call chain through decompilers, analyzers and the AI agent; a sentinel return would have to be checked and forwarded at every level, and one missed check would leave work running after the user asked it to stop.
"""

class ScanCancelled(Exception):
    """
    Purpose:
        Raised to abort an in-progress scan at the next cancellation check point, in response to an explicit user stop request.

    Invariants:
        Signals user intent, never a fault. Handlers must not report it as an analysis failure, must not retry the operation, and must let it propagate after any cleanup.

    Thread-safety:
        The exception carries no state and is safe to raise from any thread. The cancellation flag it is raised in response to is owned elsewhere.
    """
