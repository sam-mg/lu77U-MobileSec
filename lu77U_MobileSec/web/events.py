"""Cross-thread event plumbing for the web layer."""

import contextvars
from typing import Optional

current_scan_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_scan_id", default=None
)