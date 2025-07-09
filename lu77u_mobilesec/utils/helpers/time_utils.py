#!/usr/bin/env python3
"""
Time utilities for lu77U-MobileSec
"""

import time


def start_analysis_timer() -> float:
    """Start the analysis timer and return the start time"""
    return time.time()


def end_analysis_timer(start_time: float) -> float:
    """End the analysis timer and return duration"""
    if start_time is None:
        return 0
    
    end_time = time.time()
    duration = end_time - start_time
    return duration


def format_duration(duration_seconds: float) -> str:
    """Format duration in a human-readable format"""
    if duration_seconds < 60:
        return f"{duration_seconds:.2f} seconds"
    elif duration_seconds < 3600:
        minutes = int(duration_seconds // 60)
        seconds = duration_seconds % 60
        return f"{minutes} minute(s) and {seconds:.2f} seconds"
    else:
        hours = int(duration_seconds // 3600)
        minutes = int((duration_seconds % 3600) // 60)
        seconds = duration_seconds % 60
        return f"{hours} hour(s), {minutes} minute(s) and {seconds:.2f} seconds"
