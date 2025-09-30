"""Time and duration utilities for lu77U-MobileSec"""

from .verbose import verbose_print

def format_duration(seconds: float, verbose: bool = False) -> str:
    verbose_print(f"Formatting duration: {seconds} seconds", verbose)
    
    if seconds < 0:
        verbose_print("Negative duration detected, returning '0s'", verbose)
        return "0s"
    
    total_seconds = seconds
    verbose_print(f"Total seconds to format: {total_seconds}", verbose)
    
    # Calculate time components
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    remaining_seconds = total_seconds % 60
    
    verbose_print(f"Time breakdown - Hours: {hours}, Minutes: {minutes}, Seconds: {remaining_seconds:.1f}", verbose)
    
    parts = []
    
    # Build time parts
    if hours > 0:
        parts.append(f"{hours}h")
        verbose_print(f"Added hours component: {hours}h", verbose)
    if minutes > 0:
        parts.append(f"{minutes}m")
        verbose_print(f"Added minutes component: {minutes}m", verbose)
    
    # Handle seconds/milliseconds formatting
    if total_seconds < 1:
        ms_value = remaining_seconds * 1000
        parts.append(f"{ms_value:.1f}ms")
        verbose_print(f"Added milliseconds component: {ms_value:.1f}ms", verbose)
    elif total_seconds < 60:
        parts.append(f"{remaining_seconds:.1f}s")
        verbose_print(f"Added precise seconds component: {remaining_seconds:.1f}s", verbose)
    else:
        parts.append(f"{remaining_seconds:.0f}s")
        verbose_print(f"Added rounded seconds component: {remaining_seconds:.0f}s", verbose)
    
    result = " ".join(parts)
    verbose_print(f"Final formatted duration: '{result}'", verbose)
    return result
