"""Logging Configuration for lu77U-MobileSec Detection"""

from ...utils.verbose import verbose_print
from ...ui.colors import Colors

try:
    from androguard.util import set_log
    ANDROGUARD_AVAILABLE = True
except ImportError as e:
    ANDROGUARD_AVAILABLE = False


def setup_androguard_logging(verbose=False):
    """Setup androguard logging with custom formatting and colors"""
    verbose_print("Starting androguard logging configuration", verbose)
    
    if not ANDROGUARD_AVAILABLE:
        verbose_print("Androguard not available - skipping logging setup", verbose)
        return
        
    verbose_print("Androguard is available, proceeding with logging setup", verbose)
    
    try:
        verbose_print("Attempting to import loguru", verbose)
        from loguru import logger
        verbose_print("Loguru imported successfully", verbose)
        
        verbose_print("Removing existing loguru handlers", verbose)
        logger.remove()
        
        if verbose:
            verbose_print("Setting up verbose logging configuration", verbose)
            def colored_sink(message):
                record = message.record
                name = record["name"]
                function = record["function"]
                line = record["line"]
                msg = record["message"]
                formatted_msg = f"[VERBOSE] {name}:{function}:{line} - {msg}"
                print(f"{Colors.VERBOSE}{formatted_msg}{Colors.RESET}")
            
            verbose_print("Adding verbose colored sink with DEBUG level", verbose)
            logger.add(
                colored_sink,
                level="DEBUG"
            )
            verbose_print("Androguard logging configured with VERBOSE color and simplified formatting", verbose)
        else:
            verbose_print("Setting up silent logging configuration", verbose)
            logger.add(lambda msg: None, level="CRITICAL")
            verbose_print("Androguard logging configured to suppress all messages", verbose)
            
    except ImportError as e:
        verbose_print(f"Loguru import failed: {e}", verbose)
        if verbose:
            verbose_print("Loguru not available, androguard logs will use default format", verbose)