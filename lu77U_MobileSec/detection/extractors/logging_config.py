"""Logging Configuration for lu77U-MobileSec Detection"""

from ...utils.verbose import verbose_print
from ...ui.colors import Colors
from ...config.settings import ANDROGUARD_LOGGING
from ...config.constants import ANDROGUARD_LOGGERS

try:
    from androguard.util import set_log
    ANDROGUARD_AVAILABLE = True
except ImportError as e:
    ANDROGUARD_AVAILABLE = False


def setup_androguard_logging(verbose=False):
    """Setup androguard logging with custom formatting and colors"""
    verbose_print("setup_androguard_logging called", verbose)
    verbose_print(f"Androguard available: {ANDROGUARD_AVAILABLE}", verbose)
    verbose_print(f"ANDROGUARD_LOGGING setting: {ANDROGUARD_LOGGING}", verbose)
    verbose_print(f"Verbose mode: {verbose}", verbose)
    
    if not ANDROGUARD_AVAILABLE:
        verbose_print("Androguard not available - skipping logging configuration", verbose)
        return
    
    import logging
    verbose_print("Setting up androguard logging with Python logging module", verbose)
    
    if not ANDROGUARD_LOGGING:
        verbose_print("ANDROGUARD_LOGGING is False - disabling androguard loggers", verbose)
        verbose_print(f"Configuring {len(ANDROGUARD_LOGGERS)} logger(s) to CRITICAL level", verbose)
        for logger_name in ANDROGUARD_LOGGERS:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.CRITICAL)
            logger.handlers.clear()
            logger.propagate = False
            logger.disabled = True
            verbose_print(f"Logger '{logger_name}' disabled and set to CRITICAL", verbose)
        
        try:
            import sys
            # Redirect androguard's set_log to use CRITICAL level (50)
            set_log(50, sys.stderr)
            verbose_print("Androguard global log level set to CRITICAL", verbose)
        except Exception as e:
            verbose_print(f"Androguard logging setup note: {e}", verbose)
    else:
        log_level_num = 20  # INFO level
        verbose_print(f"ANDROGUARD_LOGGING is True - enabling androguard loggers at INFO", verbose)
        verbose_print(f"Configuring {len(ANDROGUARD_LOGGERS)} logger(s) to INFO level", verbose)
        
        for logger_name in ANDROGUARD_LOGGERS:
            logger = logging.getLogger(logger_name)
            logger.setLevel(log_level_num)
            logger.propagate = True
            logger.disabled = False
            verbose_print(f"Logger '{logger_name}' enabled and set to INFO", verbose)
        
        try:
            import sys
            set_log(log_level_num, sys.stderr)
            verbose_print(f"Androguard global log level set to INFO", verbose)
        except Exception as e:
            verbose_print(f"Androguard logging setup note: {e}", verbose)
    
    try:
        from loguru import logger
        logger.remove()
        
        if verbose:
            def colored_sink(message):
                record = message.record
                name = record["name"]
                if name.startswith('androguard') and not ANDROGUARD_LOGGING:
                    return
                function = record["function"]
                line = record["line"]
                msg = record["message"]
                
                if name.startswith('androguard') and ANDROGUARD_LOGGING:
                    formatted_msg = f"[VERBOSE] {msg}"
                    print(f"{Colors.VERBOSE}{formatted_msg}{Colors.RESET}")
                else:
                    formatted_msg = f"[VERBOSE] {name}:{function}:{line} - {msg}"
                    print(f"{Colors.VERBOSE}{formatted_msg}{Colors.RESET}")
            
            logger.add(colored_sink, level="DEBUG")
        else:
            logger.add(lambda msg: None, level="CRITICAL")
    except ImportError:
        verbose_print("Loguru not available - skipping loguru configuration", verbose)