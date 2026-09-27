#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.detection.extractors.logging_config

Purpose:
    Stop androguard's logging from drowning the tool's own output, while still letting it through when the user asked for detail.

Responsibilities:
    Configure the androguard logger hierarchy, its global log level, and the loguru sink it routes through.

Dependencies:
    logging, androguard's set_log when installed, loguru when installed, ...config for the switch and the logger list.

Implementation notes:
    androguard logs prolifically at INFO and below, including parser internals for every malformed structure it meets -- and a real APK has many. Left alone, that output buries the scan's own progress lines. Three separate mechanisms have to be configured because androguard has changed how it logs across versions: the standard logging hierarchy, its own global level, and loguru. Configuring only one leaves a version of androguard that uses another still noisy.

Security considerations:
    androguard's messages can contain fragments of the untrusted APK. Routing them through a controlled sink rather than letting them reach stdout directly is what keeps them out of the dashboard feed, which does not redact.
"""

from ...utils.verbose import plural, verbose_print
from ...ui.colors import Colors
from ...config.settings import ANDROGUARD_LOGGING
from ...config.constants import ANDROGUARD_LOGGERS

try:
    from androguard.util import set_log
    ANDROGUARD_AVAILABLE = True
except ImportError as e:
    ANDROGUARD_AVAILABLE = False


def setup_androguard_logging(verbose=False):
    """
    Purpose:
        Configure androguard's logging for this run.

    Parameters:
        verbose: When set, androguard output is shown through the tool's own verbose formatting; otherwise it is suppressed.

    Side effects:
        Mutates process-wide logging state: logger levels, handlers, propagation and the loguru sink registry.

    Implementation notes:
        Each named logger is disabled thoroughly rather than merely raised to CRITICAL -- handlers cleared, propagation off, disabled set -- because androguard attaches its own handlers and a level alone does not stop output that a handler already holds. loguru's default sink is removed in both modes. Left in place it writes to stderr independently of the standard logging configuration, which is the usual reason androguard appears to ignore being silenced. Both androguard and loguru are treated as optional, so a partial install degrades to unconfigured logging rather than failing the scan.

    Known limitations:
        This reconfigures logging for the whole process, including loggers the embedding application may own. Removing loguru's default sink in particular affects any other loguru user in the same process.
    """
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
        verbose_print(f"Configuring {plural(len(ANDROGUARD_LOGGERS), 'logger')} to CRITICAL level", verbose)
        for logger_name in ANDROGUARD_LOGGERS:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.CRITICAL)
            logger.handlers.clear()
            logger.propagate = False
            logger.disabled = True
            verbose_print(f"Logger '{logger_name}' disabled and set to CRITICAL", verbose)
        
        try:
            import sys
            set_log(50, sys.stderr)
            verbose_print("Androguard global log level set to CRITICAL", verbose)
        except Exception as e:
            verbose_print(f"Androguard logging setup note: {e}", verbose)
    else:
        log_level_num = 20
        verbose_print(f"ANDROGUARD_LOGGING is True - enabling androguard loggers at INFO", verbose)
        verbose_print(f"Configuring {plural(len(ANDROGUARD_LOGGERS), 'logger')} to INFO level", verbose)
        
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
                """
                Purpose:
                    loguru sink that renders records in the tool's own verbose style, applying the androguard switch.

                Parameters:
                    message: The loguru message, carrying the structured record.

                Side effects:
                    Writes to stdout.

                Implementation notes:
                    androguard records are dropped here when the configuration switch is off, so the two controls compose: running with verbose does not force androguard's internals into the output unless that is separately enabled. androguard messages are printed without the module, function and line prefix that other records get, because that prefix points into a third-party library and is noise to the reader. Defined inside the setup function because it exists only on the verbose path and closes over nothing that outlives it.
                """
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
