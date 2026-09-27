#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.analysis_checker

Purpose:
    Aggregate the individual tool checks into a single answer about whether a scan can run, and into the readiness status the dashboard displays.

Responsibilities:
    Combine the checks, report failures to the terminal, and expose the full status as data.

Dependencies:
    The sibling checker modules, ..ui.colors.

Implementation notes:
    Only JADX and an AI provider are required. The framework-specific decompilers are reported in the status but never block a scan, because an app that needs none of them analyses perfectly well without them.
"""

from ..ui.colors import Colors
from .blutter_checker import check_blutter_configured
from .hermes_checker import check_hermes_configured
from .jadx_checker import check_jadx_configured, get_jadx_setup_message
from .ollama_checker import check_ollama_configured, get_ollama_setup_message
from .rn_decompiler_checker import check_rn_decompiler_configured
from ..utils.verbose import verbose_print

def check_analysis_requirements(verbose: bool = False, show_messages: bool = True) -> bool:
    """
    Purpose:
        Decide whether a scan can start, optionally explaining to the terminal why not.

    Parameters:
        verbose: Includes the full per-tool setup messages in the output.
        show_messages: Prints the failure explanation and waits for Enter.

    Returns:
        True when the required tools are configured.

    Side effects:
        May print to the terminal and block on input.

    Implementation notes:
        The two requirements are checked independently and both are reported, so a user missing both is told about both rather than fixing one and discovering the other. The detailed setup messages appear only under verbose, keeping the default failure short while leaving the full instructions one flag away.

    Known limitations:
        The blocking input call makes this unsuitable for the web path, which uses get_analysis_status instead.
    """
    jadx_ok = check_jadx_configured(verbose=verbose)
    ollama_ok = check_ollama_configured(verbose=verbose)
    
    if jadx_ok and ollama_ok:
        verbose_print("All requirements satisfied for APK Analysis", verbose)
        return True
    
    if show_messages:
        print(f"\n{Colors.ERROR}Configuration Required{Colors.RESET}\n")
        
        if not jadx_ok:
            print(f"{Colors.WARNING}JADX is not configured{Colors.RESET}")
        
        if not ollama_ok:
            print(f"{Colors.WARNING}Ollama API Key is not configured{Colors.RESET}")
        
        print(f"\n{Colors.INFO}Please use {Colors.CYAN}4. Edit Settings{Colors.RESET} {Colors.INFO}to configure required tools{Colors.RESET}")
        
        if verbose:
            print()
            if not jadx_ok:
                get_jadx_setup_message(verbose=True)
                print()
            
            if not ollama_ok:
                get_ollama_setup_message(verbose=True)
                print()
        
        print(f"\n{Colors.CYAN}Press Enter to return to main menu...{Colors.RESET}")
        input()
    
    return False

def get_analysis_status() -> dict:
    """
    Purpose:
        Report the configuration state of every tool as data, for the dashboard's readiness panel.

    Returns:
        A dict with one flag per tool plus an overall readiness flag.

    Side effects:
        Reads settings and stats the configured paths.

    Implementation notes:
        The non-interactive counterpart to check_analysis_requirements: it prints nothing and never blocks, so it is safe to call while serving a request. Every tool is reported, including the optional ones, so the UI can show a Flutter or React Native user what they would gain by configuring more -- while readiness itself depends only on the two required tools.
    """
    jadx_ok = check_jadx_configured(verbose=False)
    ollama_ok = check_ollama_configured(verbose=False)

    return {
        'jadx_configured': jadx_ok,
        'ollama_configured': ollama_ok,
        'blutter_configured': check_blutter_configured(verbose=False),
        'hermes_decomp_configured': check_hermes_configured(verbose=False),
        'rn_decompiler_configured': check_rn_decompiler_configured(verbose=False),
        'ready_for_analysis': jadx_ok and ollama_ok
    }
