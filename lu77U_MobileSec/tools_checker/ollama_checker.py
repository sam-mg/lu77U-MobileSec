#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.tools_checker.ollama_checker

Purpose:
    Report whether the active AI provider is usable, and produce provider-specific setup instructions when it is not.

Responsibilities:
    Resolve what "configured" means for each provider family, and render the setup message.

Dependencies:
    os, shutil, ..config.user_settings, ..config.credentials, ..ai.cli_provider for the CLI specs.

Implementation notes:
    The module is named after Ollama for historical reasons; it covers every provider. The old entry point is kept as a thin alias. What counts as configured differs per family, and each branch reflects a real distinction: a local Ollama server needs no credential at all, a custom endpoint needs a URL rather than a key, a CLI provider needs an installed binary rather than either, and the rest need an API key.

Security considerations:
    Only the presence of a credential is tested, never its value, so a readiness check never handles or reveals key material.
"""

import os
import shutil

from ..config import user_settings, credentials
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

def check_ai_provider_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether the active AI provider has what it needs to run.

    Parameters:
        verbose: Traces the provider name and the verdict.

    Returns:
        True when the provider is configured.

    Side effects:
        Reads user settings and the credential store, and may probe PATH.

    Implementation notes:
        Local Ollama returns True unconditionally, because it needs no credential; whether the server is actually running is a separate question answered at request time. A CLI provider counts as configured when either an explicit binary path points at a real file or the binary is on PATH -- the same resolution the provider itself uses, so the check cannot disagree with reality.

    Security considerations:
        Uses has_api_key, which returns only a boolean, so no key is read into this code path. The log line is picked from fixed text rather than formatted from the result, so nothing derived from the credential store reaches the log even if that call ever returns more than a flag.
    """
    name = user_settings.get_active_provider()
    cfg = user_settings.get_provider_config(name)
    verbose_print(f"Active AI provider: {name}", verbose)

    if name == "ollama":
        if cfg.get("mode") == "local":
            return True
        configured = credentials.has_api_key("ollama")
    elif name == "custom":
        configured = bool(cfg.get("base_url"))
    elif name in user_settings.CLI_PROVIDERS:
        from ..ai.cli_provider import CLI_SPECS
        spec = CLI_SPECS.get(name)
        binary_path = cfg.get("binary_path")
        configured = bool(
            (binary_path and os.path.isfile(binary_path))
            or (spec and shutil.which(spec.binary)))
    else:
        configured = credentials.has_api_key(name)

    verbose_print("  Configured: True" if configured else "  Configured: False", verbose)
    return configured

def check_ollama_configured(verbose: bool = False) -> bool:
    """
    Purpose:
        Report whether the active AI provider is configured.

    Parameters:
        verbose: Traces the verdict.

    Returns:
        True when the provider is configured.

    Deprecation:
        Kept as an alias from when Ollama was the only provider. New code should call check_ai_provider_configured, whose name matches what it does.
    """
    return check_ai_provider_configured(verbose=verbose)

def get_ollama_setup_message(verbose: bool = False) -> str:
    """
    Purpose:
        Render setup instructions for whichever provider is active.

    Parameters:
        verbose: Also writes the message to the verbose stream.

    Returns:
        The message text.

    Implementation notes:
        The steps differ by provider family: a CLI provider needs installing and signing in, while an API provider needs a key entered in Settings. Showing generic instructions would send a subscription-CLI user looking for an API key they do not have. For a CLI provider the spec's own sign-in hint is embedded, so the instructions stay correct as CLIs change without this module needing to know how each one authenticates.
    """
    name = user_settings.get_active_provider()
    if name in user_settings.CLI_PROVIDERS:
        from ..ai.cli_provider import CLI_SPECS
        spec = CLI_SPECS.get(name)
        binary = spec.binary if spec else name
        hint = spec.signin_hint if spec else ""
        setup_lines = "\n".join([
            f"  1. Install the {binary} CLI and make sure it's on PATH",
            "     (or set its path directly in Settings)",
            f"  2. {hint}",
            "  3. Open Settings in the web dashboard and select this provider",
        ])
    else:
        setup_lines = "\n".join([
            "  1. Open Settings in the web dashboard",
            "  2. Choose the provider you want and set its API key",
            "     (or, for Custom, its base URL/IP and key)",
            "  3. Optionally switch the active provider or pick a model",
        ])
    message = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AI Provider Configuration Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The active AI provider ("{name}") is not fully configured.

To perform vulnerability analysis:
{setup_lines}

Note: Analysis cannot proceed until the active provider is configured.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
    verbose_print(message, verbose)
    return message

def validate_ollama_before_analysis(require_confirmation: bool = True) -> bool:
    """
    Purpose:
        Gate an analysis on the provider being configured, showing setup instructions and optionally pausing when it is not.

    Parameters:
        require_confirmation: Waits for Enter before returning, so the message is read before a terminal menu redraws over it.

    Returns:
        True when analysis may proceed.

    Side effects:
        Prints the setup message and may block on input.

    Implementation notes:
        The pause exists for the interactive terminal flow, where returning immediately would clear the message before it could be read. Callers in the web path pass False.
    """
    if not check_ai_provider_configured(verbose=False):
        print(get_ollama_setup_message())
        if require_confirmation:
            print(f"\n{Colors.INFO}Press Enter to return to main menu...{Colors.RESET}")
            input()
        return False
    return True
