#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.provider_factory

Purpose:
    Construct a ready-to-use provider from stored configuration and credentials, so that no caller has to know which provider class to instantiate or where its API keys live.

Responsibilities:
    Map provider identifiers to classes, resolve configuration and credentials, apply the cheap-model substitution, and build the instance.

Dependencies:
    Every provider module, ..config.user_settings and ..config.credentials.

Implementation notes:
    This module imports every provider eagerly, and therefore transitively every provider SDK that is installed. That is why the ai package facade does not re-export it implicitly and why credential lookup happens here rather than at import time.

Security considerations:
    This is the single point where API keys leave the keychain and enter a provider object. Keys are passed as a list to support rotation, and no key is logged here or by anything this module calls directly.
"""

from typing import Optional

from .base_provider import BaseAIProvider
from .ollama_provider import OllamaProvider
from .claude_provider import ClaudeProvider
from .openai_provider import OpenAIProvider
from .gemini_provider import GeminiProvider
from .custom_provider import CustomProvider
from .cli_provider import (
    ClaudeCliProvider,
    CopilotCliProvider,
    KimiCliProvider,
    CodexCliProvider,
    AntigravityCliProvider,
)
from ..config import user_settings
from ..config import credentials

PROVIDER_CLASSES = {
    "ollama": OllamaProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "custom": CustomProvider,
    "claude_cli": ClaudeCliProvider,
    "copilot_cli": CopilotCliProvider,
    "kimi_cli": KimiCliProvider,
    "codex_cli": CodexCliProvider,
    "antigravity_cli": AntigravityCliProvider,
}

def build_provider(
    name: str,
    verbose: bool = False,
    output_manager=None,
    apk_name: Optional[str] = None,
    cheap: bool = False,
) -> BaseAIProvider:
    """
    Purpose:
        Build a provider instance by name, wired to its stored settings and credentials.

    Parameters:
        name: Provider identifier.
        verbose: Enables provider-level tracing.
        output_manager: Supplies the paths for request and response transcripts; None disables transcript logging.
        apk_name: Labels transcripts with the APK under analysis.
        cheap: Selects the provider's cheap model instead of its main one, for high-volume, low-stakes calls.

    Returns:
        A configured provider.

    Raises:
        ValueError: When the identifier is unknown. Raised here so the failure names the provider, rather than surfacing later as a None attribute error.

    Side effects:
        Reads user settings and the credential store.

    Implementation notes:
        The cheap substitution overwrites the model field in a copy of the config -- get_provider_config already returns a deep copy, so the stored settings are untouched. It is applied only when a cheap model is actually configured, so leaving the field blank transparently falls back to the main model instead of sending an empty model name.

    Security considerations:
        Retrieves live API keys. The returned provider holds them in memory for its lifetime.
    """
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        raise ValueError(f"Unknown provider: {name!r}")
    config = user_settings.get_provider_config(name)
    if cheap:
        cheap_model = str(config.get("cheap_model") or "").strip()
        if cheap_model:
            config["model"] = cheap_model
    return cls(
        config=config,
        api_keys=credentials.get_api_keys(name),
        verbose=verbose,
        output_manager=output_manager,
        apk_name=apk_name,
    )

def get_active_provider(
    verbose: bool = False,
    output_manager=None,
    apk_name: Optional[str] = None,
    cheap: bool = False,
) -> BaseAIProvider:
    """
    Purpose:
        Build whichever provider the user has selected.

    Parameters:
        verbose: Enables provider-level tracing.
        output_manager: Supplies transcript paths.
        apk_name: Labels transcripts with the APK under analysis.
        cheap: Selects the cheap model variant.

    Returns:
        A configured provider.

    Raises:
        ValueError: When the stored active provider is not a known identifier, which can happen after a downgrade that removed a provider.

    Side effects:
        Reads user settings and the credential store.
    """
    return build_provider(
        user_settings.get_active_provider(),
        verbose=verbose,
        output_manager=output_manager,
        apk_name=apk_name,
        cheap=cheap,
    )
