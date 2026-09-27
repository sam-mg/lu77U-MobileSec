#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai

Purpose:
    Facade for the AI provider layer: the abstract provider contract, the response schema, the factory that resolves the configured provider, and the local Ollama provider.

Responsibilities:
    Re-export the provider base class, VULNERABILITY_SCHEMA, DEFAULT_SYSTEM_MESSAGE, the factory helpers and OllamaProvider.

Dependencies:
    .base_provider, .schema, .provider_factory, .ollama_provider.

Implementation notes:
    OllamaProvider is the only concrete provider re-exported because it is the local default and has no credential requirement. Remote providers are reached through build_provider so that credential resolution always runs.

Security considerations:
    Importing this package must not read any API key. Credentials are resolved inside build_provider, at call time.
"""

from .base_provider import BaseAIProvider
from .schema import VULNERABILITY_SCHEMA, DEFAULT_SYSTEM_MESSAGE
from .provider_factory import build_provider, get_active_provider, PROVIDER_CLASSES
from .ollama_provider import OllamaProvider

__all__ = [
    "BaseAIProvider",
    "VULNERABILITY_SCHEMA",
    "DEFAULT_SYSTEM_MESSAGE",
    "build_provider",
    "get_active_provider",
    "PROVIDER_CLASSES",
    "OllamaProvider",
]
