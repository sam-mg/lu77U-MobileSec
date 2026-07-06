"""Provider factory — the single seam the rest of the pipeline builds against."""

from typing import Optional

from .base_provider import BaseAIProvider
from .ollama_provider import OllamaProvider
from .claude_provider import ClaudeProvider
from .openai_provider import OpenAIProvider
from .gemini_provider import GeminiProvider
from .custom_provider import CustomProvider
from ..config import user_settings
from ..config import credentials

PROVIDER_CLASSES = {
    "ollama": OllamaProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "custom": CustomProvider,
}

def build_provider(
    name: str,
    verbose: bool = False,
    output_manager=None,
    apk_name: Optional[str] = None,
) -> BaseAIProvider:
    """Construct a provider by name, wiring its config + stored API key."""
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        raise ValueError(f"Unknown provider: {name!r}")
    config = user_settings.get_provider_config(name)
    api_key = credentials.get_api_key(name)
    return cls(
        config=config,
        api_key=api_key,
        verbose=verbose,
        output_manager=output_manager,
        apk_name=apk_name,
    )

def get_active_provider(
    verbose: bool = False,
    output_manager=None,
    apk_name: Optional[str] = None,
) -> BaseAIProvider:
    """Construct the provider currently selected in Settings."""
    return build_provider(
        user_settings.get_active_provider(),
        verbose=verbose,
        output_manager=output_manager,
        apk_name=apk_name,
    )