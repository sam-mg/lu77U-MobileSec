"""Provider display metadata and curated model lists."""

#: Human-readable provider names for menus.
PROVIDER_DISPLAY_NAMES = {
    "ollama": "Ollama (local or cloud)",
    "claude": "Claude (Anthropic)",
    "openai": "OpenAI",
    "gemini": "Google Gemini",
    "custom": "Custom (OpenAI-compatible endpoint)",
}

CURATED_MODELS = {
    "claude": [
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4.1",
        "o4-mini",
    ],
    "gemini": [
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
    ],
}

OLLAMA_CLOUD_FALLBACK_MODELS = [
    "deepseek-v3.1:671b-cloud",
    "gpt-oss:20b-cloud",
    "gpt-oss:120b-cloud",
    "kimi-k2:1t-cloud",
    "qwen3-coder:480b-cloud",
    "glm-4.6:cloud",
    "minimax-m2:cloud",
]

DEFAULT_MODELS = {
    "ollama": "glm-4.6:cloud",
    "claude": "claude-opus-4-8",
    "openai": "gpt-4o",
    "gemini": "gemini-2.5-flash",
    "custom": "",
}