#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.registry

Purpose:
    Static catalogue of the AI providers the tool supports: their display names, how vendors group into API and CLI variants, curated model lists, defaults, and presets for OpenAI-compatible endpoints.

Responsibilities:
    Declare data only, for the settings UI and the provider factory to read.

Dependencies:
    None.

Implementation notes:
    Kept as data with no logic so the settings UI can render the provider chooser without importing any provider module, and therefore without importing any provider SDK. PROVIDER_VENDORS exists because one vendor can be reached two ways -- an API key or a subscription CLI -- and the UI groups them under the vendor while the rest of the tool keeps them as distinct providers. Model lists are curated rather than fetched. A live list needs a credential and a network round trip before the user has configured anything, so these give the settings page something useful to show immediately. They go stale, which is why a user can always type a model name that is not listed.

Security considerations:
    CUSTOM_PRESETS ship third-party base URLs. Selecting one sends decompiled application source to that operator, so the presets are conveniences the user opts into, never defaults.
"""

PROVIDER_DISPLAY_NAMES = {
    "ollama": "Ollama (local or cloud)",
    "claude": "Claude (Anthropic)",
    "openai": "OpenAI",
    "gemini": "Google Gemini",
    "custom": "Custom (OpenAI-compatible endpoint)",
    "claude_cli": "Claude Code CLI (Claude Pro/Max)",
    "copilot_cli": "GitHub Copilot CLI (Copilot Pro)",
    "kimi_cli": "Kimi CLI (Kimi Plus/Pro/Max/Ultra)",
    "codex_cli": "Codex CLI (ChatGPT Plus/Pro)",
    "antigravity_cli": "Antigravity CLI (Google AI Pro/Ultra)",
}

PROVIDER_VENDORS = (
    {"id": "ollama", "label": "Ollama", "api": "ollama"},
    {"id": "claude", "label": "Claude", "api": "claude", "cli": "claude_cli"},
    {"id": "openai", "label": "OpenAI", "api": "openai", "cli": "codex_cli"},
    {"id": "google", "label": "Google", "api": "gemini", "cli": "antigravity_cli"},
    {"id": "copilot", "label": "GitHub Copilot", "cli": "copilot_cli"},
    {"id": "kimi", "label": "Kimi", "cli": "kimi_cli"},
    {"id": "custom", "label": "Custom", "api": "custom"},
)

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
    "claude_cli": "opus",
    "copilot_cli": "",
    "kimi_cli": "",
    "codex_cli": "",
    "antigravity_cli": "",
}

CUSTOM_PRESETS = [
    {
        "label": "Groq (free tier)",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
    },
    {
        "label": "OpenRouter (free models)",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
    },
    {
        "label": "Together AI (free tier)",
        "base_url": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",
    },
]
