"""Structured, per-user settings for lu77U-MobileSec."""

import copy
import json
from typing import Any, Dict, Optional

from .paths import get_settings_path

PROVIDERS = ("ollama", "claude", "openai", "gemini", "custom")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "active_provider": "ollama",
    "providers": {
        "ollama": {
            "mode": "cloud",                     # "cloud" | "local"
            "model": "",
            "cloud_host": "https://api.ollama.com",
            "local_host": "http://localhost:11434",
        },
        "claude": {"model": ""},
        "openai": {"model": ""},
        "gemini": {"model": ""},
        "custom": {"model": "", "base_url": ""},
    },
    "jadx_path": "",
    "output_dir": "",
    "pdf_generation": True,
    "dynamic_verification": True,
    "agent_memory": True,
    "prompt_overrides": {},
}

_cache: Optional[Dict[str, Any]] = None

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` onto a copy of ``base`` (defaults win for
    keys absent from override, so new fields appear after an upgrade)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def _migrate_from_legacy() -> Dict[str, Any]:
    """Seed defaults from the legacy ``config/settings.py`` constants on first
    run so existing users keep their JADX path and Ollama model. Secrets are
    never migrated (the key is a placeholder after the Phase 0 scrub)."""
    seeded = copy.deepcopy(DEFAULT_SETTINGS)
    try:
        from . import settings as legacy
        jadx = getattr(legacy, "JADX_PATH", "")
        if jadx and jadx != "path_goes_here":
            seeded["jadx_path"] = jadx
        model = getattr(legacy, "AI_MODEL_OLLAMA_ID", "")
        if model:
            seeded["providers"]["ollama"]["model"] = model
        host = getattr(legacy, "OLLAMA_API_HOST", "")
        if host:
            seeded["providers"]["ollama"]["cloud_host"] = host
    except Exception:
        pass
    return seeded

def load(force: bool = False) -> Dict[str, Any]:
    """Load settings (cached). Creates the file from migrated defaults on first
    use, and back-fills any keys added in newer versions."""
    global _cache
    if _cache is not None and not force:
        return _cache

    path = get_settings_path()
    if path.exists():
        try:
            on_disk = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            on_disk = {}
        _cache = _deep_merge(DEFAULT_SETTINGS, on_disk)
    else:
        _cache = _migrate_from_legacy()
        save(_cache)
    return _cache

def save(data: Optional[Dict[str, Any]] = None) -> None:
    """Persist settings to disk and refresh the cache."""
    global _cache
    if data is not None:
        _cache = data
    get_settings_path().write_text(
        json.dumps(_cache, indent=2, sort_keys=True), encoding="utf-8"
    )

def get_active_provider() -> str:
    return load().get("active_provider", "ollama")

def set_active_provider(name: str) -> None:
    if name not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name!r}")
    data = load()
    data["active_provider"] = name
    save(data)

def get_provider_config(name: str) -> Dict[str, Any]:
    return copy.deepcopy(load().get("providers", {}).get(name, {}))

def set_provider_field(name: str, field: str, value: Any) -> None:
    data = load()
    data.setdefault("providers", {}).setdefault(name, {})[field] = value
    save(data)

def get_jadx_path() -> str:
    return load().get("jadx_path", "")

def set_jadx_path(path: str) -> None:
    data = load()
    data["jadx_path"] = path
    save(data)

def get_output_dir() -> str:
    """User-configured base directory for scan output (empty = default)."""
    return load().get("output_dir", "")

def set_output_dir(path: str) -> None:
    data = load()
    data["output_dir"] = path or ""
    save(data)

def get_pdf_generation() -> bool:
    return bool(load().get("pdf_generation", True))

def set_pdf_generation(enabled: bool) -> None:
    data = load()
    data["pdf_generation"] = bool(enabled)
    save(data)

def get_dynamic_verification() -> bool:
    """Whether the merged scan should run Phase 2 (dynamic verification) when
    a device/emulator is available."""
    return bool(load().get("dynamic_verification", True))

def set_dynamic_verification(enabled: bool) -> None:
    data = load()
    data["dynamic_verification"] = bool(enabled)
    save(data)

def get_agent_memory() -> bool:
    """Whether Phase 2 also receives Phase 1's investigation transcript as
    extra context, in addition to the static findings themselves."""
    return bool(load().get("agent_memory", True))

def set_agent_memory(enabled: bool) -> None:
    data = load()
    data["agent_memory"] = bool(enabled)
    save(data)

def get_prompt_override(prompt_id: str) -> Optional[str]:
    """The user-saved replacement text for ``prompt_id``, or ``None`` if the
    prompt hasn't been customized (use the built-in default)."""
    text = load().get("prompt_overrides", {}).get(prompt_id)
    return text if text else None

def set_prompt_override(prompt_id: str, text: str) -> None:
    data = load()
    data.setdefault("prompt_overrides", {})[prompt_id] = text
    save(data)

def clear_prompt_override(prompt_id: str) -> None:
    """Revert ``prompt_id`` back to its built-in default."""
    data = load()
    data.get("prompt_overrides", {}).pop(prompt_id, None)
    save(data)