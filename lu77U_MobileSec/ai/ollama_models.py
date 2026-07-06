"""Ollama model discovery and local-server health checks."""

from typing import List, Optional

import httpx

from .registry import OLLAMA_CLOUD_FALLBACK_MODELS

DEFAULT_LOCAL_HOST = "http://localhost:11434"
_HEALTH_TIMEOUT = 2.0
_LIST_TIMEOUT = 5.0

def is_server_running(host: str = DEFAULT_LOCAL_HOST) -> bool:
    """True if an Ollama server answers at ``host`` (health check)."""
    try:
        resp = httpx.get(host.rstrip("/") + "/", timeout=_HEALTH_TIMEOUT)
        return resp.status_code < 500
    except Exception:
        return False

def _tags(host: str) -> List[dict]:
    """Raw ``/api/tags`` model entries, or [] on any failure."""
    try:
        resp = httpx.get(host.rstrip("/") + "/api/tags", timeout=_LIST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("models", []) or []
    except Exception:
        return []

def list_local_models(host: str = DEFAULT_LOCAL_HOST) -> List[str]:
    """Model names present on the local daemon (includes used ``-cloud`` models)."""
    names = [m.get("name", "") for m in _tags(host)]
    return [n for n in names if n]

def list_used_cloud_models(host: str = DEFAULT_LOCAL_HOST) -> List[str]:
    """Cloud models the user has already pulled/used (``-cloud``/``:cloud`` tagged)."""
    out = []
    for name in list_local_models(host):
        if name.endswith("-cloud") or name.endswith(":cloud"):
            out.append(name)
    return out

def list_models_for_mode(
    mode: str, host: str, api_key: Optional[str] = None,
    local_host: str = DEFAULT_LOCAL_HOST,
) -> List[str]:
    if mode == "local":
        return list_local_models(host)

    used = list_used_cloud_models(local_host)
    combined = list(used)
    for name in OLLAMA_CLOUD_FALLBACK_MODELS:
        if name not in combined:
            combined.append(name)
    return combined