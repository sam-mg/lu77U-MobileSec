#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.ollama_models

Purpose:
    Discover which Ollama models are actually available, so the settings UI can offer real choices instead of a free-text field the user can get wrong.

Responsibilities:
    Probe a local Ollama server for liveness, list its installed models, and produce a combined list for cloud mode.

Dependencies:
    httpx, .registry for the cloud fallback list.

Implementation notes:
    Every network call is guarded and returns an empty result on failure. This module runs while rendering a settings page, where a missing or slow Ollama server is routine and must degrade to an empty list rather than an error page. The timeouts are short -- two seconds for liveness, five for listing -- for the same reason: a page that blocks on an unreachable host is worse than one that shows nothing.

Security considerations:
    Requests go to a user-configured host, typically localhost. No credential is sent by these probes; the API key parameter on the mode helper is accepted for interface symmetry and is not used.
"""

from typing import List, Optional

import httpx

from .registry import OLLAMA_CLOUD_FALLBACK_MODELS

DEFAULT_LOCAL_HOST = "http://localhost:11434"
_HEALTH_TIMEOUT = 2.0
_LIST_TIMEOUT = 5.0

def is_server_running(host: str = DEFAULT_LOCAL_HOST) -> bool:
    """
    Purpose:
        Check whether an Ollama server is reachable.

    Parameters:
        host: Base URL to probe.

    Returns:
        True when the host answered with anything below a 500.

    Implementation notes:
        Any sub-500 response counts as running, including a 404. The check is for a process listening and answering HTTP, not for a particular route, and Ollama versions differ in what they serve at the root. Every exception is swallowed, since connection refused and DNS failure are the expected negative answers rather than errors.
    """
    try:
        resp = httpx.get(host.rstrip("/") + "/", timeout=_HEALTH_TIMEOUT)
        return resp.status_code < 500
    except Exception:
        return False

def _tags(host: str) -> List[dict]:
    """
    Purpose:
        Fetch the raw model list from an Ollama server.

    Parameters:
        host: Base URL of the server.

    Returns:
        The server's model entries, or an empty list on any failure.

    Implementation notes:
        The guard covers connection failure, a non-200 status and a response that is not the expected JSON shape, so every caller can treat an empty list as "nothing available" without distinguishing why.
    """
    try:
        resp = httpx.get(host.rstrip("/") + "/api/tags", timeout=_LIST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("models", []) or []
    except Exception:
        return []

def list_local_models(host: str = DEFAULT_LOCAL_HOST) -> List[str]:
    """
    Purpose:
        List the models installed on a local Ollama server.

    Parameters:
        host: Base URL of the server.

    Returns:
        Model names, or an empty list when the server is unreachable or has none.

    Implementation notes:
        Entries with no name are dropped rather than yielding empty strings, which would render as blank options in the settings UI.
    """
    names = [m.get("name", "") for m in _tags(host)]
    return [n for n in names if n]

def list_used_cloud_models(host: str = DEFAULT_LOCAL_HOST) -> List[str]:
    """
    Purpose:
        Find the cloud-hosted models this user has already pulled, so the cloud list leads with models they have shown interest in.

    Parameters:
        host: Base URL of the local server.

    Returns:
        Names of locally-known models that are cloud-backed.

    Implementation notes:
        Recognised by the -cloud and :cloud name suffixes, which is how Ollama marks cloud-backed models. There is no local API that reports this otherwise.
    """
    out = []
    for name in list_local_models(host):
        if name.endswith("-cloud") or name.endswith(":cloud"):
            out.append(name)
    return out

def list_models_for_mode(
    mode: str, host: str, api_key: Optional[str] = None,
    local_host: str = DEFAULT_LOCAL_HOST,
) -> List[str]:
    """
    Purpose:
        Produce the model list the settings UI should show for the selected Ollama mode.

    Parameters:
        mode: "local" or anything else, which is treated as cloud.
        host: Base URL for local mode.
        api_key: Accepted for interface symmetry with other providers; unused, because the cloud list is assembled from local knowledge and a static fallback rather than fetched.
        local_host: Local server consulted in cloud mode to find already-pulled cloud models.

    Returns:
        Model names, most relevant first. Never empty in cloud mode, since the static fallback always applies.

    Implementation notes:
        Cloud mode merges the user's already-pulled cloud models with the curated fallback list, in that order, so familiar choices appear first. Duplicates are removed by membership test rather than by set, to keep that ordering stable across runs. Local mode returns exactly what the server reports, with no fallback: offering a model that is not installed would fail at request time.
    """
    if mode == "local":
        return list_local_models(host)

    used = list_used_cloud_models(local_host)
    combined = list(used)
    for name in OLLAMA_CLOUD_FALLBACK_MODELS:
        if name not in combined:
            combined.append(name)
    return combined
