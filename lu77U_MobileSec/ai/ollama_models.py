#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.ollama_models

Purpose:
    Discover which Ollama models are actually available, so the settings UI can offer real choices instead of a free-text field the user can get wrong.

Responsibilities:
    Probe a local Ollama server for liveness, list its installed models, and fetch Ollama's live cloud catalogue for cloud mode.

Dependencies:
    httpx.

Implementation notes:
    Every network call is guarded and returns an empty result on failure. This module runs while rendering a settings page, where a missing or slow Ollama server is routine and must degrade to an empty list rather than an error page. The timeouts are short -- two seconds for liveness, five for listing -- for the same reason: a page that blocks on an unreachable host is worse than one that shows nothing. The cloud list is fetched rather than curated: a curated list went entirely stale within months, offering retired models that answered 410, while the cloud host serves its current catalogue from the same /api/tags route a local server uses.

Security considerations:
    Requests go to a user-configured host: localhost, or the configured Ollama cloud host. No credential is sent by these probes -- the cloud catalogue is public -- and the API key parameter on the mode helper is accepted for interface symmetry and is not used.
"""

from typing import List, Optional

import httpx

DEFAULT_LOCAL_HOST = "http://localhost:11434"
_HEALTH_TIMEOUT = 2.0
_LIST_TIMEOUT = 5.0
_CLOUD_SUFFIXES = (":cloud", "-cloud")

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

def list_cloud_models(host: str) -> List[str]:
    """
    Purpose:
        Fetch the models Ollama's cloud currently serves.

    Parameters:
        host: Base URL of the cloud API, the provider's configured cloud host.

    Returns:
        Model names in the form the cloud API accepts, or an empty list when the catalogue cannot be fetched.

    Implementation notes:
        Entries that declare capabilities without "completion" are dropped, since the analysis needs a model that generates text and an embedding-only model would fail on the first request. Entries that declare no capabilities are kept, because older servers omit the field and dropping them would empty the list. Nothing here says which models the user's plan includes -- a free plan is refused most of them -- so the list is what exists, not what will succeed.
    """
    names = []
    for entry in _tags(host):
        name = entry.get("name", "")
        capabilities = entry.get("capabilities")
        if not name or (isinstance(capabilities, list) and "completion" not in capabilities):
            continue
        names.append(name)
    return names

def _cloud_api_name(name: str) -> str:
    """
    Purpose:
        Convert a locally pulled cloud model's name to the name the cloud API itself uses.

    Parameters:
        name: The local name, such as gpt-oss:120b-cloud.

    Returns:
        The name without the local cloud suffix, such as gpt-oss:120b.

    Implementation notes:
        A local Ollama install marks a cloud-backed model with a -cloud or :cloud suffix, but this provider talks to the cloud host directly in cloud mode, where the catalogue lists the bare name.
    """
    for suffix in _CLOUD_SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name

def list_models_for_mode(
    mode: str, host: str, api_key_unused: Optional[str] = None,
    local_host: str = DEFAULT_LOCAL_HOST,
) -> List[str]:
    """
    Purpose:
        Produce the model list the settings UI should show for the selected Ollama mode.

    Parameters:
        mode: "local" or anything else, which is treated as cloud.
        host: Base URL for local mode.
        api_key_unused: Accepted for interface symmetry with other providers; unused, because Ollama's cloud catalogue is public.
        local_host: Local server consulted in cloud mode to find already-pulled cloud models.

    Returns:
        Model names, most relevant first; empty when the server or catalogue cannot be reached.

    Implementation notes:
        Cloud mode fetches the live catalogue from the configured cloud host and puts the user's already-pulled cloud models first, renamed to the cloud API's form, so familiar choices lead; a pulled model the catalogue no longer lists is dropped, because it has been retired and would fail. The rest is sorted, since the catalogue's own order changes between requests. An empty result is safe: the settings page still accepts a typed model name. Local mode returns exactly what the server reports: offering a model that is not installed would fail at request time.
    """
    if mode == "local":
        return list_local_models(host)

    live = list_cloud_models(host)
    pulled = [_cloud_api_name(name) for name in list_used_cloud_models(local_host)]
    first = [name for name in dict.fromkeys(pulled) if name in live]
    return first + [name for name in sorted(live) if name not in first]
