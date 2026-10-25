#!/usr/bin/env python3
"""
Module: test_ollama_models

Purpose:
    The Ollama model chooser: the live cloud catalogue, the local install's models, and how the two are combined for cloud mode.

Responsibilities:
    Pin that the cloud list is fetched from the configured cloud host without a credential, that text-generation models are kept and others dropped, that pulled cloud models lead under the cloud API's names and retired ones disappear, that failures degrade to an empty list, that the default is a name the cloud API accepts, and that a fresh install actually ends up on that default.

Dependencies:
    pytest, the Ollama model module, the provider registry and the user settings module.

Implementation notes:
    httpx.get is replaced with a fake that answers by URL, so nothing reaches the network. The catalogue fixture is shaped like the real /api/tags response, including the capabilities field the filter reads.
"""

import pytest

from lu77U_MobileSec.ai import ollama_models
from lu77U_MobileSec.ai.registry import DEFAULT_MODELS

CLOUD = "https://api.ollama.com"
LOCAL = "http://localhost:11434"

CATALOGUE = {"models": [
    {"name": "kimi-k3", "capabilities": ["vision", "thinking", "completion", "tools"]},
    {"name": "gpt-oss:120b", "capabilities": ["completion", "tools", "thinking"]},
    {"name": "embed-large", "capabilities": ["embedding"]},
    {"name": "legacy-model"},
    {"name": "", "capabilities": ["completion"]},
    {"name": "gemma4:31b", "capabilities": ["completion"]},
]}

PULLED = {"models": [
    {"name": "gpt-oss:120b-cloud"},
    {"name": "glm-4.6:cloud"},
    {"name": "llama3:8b"},
]}


class FakeResponse:
    """
    Purpose:
        A minimal httpx response.

    Attributes:
        status_code: The HTTP status.
        payload: The JSON body.
    """
    def __init__(self, payload, status_code=200):
        """
        Purpose:
            Build the response.

        Parameters:
            payload: The JSON body.
            status_code: The HTTP status.
        """
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        """
        Purpose:
            Raise for an error status, as httpx does.

        Raises:
            RuntimeError: When the status is 400 or above.
        """
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        """
        Purpose:
            Return the body.

        Returns:
            The JSON payload.
        """
        return self.payload


@pytest.fixture
def fake_get(monkeypatch):
    """
    Purpose:
        Answer /api/tags by host and record every request.

    Parameters:
        monkeypatch: Replaces httpx.get in the module under test.

    Returns:
        A dict of host to payload the test may change, and the request log under the "calls" key.
    """
    state = {CLOUD: CATALOGUE, LOCAL: PULLED, "calls": []}

    def get(url, **kwargs):
        """
        Purpose:
            Serve the payload configured for the requested host.

        Parameters:
            url: The requested URL.
            kwargs: The request options, recorded so a test can check no credential was sent.

        Returns:
            The fake response.

        Raises:
            ConnectionError: When the host has no payload, as an unreachable server would.
        """
        state["calls"].append((url, kwargs))
        host = url[:-len("/api/tags")]
        if state.get(host) is None:
            raise ConnectionError(host)
        return FakeResponse(state[host])

    monkeypatch.setattr(ollama_models.httpx, "get", get)
    return state


class TestCloudCatalogue:
    """
    Purpose:
        Fetching the models Ollama's cloud serves.
    """
    def test_text_models_from_the_configured_host_without_a_credential(self, fake_get):
        """
        Purpose:
            Pin the URL, the absence of an auth header, and the capability filter.

        Parameters:
            fake_get: The fake transport.
        """
        names = ollama_models.list_cloud_models(CLOUD)
        assert names == ["kimi-k3", "gpt-oss:120b", "legacy-model", "gemma4:31b"]
        url, kwargs = fake_get["calls"][0]
        assert url == CLOUD + "/api/tags"
        assert "headers" not in kwargs and "auth" not in kwargs

    def test_unreachable_catalogue_is_empty(self, fake_get):
        """
        Purpose:
            Pin that a failed fetch yields an empty list rather than an error.

        Parameters:
            fake_get: The fake transport, told the cloud host is down.
        """
        fake_get[CLOUD] = None
        assert ollama_models.list_cloud_models(CLOUD) == []


class TestModelsForMode:
    """
    Purpose:
        The list the settings page shows for each Ollama mode.
    """
    @pytest.mark.usefixtures("fake_get")
    def test_cloud_mode_leads_with_pulled_models_under_cloud_names(self):
        """
        Purpose:
            Pin that a pulled cloud model leads under the cloud API's name, a retired pulled model is dropped, a local-only model is not offered, and the rest is sorted.
        """
        names = ollama_models.list_models_for_mode("cloud", CLOUD, local_host=LOCAL)
        assert names == ["gpt-oss:120b", "gemma4:31b", "kimi-k3", "legacy-model"]

    def test_cloud_mode_without_a_local_server(self, fake_get):
        """
        Purpose:
            Pin that the catalogue alone is offered when no local server answers.

        Parameters:
            fake_get: The fake transport, told the local server is down.
        """
        fake_get[LOCAL] = None
        names = ollama_models.list_models_for_mode("cloud", CLOUD, local_host=LOCAL)
        assert names == ["gemma4:31b", "gpt-oss:120b", "kimi-k3", "legacy-model"]

    def test_cloud_mode_with_the_catalogue_down_is_empty(self, fake_get):
        """
        Purpose:
            Pin that nothing stale is offered when the catalogue cannot be fetched.

        Parameters:
            fake_get: The fake transport, told the cloud host is down.

        Implementation notes:
            The settings page still accepts a typed name, so an empty list costs suggestions only, where a stale list offered retired models.
        """
        fake_get[CLOUD] = None
        assert ollama_models.list_models_for_mode("cloud", CLOUD, local_host=LOCAL) == []

    def test_local_mode_is_exactly_what_is_installed(self, fake_get):
        """
        Purpose:
            Pin that local mode offers the installed models unchanged and never consults the cloud.

        Parameters:
            fake_get: The fake transport.
        """
        assert ollama_models.list_models_for_mode("local", LOCAL) == [
            "gpt-oss:120b-cloud", "glm-4.6:cloud", "llama3:8b"]
        assert all(not url.startswith(CLOUD) for url, _ in fake_get["calls"])


@pytest.mark.parametrize("local, cloud", [
    ("gpt-oss:120b-cloud", "gpt-oss:120b"),
    ("glm-4.6:cloud", "glm-4.6"),
    ("deepseek-v3.1:671b-cloud", "deepseek-v3.1:671b"),
    ("gemma4:31b", "gemma4:31b"),
])
def test_cloud_api_name(local, cloud):
    """
    Purpose:
        Pin the conversion from a local install's cloud model name to the cloud API's.

    Parameters:
        local: The name a local install shows.
        cloud: The name the cloud API lists.
    """
    assert ollama_models._cloud_api_name(local) == cloud


def test_default_is_a_cloud_api_name():
    """
    Purpose:
        Pin that the default carries no local cloud suffix, since cloud mode sends it to the cloud host directly.

    Implementation notes:
        The previous default carried the local suffix and named a model the cloud had since retired, so a fresh install's first scan failed.
    """
    assert DEFAULT_MODELS["ollama"]
    assert ollama_models._cloud_api_name(DEFAULT_MODELS["ollama"]) == DEFAULT_MODELS["ollama"]


def test_fresh_install_resolves_to_the_registry_default(monkeypatch, tmp_path):
    """
    Purpose:
        Pin that a machine with no settings file yet ends up scanning with the registry default, not a model seeded from the legacy settings module.

    Parameters:
        monkeypatch: Redirects the settings path and clears the settings cache.
        tmp_path: An empty directory standing in for the per-user configuration directory.

    Implementation notes:
        The first load seeds a new settings file from the legacy module, and a configured model wins over the registry default. A retired model left in the legacy module therefore reached every fresh install even after the registry default was fixed, which the test above cannot see because it reads the registry alone.

    Security considerations:
        The real settings file is never read or written; it sits alongside the user's credentials.
    """
    from lu77U_MobileSec.config import user_settings

    monkeypatch.setattr(user_settings, "get_settings_path", lambda: tmp_path / "settings.json")
    monkeypatch.setattr(user_settings, "_cache", None)
    seeded = user_settings.load()["providers"]["ollama"]["model"]
    monkeypatch.setattr(user_settings, "_cache", None)
    assert (seeded or DEFAULT_MODELS["ollama"]) == DEFAULT_MODELS["ollama"]
