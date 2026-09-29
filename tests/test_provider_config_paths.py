#!/usr/bin/env python3
"""
Module: test_provider_config_paths

Purpose:
    The provider, credential and output-path fixes made while clearing the static-analysis findings: the ones that changed behaviour, and the refactors whose contract must survive.

Responsibilities:
    Pin that a zero retry budget returns an error instead of looping, that a failed keychain delete is reported unless there was nothing to delete, that the keychain fallback warning prints once, that the output base honours the setting and falls back when it is empty, that the config modules no longer import each other, that a CLI provider's default model is still reachable from an instance, and that a failed custom-endpoint listing is traced.

Dependencies:
    pytest, the Ollama, CLI and custom providers, the credentials, settings and paths modules, and the scan store.

Security considerations:
    Every keychain interaction is faked and the fallback store is replaced, so nothing here reads, writes or deletes a real stored API key, and the output base is redirected into a temporary directory.
"""

import ast
import types
from pathlib import Path

import pytest
from keyring.errors import KeyringError, PasswordDeleteError

from lu77U_MobileSec.ai import cli_provider, custom_provider, ollama_provider
from lu77U_MobileSec.config import credentials, paths, user_settings
from lu77U_MobileSec.web import store


@pytest.fixture
def fresh_fallback_warning():
    """
    Purpose:
        Reset the once-per-process keychain fallback warning around a test.

    Returns:
        The cached warning function.

    Side effects:
        Clears the function's cache before the test and again after it.

    Implementation notes:
        The warning's once-only behaviour lives in functools.cache, so an earlier test that took the fallback path would otherwise leave it already spent. Clearing afterwards keeps this test from spending it for whatever runs next.
    """
    credentials._warn_fallback_once.cache_clear()
    yield credentials._warn_fallback_once
    credentials._warn_fallback_once.cache_clear()


class TestOllamaZeroRetries:
    """
    Purpose:
        A retry budget of zero, which previously made analyze spin forever.
    """
    def test_zero_retries_returns_an_error_instead_of_looping(self, monkeypatch):
        """
        Purpose:
            Pin that with no attempts allowed the attempt helper returns an error dict and analyze returns it, without the client ever being called.

        Parameters:
            monkeypatch: Sets the retry budget to zero.

        Implementation notes:
            The helper is checked directly first. Falling off the end of its loop returned None, which analyze reads as a key rotation and re-enters, so asserting on analyze alone would hang the suite instead of failing it if the fix regressed.
        """
        monkeypatch.setattr(ollama_provider, "OLLAMA_MAX_RETRIES", 0)
        calls = []

        class _Client:
            """
            Purpose:
                A client that records any call made to it.
            """
            def chat(self, model, **_unused_kwargs):
                """
                Purpose:
                    Record that a request was attempted.

                Parameters:
                    model: The model name.
                    _unused_kwargs: The call keywords, unused by the fake.

                Returns:
                    An empty stream.

                Side effects:
                    Records the model name.
                """
                calls.append(model)
                return iter(())

        prov = ollama_provider.OllamaProvider(
            config={"mode": "cloud"}, api_keys=["k"], verbose=False)
        prov._client = _Client()

        direct = prov._attempt_with_current_key("p", "s", None, None)
        assert direct is not None
        assert "OLLAMA_MAX_RETRIES=0" in direct["error"]

        outcome = prov.analyze("p", system_message="s")
        assert "OLLAMA_MAX_RETRIES=0" in outcome["error"]
        assert calls == []


class TestKeychainDelete:
    """
    Purpose:
        Deleting a provider's key when the keychain refuses.
    """
    @staticmethod
    def _install(monkeypatch, error):
        """
        Purpose:
            Fake a keychain whose delete raises the given error, and record fallback-store deletes.

        Parameters:
            monkeypatch: Replaces the keychain, its availability check and the fallback delete.
            error: The exception the keychain delete raises.

        Returns:
            The list the fallback delete appends provider names to.

        Security considerations:
            Replacing both stores keeps the test away from the user's real keychain and fallback file.
        """
        deleted = []

        def _delete_password(_, __):
            """
            Purpose:
                Stand in for the keychain delete by raising.

            Parameters:
                _: The keychain service name, unused by the stand-in.
                __: The entry name, unused by the stand-in.

            Raises:
                Exception: The error the test configured.
            """
            raise error

        def _fallback_delete(provider):
            """
            Purpose:
                Record a fallback-store delete instead of touching the file.

            Parameters:
                provider: The provider identifier.

            Side effects:
                Appends to the recorded list.
            """
            deleted.append(provider)

        monkeypatch.setattr(credentials, "keyring_available", lambda: True)
        monkeypatch.setattr(
            credentials, "keyring", types.SimpleNamespace(delete_password=_delete_password))
        monkeypatch.setattr(credentials, "_fallback_delete", _fallback_delete)
        return deleted

    @pytest.mark.parametrize("error", [
        RuntimeError("backend exploded"),
        KeyringError("keychain is locked"),
    ])
    def test_a_real_failure_warns_and_still_clears_the_fallback(self, monkeypatch, capsys, error):
        """
        Purpose:
            Pin that a keychain delete failing for any reason other than a missing entry prints a warning naming the provider, and that the fallback store is still cleared.

        Parameters:
            monkeypatch: Installs the fake keychain.
            capsys: Captures the warning.
            error: The failure the keychain raises.

        Implementation notes:
            This used to be swallowed, leaving a key the user believed they had removed still stored in the keychain with nothing to say so.
        """
        deleted = self._install(monkeypatch, error)
        credentials.delete_api_key("claude")
        out = capsys.readouterr().out
        assert "Could not remove the claude key from the OS keychain" in out
        assert deleted == ["claude"]

    def test_nothing_to_delete_stays_silent(self, monkeypatch, capsys):
        """
        Purpose:
            Pin that the keychain reporting there was no entry to delete prints nothing, and that the fallback store is still cleared.

        Parameters:
            monkeypatch: Installs the fake keychain.
            capsys: Captures any output.

        Implementation notes:
            A provider whose key lives only in the fallback store has no keychain entry, so this is the normal case and must not produce a false alarm.
        """
        deleted = self._install(monkeypatch, PasswordDeleteError("not found"))
        credentials.delete_api_key("claude")
        out = capsys.readouterr().out
        assert out == ""
        assert deleted == ["claude"]


class TestFallbackWarning:
    """
    Purpose:
        The one-time warning that keys are going to a file instead of a keychain.
    """
    def test_prints_once_across_calls(self, monkeypatch, capsys, tmp_path, fresh_fallback_warning):
        """
        Purpose:
            Pin that two calls print the warning exactly once, and that clearing the cache arms it again.

        Parameters:
            monkeypatch: Redirects the config directory the warning names.
            capsys: Captures the warning.
            tmp_path: Stands in for the config directory.
            fresh_fallback_warning: The warning function, with its cache cleared.
        """
        monkeypatch.setattr(credentials, "get_config_dir", lambda: tmp_path)
        fresh_fallback_warning()
        fresh_fallback_warning()
        first = capsys.readouterr().out
        assert first.count("No OS keychain is available") == 1

        fresh_fallback_warning.cache_clear()
        fresh_fallback_warning()
        second = capsys.readouterr().out
        assert second.count("No OS keychain is available") == 1


class TestOutputBase:
    """
    Purpose:
        Resolving the directory scans are written into, now owned by the settings module.
    """
    def test_configured_directory_is_used_and_created(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a configured output directory is returned and created.

        Parameters:
            monkeypatch: Supplies the configured value.
            tmp_path: Parent of the configured directory.
        """
        target = tmp_path / "scans"
        monkeypatch.setattr(user_settings, "get_output_dir", lambda: str(target))
        base = user_settings.get_output_base()
        assert base == target
        assert target.is_dir()

    def test_tilde_is_expanded(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a configured path written with a tilde resolves under the home directory.

        Parameters:
            monkeypatch: Points the home directory at a temporary one and supplies the configured value.
            tmp_path: Stands in for the home directory.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(user_settings, "get_output_dir", lambda: "~/reports")
        base = user_settings.get_output_base()
        assert base == tmp_path / "reports"

    @pytest.mark.parametrize("configured", ["", "   ", None])
    def test_empty_setting_falls_back_to_the_default(self, monkeypatch, tmp_path, configured):
        """
        Purpose:
            Pin that an empty, blank or missing setting resolves to the default base rather than the working directory.

        Parameters:
            monkeypatch: Supplies the configured value and the default base.
            tmp_path: Parent of the default base.
            configured: The stored setting.
        """
        default = tmp_path / "default"
        monkeypatch.setattr(user_settings, "get_output_dir", lambda: configured)
        monkeypatch.setattr(user_settings, "default_output_base", lambda: default)
        base = user_settings.get_output_base()
        assert base == default
        assert default.is_dir()

    def test_store_uses_the_settings_resolver(self):
        """
        Purpose:
            Pin that the scan store resolves its base through the settings module, under the name tests redirect.
        """
        assert store.get_output_base is user_settings.get_output_base

    def test_paths_does_not_import_user_settings(self):
        """
        Purpose:
            Pin that the paths module imports nothing from the settings module, so the two can no longer form an import cycle.

        Implementation notes:
            Checked on the source rather than at runtime, because the cycle was hidden inside a function body and only formed when that function ran.
        """
        source = Path(paths.__file__).read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any("user_settings" in name for name in imported)


class TestCliDefaultModel:
    """
    Purpose:
        The CLI providers' default model, now a classmethod so the base constructor never calls an instance override.
    """
    @pytest.mark.parametrize("spec_key", sorted(cli_provider.CLI_SPECS))
    def test_default_model_is_reachable_from_class_and_instance(self, spec_key):
        """
        Purpose:
            Pin that the default model is the spec's first model, or empty, whether asked of the class or an instance, and that an unconfigured provider adopts it.

        Parameters:
            spec_key: The CLI specification to build from.
        """
        spec = cli_provider.CLI_SPECS[spec_key]
        cls = cli_provider._make_provider_class(spec)
        expected = spec.models[0] if spec.models else ""
        prov = cls(config={"model": "", "binary_path": "", "max_concurrent_requests": 1})
        assert cls.default_model() == expected
        assert prov.default_model() == expected
        assert prov.model == expected

    def test_a_configured_model_still_wins(self):
        """
        Purpose:
            Pin that a configured model takes precedence over the spec default.
        """
        cls = cli_provider._make_provider_class(cli_provider.CLI_SPECS["claude_cli"])
        prov = cls(config={"model": "haiku", "binary_path": "", "max_concurrent_requests": 1})
        assert prov.model == "haiku"


class TestCustomModelListing:
    """
    Purpose:
        The custom endpoint's model listing when the endpoint cannot be listed.
    """
    def test_failure_is_traced_and_falls_back_to_the_configured_model(self, monkeypatch, capsys):
        """
        Purpose:
            Pin that a failed listing returns the configured model and says why under verbose.

        Parameters:
            monkeypatch: Makes the listing request fail.
            capsys: Captures the verbose trace.

        Implementation notes:
            The failure used to vanish, which made an endpoint with a wrong URL look identical to one that simply has no models route.
        """
        def _refuse(*_, **__):
            """
            Purpose:
                Stand in for the HTTP request by failing.

            Parameters:
                _: Positional arguments, unused by the stand-in.
                __: Keyword arguments, unused by the stand-in.

            Raises:
                OSError: Always.
            """
            raise OSError("connection refused")

        monkeypatch.setattr(custom_provider.httpx, "get", _refuse)
        prov = custom_provider.CustomProvider(
            config={"base_url": "http://x", "model": "my-model"}, verbose=True)
        models = prov.list_models()
        out = capsys.readouterr().out
        assert models == ["my-model"]
        assert "Custom endpoint model listing failed" in out
        assert "connection refused" in out
