#!/usr/bin/env python3
"""
Module: test_credentials_pool

Purpose:
    Holding several API keys per provider: how they are stored, how a provider rolls to the next one, and how the settings surface shows and reveals them.

Responsibilities:
    Pin the pool storage and its handling of older single-key installs, the masking helper, the rotation rules in the shared provider base and in each concrete provider, the factory wiring that loads a pool out of storage, the cheap-model routing that shares the same construction path, the settings endpoints that add, list, reveal and remove keys, and the configured line the provider check logs.

Dependencies:
    pytest, the credential store, the provider base class, the four HTTP-backed providers, the Ollama provider, the provider factory, the analysis service, the settings routes and the provider configuration check.

Implementation notes:
    A single cloud key running out of quota used to end a scan outright. The circuit breaker stops it honestly, but there was no recovery short of pasting a different key into the settings page and starting again. The pool lets the settings page hold several keys per provider and roll to the next automatically when one is exhausted or rejected.

Security considerations:
    Nothing here touches the real keychain, the network, or a live quota, and every key in the fixtures is invented. The settings payload is asserted not to contain a full key anywhere, since that response is rendered in a browser and would otherwise put the user's credentials into the page source.
"""

import hmac

import pytest

from lu77U_MobileSec.ai.base_provider import BaseAIProvider


@pytest.fixture
def fake_store(monkeypatch):
    """
    Purpose:
        Stand in for the credential backend with an in-memory store.

    Parameters:
        monkeypatch: Replaces the backend's availability check and its read and write functions.

    Returns:
        The credentials module and the backing store, so a test can assert against the stored form as well as through the interface.

    Implementation notes:
        The read returns a copy, matching what the real function does. The setting and writing helpers mutate whatever they are handed, so returning the live store instead of a copy would make writes vanish into the object the caller was already holding.

    Security considerations:
        Replacing the backend is what keeps the test run out of the user's real keychain, where their actual provider keys are stored.
    """
    from lu77U_MobileSec.config import credentials as c

    store: dict = {}
    monkeypatch.setattr(c, "keyring_available", lambda: False)
    monkeypatch.setattr(c, "_fallback_read", lambda: dict(store))

    def _write(data):
        """
        Purpose:
            Replace the store's contents with what was written.

        Parameters:
            data: The complete stored mapping.

        Side effects:
            Clears and repopulates the backing store.
        """
        store.clear()
        store.update(data)

    monkeypatch.setattr(c, "_fallback_write", _write)
    return c, store


class TestKeyPoolStorage:
    """
    Purpose:
        Reading and writing a provider's pool of keys.
    """
    def test_set_and_get_round_trip(self, fake_store):
        """
        Purpose:
            Pin that a pool reads back as it was written, in order.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1", "k2", "k3"])
        assert c.get_api_keys("ollama") == ["k1", "k2", "k3"]

    def test_blanks_and_duplicates_are_cleaned(self, fake_store):
        """
        Purpose:
            Pin that blank entries and repeats are removed while the order of what remains is kept.

        Parameters:
            fake_store: The credentials module and its in-memory store.

        Implementation notes:
            Both arrive from pasting into the settings page, and a duplicate in the pool would cost an extra doomed request per rotation once that key is exhausted.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1", "k2", "k1", "  ", ""])
        assert c.get_api_keys("ollama") == ["k1", "k2"]

    def test_add_appends(self, fake_store):
        """
        Purpose:
            Pin that adding a key puts it after the existing ones.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1"])
        c.add_api_key("ollama", "k2")
        assert c.get_api_keys("ollama") == ["k1", "k2"]

    def test_add_ignores_a_blank_value(self, fake_store):
        """
        Purpose:
            Pin that adding a blank value leaves the pool empty.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.add_api_key("ollama", "   ")
        assert c.get_api_keys("ollama") == []

    def test_remove_by_index(self, fake_store):
        """
        Purpose:
            Pin that removing by position drops that key and no other.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1", "k2", "k3"])
        c.remove_api_key("ollama", 1)
        assert c.get_api_keys("ollama") == ["k1", "k3"]

    def test_remove_out_of_range_is_a_no_op(self, fake_store):
        """
        Purpose:
            Pin that a position past the end or below the start removes nothing.

        Parameters:
            fake_store: The credentials module and its in-memory store.

        Implementation notes:
            A negative position would otherwise count from the end and silently delete the wrong key, since the position comes from a request naming a row the page was showing before the pool changed.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1"])
        c.remove_api_key("ollama", 5)
        c.remove_api_key("ollama", -1)
        assert c.get_api_keys("ollama") == ["k1"]

    def test_clearing_the_pool_removes_the_stored_entry(self, fake_store):
        """
        Purpose:
            Pin that emptying a pool removes the stored entry rather than leaving an empty one behind.

        Parameters:
            fake_store: The credentials module and its in-memory store.

        Security considerations:
            An entry left behind would keep the provider reading as configured, so a user who removed their keys would see the tool still claim to hold credentials for it.
        """
        c, store = fake_store
        c.set_api_keys("ollama", ["k1"])
        c.set_api_keys("ollama", [])
        assert c.get_api_keys("ollama") == []
        assert c.has_api_key("ollama") is False
        assert c._key_name("ollama") not in store

    def test_get_api_key_is_the_first_of_the_pool(self, fake_store):
        """
        Purpose:
            Pin that asking for a single key returns the first of the pool.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["first", "second"])
        assert c.get_api_key("ollama") == "first"

    def test_set_api_key_replaces_the_whole_pool(self, fake_store):
        """
        Purpose:
            Pin that setting a single key replaces the pool rather than adding to it.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["old1", "old2"])
        c.set_api_key("ollama", "new")
        assert c.get_api_keys("ollama") == ["new"]


class TestBackCompat:
    """
    Purpose:
        Reading credentials written by an install that predates the pool.

    Implementation notes:
        Those installs stored a bare string rather than an encoded list, and the reader has to tell one from the other by inspection, since both are just text in the same slot.
    """
    def test_a_legacy_bare_key_reads_back_as_a_one_item_pool(self, fake_store):
        """
        Purpose:
            Pin that a key stored as a bare string reads back as a pool holding it.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, store = fake_store
        store[c._key_name("claude")] = "sk-legacy-bare-string"
        assert c.get_api_keys("claude") == ["sk-legacy-bare-string"]

    def test_a_key_that_parses_as_json_but_not_a_string_list_is_one_key(
            self, fake_store):
        """
        Purpose:
            Pin that a stored value which happens to parse as structured data but is not a list of strings is treated as one key.

        Parameters:
            fake_store: The credentials module and its in-memory store.

        Implementation notes:
            Without the type check the parsed value would be iterated, which for a mapping yields its field names and for a string yields its characters, shredding a working key into unusable fragments.
        """
        c, store = fake_store
        store[c._key_name("gemini")] = '{"not":"a list"}'
        assert c.get_api_keys("gemini") == ['{"not":"a list"}']

    def test_a_key_that_is_literally_a_json_array_of_ints_is_one_key(
            self, fake_store):
        """
        Purpose:
            Pin that a stored value parsing to a list of non-strings is treated as one key.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, store = fake_store
        store[c._key_name("openai")] = "[1,2,3]"
        assert c.get_api_keys("openai") == ["[1,2,3]"]

    def test_a_missing_provider_is_an_empty_pool(self, fake_store):
        """
        Purpose:
            Pin that a provider with nothing stored reads back as an empty pool and no single key.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        assert c.get_api_keys("openai") == []
        assert c.get_api_key("openai") is None


class TestKeyLabels:
    """
    Purpose:
        An optional label stored with each key, so a user with several keys can tell which account each belongs to.

    Implementation notes:
        The label lives in the same entry as its key, so removing or reordering keys carries labels along. An unlabelled pool keeps the earlier storage format byte for byte.
    """
    def test_a_labelled_key_reads_back_with_its_label(self, fake_store):
        """
        Purpose:
            Pin that a label round-trips beside its key, and that the plain key list providers read is unchanged by it.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.add_api_key("ollama", "k1", "abc@gmail.com")
        c.add_api_key("ollama", "k2")
        assert c.get_api_key_entries("ollama") == [
            {"key": "k1", "label": "abc@gmail.com"}, {"key": "k2", "label": ""}]
        assert c.get_api_keys("ollama") == ["k1", "k2"]

    def test_an_unlabelled_pool_keeps_the_old_format(self, fake_store):
        """
        Purpose:
            Pin that keys without labels are stored as a plain list of strings, which an older version of the tool still reads.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        import json
        c, store = fake_store
        c.set_api_keys("ollama", ["k1", "k2"])
        assert json.loads(store[c._key_name("ollama")]) == ["k1", "k2"]
        c.add_api_key("ollama", "k3", "work")
        assert json.loads(store[c._key_name("ollama")]) == ["k1", "k2", {"key": "k3", "label": "work"}]

    def test_older_entries_read_with_no_label(self, fake_store):
        """
        Purpose:
            Pin that a bare string and a list of strings, as earlier versions wrote them, read back with empty labels.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, store = fake_store
        store[c._key_name("claude")] = "sk-legacy-bare-string"
        store[c._key_name("ollama")] = '["k1", "k2"]'
        assert c.get_api_key_entries("claude") == [{"key": "sk-legacy-bare-string", "label": ""}]
        assert c.get_api_key_entries("ollama") == [{"key": "k1", "label": ""}, {"key": "k2", "label": ""}]

    def test_a_list_holding_anything_else_is_still_one_literal_key(self, fake_store):
        """
        Purpose:
            Pin that a JSON list with an item that is neither a string nor a key object is read as one literal key, as before.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, store = fake_store
        store[c._key_name("openai")] = '["k1", 2]'
        assert c.get_api_keys("openai") == ['["k1", 2]']

    def test_adding_a_stored_key_with_a_label_labels_it(self, fake_store):
        """
        Purpose:
            Pin that pasting a key that is already stored, with a label, labels it rather than adding a duplicate, and that pasting it bare keeps the label.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.add_api_key("ollama", "k1")
        c.add_api_key("ollama", "k1", "abc@gmail.com")
        c.add_api_key("ollama", " k1 ")
        assert c.get_api_key_entries("ollama") == [{"key": "k1", "label": "abc@gmail.com"}]

    def test_a_label_is_set_changed_and_cleared_by_position(self, fake_store):
        """
        Purpose:
            Pin that a stored key's label can be set, changed and cleared by its position, and that a stale position changes nothing.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1", "k2"])
        assert c.set_api_key_label("ollama", 1, "def@gmail.com")
        assert c.get_api_key_entries("ollama")[1]["label"] == "def@gmail.com"
        assert c.set_api_key_label("ollama", 1, "")
        assert c.get_api_key_entries("ollama")[1]["label"] == ""
        assert not c.set_api_key_label("ollama", 5, "x")
        assert c.get_api_keys("ollama") == ["k1", "k2"]

    def test_removing_a_key_keeps_the_other_labels(self, fake_store):
        """
        Purpose:
            Pin that removing one key leaves every other key with its own label, since labels travel with their keys.

        Parameters:
            fake_store: The credentials module and its in-memory store.
        """
        c, _ = fake_store
        c.add_api_key("ollama", "k1", "first")
        c.add_api_key("ollama", "k2", "second")
        c.add_api_key("ollama", "k3", "third")
        c.remove_api_key("ollama", 0)
        assert c.get_api_key_entries("ollama") == [
            {"key": "k2", "label": "second"}, {"key": "k3", "label": "third"}]

    @pytest.mark.parametrize("label, cleaned", [
        ("  abc@gmail.com  ", "abc@gmail.com"),
        ("work\n account", "work account"),
        ("", ""),
        (None, ""),
        ("prénom@exemple.fr", "prénom@exemple.fr"),
    ])
    def test_a_label_is_normalised(self, label, cleaned):
        """
        Purpose:
            Pin that a label's whitespace is collapsed to single spaces, so it always fits on one line.

        Parameters:
            label: The label as typed.
            cleaned: What is stored.
        """
        from lu77U_MobileSec.config import credentials as c
        assert c.clean_label(label) == cleaned

    @pytest.mark.parametrize("label", ["x" * 81, "bad\x00label", "gmail.com\u202eevil"])
    def test_a_label_that_cannot_show_safely_is_refused(self, label):
        """
        Purpose:
            Pin that an overlong label, a control character and an invisible bidirectional override are refused.

        Parameters:
            label: A label that must be rejected.
        """
        from lu77U_MobileSec.config import credentials as c
        with pytest.raises(ValueError):
            c.clean_label(label)


class TestMasking:
    """
    Purpose:
        The masking applied before a key is shown anywhere.
    """
    def test_a_real_shaped_key_shows_first_and_last_four(self):
        """
        Purpose:
            Pin that a full-length key is shown as its first and last few characters only.

        Security considerations:
            The value in the fixture is invented. Enough is shown for the user to tell two of their own keys apart and not enough to reconstruct either.
        """
        from lu77U_MobileSec.config.credentials import mask_key

        assert mask_key(
            "3f495713f5a74abf8195fbb12b002e0c.UAruzDoAe8YmF6TgJw61avIX"
        ) == "3f49…avIX"

    def test_a_short_value_is_masked_whole(self):
        """
        Purpose:
            Pin that a value too short to mask partially is hidden entirely.

        Security considerations:
            Showing the first and last few characters of a short value would reveal most of it, so the rule changes rather than degrading.
        """
        from lu77U_MobileSec.config.credentials import mask_key

        assert mask_key("short") == "•" * len("short")

    def test_blank_masks_to_blank(self):
        """
        Purpose:
            Pin that an empty or absent value masks to an empty string rather than to a row of mask characters.

        Implementation notes:
            A masked empty value would render as a key that exists, which is exactly the state the settings page needs to distinguish.
        """
        from lu77U_MobileSec.config.credentials import mask_key

        assert mask_key("") == ""
        assert mask_key(None) == ""


class _Provider(BaseAIProvider):
    """
    Purpose:
        A minimal concrete provider, used so the rotation under test is the base class's own rather than a stub of it.

    Attributes:
        name: The provider name the base class requires.
    """
    name = "test"

    def analyze(self, *a, **kw):
        """
        Purpose:
            Answer any request with an empty finding list.

        Parameters:
            a: Positional arguments, ignored.
            kw: Keyword arguments, ignored.

        Returns:
            A response holding an empty list.
        """
        return {"response": "[]"}

    def list_models(self):
        """
        Purpose:
            Satisfy the base class's model listing requirement.

        Returns:
            An empty list.
        """
        return []

    def validate_credentials(self):
        """
        Purpose:
            Satisfy the base class's credential check requirement.

        Returns:
            True, since there is nothing to validate against.
        """
        return True


class TestKeyRotation:
    """
    Purpose:
        When the shared provider base rolls to the next key and when it gives up instead.
    """
    def test_a_single_key_constructor_still_works(self):
        """
        Purpose:
            Pin that a provider built with one key holds a pool of one and has nothing to rotate to.
        """
        prov = _Provider(api_key="onlyKey")
        assert prov._keys == ["onlyKey"]
        assert prov.api_key == "onlyKey"
        assert prov.advance_key() is False

    def test_a_pool_starts_on_the_first_key(self):
        """
        Purpose:
            Pin that a provider built with a pool begins on its first key.
        """
        prov = _Provider(api_keys=["k1", "k2", "k3"])
        assert prov.api_key == "k1"

    def test_a_later_provider_skips_a_key_an_earlier_one_found_spent(self):
        """
        Purpose:
            Pin that a key one provider found exhausted is skipped by the providers created after it, until its hour is up, and that resetting the circuit tries it again.
        """
        from lu77U_MobileSec.ai import base_provider
        first = _Provider(api_keys=["k1", "k2", "k3"])
        first._handle_exception(Exception("you have reached your session usage limit, upgrade for higher limits"))
        assert _Provider(api_keys=["k1", "k2", "k3"]).api_key == "k2"
        base_provider._SPENT_KEYS["k1"] -= base_provider.SPENT_KEY_RETRY_SECONDS
        assert _Provider(api_keys=["k1", "k2", "k3"]).api_key == "k1"
        base_provider.mark_key_spent("k1")
        first.reset_circuit()
        assert _Provider(api_keys=["k1", "k2", "k3"]).api_key == "k1"

    def test_a_pool_spent_throughout_starts_on_its_first_key(self):
        """
        Purpose:
            Pin that when every key is marked spent a provider starts on the first, so the refusal is still seen and the scan pauses on quota.
        """
        from lu77U_MobileSec.ai import base_provider
        for key in ("k1", "k2"):
            base_provider.mark_key_spent(key)
        assert _Provider(api_keys=["k1", "k2"]).api_key == "k1"

    def test_a_fatal_quota_error_rotates_instead_of_tripping(self):
        """
        Purpose:
            Pin that an exhausted quota moves to the next key and leaves the circuit closed.

        Implementation notes:
            Returning nothing is how the base signals that the call should be retried rather than reported, so the absence of an error object is the assertion that matters here.
        """
        prov = _Provider(api_keys=["k1", "k2"])
        result = prov._handle_exception(Exception(
            "you have reached your session usage limit, upgrade for higher "
            "limits"))
        assert result is None, "should signal 'retry', not return an error"
        assert prov.api_key == "k2"
        assert prov.unavailable is None

    def test_a_fatal_auth_error_also_rotates(self):
        """
        Purpose:
            Pin that a rejected key also moves to the next one.

        Implementation notes:
            A revoked or mistyped key should not end a scan when a working one is sitting behind it in the pool.
        """
        prov = _Provider(api_keys=["bad", "good"])
        result = prov._handle_exception(Exception("invalid api key provided"))
        assert result is None
        assert prov.api_key == "good"

    def test_a_transient_error_never_rotates(self):
        """
        Purpose:
            Pin that a temporary network failure stays on the current key.

        Implementation notes:
            Rotating on a dropped connection would burn through the whole pool during one bad minute of network and leave the scan with nothing to fall back on when a key genuinely runs out.
        """
        prov = _Provider(api_keys=["k1", "k2"])
        result = prov._handle_exception(Exception("peer closed connection"))
        assert result is None
        assert prov.api_key == "k1"

    def test_the_circuit_opens_only_once_the_whole_pool_is_spent(self):
        """
        Purpose:
            Pin that the circuit opens on the failure after the last key, not before.
        """
        prov = _Provider(api_keys=["k1", "k2", "k3"])
        for _ in range(2):
            r = prov._handle_exception(Exception("session usage limit"))
            assert r is None
        final = prov._handle_exception(Exception("session usage limit"))
        assert final is not None
        assert final["fatal"] is True
        assert prov.unavailable is not None

    def test_short_circuit_after_exhaustion_is_effectively_free(self):
        """
        Purpose:
            Pin that once the circuit is open, further calls are refused immediately rather than doing any work.

        Implementation notes:
            The remaining regions of a scan keep calling after exhaustion, so the refusal has to be cheap; the timing assertion is loose enough to be stable and tight enough to catch a refusal path that still built a request.
        """
        import time

        prov = _Provider(api_keys=["k1"])
        prov._handle_exception(Exception("session usage limit"))
        assert prov.unavailable is not None

        started = time.monotonic()
        for _ in range(50):
            tripped = prov._short_circuit()
            assert tripped["short_circuited"] is True
        assert time.monotonic() - started < 0.1

    def test_reset_circuit_rewinds_to_the_first_key(self):
        """
        Purpose:
            Pin that resetting the circuit closes it and returns to the first key.

        Implementation notes:
            A reset happens when the user adds new keys mid-run, so leaving the cursor at the end of the spent pool would keep refusing with fresh credentials available.
        """
        prov = _Provider(api_keys=["k1", "k2"])
        prov._handle_exception(Exception("session usage limit"))
        prov._handle_exception(Exception("session usage limit"))
        assert prov.unavailable is not None

        prov.reset_circuit()
        assert prov.unavailable is None
        assert prov.api_key == "k1"

    def test_an_empty_pool_never_rotates(self):
        """
        Purpose:
            Pin that a provider with no keys has none to rotate to and reports no current key.
        """
        prov = _Provider()
        assert prov._keys == []
        assert prov.api_key is None
        assert prov.advance_key() is False

    def test_on_key_rotated_hook_fires_on_every_rotation(self):
        """
        Purpose:
            Pin that the rotation hook fires once per rotation, with the new key already in place.

        Implementation notes:
            Providers use the hook to discard state built around the old key, so firing before the change or skipping a rotation would leave that state pointing at a spent credential.
        """
        calls = []
        prov = _Provider(api_keys=["k1", "k2", "k3"])
        prov._on_key_rotated = lambda: calls.append(prov.api_key)
        prov._handle_exception(Exception("session usage limit"))
        prov._handle_exception(Exception("session usage limit"))
        assert calls == ["k2", "k3"]


class TestUsageSummaryKeyFields:
    """
    Purpose:
        The key counts the usage summary reports.
    """
    def test_keys_total_and_used_track_the_pool(self):
        """
        Purpose:
            Pin that the summary reports the pool size and how many keys have been reached so far.

        Implementation notes:
            This is what tells the user a scan quietly consumed several of their keys, which is otherwise invisible until they all run out.
        """
        prov = _Provider(api_keys=["k1", "k2", "k3"])
        summary = prov.usage_summary()
        assert summary["keys_total"] == 3
        assert summary["keys_used"] == 1

        prov._handle_exception(Exception("session usage limit"))
        assert prov.usage_summary()["keys_used"] == 2

    def test_an_empty_pool_reports_zero_zero(self):
        """
        Purpose:
            Pin that a provider with no keys reports both counts as zero.
        """
        prov = _Provider()
        summary = prov.usage_summary()
        assert summary["keys_total"] == 0
        assert summary["keys_used"] == 0


class TestOllamaKeyRotation:
    """
    Purpose:
        Rotation in the Ollama provider, which holds a cached client and its own retry loop.
    """
    def _provider(self, **kw):
        """
        Purpose:
            Build an Ollama provider in cloud mode.

        Parameters:
            kw: Constructor keywords, such as the key pool.

        Returns:
            The provider.
        """
        from lu77U_MobileSec.ai.ollama_provider import OllamaProvider

        return OllamaProvider(config={"mode": "cloud"}, verbose=False, **kw)

    def test_client_is_cleared_on_rotation(self):
        """
        Purpose:
            Pin that rotating discards the cached client.

        Implementation notes:
            The client is built lazily with the credential baked into its headers, so a rotation that left it cached would keep sending the exhausted key while believing it had moved on.
        """
        prov = self._provider(api_keys=["dead", "alive"])
        prov._client = object()
        prov.advance_key()
        assert prov._client is None

    def test_each_key_gets_its_own_retry_budget(self, monkeypatch):
        """
        Purpose:
            Pin that a key exhausted part way through its attempts does not leave the next key with fewer of its own.

        Parameters:
            monkeypatch: Removes the backoff delay so the retries run immediately.

        Implementation notes:
            The call counts are asserted per key: the first fails immediately because an exhausted quota is not worth retrying, and the second then succeeds on its own first attempt rather than on a leftover one.
        """
        from lu77U_MobileSec.ai import ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        calls_per_key = {}

        class _FakeClient:
            """
            Purpose:
                A client that fails for the first key and streams a successful answer for any other, counting calls per key.
            """
            def chat(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Record the call against the current key, then either fail or stream a reply.

                Parameters:
                    _unused_args: Positional arguments, ignored.
                    _unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A stream of response chunks, for any key but the first.

                Raises:
                    Exception: For the first key, carrying an exhausted-quota message.

                Side effects:
                    Increments the recorded call count for the current key.
                """
                key = prov.api_key
                calls_per_key[key] = calls_per_key.get(key, 0) + 1
                if key == "k1":
                    raise Exception("session usage limit")
                yield {"message": {"content": "ok"}, "done": False}
                yield {"message": {"content": ""}, "done": True}

        prov = self._provider(api_keys=["k1", "k2"])
        prov._client = _FakeClient()
        prov._on_key_rotated = lambda: None

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "ok"
        assert calls_per_key == {"k1": 1, "k2": 1}

    def test_pool_exhaustion_stops_the_outer_loop(self, monkeypatch):
        """
        Purpose:
            Pin that a pool where every key is exhausted ends as a fatal error with the circuit open.

        Parameters:
            monkeypatch: Removes the backoff delay so the retries run immediately.
        """
        from lu77U_MobileSec.ai import ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _AllFail:
            """
            Purpose:
                A client that reports an exhausted quota for every key.
            """
            def chat(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Fail with an exhausted-quota message.

                Parameters:
                    _unused_args: Positional arguments, ignored.
                    _unused_kwargs: Keyword arguments, ignored.

                Raises:
                    Exception: Always, carrying an exhausted-quota message.
                """
                raise Exception("session usage limit")

        prov = self._provider(api_keys=["k1", "k2"])
        prov._client = _AllFail()
        prov._on_key_rotated = lambda: None

        result = prov.analyze("p", system_message="s")
        assert result.get("fatal") is True
        assert prov.unavailable is not None

    def test_a_transient_error_still_gets_its_normal_retry_budget(
            self, monkeypatch):
        """
        Purpose:
            Pin that a temporary failure uses the full retry budget, stays non-fatal, and does not rotate.

        Parameters:
            monkeypatch: Removes the backoff delay so the retries run immediately.

        Implementation notes:
            The attempt count is asserted against the configured maximum, so the pool work is shown not to have changed the retry behaviour that existed before it.
        """
        from lu77U_MobileSec.ai import ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _Transient:
            """
            Purpose:
                A client that always fails with a temporary network error, counting attempts.

            Attributes:
                n: How many attempts were made.
            """
            def __init__(self):
                """
                Purpose:
                    Build the client with no attempts recorded.
                """
                self.n = 0

            def chat(self, *_unused_args, **_unused_kwargs):
                """
                Purpose:
                    Count the attempt and fail with a temporary network error.

                Parameters:
                    _unused_args: Positional arguments, ignored.
                    _unused_kwargs: Keyword arguments, ignored.

                Raises:
                    Exception: Always, carrying a dropped-connection message.

                Side effects:
                    Increments the attempt count.
                """
                self.n += 1
                raise Exception("peer closed connection")

        prov = self._provider(api_keys=["only"])
        client = _Transient()
        prov._client = client

        result = prov.analyze("p", system_message="s")
        assert "error" in result and result.get("fatal") is not True
        assert client.n == 3
        assert prov.api_key == "only"


def _resp(status, **kw):
    """
    Purpose:
        Build an HTTP response with a request attached, as the client library requires.

    Parameters:
        status: The status code.
        kw: The body, given as text or as structured data.

    Returns:
        The response.
    """
    import httpx

    return httpx.Response(status, request=httpx.Request("POST", "http://x"), **kw)


class TestHttpProviderKeyRotation:
    """
    Purpose:
        Rotation in the four providers that speak HTTP directly, each of which carries its credential differently.
    """
    def test_openai_rotates_on_a_quota_429(self, monkeypatch):
        """
        Purpose:
            Pin that an exhausted quota rolls to the next key, succeeds on it, and leaves the circuit closed.

        Parameters:
            monkeypatch: Replaces the HTTP call with a recorder that fails for the first key.

        Implementation notes:
            The credentials seen by the transport are asserted in order, so a rotation that changed the stored key without changing what was actually sent would still fail here.
        """
        import httpx

        from lu77U_MobileSec.ai.openai_provider import OpenAIProvider

        calls = []

        def fake_post(url_unused, headers=None, **_unused_kwargs):
            """
            Purpose:
                Record the credential sent, then fail for the first key and succeed for any other.

            Parameters:
                url_unused: The endpoint, unused here.
                headers: The request headers, read for the credential.
                _unused_kwargs: The request body and timeout, unused here.

            Returns:
                A quota error for the first key, and a successful empty finding list otherwise.

            Side effects:
                Records the credential.
            """
            calls.append(headers["Authorization"])
            if headers["Authorization"] == "Bearer k1":
                return _resp(429, text='{"error":{"message":"insufficient_quota"}}')
            return _resp(200, json={"choices": [{"message": {"content": "[]"}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = OpenAIProvider(api_keys=["k1", "k2"])
        result = prov.analyze("p", system_message="s")

        assert result == {"response": "[]"}
        assert calls == ["Bearer k1", "Bearer k2"]
        assert prov.api_key == "k2"
        assert prov.unavailable is None

    def test_gemini_rotates_on_a_quota_error(self, monkeypatch):
        """
        Purpose:
            Pin that the same rotation happens for a provider carrying its credential in its own header.

        Parameters:
            monkeypatch: Replaces the HTTP call with a recorder that fails for the first key.
        """
        import httpx

        from lu77U_MobileSec.ai.gemini_provider import GeminiProvider

        calls = []

        def fake_post(url_unused, headers=None, **_unused_kwargs):
            """
            Purpose:
                Record the credential sent, then fail for the first key and succeed for any other.

            Parameters:
                url_unused: The endpoint, unused here.
                headers: The request headers, read for the credential.
                _unused_kwargs: The request body and timeout, unused here.

            Returns:
                A quota error for the first key, and a successful empty finding list otherwise.

            Side effects:
                Records the credential.
            """
            calls.append(headers["x-goog-api-key"])
            if headers["x-goog-api-key"] == "g1":
                return _resp(429, text="quota exceeded")
            return _resp(200, json={
                "candidates": [{"content": {"parts": [{"text": "[]"}]}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = GeminiProvider(api_keys=["g1", "g2"])
        result = prov.analyze("p", system_message="s")

        assert result == {"response": "[]"}
        assert calls == ["g1", "g2"]

    def test_custom_rotates_on_a_quota_error(self, monkeypatch):
        """
        Purpose:
            Pin that the same rotation happens for a user-configured endpoint.

        Parameters:
            monkeypatch: Replaces the HTTP call with a recorder that fails for the first key.
        """
        import httpx

        from lu77U_MobileSec.ai.custom_provider import CustomProvider

        calls = []

        def fake_post(url_unused, headers=None, **_unused_kwargs):
            """
            Purpose:
                Record the credential sent, then fail for the first key and succeed for any other.

            Parameters:
                url_unused: The endpoint, unused here.
                headers: The request headers, read for the credential.
                _unused_kwargs: The request body and timeout, unused here.

            Returns:
                A quota error for the first key, and a successful answer otherwise.

            Side effects:
                Records the credential.
            """
            calls.append(headers.get("Authorization"))
            if headers.get("Authorization") == "Bearer c1":
                return _resp(429, text="session usage limit")
            return _resp(200, json={"choices": [{"message": {"content": "ok"}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = CustomProvider(config={"base_url": "http://x"}, api_keys=["c1", "c2"])
        result = prov.analyze("p", system_message="s")

        assert result == {"response": "ok"}
        assert calls == ["Bearer c1", "Bearer c2"]

    def test_claude_rotates_on_a_quota_error(self):
        """
        Purpose:
            Pin that the same rotation happens for the provider that goes through a vendor client rather than a raw HTTP call.

        Implementation notes:
            The client is replaced rather than the transport, because this provider never issues an HTTP call of its own and there would be nothing to intercept.
        """
        from lu77U_MobileSec.ai.claude_provider import ClaudeProvider

        class _Block:
            """
            Purpose:
                One response block shaped like the tool call the provider reads its findings out of.

            Attributes:
                type: The block type the provider matches on.
                name: The tool name the block reports.
                input: The tool arguments, holding an empty finding list.
            """
            type = "tool_use"
            name = "report_vulnerabilities"
            input = {"vulnerabilities": []}

        class _Resp:
            """
            Purpose:
                A response carrying the single block.

            Attributes:
                content: The response blocks.
            """
            content = [_Block()]

        class _FakeMessages:
            """
            Purpose:
                The message interface, failing for the first key and answering for any other.

            Attributes:
                prov: The provider, read to learn which key is current.
            """
            def __init__(self, prov):
                """
                Purpose:
                    Build the interface bound to the provider.

                Parameters:
                    prov: The provider whose current key decides the outcome.
                """
                self.prov = prov

            def create(self, **_unused_kwargs):
                """
                Purpose:
                    Fail for the first key and return the canned response for any other.

                Parameters:
                    _unused_kwargs: The request arguments, ignored.

                Returns:
                    The canned response.

                Raises:
                    Exception: For the first key, carrying an exhausted-quota message.
                """
                if self.prov.api_key == "cl1":
                    raise Exception(
                        "you have reached your session usage limit, upgrade "
                        "for higher limits")
                return _Resp()

        class _FakeSdkClient:
            """
            Purpose:
                A client exposing only the message interface the provider uses.

            Attributes:
                messages: The message interface.
            """
            def __init__(self, prov):
                """
                Purpose:
                    Build the client bound to the provider.

                Parameters:
                    prov: The provider the message interface reads its current key from.
                """
                self.messages = _FakeMessages(prov)

        prov = ClaudeProvider(api_keys=["cl1", "cl2"])
        prov._sdk_client = lambda: _FakeSdkClient(prov)
        result = prov.analyze("p", system_message="s")

        assert result == {"response": "[]"}
        assert prov.api_key == "cl2"

    def test_a_transient_error_does_not_rotate_and_stops_at_one_attempt(
            self, monkeypatch):
        """
        Purpose:
            Pin that a temporary failure stays on the first key, ends after one attempt, and is not fatal.

        Parameters:
            monkeypatch: Makes the HTTP call raise a connection error.

        Implementation notes:
            These four providers never had a retry loop of their own, so the pool work must not have given them one; the attempt count is what holds that in place.
        """
        import httpx

        from lu77U_MobileSec.ai.openai_provider import OpenAIProvider

        calls = []

        def fake_post(url_unused, headers=None, **_unused_kwargs):
            """
            Purpose:
                Record the credential sent, then fail with a connection error.

            Parameters:
                url_unused: The endpoint, unused here.
                headers: The request headers, read for the credential.
                _unused_kwargs: The request body and timeout, unused here.

            Raises:
                httpx.ConnectError: Always.

            Side effects:
                Records the credential.
            """
            calls.append(headers["Authorization"])
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = OpenAIProvider(api_keys=["k1", "k2"])
        result = prov.analyze("p", system_message="s")

        assert calls == ["Bearer k1"]
        assert prov.api_key == "k1"
        assert result.get("fatal") is not True

    def test_pool_exhaustion_trips_the_circuit(self, monkeypatch):
        """
        Purpose:
            Pin that every key is tried once, the result is fatal, the counts report the pool spent, and the next call reaches no transport at all.

        Parameters:
            monkeypatch: Makes every HTTP call return an exhausted quota.
        """
        import httpx

        from lu77U_MobileSec.ai.openai_provider import OpenAIProvider

        calls = []

        def fake_post(url_unused, headers=None, **_unused_kwargs):
            """
            Purpose:
                Record the credential sent and report an exhausted quota.

            Parameters:
                url_unused: The endpoint, unused here.
                headers: The request headers, read for the credential.
                _unused_kwargs: The request body and timeout, unused here.

            Returns:
                A quota error response.

            Side effects:
                Records the credential.
            """
            calls.append(headers["Authorization"])
            return _resp(429, text="insufficient_quota")

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = OpenAIProvider(api_keys=["k1", "k2", "k3"])
        result = prov.analyze("p", system_message="s")

        assert calls == ["Bearer k1", "Bearer k2", "Bearer k3"]
        assert result.get("fatal") is True
        summary = prov.usage_summary()
        assert summary["keys_used"] == 3 and summary["keys_total"] == 3

        calls_before = len(calls)
        result2 = prov.analyze("p2", system_message="s")
        assert len(calls) == calls_before
        assert result2.get("short_circuited") is True


class TestProviderFactoryWiring:
    """
    Purpose:
        The factory loading a provider's pool out of storage.
    """
    def test_build_provider_loads_the_whole_pool(self, fake_store):
        """
        Purpose:
            Pin that a built provider holds every stored key and starts on the first.

        Parameters:
            fake_store: The credentials module and its in-memory store.

        Implementation notes:
            Loading only the first key would leave the rotation correct and the pool empty, which looks identical until the first key runs out.
        """
        c, _ = fake_store
        c.set_api_keys("ollama", ["k1", "k2", "k3"])

        from lu77U_MobileSec.ai.provider_factory import build_provider

        prov = build_provider("ollama")
        assert prov._keys == ["k1", "k2", "k3"]
        assert prov.api_key == "k1"

    @pytest.mark.usefixtures("fake_store")
    def test_build_provider_with_no_stored_keys_is_an_empty_pool(self):
        """
        Purpose:
            Pin that a provider with nothing stored is built with an empty pool rather than failing to build.

        Implementation notes:
            The in-memory credential store is activated through usefixtures rather than a parameter, since building a provider reads it for isolation from the real keychain but the test never inspects it directly.
        """
        from lu77U_MobileSec.ai.provider_factory import build_provider

        prov = build_provider("ollama")
        assert prov._keys == []
        assert prov.api_key is None


class TestCheapModelRouting:
    """
    Purpose:
        Routing the phases that do not need the main model to a smaller one.

    Implementation notes:
        Triage, the validation judge and chain confirmation all work from identifiers or short verdicts rather than from reasoning over source, so a smaller model does the same job for less. It is off by default, and an unset setting must change nothing at all.
    """
    @pytest.mark.usefixtures("fake_store")
    def test_an_unset_cheap_model_falls_back_to_the_main_one(self, monkeypatch):
        """
        Purpose:
            Pin that asking for the cheap model with none configured yields the main one.

        Parameters:
            monkeypatch: Returns a configuration with no cheap model set.

        Implementation notes:
            The in-memory credential store is activated through usefixtures rather than a parameter, since building a provider reads it for isolation from the real keychain but the test never inspects it directly.
        """
        from lu77U_MobileSec.ai import provider_factory as pf

        monkeypatch.setattr(pf.user_settings, "get_provider_config",
                            lambda _: {"model": "gpt-oss:120b", "cheap_model": ""})
        prov = pf.build_provider("ollama", cheap=True)
        assert prov.model == "gpt-oss:120b"

    @pytest.mark.usefixtures("fake_store")
    def test_a_configured_cheap_model_is_used_instead(self, monkeypatch):
        """
        Purpose:
            Pin that asking for the cheap model with one configured yields that model.

        Parameters:
            monkeypatch: Returns a configuration naming a cheap model.

        Implementation notes:
            The in-memory credential store is activated through usefixtures rather than a parameter, since building a provider reads it for isolation from the real keychain but the test never inspects it directly.
        """
        from lu77U_MobileSec.ai import provider_factory as pf

        monkeypatch.setattr(pf.user_settings, "get_provider_config",
                            lambda _: {"model": "gpt-oss:120b", "cheap_model": "gpt-oss:20b"})
        prov = pf.build_provider("ollama", cheap=True)
        assert prov.model == "gpt-oss:20b"

    @pytest.mark.usefixtures("fake_store")
    def test_cheap_false_never_looks_at_cheap_model(self, monkeypatch):
        """
        Purpose:
            Pin that an ordinary build ignores the cheap model even when one is configured.

        Parameters:
            monkeypatch: Returns a configuration naming a cheap model.

        Implementation notes:
            This is the assertion that keeps the setting from quietly downgrading the main analysis, which would change every finding in a scan. The in-memory credential store is activated through usefixtures rather than a parameter, since building a provider reads it for isolation from the real keychain but the test never inspects it directly.
        """
        from lu77U_MobileSec.ai import provider_factory as pf

        monkeypatch.setattr(pf.user_settings, "get_provider_config",
                            lambda _: {"model": "gpt-oss:120b", "cheap_model": "gpt-oss:20b"})
        prov = pf.build_provider("ollama")
        assert prov.model == "gpt-oss:120b"

    def test_the_analysis_service_helper_reuses_the_same_instance_by_default(self, monkeypatch):
        """
        Purpose:
            Pin that with no cheap model configured the service hands back the very same provider instance.

        Parameters:
            monkeypatch: Returns a configuration with no cheap model set.

        Implementation notes:
            Identity is asserted rather than equality, because a second instance would carry its own key cursor and circuit state, so an exhaustion reached in one would be invisible to the other.
        """
        import lu77U_MobileSec.web.services.analysis_service as svc

        monkeypatch.setattr(svc.user_settings, "get_provider_config",
                            lambda _: {"model": "gpt-oss:120b", "cheap_model": ""})

        class FakeProvider:
            """
            Purpose:
                The smallest stand-in the routing helper reads.

            Attributes:
                name: The provider name.
                model: The configured model.
            """
            name = "ollama"
            model = "gpt-oss:120b"

        main = FakeProvider()
        assert svc._cheap_provider_or_same(main, False) is main

    @pytest.mark.usefixtures("fake_store")
    def test_the_analysis_service_helper_builds_a_second_instance_when_configured(
        self, monkeypatch
    ):
        """
        Purpose:
            Pin that with a cheap model configured the service builds a second provider using it.

        Parameters:
            monkeypatch: Returns a configuration naming a cheap model.

        Implementation notes:
            The in-memory credential store is activated through usefixtures rather than a parameter, since building the cheap provider reads it for isolation from the real keychain but the test never inspects it directly.
        """
        import lu77U_MobileSec.web.services.analysis_service as svc

        monkeypatch.setattr(svc.user_settings, "get_provider_config",
                            lambda _: {"model": "gpt-oss:120b", "cheap_model": "gpt-oss:20b"})

        class FakeProvider:
            """
            Purpose:
                The smallest stand-in the routing helper reads.

            Attributes:
                name: The provider name.
                model: The configured model.
            """
            name = "ollama"
            model = "gpt-oss:120b"

        cheap = svc._cheap_provider_or_same(FakeProvider(), False)
        assert cheap.model == "gpt-oss:20b"


@pytest.fixture
def api_client(fake_store):
    """
    Purpose:
        Build a test client over the settings routes alone, against the in-memory credential store.

    Parameters:
        fake_store: The credentials module and its in-memory store.

    Returns:
        The client and the credentials module.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from lu77U_MobileSec.web.routes import settings as settings_routes

    app = FastAPI()
    app.include_router(settings_routes.router)
    return TestClient(app), fake_store[0]


def _contains_constant_time(haystack, needle):
    """
    Purpose:
        Check whether a secret value appears anywhere inside a longer string, without relying on Python's ordinary substring search.

    Parameters:
        haystack: The text to search.
        needle: The value being searched for.

    Returns:
        True if some same-length window of haystack matches needle, False otherwise.

    Security considerations:
        An ordinary `in` check is a variable-time operation on the very value this test exists to keep out of the response, so each candidate window is matched with hmac.compare_digest instead.
    """
    if not needle:
        return True
    encoded_haystack = haystack.encode()
    encoded_needle = needle.encode()
    width = len(encoded_needle)
    return any(
        hmac.compare_digest(encoded_haystack[start:start + width], encoded_needle)
        for start in range(len(encoded_haystack) - width + 1)
    )


class TestSettingsWebLayer:
    """
    Purpose:
        The settings endpoints that add, list, reveal and remove keys.
    """
    def test_adding_two_keys_shows_two_masked_entries(self, api_client):
        """
        Purpose:
            Pin that two added keys are listed as two masked entries with a matching count.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "k1_longenough_key"})
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "k2_longenough_key"})

        data = client.get("/api/settings").json()
        keys = data["providers"]["ollama"]["api_keys"]
        assert len(keys) == 2
        assert data["providers"]["ollama"]["api_key_count"] == 2
        assert all("k1_longenough_key" != k["masked"] for k in keys)

    def test_no_full_key_ever_appears_in_the_settings_payload(self, api_client):
        """
        Purpose:
            Pin that no full key appears anywhere in the settings response.

        Parameters:
            api_client: The test client and the credentials module.

        Security considerations:
            Asserted against the raw response text rather than against the parsed fields, so a key leaking through a field nobody thought to check is still caught. That response is rendered in a browser and cached by it.
        """
        client, c = api_client
        secret = "3f495713f5a74abf8195fbb12b002e0c.UAruzDoAe8YmF6TgJw61avIX"
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": secret})

        raw = client.get("/api/settings").text
        assert not _contains_constant_time(raw, secret)

    def test_reveal_returns_the_full_key(self, api_client):
        """
        Purpose:
            Pin that the reveal endpoint returns the whole key for the position asked for.

        Parameters:
            api_client: The test client and the credentials module.

        Security considerations:
            This is the one endpoint that returns a credential in full, which is why it is a separate deliberate request rather than part of the settings payload every page load fetches.
        """
        client, c = api_client
        secret = "3f495713f5a74abf8195fbb12b002e0c.UAruzDoAe8YmF6TgJw61avIX"
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": secret})

        r = client.post("/api/settings/credentials/ollama/reveal", json={"index": 0})
        assert r.status_code == 200
        assert hmac.compare_digest(r.json()["key"], secret)

    def test_reveal_out_of_range_is_a_400(self, api_client):
        """
        Purpose:
            Pin that revealing a position that does not exist is refused rather than erroring or returning something else.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        r = client.post("/api/settings/credentials/ollama/reveal", json={"index": 0})
        assert r.status_code == 400

    def test_remove_drops_only_that_key(self, api_client):
        """
        Purpose:
            Pin that removing one key leaves the other in place.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "aaaaaaaaaaaa"})
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "bbbbbbbbbbbb"})

        client.delete("/api/settings/credentials/ollama/0")
        keys = client.get("/api/settings").json()["providers"]["ollama"]["api_keys"]
        assert len(keys) == 1
        assert keys[0]["masked"].startswith("bbbb")

    def test_posting_add_appends_rather_than_replaces(self, api_client):
        """
        Purpose:
            Pin that the single-key request shape now appends instead of replacing.

        Parameters:
            api_client: The test client and the credentials module.

        Implementation notes:
            That request shape predates the pool and is still what the page sends, so changing its meaning silently is the risk this pins down.
        """
        client, c = api_client
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "aaaaaaaaaaaa"})
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "bbbbbbbbbbbb"})

        assert client.get("/api/settings").json()[
            "providers"]["ollama"]["api_key_count"] == 2

    def test_posting_null_clears_the_whole_pool(self, api_client):
        """
        Purpose:
            Pin that posting an absent key empties the pool and reports the provider as unconfigured.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": "aaaaaaaaaaaa"})
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": None})

        data = client.get("/api/settings").json()["providers"]["ollama"]
        assert data["api_key_count"] == 0
        assert data["has_api_key"] is False

    def test_an_unknown_provider_is_rejected(self, api_client):
        """
        Purpose:
            Pin that storing a credential under an unrecognised provider name is refused.

        Parameters:
            api_client: The test client and the credentials module.

        Security considerations:
            The provider name selects the slot a credential is written to, so accepting an arbitrary one would let a request write into the store under a name nothing will ever read back or clear.
        """
        client, c = api_client
        r = client.post("/api/settings/credentials",
                        json={"provider": "not-a-real-provider", "api_key": "x"})
        assert r.status_code == 400


class TestKeyLabelsWebLayer:
    """
    Purpose:
        The settings endpoints that take, show and change a key's label.
    """
    def test_a_label_given_with_a_key_is_shown_beside_its_masked_form(self, api_client):
        """
        Purpose:
            Pin that a label sent with a new key comes back beside the masked key, and that the payload still carries no full key.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        secret = "sk-label-test-0123456789abcdef"
        client.post("/api/settings/credentials",
                    json={"provider": "ollama", "api_key": secret, "label": "abc@gmail.com"})
        response = client.get("/api/settings")
        stored = response.json()["providers"]["ollama"]["api_keys"]
        assert stored == [{"index": 0, "masked": c.mask_key(secret), "label": "abc@gmail.com"}]
        assert not _contains_constant_time(response.text, secret)

    def test_a_stored_key_is_labelled_by_position(self, api_client):
        """
        Purpose:
            Pin that the label endpoint sets and clears a stored key's label without the key being sent.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        c.set_api_keys("ollama", ["k1-0123456789ab", "k2-0123456789ab"])
        assert client.put("/api/settings/credentials/ollama/1/label", json={"label": "def@gmail.com"}).status_code == 200
        labels = [k["label"] for k in client.get("/api/settings").json()["providers"]["ollama"]["api_keys"]]
        assert labels == ["", "def@gmail.com"]
        client.put("/api/settings/credentials/ollama/1/label", json={"label": ""})
        assert c.get_api_key_entries("ollama")[1]["label"] == ""

    @pytest.mark.parametrize("path, body", [
        ("/api/settings/credentials/ollama/3/label", {"label": "x"}),
        ("/api/settings/credentials/ollama/0/label", {"label": "x" * 81}),
        ("/api/settings/credentials/nope/0/label", {"label": "x"}),
    ])
    def test_a_bad_label_request_is_a_400(self, api_client, path, body):
        """
        Purpose:
            Pin that a missing position, an overlong label and an unknown provider are refused with a 400 and change nothing.

        Parameters:
            api_client: The test client and the credentials module.
            path: The label endpoint path.
            body: The request body.
        """
        client, c = api_client
        c.set_api_keys("ollama", ["k1-0123456789ab"])
        assert client.put(path, json=body).status_code == 400
        assert c.get_api_key_entries("ollama") == [{"key": "k1-0123456789ab", "label": ""}]

    def test_an_overlong_label_on_a_new_key_stores_nothing(self, api_client):
        """
        Purpose:
            Pin that a key sent with a label the store refuses is rejected whole, so a key never lands without the label the user meant to give it.

        Parameters:
            api_client: The test client and the credentials module.
        """
        client, c = api_client
        response = client.post("/api/settings/credentials",
                               json={"provider": "ollama", "api_key": "k1-0123456789ab", "label": "x" * 81})
        assert response.status_code == 400
        assert c.get_api_keys("ollama") == []


class TestConfiguredCheckLogging:
    """
    Purpose:
        The line the provider check logs about whether a key is configured.
    """
    def test_the_log_line_never_carries_what_the_store_returned(self, monkeypatch, capsys):
        """
        Purpose:
            Pin that the configured line is fixed text even when the credential check hands back the key itself.

        Parameters:
            monkeypatch: Selects a key-based provider and makes the credential check return a key rather than a flag.
            capsys: Captures the terminal output.

        Security considerations:
            The check is meant to return a boolean, but formatting its result into the log would print a key the moment it returned one, and verbose logs get pasted into bug reports. The key here is invented.
        """
        from lu77U_MobileSec.config import credentials, user_settings
        from lu77U_MobileSec.tools_checker import ollama_checker

        monkeypatch.setattr(user_settings, "get_active_provider", lambda: "openai")
        monkeypatch.setattr(user_settings, "get_provider_config", lambda _: {})
        monkeypatch.setattr(credentials, "has_api_key", lambda _: ["sk-invented-0000"])
        assert ollama_checker.check_ai_provider_configured(verbose=True)
        out = capsys.readouterr().out
        assert "Configured: True" in out
        assert "sk-invented-0000" not in out
