#!/usr/bin/env python3
"""
Module: test_custom_provider_schema

Purpose:
    Structured output on the custom OpenAI-compatible provider, and the one-time downgrade for endpoints that do not implement it.

Responsibilities:
    Pin the array wrap and unwrap, the untouched object schema, and each branch of the downgrade decision.

Dependencies:
    pytest, httpx, the custom provider and the shared vulnerability schema.

Implementation notes:
    The provider previously accepted a schema argument and ignored it, so every free or self-hosted endpoint ran schema-free and leaned entirely on downstream salvage. It now sends the structured-output field, with two behaviours the built-in provider gets wrong for a schema whose root is not an array: only the array-rooted schema is wrapped, and the unwrap pulls the wrapped key out directly rather than coercing it, so a next-action object comes back as an object rather than a list holding one. Nothing here touches the network; every request is monkeypatched.
"""

import json

import httpx

from lu77U_MobileSec.ai.custom_provider import CustomProvider
from lu77U_MobileSec.ai.schema import VULNERABILITY_SCHEMA


def _resp(status, **kw):
    """
    Purpose:
        Build an httpx response with a request attached, as the provider expects.

    Parameters:
        status: The HTTP status code.
        kw: Passed through to the response, typically the body.

    Returns:
        The response.
    """
    return httpx.Response(status, request=httpx.Request("POST", "http://x"), **kw)


def _provider(**config):
    """
    Purpose:
        Build a custom provider pointed at a dummy endpoint.

    Parameters:
        config: Extra configuration merged over the base URL.

    Returns:
        The provider.
    """
    return CustomProvider(config={"base_url": "http://x", **config})


class TestArraySchemaWrapUnwrap:
    """
    Purpose:
        That an array schema is wrapped on the way out and unwrapped on the way back, while an object schema is left alone.
    """
    def test_array_schema_is_wrapped_in_the_request_and_unwrapped_in_the_reply(self, monkeypatch):
        """
        Purpose:
            Pin that the findings schema is sent wrapped in an object and that the reply comes back as a plain list.

        Parameters:
            monkeypatch: Replaces the HTTP call with a fake that records the request body.

        Implementation notes:
            Structured output requires an object at the top level, so the array has to be wrapped; the caller still expects a list, so the wrapper has to come back off. Both halves are asserted because either alone would leave the other free to drift.
        """
        seen = {}

        def fake_post(url_unused, json=None, **_unused_kwargs):
            """
            Purpose:
                Stand in for the HTTP call, recording the request body and returning a wrapped findings list.

            Parameters:
                url_unused: The endpoint; unused by the fake.
                json: The request body, which the assertions inspect.
                _unused_kwargs: Request headers and timeout; unused by the fake.

            Returns:
                The canned response.
            """
            seen["body"] = json
            reply = {"vulnerabilities": [{"title": "x", "file": "f.java", "line": "1"}]}
            return _resp(200, json={"choices": [{"message": {"content": __import__("json").dumps(reply)}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = _provider()
        result = prov.analyze("p", system_message="s", schema=VULNERABILITY_SCHEMA)

        sent_schema = seen["body"]["response_format"]["json_schema"]["schema"]
        assert sent_schema["type"] == "object"
        assert sent_schema["properties"]["vulnerabilities"] is VULNERABILITY_SCHEMA

        parsed = json.loads(result["response"])
        assert isinstance(parsed, list)
        assert parsed == [{"title": "x", "file": "f.java", "line": "1"}]

    def test_object_schema_is_sent_unwrapped_and_returned_unwrapped(self, monkeypatch):
        """
        Purpose:
            Pin that a schema already rooted in an object is sent and returned untouched.

        Parameters:
            monkeypatch: Replaces the HTTP call with a fake that records the request body.

        Implementation notes:
            Wrapping here would ask the endpoint for the wrong shape entirely, and coercing the reply would turn a single next-action object into a list holding it, which the agent loop would not understand.
        """
        object_schema = {"type": "object", "properties": {"action": {"type": "string"}},
                          "required": ["action"]}
        seen = {}

        def fake_post(url_unused, json=None, **_unused_kwargs):
            """
            Purpose:
                Stand in for the HTTP call, recording the request body and returning a next-action object.

            Parameters:
                url_unused: The endpoint; unused by the fake.
                json: The request body, which the assertions inspect.
                _unused_kwargs: Request headers and timeout; unused by the fake.

            Returns:
                The canned response.
            """
            seen["body"] = json
            action = {"action": "list_files", "path": "."}
            return _resp(200, json={"choices": [{"message": {"content": __import__("json").dumps(action)}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = _provider()
        result = prov.analyze("p", system_message="s", schema=object_schema)

        sent_schema = seen["body"]["response_format"]["json_schema"]["schema"]
        assert sent_schema is object_schema

        parsed = json.loads(result["response"])
        assert isinstance(parsed, dict)
        assert parsed == {"action": "list_files", "path": "."}


class TestGracefulDowngrade:
    """
    Purpose:
        The one-time downgrade for endpoints that reject structured output, and the cases that must not trigger it.
    """
    def test_a_400_after_response_format_falls_back_and_is_cached(self, monkeypatch):
        """
        Purpose:
            Pin that a rejection of the structured-output field retries without it once, and that the verdict is remembered for the rest of the provider's life.

        Parameters:
            monkeypatch: Replaces the HTTP call with a fake that rejects the structured-output field.

        Implementation notes:
            The caching is the point. Without it the provider would pay for a rejected request on every one of a scan's dozens of turns, which doubles the request count against exactly the endpoints least able to absorb it.
        """
        calls = []

        def fake_post(url_unused, json=None, **_unused_kwargs):
            """
            Purpose:
                Stand in for the HTTP call, rejecting any request carrying the structured-output field and accepting the rest.

            Parameters:
                url_unused: The endpoint; unused by the fake.
                json: The request body, which the assertions inspect.
                _unused_kwargs: Request headers and timeout; unused by the fake.

            Returns:
                The canned response.
            """
            calls.append(dict(json))
            if "response_format" in json:
                return _resp(400, text="unknown field: response_format")
            return _resp(200, json={"choices": [{"message": {"content": "[]"}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = _provider()

        result1 = prov.analyze("p1", system_message="s")
        assert result1 == {"response": "[]"}
        assert prov._schema_unsupported is True
        assert len(calls) == 2
        assert "response_format" in calls[0]
        assert "response_format" not in calls[1]

        result2 = prov.analyze("p2", system_message="s")
        assert result2 == {"response": "[]"}
        assert len(calls) == 3
        assert "response_format" not in calls[2]

    def test_a_400_that_is_not_about_response_format_still_fails_normally(self, monkeypatch):
        """
        Purpose:
            Pin that a rejection for an unrelated reason is reported as an error rather than treated as missing schema support.

        Parameters:
            monkeypatch: Replaces the HTTP call with a fake that rejects for a different reason.

        Implementation notes:
            Treating any rejection as a capability signal would permanently disable structured output because of a transient or unrelated fault, silently degrading every later request.
        """
        def fake_post(*_unused_args, **_unused_kwargs):
            """
            Purpose:
                Stand in for the HTTP call, rejecting every request for an unrelated reason.

            Parameters:
                _unused_args: The endpoint, unused by the fake.
                _unused_kwargs: The request headers, body and timeout, unused by the fake.

            Returns:
                The canned response.
            """
            return _resp(400, text="model not found")

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = _provider()
        result = prov.analyze("p", system_message="s")

        assert "error" in result
        assert prov._schema_unsupported is False

    def test_a_200_with_an_unfollowed_schema_is_not_mistaken_for_rejection(self, monkeypatch):
        """
        Purpose:
            Pin that an endpoint answering successfully with off-shape content does not trigger the downgrade.

        Parameters:
            monkeypatch: Replaces the HTTP call with a fake returning content that does not match the schema.

        Implementation notes:
            An endpoint that accepts the field but ignores it returns a normal success, never an HTTP error, so the downgrade must key on the rejection rather than on the content being unusable.
        """
        def fake_post(*_unused_args, **_unused_kwargs):
            """
            Purpose:
                Stand in for the HTTP call, succeeding with content that does not match the requested schema.

            Parameters:
                _unused_args: The endpoint, unused by the fake.
                _unused_kwargs: The request headers, body and timeout, unused by the fake.

            Returns:
                The canned response.
            """
            return _resp(200, json={"choices": [{"message": {"content": "not json at all"}}]})

        monkeypatch.setattr(httpx, "post", fake_post)
        prov = _provider()
        result = prov.analyze("p", system_message="s", schema=VULNERABILITY_SCHEMA)

        assert result == {"response": "not json at all"}
        assert prov._schema_unsupported is False
