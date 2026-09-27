#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.custom_provider

Purpose:
    Provider for any OpenAI-compatible endpoint -- a self-hosted gateway, a proxy, or a third-party service such as Groq or OpenRouter -- where compatibility is claimed but not guaranteed.

Responsibilities:
    Build requests in the Chat Completions shape, degrade gracefully when the endpoint rejects structured output, and implement analyze, list_models and validate_credentials.

Dependencies:
    httpx, the shared base provider.

Implementation notes:
    This provider assumes less than the OpenAI one. "OpenAI-compatible" in practice means the chat completions route works and everything else is optional, so structured output is attempted, detected as unsupported, and disabled for the rest of the scan rather than being relied on.

Security considerations:
    The base URL is entirely operator-supplied. Every prompt, including decompiled application source, is sent there. No certificate pinning or host allowlist is applied, so the operator is trusting that endpoint completely.
"""

import base64
import json
import time
from typing import Any, Dict, List, Optional

import httpx

from .base_provider import BaseAIProvider
from .errors import classify
from ..utils.verbose import verbose_print

_TIMEOUT = 120.0


def _usage_metrics(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Translate an OpenAI-shaped usage block into the shared metrics shape.

    Parameters:
        usage: The usage object from the response body, or None.

    Returns:
        A metrics dict, or an empty dict when usage was absent.

    Implementation notes:
        Duplicated from the OpenAI provider rather than shared, because a compatible endpoint may omit or rename these fields and this copy is free to diverge without affecting the real OpenAI path.
    """
    if not usage:
        return {}
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens")
    return {
        "prompt_eval_count": usage.get("prompt_tokens"),
        "eval_count": usage.get("completion_tokens"),
        "cache_read_tokens": cached or 0,
    }

class CustomProvider(BaseAIProvider):
    """
    Purpose:
        Provider implementation for OpenAI-compatible endpoints of unknown fidelity.

    Attributes:
        name: The provider identifier, "custom".

    Invariants:
        Once structured output has been observed to fail, it is disabled for the lifetime of this provider instance and never retried.

    Thread-safety:
        Inherits the base provider's guarantees. The structured-output flag is a plain boolean written without a lock; a concurrent write can only set it to the same value, and the worst outcome is one extra probe request.
    """
    name = "custom"

    def __init__(self, *args, **kwargs):
        """
        Purpose:
            Initialise the provider and the structured-output capability flag.

        Parameters:
            args: Forwarded to the base provider.
            kwargs: Forwarded to the base provider.

        Postconditions:
            Structured output is assumed supported until a request proves otherwise.
        """
        super().__init__(*args, **kwargs)
        self._schema_unsupported = False

    def base_url(self) -> str:
        """
        Purpose:
            Resolve the configured endpoint URL.

        Returns:
            The base URL without a trailing slash, or an empty string when none is configured.

        Implementation notes:
            Unlike the other providers there is no default. An unconfigured custom provider has no meaningful endpoint to guess, so the empty string is checked explicitly by callers.

        Security considerations:
            Operator-supplied and used as given.
        """
        return (self.config.get("base_url") or "").rstrip("/")

    def _headers(self) -> Dict[str, str]:
        """
        Purpose:
            Build request headers, adding bearer authentication only when a key is configured.

        Returns:
            The header mapping.

        Implementation notes:
            The Authorization header is omitted entirely when there is no key, because many self-hosted gateways reject a request carrying an empty bearer token where they would have accepted one with no header at all.

        Security considerations:
            May embed a live API key; never log the result.
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def supports_vision(self) -> bool:
        """
        Purpose:
            Report that this provider accepts image input.

        Returns:
            True.

        Known limitations:
            This is optimistic. The endpoint may not support images at all, in which case the request fails at call time rather than being avoided.
        """
        return True

    @staticmethod
    def _wrapped_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Purpose:
            Wrap an array schema in the object envelope that structured outputs require.

        Parameters:
            schema: The array schema describing a finding list.

        Returns:
            An object schema with a required "vulnerabilities" array.

        Implementation notes:
            additionalProperties is deliberately not set here, unlike the OpenAI provider. Strict mode is uneven across compatible endpoints, and omitting the constraint avoids rejections from servers that validate the schema more literally than OpenAI does.
        """
        return {
            "type": "object",
            "properties": {"vulnerabilities": schema},
            "required": ["vulnerabilities"],
        }

    @staticmethod
    def _unwrap(content: str, wrapped: bool) -> str:
        """
        Purpose:
            Recover the plain findings array from a response that was wrapped in the schema envelope.

        Parameters:
            content: The response content.
            wrapped: Whether the request actually used the wrapped schema.

        Returns:
            The unwrapped array as JSON text, or the content unchanged.

        Implementation notes:
            Returns the content untouched when the request was not wrapped, when it will not parse, or when the expected key is absent. Every one of those cases is better handled by the response parser than guessed at here. The wrapped flag is threaded through rather than inferred from the content, because a model can legitimately return an object containing a "vulnerabilities" key even when no envelope was requested.
        """
        if not wrapped:
            return content
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, ValueError, TypeError):
            return content
        if isinstance(parsed, dict) and "vulnerabilities" in parsed:
            return json.dumps(parsed["vulnerabilities"])
        return content

    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
        max_tokens: Optional[int] = None,
        session_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Purpose:
            Send an analysis prompt to the configured endpoint and return the findings it reports, adapting to endpoints that do not support structured output.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the shared default applies when None.
            schema: Response schema; the vulnerability schema applies when None.
            images: PNG payloads, encoded as data URLs.
            max_tokens: Output cap.
            session_key: Recorded in the transcript.

        Returns:
            A result dict carrying "response" on success, or "error" on failure, with "fatal" when the circuit tripped. Never raises.

        Side effects:
            Makes one or two network requests per attempt, updates usage counters, writes a transcript, and may permanently disable structured output for this provider instance.

        Complexity:
            At most one attempt per configured API key, each costing up to two requests on the first structured-output probe.

        Implementation notes:
            A missing base URL fails immediately with a clear message rather than attempting a request against an empty URL. The structured-output fallback is the substantive behaviour here. A 400 on a request carrying response_format is treated as a capability signal: the request is retried once without it, and if that retry is not also a 400, structured output is disabled for the rest of this provider's life. Pinning the verdict avoids paying for a failed probe on every subsequent call, and a second 400 leaves the flag alone because the failure was evidently about something else. Falling back means the endpoint returns free-form text, which the response parser then has to recover findings from -- a real quality loss, which is why it is traced rather than silent. The attempt loop runs once per key inside the concurrency gate, rotating on a recoverable failure and returning otherwise.

        Security considerations:
            The prompt contains decompiled application source and is transmitted to an operator-chosen endpoint.
        """
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"Custom provider circuit open ({self._fatal}); skipping call",
                self.verbose)
            return tripped

        if not self.base_url():
            return {"error": "Custom provider has no base URL configured"}
        system_message = system_message or self.default_system_message
        schema = schema or self.schema
        user_content: Any = prompt
        if images:
            user_content = [{"type": "text", "text": prompt}]
            for img in images:
                b64 = base64.b64encode(img).decode()
                user_content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}})
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_content},
            ],
        }
        if max_tokens:
            body["max_tokens"] = max_tokens
        wrap_array = False
        if not self._schema_unsupported:
            wrap_array = schema.get("type") == "array"
            schema_for_body = self._wrapped_schema(schema) if wrap_array else schema
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "structured_response", "schema": schema_for_body},
            }
        with self._request_gate:
            for _ in range(max(len(self._keys), 1)):
                started = time.monotonic()
                try:
                    resp = self._post(body)
                    if (resp.status_code == 400 and "response_format" in body
                            and not self._schema_unsupported):
                        verbose_print(
                            "Custom provider rejected response_format (400); "
                            "retrying without structured output and falling "
                            "back to prompt-based JSON for this scan", self.verbose)
                        fallback_body = {k: v for k, v in body.items() if k != "response_format"}
                        resp = self._post(fallback_body)
                        if resp.status_code != 400:
                            self._schema_unsupported = True
                            wrap_array = False
                    resp.raise_for_status()
                    payload = resp.json()
                    elapsed = time.monotonic() - started
                    metrics = _usage_metrics(payload.get("usage"))
                    content = payload["choices"][0]["message"]["content"]
                    content = self._unwrap(content, wrap_array)
                    self.record_usage(elapsed, metrics, ok=True)
                    self.log_exchange(
                        system_message, prompt, content,
                        elapsed=elapsed, metrics=metrics, session_key=session_key)
                    return {"response": content}
                except Exception as e:
                    elapsed = time.monotonic() - started
                    verbose_print(f"Custom provider analysis failed: {e}", self.verbose)
                    self.record_usage(elapsed, ok=False)
                    self.log_exchange(
                        system_message, prompt, "", elapsed=elapsed,
                        error=str(e), session_key=session_key)
                    key_before = self.api_key
                    fatal = self._handle_exception(e)
                    if fatal:
                        return fatal
                    if self.api_key != key_before:
                        continue
                    return {"error": f"Custom request failed: {e}"}
            return {"error": "Custom request failed: exhausted the key pool"}

    def _post(self, body: Dict[str, Any]) -> httpx.Response:
        """
        Purpose:
            Issue a chat completions request to the configured endpoint.

        Parameters:
            body: The request body.

        Returns:
            The raw httpx response, unraised, so the caller can inspect the status code before deciding whether it is a capability signal or an error.

        Implementation notes:
            Deliberately does not call raise_for_status. The structured-output fallback needs to see a 400 as data rather than as an exception.
        """
        return httpx.post(
            self.base_url() + "/chat/completions",
            headers=self._headers(),
            json=body,
            timeout=_TIMEOUT,
        )

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the models the endpoint offers, for the settings UI.

        Returns:
            The endpoint's model identifiers, or the configured model alone, or an empty list.

        Implementation notes:
            Fetched rather than curated, because nothing is known in advance about a custom endpoint. Every failure falls back to the configured model, so the settings UI always shows the user their own choice even when the endpoint has no models route. Entries without an id are dropped so the chooser shows no blanks.
        """
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            ids = [m.get("id", "") for m in data if m.get("id")]
            if ids:
                return ids
        except Exception:
            pass
        return [self.model] if self.model else []

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that the configured endpoint is reachable and not rejecting the request outright.

        Returns:
            True when the models endpoint answers with anything below a 500.

        Side effects:
            Makes one request.

        Implementation notes:
            Any sub-500 response counts, unlike the OpenAI provider's strict 200. A compatible endpoint may not implement the models route at all, and a 404 there says nothing about whether chat completions work. This tests reachability rather than authentication, which is the most that can be established without spending tokens.

        Known limitations:
            Because of that, a wrong API key can still validate successfully, and the failure appears on the first real request instead.
        """
        if not self.base_url():
            return False
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            return resp.status_code < 500
        except Exception as e:
            verbose_print(f"Custom credential validation failed: {e}", self.verbose)
            return False
