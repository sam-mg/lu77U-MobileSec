#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.openai_provider

Purpose:
    OpenAI provider, using structured outputs to constrain responses to the findings schema.

Responsibilities:
    Build request headers and the wrapped schema, translate usage figures, and implement analyze, list_models and validate_credentials.

Dependencies:
    httpx, the shared base provider, .schema for response coercion.

Implementation notes:
    The Chat Completions API is called directly over httpx rather than through the OpenAI SDK, which keeps the dependency surface small and lets the same code serve any OpenAI-compatible endpoint through the base_url override.

Security considerations:
    Prompts carrying decompiled application source are sent to the configured endpoint, which is api.openai.com unless a base_url is configured. The key is sent as a bearer token and never logged.
"""

import base64
import json
import time
from typing import Any, Dict, List, Optional

import httpx

from .base_provider import BaseAIProvider
from .registry import CURATED_MODELS, DEFAULT_MODELS
from .schema import coerce_to_vuln_list
from ..utils.verbose import verbose_print

OPENAI_BASE_URL = "https://api.openai.com/v1"
_TIMEOUT = 120.0


def _usage_metrics(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Translate the API's usage block into the shared metrics shape.

    Parameters:
        usage: The usage object from the response body, or None.

    Returns:
        A metrics dict, or an empty dict when usage was absent.

    Implementation notes:
        Cached prompt tokens live in a nested details object that is absent on models without caching, so the lookup defaults the intermediate to an empty dict rather than chaining through a possible None.
    """
    if not usage:
        return {}
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens")
    return {
        "prompt_eval_count": usage.get("prompt_tokens"),
        "eval_count": usage.get("completion_tokens"),
        "cache_read_tokens": cached or 0,
    }

class OpenAIProvider(BaseAIProvider):
    """
    Purpose:
        Provider implementation for OpenAI and OpenAI-compatible endpoints.

    Attributes:
        name: The provider identifier, "openai".

    Invariants:
        supports_vision is True. The endpoint is api.openai.com unless base_url is configured.

    Thread-safety:
        Inherits the base provider's guarantees. Each request builds its own headers, so key rotation is picked up immediately.
    """
    name = "openai"

    def default_model(self) -> str:
        """
        Purpose:
            The OpenAI model used when the user has configured none.

        Returns:
            The registry default for this provider.
        """
        return DEFAULT_MODELS["openai"]

    def base_url(self) -> str:
        """
        Purpose:
            Resolve the API base URL, honouring a configured override.

        Returns:
            The base URL without a trailing slash, so path concatenation cannot produce a double slash.

        Security considerations:
            A configured base_url redirects every prompt -- including decompiled application source -- to that operator. It is operator-supplied and used as given.
        """
        return (self.config.get("base_url") or OPENAI_BASE_URL).rstrip("/")

    def _headers(self) -> Dict[str, str]:
        """
        Purpose:
            Build the request headers, including bearer authentication.

        Returns:
            The header mapping.

        Security considerations:
            Embeds the live API key. The result must never be logged or attached to an error report.
        """
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _wrapped_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Purpose:
            Wrap the findings schema in the object envelope that structured outputs require.

        Parameters:
            schema: The array schema describing a finding list.

        Returns:
            An object schema with a required "vulnerabilities" array.

        Implementation notes:
            additionalProperties is false because OpenAI's strict structured-output mode rejects a schema without it, and because it stops the model appending commentary fields that the parser would then discard.
        """
        return {
            "type": "object",
            "properties": {"vulnerabilities": schema},
            "required": ["vulnerabilities"],
            "additionalProperties": False,
        }

    def supports_vision(self) -> bool:
        """
        Purpose:
            Report that this provider accepts image input.

        Returns:
            True.
        """
        return True

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
            Send an analysis prompt to OpenAI and return the findings it reports.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the shared default applies when None.
            schema: Response schema; the vulnerability schema applies when None.
            images: PNG payloads, base64-encoded into the request.
            max_tokens: Output cap.
            session_key: Recorded in the transcript; this provider holds no server-side session.

        Returns:
            A result dict carrying "response" on success, or "error" on failure, with "fatal" when the circuit tripped. Never raises.

        Side effects:
            Makes a network request, updates usage counters, writes a transcript, and may rotate the API key or trip the circuit.

        Complexity:
            At most one attempt per configured API key.

        Implementation notes:
            The circuit is checked before anything else, so a provider already known to be out of quota costs nothing. The whole attempt loop runs inside the concurrency gate, so the gate bounds requests in flight across every worker sharing this provider. Holding it across retries is deliberate: a retrying worker is still consuming the provider's capacity. The loop runs once per key. After a failure, the active key is compared before and after exception handling -- a changed key means rotation happened and the request is worth retrying, an unchanged key means the failure was not recoverable here and is returned to the caller, which owns the backoff policy. The text block is placed first and images after it, matching the ordering this API expects. The response content is passed through coerce_to_vuln_list before being re-serialised, so a model that wraps its array in an object still yields a plain list. Content that cannot be coerced is returned unchanged for the response parser to handle. max_completion_tokens is sent rather than max_tokens, which is the parameter current models accept.

        Security considerations:
            The prompt contains decompiled application source and is transmitted to OpenAI. Failures are logged through the verbose module so credential-shaped text is redacted.
        """
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"OpenAI circuit open ({self._fatal}); skipping call",
                self.verbose)
            return tripped

        system_message = system_message or self.default_system_message
        schema = schema or self.schema
        user_content: Any = prompt
        if images:
            user_content = [{"type": "text", "text": prompt}]
            for img in images:
                b64 = base64.b64encode(img).decode()
                user_content.append({"type": "image_url",
                                     "image_url": {"url": f"data:image/png;base64,{b64}"}})
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "vulnerability_report",
                    "schema": self._wrapped_schema(schema),
                },
            },
        }
        if max_tokens:
            body["max_completion_tokens"] = max_tokens
        with self._request_gate:
            for _ in range(max(len(self._keys), 1)):
                started = time.monotonic()
                try:
                    resp = httpx.post(
                        self.base_url() + "/chat/completions",
                        headers=self._headers(),
                        json=body,
                        timeout=_TIMEOUT,
                    )
                    resp.raise_for_status()
                    payload = resp.json()
                    elapsed = time.monotonic() - started
                    metrics = _usage_metrics(payload.get("usage"))
                    content = payload["choices"][0]["message"]["content"]
                    vulns = coerce_to_vuln_list(content)
                    response_text = json.dumps(vulns) if isinstance(vulns, (list, dict)) else content
                    self.record_usage(elapsed, metrics, ok=True)
                    self.log_exchange(
                        system_message, prompt, response_text,
                        elapsed=elapsed, metrics=metrics, session_key=session_key)
                    return {"response": response_text}
                except Exception as e:
                    elapsed = time.monotonic() - started
                    verbose_print(f"OpenAI analysis failed: {e}", self.verbose)
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
                    return {"error": f"OpenAI request failed: {e}"}
            return {"error": "OpenAI request failed: exhausted the key pool"}

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the OpenAI models offered in the settings UI.

        Returns:
            The curated list from the registry.

        Implementation notes:
            Curated rather than fetched, so the settings page works before a key is configured. The live endpoint also returns hundreds of non-chat models, which would be unusable as a chooser.
        """
        return list(CURATED_MODELS["openai"])

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that the configured key is accepted by the endpoint.

        Returns:
            True when the models endpoint answers 200.

        Side effects:
            Makes one authenticated request.

        Implementation notes:
            Only an exact 200 counts. An OpenAI-compatible endpoint that does not implement the models route returns 404, and treating that as success would report a working configuration that then fails on the first real request.

        Security considerations:
            Sends the key but no analysis content.
        """
        if not self.api_key:
            return False
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            return resp.status_code == 200
        except Exception as e:
            verbose_print(f"OpenAI credential validation failed: {e}", self.verbose)
            return False
