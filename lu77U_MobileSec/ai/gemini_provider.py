#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.gemini_provider

Purpose:
    Google Gemini provider, using the generateContent endpoint with a response schema to constrain output to the findings shape.

Responsibilities:
    Build the request URL and auth header, translate usage figures, and implement analyze, list_models and validate_credentials.

Dependencies:
    httpx, the shared base provider, .schema for response coercion.

Implementation notes:
    Called directly over httpx rather than through the Google SDK. The request shape is stable and the SDK is large, so the direct call keeps the dependency surface small and the failure modes visible.

Security considerations:
    Prompts carrying decompiled application source are sent to Google. The key travels in a header rather than a query parameter, which keeps it out of server access logs and out of any URL that gets traced.
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

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
_TIMEOUT = 120.0


def _usage_metrics(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Translate Gemini's usageMetadata block into the shared metrics shape.

    Parameters:
        usage: The usageMetadata object from the response, or None.

    Returns:
        A metrics dict, or an empty dict when usage was absent.

    Implementation notes:
        Gemini names its counters in camel case and differently from every other provider, which is the whole reason each provider owns this translation instead of sharing one. The cached-token counter defaults to zero so it aggregates without a None check.
    """
    if not usage:
        return {}
    return {
        "prompt_eval_count": usage.get("promptTokenCount"),
        "eval_count": usage.get("candidatesTokenCount"),
        "cache_read_tokens": usage.get("cachedContentTokenCount") or 0,
    }

class GeminiProvider(BaseAIProvider):
    """
    Purpose:
        Provider implementation for Google Gemini.

    Attributes:
        name: The provider identifier, "gemini".

    Invariants:
        supports_vision is True. The endpoint is Google's public generative-language host unless base_url is configured.

    Thread-safety:
        Inherits the base provider's guarantees. Headers are built per request, so key rotation takes effect immediately.
    """
    name = "gemini"

    def default_model(self) -> str:
        """
        Purpose:
            The Gemini model used when the user has configured none.

        Returns:
            The registry default for this provider.
        """
        return DEFAULT_MODELS["gemini"]

    def base_url(self) -> str:
        """
        Purpose:
            Resolve the API base URL, honouring a configured override.

        Returns:
            The base URL without a trailing slash.

        Security considerations:
            A configured base_url redirects every prompt, including decompiled application source, to that operator.
        """
        return (self.config.get("base_url") or GEMINI_BASE_URL).rstrip("/")

    def _auth_headers(self) -> Dict[str, str]:
        """
        Purpose:
            Build the authentication header for a Gemini request.

        Returns:
            A mapping carrying the API key header.

        Implementation notes:
            The key is sent in the x-goog-api-key header rather than as a URL query parameter. Both are accepted by the API, but a key in the URL ends up in server logs, proxy logs and any traced request line. An absent key yields an empty header value rather than None, so the request is well formed and fails with a clear authentication error instead of a client-side type error.

        Security considerations:
            Embeds the live API key; never log the result.
        """
        return {"x-goog-api-key": self.api_key or ""}

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
            Send an analysis prompt to Gemini and return the findings it reports.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the shared default applies when None.
            schema: Response schema; the vulnerability schema applies when None.
            images: PNG payloads, inlined base64-encoded.
            max_tokens: Output cap.
            session_key: Recorded in the transcript; this provider holds no server-side session.

        Returns:
            A result dict carrying "response" on success, or "error" on failure, with "fatal" when the circuit tripped. Never raises.

        Side effects:
            Makes a network request, updates usage counters, writes a transcript, and may rotate the API key or trip the circuit.

        Complexity:
            At most one attempt per configured API key.

        Implementation notes:
            The model name is interpolated into the URL path, which is how this API selects a model -- unlike the other providers, where it is a body field. responseMimeType and responseSchema together are what make Gemini return schema-valid JSON rather than prose containing JSON. The response text is dug out of a deeply nested candidates structure; a response that does not match that shape raises inside the try and is handled as a failed call, which is the intended behaviour for a truncated or blocked response. The attempt loop runs once per key inside the concurrency gate, rotating on a recoverable failure and returning otherwise. Comparing the active key before and after exception handling is what distinguishes the two.

        Security considerations:
            The prompt contains decompiled application source and is transmitted to Google. Failures are traced through the verbose module so credential-shaped text is redacted.
        """
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"Gemini circuit open ({self._fatal}); skipping call",
                self.verbose)
            return tripped

        system_message = system_message or self.default_system_message
        schema = schema or self.schema
        url = f"{self.base_url()}/models/{self.model}:generateContent"
        verbose_print(f"Gemini request: {url}", self.verbose)
        parts: List[Dict[str, Any]] = [{"text": prompt}]
        for img in images or []:
            parts.append({"inline_data": {"mime_type": "image/png",
                                          "data": base64.b64encode(img).decode()}})
        generation_config: Dict[str, Any] = {
            "responseMimeType": "application/json",
            "responseSchema": schema,
        }
        if max_tokens:
            generation_config["maxOutputTokens"] = max_tokens
        body = {
            "system_instruction": {"parts": [{"text": system_message}]},
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": generation_config,
        }
        with self._request_gate:
            for _ in range(max(len(self._keys), 1)):
                started = time.monotonic()
                try:
                    resp = httpx.post(url, json=body, headers=self._auth_headers(),
                                      timeout=_TIMEOUT)
                    resp.raise_for_status()
                    data = resp.json()
                    elapsed = time.monotonic() - started
                    metrics = _usage_metrics(data.get("usageMetadata"))
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    vulns = coerce_to_vuln_list(text)
                    response_text = json.dumps(vulns) if isinstance(vulns, (list, dict)) else text
                    self.record_usage(elapsed, metrics, ok=True)
                    self.log_exchange(
                        system_message, prompt, response_text,
                        elapsed=elapsed, metrics=metrics, session_key=session_key)
                    return {"response": response_text}
                except Exception as e:
                    elapsed = time.monotonic() - started
                    verbose_print(f"Gemini analysis failed: {e}", self.verbose)
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
                    return {"error": f"Gemini request failed: {e}"}
            return {"error": "Gemini request failed: exhausted the key pool"}

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the Gemini models offered in the settings UI.

        Returns:
            The curated list from the registry.

        Implementation notes:
            Curated rather than fetched, so the settings page works before a key is configured.
        """
        return list(CURATED_MODELS["gemini"])

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that the configured key is accepted by Google.

        Returns:
            True when the models endpoint answers 200.

        Side effects:
            Makes one authenticated request.

        Implementation notes:
            A missing key short-circuits to False without a request. Only an exact 200 counts as valid.

        Security considerations:
            Sends the key but no analysis content.
        """
        if not self.api_key:
            return False
        try:
            resp = httpx.get(f"{self.base_url()}/models",
                             headers=self._auth_headers(), timeout=30.0)
            return resp.status_code == 200
        except Exception as e:
            verbose_print(f"Gemini credential validation failed: {e}", self.verbose)
            return False
