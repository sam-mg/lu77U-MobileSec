#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.claude_provider

Purpose:
    Anthropic Claude provider, using tool-calling to force schema-valid findings and prompt caching to cut the cost of a repeated system prompt.

Responsibilities:
    Build the SDK client per request, expose the reporting tool, translate SDK usage figures into the shared metrics shape, and implement analyze, list_models and validate_credentials.

Dependencies:
    The anthropic SDK, imported lazily, plus the shared base provider.

Implementation notes:
    Findings are collected through a forced tool call rather than by parsing free text. Claude validates tool input against the schema before emitting it, which makes malformed findings a provider-side error instead of a parsing problem downstream.

Security considerations:
    Prompts carrying decompiled application source are sent to Anthropic. The API key is read from the base provider per request and never logged.
"""

import base64
import json
import time
from typing import Any, Dict, List, Optional

from .base_provider import BaseAIProvider
from .registry import CURATED_MODELS, DEFAULT_MODELS
from ..utils.verbose import verbose_print

_MIN_CACHEABLE_CHARS = 4000


def _cacheable(system_message: str):
    """
    Purpose:
        Mark a system message for Anthropic prompt caching when it is long enough to be worth caching.

    Parameters:
        system_message: The system prompt.

    Returns:
        The message unchanged when short, or a single-element content block carrying an ephemeral cache_control marker when long.

    Implementation notes:
        Caching has a minimum size below which Anthropic ignores the marker, and the threshold here keeps short messages in their plain string form rather than paying the structural overhead for nothing. This matters because the system prompt is identical across every region of a fan-out scan; caching turns dozens of full-price prompt evaluations into one. The ephemeral cache type is used because the prompt is stable only within a scan, not across scans.
    """
    if not system_message or len(system_message) < _MIN_CACHEABLE_CHARS:
        return system_message
    return [{"type": "text", "text": system_message,
             "cache_control": {"type": "ephemeral"}}]


def _usage_metrics(usage: Any) -> Dict[str, Any]:
    """
    Purpose:
        Translate the SDK's usage object into the shared metrics shape used by the base provider.

    Parameters:
        usage: The SDK usage object, or None.

    Returns:
        A metrics dict, or an empty dict when no usage was reported.

    Implementation notes:
        Fields are read with getattr rather than attribute access, because the SDK omits cache fields entirely on models or requests that do not support caching, and a missing attribute must read as absent rather than raise. Cache counters default to zero rather than None so that they aggregate arithmetically in the base provider without a None check.
    """
    if usage is None:
        return {}
    return {
        "prompt_eval_count": getattr(usage, "input_tokens", None),
        "eval_count": getattr(usage, "output_tokens", None),
        "cache_read_tokens": getattr(usage, "cache_read_input_tokens", None) or 0,
        "cache_creation_tokens": getattr(usage, "cache_creation_input_tokens", None) or 0,
    }


_REPORT_TOOL_NAME = "report_vulnerabilities"

class ClaudeProvider(BaseAIProvider):
    """
    Purpose:
        Provider implementation for Anthropic Claude.

    Attributes:
        name: The provider identifier, "claude".

    Invariants:
        supports_vision is True, so this provider may be selected for the dynamic pipeline's screenshot checks.

    Thread-safety:
        Inherits the base provider's guarantees. A fresh SDK client is built per request rather than shared, so no client state crosses threads.
    """
    name = "claude"

    def default_model(self) -> str:
        """
        Purpose:
            The Claude model used when the user has configured none.

        Returns:
            The registry default for this provider.
        """
        return DEFAULT_MODELS["claude"]

    def _sdk_client(self):
        """
        Purpose:
            Build an Anthropic SDK client bound to the currently active API key.

        Returns:
            A configured client.

        Raises:
            ImportError: When the anthropic SDK is not installed.

        Implementation notes:
            The SDK is imported inside the method and a client is constructed per request rather than cached. That costs little and means a key rotation takes effect immediately, without needing the base provider's rotation hook to invalidate a stored client.
        """
        import anthropic
        return anthropic.Anthropic(api_key=self.api_key)

    def _tool_for(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Purpose:
            Wrap the findings schema in the tool definition Claude is forced to call.

        Parameters:
            schema: The array schema describing a finding list.

        Returns:
            A tool definition whose input schema requires a "vulnerabilities" array.

        Implementation notes:
            Tool input must be an object, so the finding array is nested under a single required property. Forcing this tool is what guarantees schema-valid output; without it the model is free to answer in prose.
        """
        return {
            "name": _REPORT_TOOL_NAME,
            "description": "Report all security vulnerabilities found in the analyzed app.",
            "input_schema": {
                "type": "object",
                "properties": {"vulnerabilities": schema},
                "required": ["vulnerabilities"],
            },
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
            Send an analysis prompt to Anthropic and return the findings it reports.

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
            The circuit is checked before anything else, so a provider already known to be out of quota costs nothing. The whole attempt loop runs inside the concurrency gate, so the gate bounds requests in flight across every worker sharing this provider. Holding it across retries is deliberate: a retrying worker is still consuming the provider's capacity. The loop runs once per key. After a failure, the active key is compared before and after exception handling -- a changed key means rotation happened and the request is worth retrying, an unchanged key means the failure was not recoverable here and is returned to the caller, which owns the backoff policy. Images are placed before the text block, which is the ordering Anthropic recommends for a prompt that asks about an image. A response containing no tool_use block is treated as a failed call that still consumed tokens: usage is recorded as successful, and an error is returned. Counting it as a success is correct for cost accounting even though the call produced nothing usable.

        Security considerations:
            The prompt contains decompiled application source and is transmitted to Anthropic. Failures are logged through the verbose module so credential-shaped text is redacted.
        """
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"Claude circuit open ({self._fatal}); skipping call",
                self.verbose)
            return tripped

        system_message = system_message or self.default_system_message
        schema = schema or self.schema
        content: Any = prompt
        if images:
            content = [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(img).decode()}}
                for img in images
            ]
            content.append({"type": "text", "text": prompt})
        with self._request_gate:
            for _ in range(max(len(self._keys), 1)):
                started = time.monotonic()
                try:
                    client = self._sdk_client()
                    response = client.messages.create(
                        model=self.model,
                        max_tokens=max_tokens or 16000,
                        system=_cacheable(system_message),
                        tools=[self._tool_for(schema)],
                        tool_choice={"type": "tool", "name": _REPORT_TOOL_NAME},
                        messages=[{"role": "user", "content": content}],
                    )
                    elapsed = time.monotonic() - started
                    metrics = _usage_metrics(getattr(response, "usage", None))
                    for block in response.content:
                        if block.type == "tool_use" and block.name == _REPORT_TOOL_NAME:
                            vulns = block.input.get("vulnerabilities", [])
                            self.record_usage(elapsed, metrics, ok=True)
                            self.log_exchange(
                                system_message, prompt, json.dumps(vulns),
                                elapsed=elapsed, metrics=metrics,
                                session_key=session_key, resumed=False)
                            return {"response": json.dumps(vulns)}
                    self.record_usage(elapsed, metrics, ok=True)
                    self.log_exchange(
                        system_message, prompt, "",
                        elapsed=elapsed, metrics=metrics,
                        error="Claude returned no tool_use block", session_key=session_key)
                    return {"error": "Claude returned no tool_use block"}
                except Exception as e:
                    elapsed = time.monotonic() - started
                    verbose_print(f"Claude analysis failed: {e}", self.verbose)
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
                    return {"error": f"Claude request failed: {e}"}
            return {"error": "Claude request failed: exhausted the key pool"}

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the Claude models offered in the settings UI.

        Returns:
            The curated list from the registry.

        Implementation notes:
            Returns a copy of the curated list rather than querying the API, so the settings page works before a key is configured. A copy is returned so a caller sorting or filtering the result cannot mutate the shared registry.
        """
        return list(CURATED_MODELS["claude"])

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that the configured key is accepted by Anthropic.

        Returns:
            True when a model listing succeeds.

        Side effects:
            Makes one authenticated request.

        Implementation notes:
            Listing models is used as the probe because it is cheap, requires no tokens, and fails distinctly on a bad key. A missing key short-circuits to False without a request.

        Security considerations:
            Sends the key but no analysis content. The failure is traced through the verbose module, which redacts credential-shaped text.
        """
        if not self.api_key:
            return False
        try:
            client = self._sdk_client()
            client.models.list()
            return True
        except Exception as e:
            verbose_print(f"Claude credential validation failed: {e}", self.verbose)
            return False
