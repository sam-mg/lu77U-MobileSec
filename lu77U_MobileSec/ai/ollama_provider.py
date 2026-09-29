#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.ollama_provider

Purpose:
    Ollama provider, serving both a local server and Ollama Cloud through one implementation, with streaming responses, reasoning capture and an in-provider retry policy.

Responsibilities:
    Resolve host and mode, build and cache the client, stream chat responses, classify and retry failures, and detect truncation.

Dependencies:
    The ollama client library, imported lazily, httpx for timeouts, ..config.settings for the retry and timeout policy.

Implementation notes:
    Local and cloud differ only in host and whether a bearer token is attached, so one class covers both rather than duplicating the streaming and retry logic. Retries live here rather than in the caller because this provider sees signals no caller can: a done_reason of "length" means truncation, which is worth retrying, and is indistinguishable from success at the call site.

Security considerations:
    In local mode nothing leaves the machine, which is why this is the default provider. In cloud mode prompts carrying decompiled application source are sent to Ollama Cloud with a bearer token.
"""

import base64
import time
from typing import Any, Dict, List, Optional

from .base_provider import BaseAIProvider
from .errors import ErrorClass, classify, is_fatal, retry_after_for
from .registry import DEFAULT_MODELS
from ..config.settings import (
    OLLAMA_KEEP_ALIVE, OLLAMA_MAX_RETRIES, OLLAMA_NUM_PREDICT,
    OLLAMA_REQUEST_TIMEOUT, OLLAMA_RETRY_DELAY,
)
from ..utils.verbose import verbose_print

THROTTLE_RETRY_DELAY = 15

DEFAULT_CLOUD_HOST = "https://api.ollama.com"
DEFAULT_LOCAL_HOST = "http://localhost:11434"

_VISION_MODEL_HINTS = (
    "llava", "vision", "-vl", "vl-", "moondream", "minicpm-v", "bakllava",
    "gemma3", "qwen2-vl", "qwen2.5vl", "pixtral", "llama3.2-vision",
)

class OllamaProvider(BaseAIProvider):
    """
    Purpose:
        Provider implementation for Ollama, local or cloud.

    Attributes:
        name: The provider identifier, "ollama".
        mode: "local" or "cloud", selecting the host and whether a key is sent.
        host: Resolved server URL.

    Invariants:
        Chat requests are always made with thinking enabled. The reasoning trace is captured separately from the response content and is never concatenated into it. The client is built once and cached, and is discarded on key rotation so a rotated key cannot keep using a stale connection.

    Thread-safety:
        Inherits the base provider's guarantees. The cached client is created lazily without a lock; a concurrent first use can build two clients, of which one is discarded -- harmless.

    Security considerations:
        In cloud mode the client carries a bearer token in its headers for its lifetime.
    """
    name = "ollama"

    def __init__(self, *args, **kwargs):
        """
        Purpose:
            Resolve mode and host, and prepare the lazy client.

        Parameters:
            args: Forwarded to the base provider.
            kwargs: Forwarded to the base provider.

        Postconditions:
            mode and host are set consistently; no client or connection exists yet.

        Implementation notes:
            Cloud is the default mode when the config says nothing, because a fresh install has no local server but the cloud host is always reachable.
        """
        super().__init__(*args, **kwargs)
        self.mode = self.config.get("mode", "cloud")
        if self.mode == "local":
            self.host = self.config.get("local_host", DEFAULT_LOCAL_HOST)
        else:
            self.host = self.config.get("cloud_host", DEFAULT_CLOUD_HOST)
        verbose_print(
            f"Initializing OllamaProvider (mode={self.mode}, model={self.model}, host={self.host})",
            self.verbose,
        )
        self._client = None

    def default_model(self) -> str:
        """
        Purpose:
            The Ollama model used when the user has configured none.

        Returns:
            The registry default for this provider.
        """
        return DEFAULT_MODELS["ollama"]

    @property
    def client(self):
        """
        Purpose:
            The Ollama client, built on first use and cached.

        Returns:
            A configured client bound to the resolved host.

        Raises:
            ImportError: When the ollama library is not installed.

        Side effects:
            Imports the library and constructs the client on first access.

        Implementation notes:
            A split timeout is used where httpx is importable: a long read timeout, because a local model can take minutes to produce a long response, paired with a short connect timeout, because a host that is not listening should fail in seconds rather than after the full request timeout. Where httpx is unavailable the single scalar timeout applies to both. The authorization header is attached only in cloud mode and only when a key exists, so a local server is never sent a token it would not understand.

        Security considerations:
            The constructed client holds the API key in its headers for its lifetime, which is why key rotation discards it.
        """
        if self._client is None:
            from ollama import Client
            try:
                import httpx
                timeout = httpx.Timeout(OLLAMA_REQUEST_TIMEOUT, connect=30.0)
            except Exception:
                timeout = OLLAMA_REQUEST_TIMEOUT
            headers = None
            if self.mode != "local" and self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            self._client = Client(host=self.host, headers=headers, timeout=timeout)
        return self._client

    def supports_vision(self) -> bool:
        """
        Purpose:
            Report whether the configured model can accept images.

        Returns:
            True when the model name matches a known vision-model marker.

        Implementation notes:
            Decided by substring match against a hint list, because Ollama's model listing does not expose modality. Model naming is the only signal available.

        Known limitations:
            Inherently approximate. A vision model named unconventionally reads as text-only and is never offered images; a text model whose name happens to contain a hint is sent images it cannot use, and the request fails at call time.
        """
        model = (self.model or "").lower()
        return any(hint in model for hint in _VISION_MODEL_HINTS)

    def _on_key_rotated(self) -> None:
        """
        Purpose:
            Discard the cached client so the next request is built with the new key.

        Side effects:
            Clears the cached client.

        Implementation notes:
            This override is the reason the hook exists on the base class. The key is baked into the client's headers at construction, so without discarding it a rotation would change self.api_key while every subsequent request kept using the failed key.
        """
        self._client = None

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
            Send an analysis prompt to Ollama and return the response, retrying internally on truncation and transient failure.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the shared default applies when None.
            schema: Response schema, passed to Ollama as the format constraint.
            images: PNG payloads, base64-encoded, for vision-capable models.
            max_tokens: Output cap; the configured default applies when None.
            session_key: Accepted for interface compatibility; this provider holds no session.

        Returns:
            A result dict carrying "response", "thinking", "metrics" and "elapsed_s" on success, or "error" on failure, with "fatal" when the circuit tripped. Never raises.

        Side effects:
            Makes one or more streamed requests, updates usage counters, writes transcripts, and may rotate the key or trip the circuit.

        Implementation notes:
            The outer loop re-enters the attempt helper when it returns None, which is its signal that the key was rotated and the request deserves a fresh start with the new credential. Total elapsed time is measured across all retries and compared against the single-request timeout. Exceeding it is recorded as a slow call, because a region blocked for longer than one request's budget distorts a fan-out scan and is worth surfacing even though the call ultimately succeeded. Everything runs inside the concurrency gate, so retries continue to count against the provider's in-flight budget.
        """
        tripped = self._short_circuit()
        if tripped:
            verbose_print(
                f"Ollama circuit open ({self._fatal}); skipping call", self.verbose)
            return tripped

        system_message = system_message or self.default_system_message
        schema = schema or self.schema

        verbose_print(
            f"Starting Ollama analysis - Prompt: {len(prompt)} chars, System: {len(system_message)} chars",
            self.verbose,
        )

        call_started = time.monotonic()
        with self._request_gate:
            while True:
                result = self._attempt_with_current_key(
                    prompt, system_message, schema, images, max_tokens)
                if result is None:
                    continue
                total = time.monotonic() - call_started
                if total > OLLAMA_REQUEST_TIMEOUT:
                    self.record_slow_call()
                    verbose_print(
                        f"Ollama: one analyze() took {total:.0f}s "
                        f"(> {OLLAMA_REQUEST_TIMEOUT}s) across its retries - the "
                        "provider is struggling; this call blocked its region "
                        "for that whole time", self.verbose)
                return result

    def _attempt_with_current_key(
        self, prompt: str, system_message: str, schema: Optional[Dict[str, Any]],
        images: Optional[List[bytes]], max_tokens: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Purpose:
            Run the retry loop for the currently active API key: stream a chat completion, detect truncation, and classify failures.

        Parameters:
            prompt: The user prompt.
            system_message: The system prompt.
            schema: Response format constraint.
            images: PNG payloads for vision models.
            max_tokens: Output cap.

        Returns:
            A result dict when the outcome is final, or None to tell the caller that the key was rotated and the whole attempt should restart.

        Side effects:
            Streams requests, sleeps between retries, updates counters, writes transcripts, and may rotate the key or trip the circuit.

        Complexity:
            Up to the configured maximum attempts, with backoff between them.

        Implementation notes:
            Thinking is always requested, and the reasoning trace is accumulated separately from the response content. Mixing the two would corrupt the JSON the schema constrains, and disabling thinking to avoid that would degrade analysis quality -- the trace is where the model does the reasoning that makes a finding correct. Both stay on. A done_reason of "length" means the model hit the output cap mid-JSON. That is retried like a failure, because a truncated response is unparseable, and it is recorded under its own counter so a systematically low cap is visible rather than appearing as generic flakiness. Usage for a truncated attempt is recorded as not-ok while still counting the tokens, which were spent regardless. Backoff grows by half each time and is capped, so a run of transient failures does not stretch into minutes of sleeping. Throttling is handled differently from other transient failures: the provider's own Retry-After is honoured when present, otherwise a longer fixed delay applies, and the throttle is reported to the base class so it can narrow concurrency for the rest of the scan. Fatal failures attempt key rotation first and only trip the circuit when no key remains. The loop can end without returning only when OLLAMA_MAX_RETRIES is zero or negative, so that case gets an explicit error dict after the loop; falling off the end would return None, which analyze reads as a key rotation and would re-enter forever.

        Security considerations:
            Error text is traced through the verbose module, which redacts credential-shaped content before it reaches the terminal or the dashboard.
        """
        retry_delay = OLLAMA_RETRY_DELAY

        for attempt in range(OLLAMA_MAX_RETRIES):
            attempt_started = time.monotonic()
            try:
                verbose_print(f"Attempt {attempt + 1}/{OLLAMA_MAX_RETRIES}", self.verbose)
                user_message = {"role": "user", "content": prompt}
                if images:
                    user_message["images"] = [base64.b64encode(img).decode() for img in images]
                messages = [
                    {"role": "system", "content": system_message},
                    user_message,
                ]
                response_content = ""
                thinking_content = ""
                metrics: Dict[str, Any] = {}
                started = time.monotonic()
                for part in self.client.chat(
                    self.model, messages=messages, stream=True, format=schema,
                    keep_alive=OLLAMA_KEEP_ALIVE,
                    options={"num_predict": max_tokens or OLLAMA_NUM_PREDICT},
                    think=True,
                ):
                    if "message" in part:
                        if "content" in part["message"]:
                            response_content += part["message"]["content"]
                        thinking = part["message"].get("thinking")
                        if thinking:
                            thinking_content += thinking
                    if part.get("done"):
                        for field in ("total_duration", "load_duration",
                                      "prompt_eval_count", "prompt_eval_duration",
                                      "eval_count", "eval_duration", "done_reason"):
                            if field in part:
                                metrics[field] = part[field]
                elapsed = time.monotonic() - started
                done_reason = metrics.get("done_reason")

                verbose_print(
                    f"Response received: {len(response_content)} chars "
                    f"(+{len(thinking_content)} thinking chars)", self.verbose)
                verbose_print(
                    f"Ollama call complete in {elapsed:.1f}s - "
                    f"prompt_eval={metrics.get('prompt_eval_count', '?')} tok, "
                    f"eval={metrics.get('eval_count', '?')} tok, "
                    f"done_reason={done_reason or '?'}",
                    self.verbose,
                )

                if done_reason == "length":
                    verbose_print(
                        f"Attempt {attempt + 1}: response truncated at the "
                        f"{OLLAMA_NUM_PREDICT}-token cap (done_reason=length)",
                        self.verbose,
                    )
                    self.record_usage(elapsed, metrics, ok=False)
                    self.log_exchange(
                        system_message, prompt, response_content,
                        elapsed=elapsed, metrics=metrics, thinking=thinking_content,
                        error=f"truncated at the {OLLAMA_NUM_PREDICT}-token cap "
                             f"(done_reason=length), attempt {attempt + 1}")
                    if attempt < OLLAMA_MAX_RETRIES - 1:
                        self.record_retry("truncation")
                        time.sleep(retry_delay)
                        retry_delay = min(retry_delay * 1.5, 10)
                        continue
                    return {"error": f"Ollama response truncated at the "
                                     f"{OLLAMA_NUM_PREDICT}-token output cap "
                                     f"after {OLLAMA_MAX_RETRIES} attempts"}

                self.record_usage(elapsed, metrics, ok=True)
                self.log_exchange(
                    system_message, prompt, response_content,
                    elapsed=elapsed, metrics=metrics, thinking=thinking_content)
                return {"response": response_content, "thinking": thinking_content,
                        "metrics": metrics, "elapsed_s": elapsed}

            except Exception as e:
                attempt_elapsed = time.monotonic() - attempt_started
                error_msg = str(e)
                kind = classify(e)
                verbose_print(
                    f"Attempt {attempt + 1} failed ({kind.value}): {error_msg}", self.verbose)

                if is_fatal(kind):
                    self.record_usage(ok=False)
                    if self.advance_key(kind, error_msg):
                        return None
                    verbose_print(
                        f"Ollama unavailable for the rest of this scan ({kind.value}); "
                        "remaining AI phases will be skipped", self.verbose)
                    return self._trip(kind, error_msg)

                if kind is ErrorClass.THROTTLED:
                    self.on_throttled(e, blocked_s=attempt_elapsed)
                else:
                    self.record_failed_attempt(kind.value, attempt_elapsed)
                self.log_exchange(
                    system_message, prompt, "", elapsed=attempt_elapsed,
                    error=f"{kind.value}: {error_msg}")

                if attempt < OLLAMA_MAX_RETRIES - 1:
                    self.record_retry("throttle" if kind is ErrorClass.THROTTLED
                                      else "transient")
                    if kind is ErrorClass.THROTTLED:
                        delay = retry_after_for(e)
                        if delay is None:
                            delay = max(retry_delay, THROTTLE_RETRY_DELAY)
                    else:
                        delay = retry_delay
                    time.sleep(delay)
                    retry_delay = min(retry_delay * 1.5, 10)
                else:
                    self.record_usage(ok=False)
                    return {"error": f"Ollama failed after {OLLAMA_MAX_RETRIES} attempts: {error_msg}"}
        return {"error": f"Ollama made no attempt (OLLAMA_MAX_RETRIES={OLLAMA_MAX_RETRIES})"}

    def list_models(self) -> List[str]:
        """
        Purpose:
            List the models available for the current mode.

        Returns:
            Model names for local or cloud mode as appropriate.

        Side effects:
            May probe the local server.
        """
        from .ollama_models import list_models_for_mode
        return list_models_for_mode(self.mode, self.host, self.api_key)

    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check that this provider is usable in its current mode.

        Returns:
            True when the local server answers, or when the cloud listing succeeds with the configured key.

        Side effects:
            Makes one request.

        Implementation notes:
            The two modes validate different things, and that is correct: local mode has no credential, so reachability is the whole question, while cloud mode needs the key to be accepted.
        """
        try:
            if self.mode == "local":
                from .ollama_models import is_server_running
                return is_server_running(self.host)
            if not self.api_key:
                return False
            self.client.list()
            return True
        except Exception as e:
            verbose_print(f"Ollama credential validation failed: {e}", self.verbose)
            return False

    def analyze_with_cloud_llm(self, prompt: str, system_message: str = None) -> Dict:
        """
        Purpose:
            Compatibility wrapper delegating to analyze.

        Parameters:
            prompt: The user prompt.
            system_message: System prompt; the shared default applies when None.

        Returns:
            Whatever analyze returns.

        Deprecation:
            Retained for call sites written before the provider interface was unified. New code should call analyze, which exposes schema, images, token cap and session parameters that this wrapper hides.
        """
        return self.analyze(prompt, system_message)
