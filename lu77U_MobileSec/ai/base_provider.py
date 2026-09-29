#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.base_provider

Purpose:
    Define the contract every AI provider implements, and supply the machinery every provider needs regardless of vendor: usage accounting, API key rotation, a fatal-error circuit breaker, adaptive concurrency limiting, and request transcript logging.

Responsibilities:
    Declare the abstract interface (analyze, list_models, validate_credentials), and implement the shared cross-cutting behaviour around it.

Dependencies:
    threading, .errors for failure classification, .schema for the default contract, ..config.user_settings for the default concurrency, ..utils.verbose.

Implementation notes:
    Concurrency, retry accounting and key rotation live in the base class rather than in each provider because they are the parts most easily got subtly wrong, and because a scan fans out across worker threads that all share one provider instance. Centralising them means a new provider gets correct behaviour by default instead of reimplementing it.

Thread-safety:
    One provider instance is shared by every analysis worker. Usage counters are guarded by a lock, the metrics file by a separate lock, and in-flight requests by a bounded semaphore. The separate locks matter: file I/O under the counter lock would serialise every worker behind a disk write.

Security considerations:
    Providers hold live API keys in memory for their lifetime. Transcripts written by log_exchange contain the full prompt, including decompiled application source, and are written in plaintext beside the APK.
"""

import contextlib
import json
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .errors import ErrorClass, classify, is_fatal
from .schema import VULNERABILITY_SCHEMA, DEFAULT_SYSTEM_MESSAGE
from ..config.user_settings import DEFAULT_MAX_CONCURRENT_REQUESTS
from ..utils.verbose import verbose_print

class BaseAIProvider(ABC):
    """
    Purpose:
        Abstract base for every AI provider, carrying the shared state and behaviour that a concrete provider should not have to reimplement.

    Attributes:
        name: Provider identifier, overridden by each subclass and used in metrics, transcripts and log lines.
        config: The provider's stored settings block.
        verbose: Whether provider activity is traced and transcripts are written.
        output_manager: Supplies transcript and metrics paths; None disables both.
        apk_name: Labels transcripts with the APK under analysis.
        model: Resolved model name -- the configured one, or the provider's default.
        api_key: The key currently in use, or None for providers that need none.
        usage: Live counters for calls, tokens, cost, retries and time.

    Invariants:
        api_key always points at the entry indexed by the internal key cursor, or is None when no keys were supplied. Once the circuit is tripped, every call short-circuits until reset_circuit is called. The request semaphore never admits more than the configured width, and narrows to one permit permanently after the first throttling response.

    Thread-safety:
        Designed to be shared across worker threads. Counter updates are serialised by a usage lock, metrics file appends by a separate lock, and concurrency by a bounded semaphore. Key rotation and the circuit flag are written without a lock: a concurrent rotation can be observed mid-update, which at worst causes one extra failed request.

    Security considerations:
        Holds API keys. Subclasses must not log self.api_key, and must route any diagnostic text through the verbose module so redaction applies.
    """
    name: str = "base"

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        api_key: Optional[str] = None,
        verbose: bool = False,
        output_manager=None,
        apk_name: Optional[str] = None,
        api_keys: Optional[List[str]] = None,
    ):
        """
        Purpose:
            Set up shared provider state: model selection, key list, usage counters, locks and the concurrency gate.

        Parameters:
            config: Stored settings block for this provider.
            api_key: Single key, for callers predating rotation support.
            verbose: Enables tracing and transcript writing.
            output_manager: Supplies transcript and metrics paths.
            apk_name: Labels transcripts; defaults to a placeholder rather than None so filenames are always well formed.
            api_keys: Full key list, in rotation order. Takes precedence over api_key.

        Postconditions:
            model is non-empty when either the config or the subclass default supplies one. api_key is the first key, or None. The concurrency gate is open at its configured width, at least one.

        Implementation notes:
            Both api_key and api_keys are accepted so that the multi-key rotation added later did not break existing call sites; api_keys wins when both are given. The gate width is coerced defensively and floored at one, because it originates in a settings file a user can hand-edit. A width of zero would deadlock every worker on the first request. Two locks are created rather than one. Metrics file appends happen under their own lock so that a slow disk write does not block every worker's counter update.

        Security considerations:
            Keys are copied into a list held for the object's lifetime and are never written to disk by this class.
        """
        self.config = config or {}
        self.verbose = verbose
        self.output_manager = output_manager
        self.apk_name = apk_name or "Unknown_APK"
        self.model = self.config.get("model") or self.default_model()
        self._keys: List[str] = list(api_keys) if api_keys else (
            [api_key] if api_key else [])
        self._key_index = 0
        self.api_key: Optional[str] = self._keys[0] if self._keys else None
        self._fatal: Optional[str] = None
        self.usage: Dict[str, Any] = {
            "provider": self.name, "calls": 0, "failed": 0,
            "wall_clock_s": 0.0, "prompt_tokens": 0, "completion_tokens": 0,
            "cache_read_tokens": 0, "cache_creation_tokens": 0, "cost_usd": 0.0,
            "throttled_attempts": 0, "transient_attempts": 0,
            "failed_attempt_seconds": 0.0,
            "retried_calls": 0, "truncation_retries": 0, "transient_retries": 0,
            "throttle_retries": 0,
            "slow_calls": 0,
            "unparseable_responses": 0, "blocked_seconds": 0.0,
        }
        self._usage_lock = threading.Lock()
        self._metrics_file_lock = threading.Lock()
        try:
            gate_size = int(self.config.get("max_concurrent_requests") or 0)
        except (TypeError, ValueError):
            gate_size = 0
        self._gate_width = max(1, gate_size or DEFAULT_MAX_CONCURRENT_REQUESTS)
        self._request_gate = threading.BoundedSemaphore(self._gate_width)
        self._gate_lock = threading.Lock()
        self._gate_shrink_started = threading.Event()
        self._gate_shrunk_done = threading.Event()
        self._absorbed = 0
        self._throttle_observers: List[Callable[[float], None]] = []

    def add_throttle_observer(self, fn: Callable[[float], None]) -> None:
        """
        Purpose:
            Register a callback invoked whenever this provider is throttled, so that a scheduler above can slow its own pacing.

        Parameters:
            fn: Callable receiving the blocked duration in seconds.

        Side effects:
            Appends to an observer list held for the provider's lifetime.

        Thread-safety:
            Unsynchronised. Observers are expected to be registered at setup, before workers start.
        """
        self._throttle_observers.append(fn)

    def on_throttled(self, exc_unused: Optional[BaseException] = None,
                     blocked_s: float = 0.0) -> None:
        """
        Purpose:
            Record a throttling response and permanently narrow this provider to a single in-flight request.

        Parameters:
            exc_unused: The throttling exception, accepted for interface completeness and currently unused.
            blocked_s: Seconds spent blocked, added to the usage counters.

        Side effects:
            Updates counters, notifies observers, and starts a background thread that shrinks the concurrency gate.

        Thread-safety:
            Safe to call from any worker. The shrink is started at most once, guarded by an event set under the gate lock.

        Implementation notes:
            Narrowing is one-way for the rest of the scan rather than adaptive. Once a provider has throttled, continuing to fan out requests tends to extend the penalty, and a scan that finishes slowly is far better than one that trips a longer ban. Recovering the width automatically would risk oscillating into exactly that. The shrink runs on a background thread because acquiring the surplus permits blocks until in-flight requests finish, and the caller is on the error path of one of those requests. Observers are invoked over a snapshot and each call is individually guarded, so a failing observer cannot break throttle handling. Blocked time is added to three counters at once -- blocked, failed-attempt and wall-clock -- so that reports can show time lost to throttling separately while total elapsed time stays correct.
        """
        blocked = max(0.0, float(blocked_s or 0.0))
        with self._usage_lock:
            self.usage["throttled_attempts"] += 1
            self.usage["blocked_seconds"] += blocked
            self.usage["failed_attempt_seconds"] += blocked
            self.usage["wall_clock_s"] += blocked
        for observer in list(self._throttle_observers):
            with contextlib.suppress(Exception):
                observer(blocked_s)
        should_start = False
        with self._gate_lock:
            if not self._gate_shrink_started.is_set():
                self._gate_shrink_started.set()
                should_start = True
        if should_start:
            threading.Thread(target=self._shrink_gate_to_one,
                             name=f"{self.name}-gate-shrink", daemon=True).start()

    def _shrink_gate_to_one(self) -> None:
        """
        Purpose:
            Absorb all but one permit from the concurrency gate, so that only a single request is in flight for the remainder of the scan.

        Side effects:
            Blocks until the surplus permits are acquired, records how many were absorbed, and signals completion.

        Preconditions:
            Runs on its own thread, started once by on_throttled.

        Implementation notes:
            The absorbed count is remembered so reset_circuit can release exactly those permits and restore the original width. Releasing a bounded semaphore more times than it was acquired raises, so the count has to be exact rather than recomputed. The completion event exists for tests and for reset ordering; normal request handling does not wait on it.
        """
        to_absorb = self._gate_width - 1
        for _ in range(to_absorb):
            self._request_gate.acquire()
        if to_absorb:
            with self._usage_lock:
                self._absorbed += to_absorb
            verbose_print(
                f"{self.name}: throttled once; narrowing to 1 in-flight "
                "request for the rest of this scan", self.verbose)
        self._gate_shrunk_done.set()

    def record_retry(self, cause: str = "") -> None:
        """
        Purpose:
            Count a retry, both in total and by cause.

        Parameters:
            cause: One of "truncation", "transient" or "throttle". Anything else counts only toward the total.

        Side effects:
            Updates usage counters under the lock.

        Implementation notes:
            Causes are separated because they mean different things about a run: truncation retries suggest the output cap is too low, throttle retries suggest the concurrency is too high, and transient retries suggest an unstable connection. One combined number would hide all three.
        """
        with self._usage_lock:
            self.usage["retried_calls"] += 1
            key = {"truncation": "truncation_retries",
                   "transient": "transient_retries",
                   "throttle": "throttle_retries"}.get(cause)
            if key:
                self.usage[key] += 1

    def record_failed_attempt(self, error_class: str, seconds: float) -> None:
        """
        Purpose:
            Record time spent on an attempt that failed, so that reported wall-clock time includes work that produced nothing.

        Parameters:
            error_class: Classification name; only "transient" increments its own counter.
            seconds: Duration of the failed attempt. Negative values are clamped.

        Side effects:
            Updates usage counters under the lock.

        Implementation notes:
            Failed time is added to both the failed-attempt total and overall wall clock, so a report can show how much of a slow scan was wasted on failures without the totals disagreeing.
        """
        seconds = max(0.0, float(seconds or 0.0))
        with self._usage_lock:
            self.usage["failed_attempt_seconds"] += seconds
            self.usage["wall_clock_s"] += seconds
            if (error_class or "").lower() == "transient":
                self.usage["transient_attempts"] += 1

    def record_slow_call(self) -> None:
        """
        Purpose:
            Count a call that completed but took long enough to be worth reporting.

        Side effects:
            Updates a usage counter under the lock.

        Implementation notes:
            The threshold is the caller's judgement, not this method's; providers differ enough in normal latency that a shared threshold would be meaningless.
        """
        with self._usage_lock:
            self.usage["slow_calls"] += 1

    def record_unparseable(self) -> None:
        """
        Purpose:
            Count a response that arrived successfully but could not be parsed into findings.

        Side effects:
            Updates a usage counter under the lock.

        Implementation notes:
            Tracked separately from failures because it is a different problem: the provider worked and was paid for, and the model produced output the schema could not accept. A high count points at the prompt or the model choice, not the connection.
        """
        with self._usage_lock:
            self.usage["unparseable_responses"] += 1

    def record_call_metrics(self, metrics: Dict[str, Any], elapsed: float = 0.0,
                            done_reason: Optional[str] = None,
                            error: Optional[str] = None) -> None:
        """
        Purpose:
            Append one JSONL row per AI call, for later cost and performance review.

        Parameters:
            metrics: Provider-reported token counts, cache figures and cost.
            elapsed: Call duration in seconds.
            done_reason: Provider-reported completion reason, which reveals truncation.
            error: Error text, truncated when stored.

        Side effects:
            Appends a line to the metrics file.

        Thread-safety:
            Appends are serialised by a dedicated lock so that concurrent workers cannot interleave partial lines.

        Implementation notes:
            The output manager is probed by duck typing rather than assumed, so that a provider constructed without one -- in a test, or for a credential check -- silently skips metrics instead of failing. The thread name is recorded as the region, which is what makes per-region cost attribution possible after a fan-out run. Error text is truncated to 200 characters so that one pathological failure cannot bloat the metrics file. The whole body is guarded: metrics are diagnostics, and failing to write them must never fail the call they describe.

        Security considerations:
            Error text can echo request content. It is truncated but not redacted, so this file should be treated with the same care as the transcripts.
        """
        get_path = getattr(self.output_manager, "get_llm_metrics_path", None)
        if not callable(get_path):
            return
        with contextlib.suppress(Exception):
            row = {
                "ts": datetime.now().isoformat(),
                "region": threading.current_thread().name,
                "provider": self.name,
                "model": self.model,
                "duration_s": round(elapsed, 3) if elapsed else 0.0,
                "prompt_eval_count": metrics.get("prompt_eval_count"),
                "eval_count": metrics.get("eval_count"),
                "cache_read_tokens": metrics.get("cache_read_tokens"),
                "cache_creation_tokens": metrics.get("cache_creation_tokens"),
                "cost_usd": metrics.get("cost_usd"),
                "done_reason": done_reason,
            }
            if error:
                row["error"] = str(error)[:200]
            with self._metrics_file_lock:
                with open(get_path(), "a", encoding="utf-8") as f:
                    f.write(json.dumps(row) + "\n")

    def log_exchange(
        self,
        system_message: str,
        user_prompt: str,
        response_content: str = "",
        *,
        elapsed: Optional[float] = None,
        metrics: Optional[Dict[str, Any]] = None,
        thinking: str = "",
        error: Optional[str] = None,
        session_key: Optional[str] = None,
        resumed: bool = False,
    ) -> None:
        """
        Purpose:
            Write a Markdown transcript of one request and response, so that a finding can be traced back to the exchange that produced it.

        Parameters:
            system_message: The system prompt sent.
            user_prompt: The user prompt sent.
            response_content: The model's response text.
            elapsed: Call duration in seconds.
            metrics: Provider-reported token, cache and cost figures.
            thinking: The model's reasoning trace, when the provider exposes one.
            error: Error text, written instead of a response when the call failed.
            session_key: Session identifier, when the provider supports conversation reuse.
            resumed: Whether that session was resumed rather than created.

        Side effects:
            Always records call metrics; writes a transcript file only when verbose is set and an output manager is available.

        Implementation notes:
            Metrics recording happens before the verbose check, so cost and timing are captured on every run while the much larger transcripts are opt-in. The filename carries a per-request timestamp and, via the output manager, the worker thread name, so concurrent workers do not overwrite each other. Nanosecond durations reported by Ollama are converted to milliseconds for readability; fields absent from a given provider render as "n/a" rather than being omitted, keeping transcripts comparable across providers. The thinking trace is written under a heading that says plainly it is not the response, because reading a reasoning trace as a conclusion is an easy and costly mistake. Failures are swallowed and traced: losing a diagnostic transcript must never fail the analysis it documents.

        Security considerations:
            The transcript contains the complete prompt, which includes decompiled application source, and the complete response. It is written in plaintext beside the APK. It is gated on verbose partly for size and partly because it is sensitive by default.
        """
        metrics = metrics or {}
        self.record_call_metrics(metrics, elapsed or 0.0,
                                 metrics.get("done_reason"), error=error)

        if not self.verbose or self.output_manager is None:
            return
        get_path = getattr(self.output_manager, "get_llm_log_path", None)
        if not callable(get_path):
            return
        try:
            request_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = get_path(self.name, request_timestamp)

            timing_lines = ""
            if elapsed is not None:
                timing_lines = f"**Duration:** {elapsed:.2f}s\n"
            if metrics:
                def _fmt_duration(field):
                    """
                    Purpose:
                        Render one of Ollama's nanosecond duration fields as milliseconds for the transcript.

                    Parameters:
                        field: Metrics key naming the duration to format.

                    Returns:
                        The duration as a millisecond string, or "n/a" when the field is absent or not numeric.

                    Complexity:
                        O(1).

                    Implementation notes:
                        Ollama reports durations in nanoseconds, which are unreadable at a glance in a transcript. Providers that report nothing comparable render as "n/a" rather than being omitted, so transcripts stay structurally identical across providers and can be diffed. Defined inside the metrics branch because it is only meaningful there and closes over nothing but the metrics mapping.
                    """
                    value = metrics.get(field)
                    return f"{value / 1e6:.0f}ms" if isinstance(value, (int, float)) else "n/a"

                prompt_tok = metrics.get("prompt_eval_count", "n/a")
                completion_tok = metrics.get("eval_count", "n/a")
                timing_lines += (
                    f"**Prompt tokens:** {prompt_tok} (eval {_fmt_duration('prompt_eval_duration')})\n"
                    f"**Completion tokens:** {completion_tok} (eval {_fmt_duration('eval_duration')})\n"
                )
                for field, label in (("cache_read_tokens", "Cache read tokens"),
                                     ("cache_creation_tokens", "Cache creation tokens"),
                                     ("cost_usd", "Cost (USD)"),
                                     ("done_reason", "Done reason")):
                    if field in metrics:
                        timing_lines += f"**{label}:** {metrics[field]}\n"
            if thinking:
                timing_lines += f"**Thinking:** {len(thinking)} chars\n"
            if session_key:
                timing_lines += (
                    f"**Session:** {session_key} "
                    f"({'resumed - only the new turn was sent' if resumed else 'seeded new'})\n"
                )

            thinking_block = (
                f"\n## Thinking (not the response - the model's reasoning trace)\n\n"
                f"```\n{thinking}\n```\n" if thinking else ""
            )
            response_block = (
                f"## Error\n\n```\n{error}\n```\n" if error else
                f"## Response Received\n\n```\n{response_content}\n```\n{thinking_block}"
            )
            mode = getattr(self, "mode", None)
            markdown_content = f"""# {self.apk_name} {self.name} Request and Response

**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Model:** {self.model}
{f'**Mode:** {mode}' + chr(10) if mode else ''}{timing_lines}
---

## Request Made

### System Message
```
{system_message}
```

### User Prompt
```
{user_prompt}
```

---

{response_block}
---

**Note:** This log was generated in verbose mode.
"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            verbose_print(f"Saved log: {filepath}", self.verbose)
        except Exception as e:
            verbose_print(f"Failed to save log: {e}", self.verbose)


    @property
    def unavailable(self) -> Optional[str]:
        """
        Purpose:
            Report why this provider has stopped accepting work, if it has.

        Returns:
            A description of the fatal condition, or None while the provider is usable.

        Implementation notes:
            Exposed as a property so callers read it as state rather than calling a predicate, and so the underlying flag stays private and is only cleared through reset_circuit.
        """
        return self._fatal

    def _trip(self, kind: "ErrorClass", message: str) -> Dict[str, Any]:
        """
        Purpose:
            Open the circuit breaker, so that every subsequent call fails immediately instead of repeating a request that cannot succeed.

        Parameters:
            kind: The fatal classification.
            message: Provider error text.

        Returns:
            An error result carrying the fatal flag, suitable for returning directly from analyze.

        Postconditions:
            The provider is unavailable until reset_circuit is called.

        Implementation notes:
            Tripping matters most for an exhausted quota: without it, a fan-out of workers would each burn their full retry budget against the same wall, turning one fatal error into minutes of pointless waiting.
        """
        self._fatal = f"{kind.value}: {message}"
        return {"error": self._fatal, "fatal": True, "error_class": kind.value}

    def _short_circuit(self) -> Optional[Dict[str, Any]]:
        """
        Purpose:
            Produce the immediate failure result for a provider whose circuit is already open.

        Returns:
            An error result marked short-circuited, or None when the provider is still usable.

        Implementation notes:
            Called at the top of a provider's analyze so that no network request is attempted. The distinct short_circuited flag lets a caller tell a fresh failure from an echo of an earlier one, which matters when reporting how many calls actually reached the provider.
        """
        if self._fatal:
            return {"error": self._fatal, "fatal": True, "short_circuited": True}
        return None

    def _handle_exception(self, exc) -> Optional[Dict[str, Any]]:
        """
        Purpose:
            Decide what a provider exception means: rotate to the next key, trip the circuit, or let the caller retry.

        Parameters:
            exc: The provider exception.

        Returns:
            An error result when the circuit was tripped; None when the caller should proceed -- either because a new key is now in use, or because the failure is retryable.

        Side effects:
            May rotate the active key or open the circuit.

        Implementation notes:
            Key rotation is attempted before tripping, so that a scan configured with several keys survives one of them being exhausted or revoked. Only when no key remains does the failure become fatal. Returning None for two different reasons -- rotated, or retryable -- is deliberate: in both cases the caller's next action is the same, which is to try again.
        """
        kind = classify(exc)
        if is_fatal(kind):
            if self.advance_key(kind, str(exc)):
                return None
            return self._trip(kind, str(exc))
        return None


    def advance_key(self, kind: Optional["ErrorClass"] = None,
                    reason: str = "") -> bool:
        """
        Purpose:
            Move to the next API key in the rotation.

        Parameters:
            kind: Classification that caused the rotation, used in the log line.
            reason: Provider error text, used in the log line.

        Returns:
            True when a further key was available and is now active; False when the list is exhausted.

        Side effects:
            Updates the active key, writes a verbose line, and invokes the subclass hook.

        Implementation notes:
            The log line reports positions and counts only -- never key material -- so that a verbose scan log remains safe to share.

        Security considerations:
            Rotation is forward-only within a scan. A key that failed is not retried until reset_circuit restarts the rotation.
        """
        if self._key_index + 1 >= len(self._keys):
            return False
        self._key_index += 1
        self.api_key = self._keys[self._key_index]
        label = f" ({kind.value})" if kind else ""
        verbose_print(
            f"Key {self._key_index} of {len(self._keys)} failed{label}"
            f"{': ' + reason if reason else ''}; switching to key "
            f"{self._key_index + 1} of {len(self._keys)}", self.verbose)
        self._on_key_rotated()
        return True

    def _on_key_rotated(self) -> None:
        """
        Purpose:
            Hook for subclasses that must rebuild state when the active key changes.

        Implementation notes:
            A no-op here because most providers read self.api_key per request. Providers holding a preconfigured SDK client override this to rebuild it; without the hook, such a provider would keep using the failed key after a rotation that appeared to succeed.
        """


    def record_usage(self, elapsed: float = 0.0,
                     metrics: Optional[Dict[str, Any]] = None,
                     ok: bool = True) -> None:
        """
        Purpose:
            Record one completed call: its duration, token counts, cache figures and cost.

        Parameters:
            elapsed: Call duration in seconds.
            metrics: Provider-reported figures. Missing or wrongly-typed fields are skipped.
            ok: False for a call that failed, which also increments the failure counter.

        Side effects:
            Updates usage counters under the lock.

        Implementation notes:
            Each metric is type-checked before being added, because providers omit fields and occasionally report a string. An unchecked addition would raise inside the lock and corrupt the accounting for the rest of the scan. Duration is coerced in its own guard for the same reason.
        """
        metrics = metrics or {}
        with self._usage_lock:
            self.usage["calls"] += 1
            if not ok:
                self.usage["failed"] += 1
            with contextlib.suppress(TypeError, ValueError):
                self.usage["wall_clock_s"] += float(elapsed or 0.0)
            for field, key in (("prompt_eval_count", "prompt_tokens"),
                               ("eval_count", "completion_tokens"),
                               ("cache_read_tokens", "cache_read_tokens"),
                               ("cache_creation_tokens", "cache_creation_tokens")):
                value = metrics.get(field)
                if isinstance(value, int):
                    self.usage[key] += value
            cost = metrics.get("cost_usd")
            if isinstance(cost, (int, float)):
                self.usage["cost_usd"] += float(cost)

    def usage_summary(self) -> Dict[str, Any]:
        """
        Purpose:
            Produce a snapshot of this provider's usage for reports and the dashboard.

        Returns:
            A copy of the counters, rounded for display, with the model, mode, availability and key-rotation position added.

        Thread-safety:
            The copy is taken under the lock, so the snapshot is internally consistent even while workers are running.

        Implementation notes:
            Rounding is applied to the copy, never to the live counters, so that repeated snapshots do not accumulate rounding error. Cost is kept to four decimal places because per-call costs are frequently in the thousandths and rounding to two would report an expensive scan as free. keys_used reports the position reached in the rotation, not a count of keys that worked, which is what makes an exhausted key visible in a report.
        """
        with self._usage_lock:
            out = dict(self.usage)
        out["wall_clock_s"] = round(out["wall_clock_s"], 1)
        out["blocked_seconds"] = round(out.get("blocked_seconds", 0.0), 1)
        out["failed_attempt_seconds"] = round(out.get("failed_attempt_seconds", 0.0), 1)
        out["cost_usd"] = round(out.get("cost_usd", 0.0), 4)
        out["mode"] = self.config.get("mode")
        out["model"] = self.model
        out["unavailable"] = self._fatal
        out["keys_total"] = len(self._keys)
        out["keys_used"] = self._key_index + 1 if self._keys else 0
        return out

    def reset_circuit(self) -> None:
        """
        Purpose:
            Return the provider to a usable state: clear the fatal flag, restart the key rotation, and restore the original concurrency width.

        Postconditions:
            unavailable is None, the first key is active, and the gate holds its configured number of permits again.

        Side effects:
            Releases exactly the permits absorbed by the shrink.

        Thread-safety:
            The absorbed count is read and cleared under the lock so that permits cannot be released twice. Calling this while requests are in flight is not supported.

        Implementation notes:
            Exists so that a user who adds credit or fixes a key can resume without restarting the tool. Releasing the recorded count rather than a recomputed one is what keeps the bounded semaphore from raising.
        """
        self._fatal = None
        self._key_index = 0
        self.api_key = self._keys[0] if self._keys else None
        with self._usage_lock:
            absorbed, self._absorbed = self._absorbed, 0
        for _ in range(absorbed):
            self._request_gate.release()
        self._gate_shrink_started.clear()
        self._gate_shrunk_done.clear()

    @abstractmethod
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
            Send a prompt to the model and return findings. The one method every provider must implement.

        Parameters:
            prompt: The user prompt, typically decompiled source plus instructions.
            system_message: System prompt; the provider's default applies when None.
            schema: Response schema; the vulnerability schema applies when None.
            images: Image payloads for providers that support vision.
            max_tokens: Output cap; the provider's own default applies when None.
            session_key: Identifier for reusing a conversation, where supported.

        Returns:
            A result dict. On success it carries the model response; on failure an "error" key, plus "fatal" when the circuit tripped.

        Postconditions:
            Implementations must return an error dict rather than raising, so that one failed region does not abort a fan-out scan.

        Security considerations:
            The prompt contains decompiled application source. Sending it transmits that source to the configured provider, which for every provider but a local Ollama server means off the machine.
        """

    @abstractmethod
    def list_models(self) -> List[str]:
        """
        Purpose:
            List the models available to this provider, for the settings UI.

        Returns:
            Model names; an empty list when they cannot be determined.

        Postconditions:
            Implementations must not raise. The settings page calls this while rendering, and an unreachable provider must degrade to an empty list.
        """

    @abstractmethod
    def validate_credentials(self) -> bool:
        """
        Purpose:
            Check whether this provider is usable with its current configuration and key.

        Returns:
            True when a request would be expected to succeed.

        Postconditions:
            Implementations must not raise; a failure is reported as False.

        Security considerations:
            Implementations typically make a minimal authenticated request. They must never log the key, and should avoid sending analysis content.
        """

    def default_model(self) -> str:
        """
        Purpose:
            The model to use when the user has configured none.

        Returns:
            The default model name; an empty string here, meaning the subclass has no opinion.

        Implementation notes:
            Overridden by providers with a sensible default. An empty string is deliberate for providers where guessing would produce a failing request -- a custom OpenAI-compatible endpoint has no knowable default.
        """
        return ""

    @property
    def schema(self) -> Dict[str, Any]:
        """
        Purpose:
            The response schema requested by default.

        Returns:
            The shared vulnerability schema.

        Implementation notes:
            Exposed as a property so a provider can substitute a dialect-specific variant without callers changing.
        """
        return VULNERABILITY_SCHEMA

    @property
    def default_system_message(self) -> str:
        """
        Purpose:
            The system message used when a caller supplies none.

        Returns:
            The shared default system message.
        """
        return DEFAULT_SYSTEM_MESSAGE

    def supports_tools(self) -> bool:
        """
        Purpose:
            Report whether this provider can drive the agentic tool loop.

        Returns:
            False by default.

        Implementation notes:
            This is the capability that decides between agentic analysis and the legacy full-dump fallback, so a provider that reports False is analysed far less thoroughly. Defaulting to False is the safe direction: claiming tool support that does not work yields an empty analysis rather than a degraded one.
        """
        return False

    def has_session(self, session_key: str) -> bool:
        """
        Purpose:
            Report whether a conversation session exists under the given key.

        Parameters:
            session_key: Session identifier.

        Returns:
            False by default, for providers that are stateless per request.
        """
        return False

    def close_session(self, session_key: str) -> None:
        """
        Purpose:
            Release a conversation session and any resources behind it.

        Parameters:
            session_key: Session identifier.

        Implementation notes:
            A no-op for stateless providers. Subprocess-backed CLI providers override this, where failing to close leaves a child process alive after the scan.
        """

    def supports_vision(self) -> bool:
        """
        Purpose:
            Report whether this provider accepts image input, which the dynamic pipeline uses for on-device screenshot checks.

        Returns:
            False by default.
        """
        return False

    def __repr__(self) -> str:
        """
        Purpose:
            Readable representation for debugging and log lines.

        Returns:
            The class name and the resolved model.

        Security considerations:
            Deliberately excludes the API key and the key list, so that a provider appearing in a traceback or a repr dump cannot leak a credential.
        """
        return f"<{self.__class__.__name__} model={self.model!r}>"
