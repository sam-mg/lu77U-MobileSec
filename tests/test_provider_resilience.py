#!/usr/bin/env python3
"""
Module: test_provider_resilience

Purpose:
    What a scan does when the provider stops answering.

Responsibilities:
    Pin the classification that separates a stalled connection from a spent account from a passing rate limit, and the circuit breaker that stops every later call site rediscovering the same failure.

Dependencies:
    pytest, the error classifier, the provider base class and the Java/Kotlin analyzer.

Implementation notes:
    A real 95-minute scan ended on a spent cloud quota and then spent another 108 seconds learning the same fact eight more times: two agent threads, six validation batches and one chain call, each retrying three times with a backoff tuned for a stalled socket. Neither agent region ever submitted a report, and nothing in the output said so. Nothing here touches the network or spends a quota.
"""

import time

import pytest

from lu77U_MobileSec.ai.errors import ErrorClass, classify, is_fatal


class _Response:
    """
    Purpose:
        The smallest stand-in for the response carried on an HTTP error.

    Attributes:
        status_code: The response status.
        text: The response body.
    """
    def __init__(self, status_code, text=""):
        """
        Purpose:
            Build the response.

        Parameters:
            status_code: The response status.
            text: The response body.
        """
        self.status_code = status_code
        self.text = text


class _HttpError(Exception):
    """
    Purpose:
        An error carrying a response, shaped the way an HTTP client's error is.

    Attributes:
        response: The response the error carries.
    """
    def __init__(self, message, status_code=0, body=""):
        """
        Purpose:
            Build the error.

        Parameters:
            message: The error message, which is all the real error stringifies to.
            status_code: The response status.
            body: The response body.
        """
        super().__init__(message)
        self.response = _Response(status_code, body)


class TestErrorClassification:
    """
    Purpose:
        That a stalled connection, a passing rate limit and a spent account are told apart.

    Implementation notes:
        They call for opposite responses. Retrying a stalled connection is right and retrying a spent account wastes the rest of the scan, so classifying one as the other is expensive in both directions.
    """
    def test_a_stalled_stream_is_transient(self):
        """
        Purpose:
            Pin that a connection dropped mid-response is classified as temporary.
        """
        assert classify(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)") is ErrorClass.TRANSIENT

    def test_the_observed_ollama_quota_message_is_fatal(self):
        """
        Purpose:
            Pin that the exact message a spent cloud subscription returns is classified as unrecoverable.

        Implementation notes:
            Taken verbatim from the scan this module exists because of, rather than paraphrased, so a change in how the provider words it fails here instead of in the field.
        """
        assert classify(
            "you (sam-mg) have reached your session usage limit, upgrade for "
            "higher limits: https://ollama.com/upgrade") is ErrorClass.FATAL_QUOTA

    def test_a_bare_429_is_throttling_not_a_dead_quota(self):
        """
        Purpose:
            Pin that a rate-limit status carrying no quota message is classified as throttling rather than as a spent account.

        Implementation notes:
            A per-minute limit clears on its own and an account limit does not, so treating every rate-limit status as unrecoverable would abandon scans that only needed to wait. The distinction lives in the message, not in the status.
        """
        assert classify(_HttpError("server busy", status_code=429)) is ErrorClass.THROTTLED

    @pytest.mark.parametrize("body", [
        '{"error": {"code": "insufficient_quota"}}',
        '{"error": {"message": "You exceeded your current quota"}}',
        '{"error": {"message": "Your credit balance is too low"}}',
    ])
    def test_a_quota_body_behind_a_429_is_fatal(self, body):
        """
        Purpose:
            Pin that a rate-limit status whose body reports a spent quota is classified as unrecoverable.

        Parameters:
            body: A response body reporting an exhausted quota, in each wording seen from the providers.

        Implementation notes:
            The HTTP client's error stringifies to the status line alone, so the phrase separating a passing rate limit from a spent account is only in the body and the classifier has to read it off the response rather than off the message.
        """
        error = _HttpError("Client error '429' for url ...", status_code=429, body=body)
        assert classify(error) is ErrorClass.FATAL_QUOTA

    @pytest.mark.parametrize("status", [401, 403])
    def test_rejected_credentials_are_fatal(self, status):
        """
        Purpose:
            Pin that a rejected or forbidden credential is classified as unrecoverable.

        Parameters:
            status: The response status reporting the rejection.
        """
        assert classify(_HttpError("nope", status_code=status)) is ErrorClass.FATAL_AUTH

    def test_only_the_unrecoverable_classes_are_fatal(self):
        """
        Purpose:
            Pin which classes are treated as unrecoverable and which are not.
        """
        assert is_fatal(ErrorClass.FATAL_QUOTA)
        assert is_fatal(ErrorClass.FATAL_AUTH)
        assert not is_fatal(ErrorClass.TRANSIENT)
        assert not is_fatal(ErrorClass.THROTTLED)


class _QuotaProvider:
    """
    Purpose:
        A provider that reports a spent quota from a chosen call onward, borrowing the real circuit breaker rather than reimplementing it.

    Attributes:
        calls: How many calls reached the provider rather than being refused.
        fail_from: The call number after which every call reports a spent quota.

    Implementation notes:
        The breaker methods are bound from the real base class so the behaviour under test is the shipped one. There is no key pool, because this fake exists to exercise the single-key path that trips on the first unrecoverable error; rotation across a pool is covered on its own elsewhere.
    """
    def __init__(self, fail_from=0):
        """
        Purpose:
            Build the provider and bind the real breaker methods onto it.

        Parameters:
            fail_from: The call number after which every call reports a spent quota.
        """
        from lu77U_MobileSec.ai.base_provider import BaseAIProvider

        self.calls = 0
        self.fail_from = fail_from
        self._fatal = None
        self._keys = []
        self._key_index = 0
        self.api_key = None
        self.verbose = False
        self._short_circuit = BaseAIProvider._short_circuit.__get__(self)
        self._trip = BaseAIProvider._trip.__get__(self)
        self._handle_exception = BaseAIProvider._handle_exception.__get__(self)
        self.advance_key = BaseAIProvider.advance_key.__get__(self)
        self._on_key_rotated = BaseAIProvider._on_key_rotated.__get__(self)

    @property
    def unavailable(self):
        """
        Purpose:
            Report why the provider is unusable, matching the real provider's attribute.

        Returns:
            The reason, or None while the circuit is closed.
        """
        return self._fatal

    def analyze(self, prompt_unused, system_message_unused=None, schema_unused=None,
                images_unused=None, max_tokens_unused=None, session_key_unused=None):
        """
        Purpose:
            Refuse immediately once the circuit is open, otherwise count the call and report a spent quota from the chosen call onward.

        Parameters:
            prompt_unused: The prompt, unused here.
            system_message_unused: The system prompt, unused here.
            schema_unused: The requested response schema, unused here.
            images_unused: Attached images, unused here.
            max_tokens_unused: The response limit, unused here.
            session_key_unused: The conversation key, unused here.

        Returns:
            The refusal, the fatal error, or a response holding an empty finding list.

        Side effects:
            Increments the call count and may open the circuit.
        """
        tripped = self._short_circuit()
        if tripped:
            return tripped
        self.calls += 1
        if self.calls > self.fail_from:
            fatal = self._handle_exception(Exception(
                "you (x) have reached your session usage limit, upgrade for "
                "higher limits"))
            if fatal:
                return fatal
        return {"response": "[]"}


class TestCircuitBreaker:
    """
    Purpose:
        That one unrecoverable failure stops every later call site rather than each of them discovering it separately.
    """
    def test_the_first_quota_error_opens_the_circuit(self):
        """
        Purpose:
            Pin that the first spent-quota response is fatal and leaves the provider marked unusable.
        """
        provider = _QuotaProvider(fail_from=1)
        assert "response" in provider.analyze("first")
        result = provider.analyze("second")
        assert result.get("fatal") is True
        assert provider.unavailable

    def test_later_call_sites_short_circuit_without_hitting_the_transport(self):
        """
        Purpose:
            Pin that once the circuit is open, later calls are refused without reaching the transport and cost effectively nothing.

        Implementation notes:
            This is the cascade the breaker exists for: eight call sites, about ten seconds each, all learning the same thing. The call count is asserted unchanged as well as the elapsed time, so a refusal that still built and sent a request would fail here even if it happened to be fast.
        """
        provider = _QuotaProvider(fail_from=1)
        provider.analyze("first")
        provider.analyze("trips it")
        calls_after_trip = provider.calls

        started = time.monotonic()
        for _ in range(8):
            result = provider.analyze("validator / chains / more agent steps")
            assert result["fatal"] is True
            assert result["short_circuited"] is True
        elapsed = time.monotonic() - started

        assert provider.calls == calls_after_trip, "transport was hit after the trip"
        assert elapsed < 0.5, "short-circuited calls must be effectively free"

    def test_a_transient_error_does_not_open_the_circuit(self):
        """
        Purpose:
            Pin that a temporary failure leaves the circuit closed.
        """
        from lu77U_MobileSec.ai.base_provider import BaseAIProvider

        provider = _QuotaProvider()
        assert provider._handle_exception(Exception("peer closed connection")) is None
        assert provider.unavailable is None

    def test_the_non_agentic_fallback_is_skipped_when_the_provider_is_dead(self):
        """
        Purpose:
            Pin that the whole-application fallback analysis is not attempted against a provider already known to be unusable.

        Implementation notes:
            That fallback sends the largest prompt of the entire scan. The agent loop routes to it precisely when the provider could not drive the loop, and the usual reason for that is a spent quota, so it used to spend a whole-application prompt to be told the same thing again.
        """
        from lu77U_MobileSec.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer

        analyzer = JavaKotlinAnalyzer()
        provider = _QuotaProvider(fail_from=0)
        provider.analyze("trip it")
        assert provider.unavailable
        analyzer.ai_provider = provider

        before = provider.calls
        out = analyzer.analyze_files_for_vulnerabilities(
            {"java_files": {"A.java": "class A {}"}, "android_manifest": ""})
        assert out == []
        assert provider.calls == before, "a dead provider was called anyway"
