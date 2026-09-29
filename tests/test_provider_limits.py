#!/usr/bin/env python3
"""
Module: test_provider_limits

Purpose:
    Runaway generation, hidden reasoning tokens, and unbounded concurrency against a provider.

Responsibilities:
    Pin that an output cap is actually requested, that a response cut off at that cap is recognised rather than parsed, that reasoning output is captured and can be salvaged for a decision, that concurrent calls are bounded and narrow themselves when the account says so, that throttling is counted honestly, and that a retry delay is read from the response when one is offered.

Dependencies:
    pytest, the provider base class, the Ollama provider, the error helpers, the agent loop and the generation settings.

Implementation notes:
    A real scan logged four throttle errors from the cloud provider. Confirmed against that scan's own transcripts, two calls each ran between 700 and 820 seconds and generated 65,536 tokens, the model's hard output ceiling, because nothing bounded generation length. Both times the sibling region thread, sharing the same account, was refused for the entire window, and both times the runaway call's own output was empty or cut off mid-structure and thrown away, because those tokens went into a reasoning field the code never looked at. Half of that scan's 49-minute runtime was lost to the two episodes. Nothing here touches the network, a real model, or a live quota.
"""

import threading
import time

from lu77U_MobileSec.ai.base_provider import BaseAIProvider
from lu77U_MobileSec.ai.errors import retry_after_for
from lu77U_MobileSec.config.settings import OLLAMA_MAX_RETRIES, OLLAMA_NUM_PREDICT


def _ollama_provider(**kw):
    """
    Purpose:
        Build an Ollama provider in cloud mode with test defaults.

    Parameters:
        kw: Constructor keywords, such as the key pool or a configuration overriding the concurrency width.

    Returns:
        The provider.
    """
    import lu77U_MobileSec.ai.ollama_provider as op

    kw.setdefault("config", {"mode": "cloud"})
    kw.setdefault("verbose", False)
    return op.OllamaProvider(**kw)


def _chunk(content="", thinking=None, done=False, done_reason=None, **metrics):
    """
    Purpose:
        Build one streamed response chunk in the shape the client yields.

    Parameters:
        content: The visible text in this chunk.
        thinking: The reasoning text in this chunk, or None to omit the field entirely.
        done: Whether this is the final chunk.
        done_reason: Why generation ended, carried only on the final chunk.
        metrics: Counters carried on the final chunk, such as the tokens generated.

    Returns:
        The chunk.

    Implementation notes:
        The reasoning field is omitted rather than set empty when none is given, because a non-reasoning model never sends the field at all and the difference is what one of the tests here is about.
    """
    part = {"message": {"content": content}, "done": done}
    if thinking is not None:
        part["message"]["thinking"] = thinking
    if done:
        part["done_reason"] = done_reason
        part.update(metrics)
    return part


class TestOutputCapIsRequested:
    """
    Purpose:
        That the generation limit and the reasoning request are actually sent with every call.
    """
    def test_num_predict_is_passed_to_the_client(self, monkeypatch):
        """
        Purpose:
            Pin that the configured output cap reaches the client as a generation option.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            Without this the only ceiling is the model's own, which is where the runaway generation came from; the cap existing in settings and never being sent looks identical from outside.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        seen_kwargs = {}

        class _Client:
            """
            Purpose:
                A client that records the keywords it was called with and answers successfully.
            """
            def chat(self, unused_model, **kwargs):
                """
                Purpose:
                    Record the call keywords and yield a complete answer.

                Parameters:
                    unused_model: The model name, unused here.
                    kwargs: The call keywords, recorded.

                Returns:
                    A single final chunk holding an empty finding list.

                Side effects:
                    Records the call keywords.
                """
                seen_kwargs.update(kwargs)
                yield _chunk("[]", done=True, done_reason="stop", eval_count=3)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _Client()
        prov.analyze("p", system_message="s")

        assert seen_kwargs.get("options") == {"num_predict": OLLAMA_NUM_PREDICT}

    def test_thinking_is_explicitly_requested_every_call(self, monkeypatch):
        """
        Purpose:
            Pin that reasoning is requested explicitly on every call rather than left to the model.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            This is policy rather than an accident of the client's default. Reasoning models analyse better with it on, and the failure this module is about was that the reasoning was invisible and unbounded, not that it happened at all. Asked for explicitly rather than left unset, so it cannot silently drift off when the client's default changes.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        seen_kwargs = {}

        class _Client:
            """
            Purpose:
                A client that records the keywords it was called with and answers successfully.
            """
            def chat(self, unused_model, **kwargs):
                """
                Purpose:
                    Record the call keywords and yield a complete answer.

                Parameters:
                    unused_model: The model name, unused here.
                    kwargs: The call keywords, recorded.

                Returns:
                    A single final chunk holding an empty finding list.

                Side effects:
                    Records the call keywords.
                """
                seen_kwargs.update(kwargs)
                yield _chunk("[]", done=True, done_reason="stop", eval_count=3)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _Client()
        prov.analyze("p", system_message="s")

        assert seen_kwargs.get("think") is True


class TestTruncationDetection:
    """
    Purpose:
        Telling a complete answer apart from one the generation limit cut off.

    Implementation notes:
        The reason generation ended is the only reliable signal, because a truncated response is ordinary text that simply stops, and the caller has no way to know it was not the whole answer.
    """
    def test_a_truncated_response_is_a_retryable_error_not_a_success(
            self, monkeypatch):
        """
        Purpose:
            Pin that a response cut off at the limit is reported as an error naming the cap, is not fatal, and leaves the circuit closed.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            The fake returns text that looks like it could be a real answer but stops mid-structure, because the danger is not an empty response but a plausible partial one the caller would try to parse. Truncation is neither a quota nor a credential failure, so opening the circuit over it would abandon a scan that would have recovered on the next attempt.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _AlwaysTruncated:
            """
            Purpose:
                A client that always stops at the generation limit mid-structure.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield a final chunk holding partial text and a limit-reached reason.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single final chunk reporting the generation limit.
                """
                yield _chunk('{"action":"read_fil', done=True,
                             done_reason="length", eval_count=65536)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _AlwaysTruncated()

        result = prov.analyze("p", system_message="s")
        assert "response" not in result
        assert "error" in result
        assert "truncated" in result["error"]
        assert str(OLLAMA_NUM_PREDICT) in result["error"]
        assert result.get("fatal") is not True
        assert prov.unavailable is None

    def test_truncation_retries_within_the_normal_budget_and_can_recover(
            self, monkeypatch):
        """
        Purpose:
            Pin that a truncated first attempt is retried and a complete second attempt is returned.

        Parameters:
            monkeypatch: Removes the backoff delay.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        calls = []

        class _RecoversOnRetry:
            """
            Purpose:
                A client that truncates once and then answers completely.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Truncate on the first call and answer completely on any later one.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single final chunk, truncated or complete depending on the attempt.

                Side effects:
                    Records the attempt.
                """
                calls.append(1)
                if len(calls) == 1:
                    yield _chunk("truncated garbage", done=True,
                                 done_reason="length", eval_count=65536)
                else:
                    yield _chunk('{"action":"report","vulnerabilities":[]}',
                                 done=True, done_reason="stop", eval_count=12)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _RecoversOnRetry()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == '{"action":"report","vulnerabilities":[]}'
        assert len(calls) == 2

    def test_every_attempt_truncating_exhausts_the_retry_budget(
            self, monkeypatch):
        """
        Purpose:
            Pin that a model truncating on every attempt uses the whole retry budget and is counted as that many failures.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            The usage counters are asserted as well as the attempt count, because a scan whose calls all truncated once reported a perfectly healthy provider.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        calls = []

        class _NeverConverges:
            """
            Purpose:
                A client that truncates on every attempt.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield an empty final chunk reporting the generation limit.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single truncated final chunk.

                Side effects:
                    Records the attempt.
                """
                calls.append(1)
                yield _chunk("", done=True, done_reason="length",
                            eval_count=65536)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _NeverConverges()

        result = prov.analyze("p", system_message="s")
        assert len(calls) == OLLAMA_MAX_RETRIES
        assert "error" in result
        summary = prov.usage_summary()
        assert summary["calls"] == OLLAMA_MAX_RETRIES
        assert summary["failed"] == OLLAMA_MAX_RETRIES

    def test_a_normal_stop_reason_is_unaffected(self, monkeypatch):
        """
        Purpose:
            Pin that an answer which ended normally is returned as a success and counted as one.

        Parameters:
            monkeypatch: Removes the backoff delay.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _Normal:
            """
            Purpose:
                A client that answers completely.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield one complete final chunk.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single final chunk holding an action.
                """
                yield _chunk('{"action":"list_files","path":""}', done=True,
                             done_reason="stop", eval_count=8)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _Normal()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == '{"action":"list_files","path":""}'
        assert prov.usage_summary()["failed"] == 0

    def test_a_response_with_no_done_reason_at_all_is_still_treated_as_ok(
            self, monkeypatch):
        """
        Purpose:
            Pin that a response omitting the reason field entirely is treated as complete rather than as truncated.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            Older servers and some intermediaries leave the field out, and treating its absence as truncation would discard every answer from them.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _NoDoneReason:
            """
            Purpose:
                A client whose final chunk carries no reason field.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield a final chunk with no reason field on it.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single final chunk.
                """
                yield {"message": {"content": "ok"}, "done": True}

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _NoDoneReason()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "ok"


class TestThinkingCapture:
    """
    Purpose:
        Capturing a model's reasoning output separately from its answer, and recording it in the saved transcript.
    """
    def test_thinking_is_accumulated_separately_from_content(self, monkeypatch):
        """
        Purpose:
            Pin that reasoning chunks accumulate into their own field and do not contaminate the answer.

        Parameters:
            monkeypatch: Removes the backoff delay.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _Reasoning:
            """
            Purpose:
                A client that streams two reasoning chunks before its answer.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield two reasoning chunks and then a complete answer.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A stream of chunks ending in a complete final one.
                """
                yield _chunk("", thinking="step one. ")
                yield _chunk("", thinking="step two.")
                yield _chunk("final answer", done=True, done_reason="stop",
                            eval_count=20)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _Reasoning()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "final answer"
        assert result["thinking"] == "step one. step two."

    def test_a_run_with_no_thinking_field_at_all_still_works(self, monkeypatch):
        """
        Purpose:
            Pin that a model which never sends reasoning yields an empty reasoning field rather than failing.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            Non-reasoning models omit the field entirely, so reading it unguarded would fail for every one of them.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)

        class _NoThinking:
            """
            Purpose:
                A client that sends no reasoning field at all.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Yield a single complete answer with no reasoning field.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single final chunk.
                """
                yield _chunk("plain answer", done=True, done_reason="stop")

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _NoThinking()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "plain answer"
        assert result["thinking"] == ""

    def test_thinking_length_reaches_the_saved_transcript(self, tmp_path):
        """
        Purpose:
            Pin that the saved transcript records the reasoning size, the reason generation ended, the answer, and the reasoning text itself.

        Parameters:
            tmp_path: Directory the transcript is written into.

        Implementation notes:
            The trace is kept in full rather than only measured, because a truncated or empty answer is usually explained by what is in the reasoning, and the size alone does not explain anything.
        """
        prov = _ollama_provider(api_keys=["k"], apk_name="Demo")

        filepath = tmp_path / "log_x.md"

        class _OutputManager:
            """
            Purpose:
                An output manager that points the transcript at one fixed file.
            """
            def get_llm_log_path(self, unused_provider_label, unused_ts):
                """
                Purpose:
                    Return the fixed transcript path.

                Parameters:
                    unused_provider_label: The provider name, unused here.
                    unused_ts: The timestamp, unused here.

                Returns:
                    The path the transcript is written to.
                """
                return filepath

        prov.verbose = True
        prov.output_manager = _OutputManager()
        prov.log_exchange(
            "system", "prompt", "the real answer",
            elapsed=1.2, metrics={"eval_count": 500, "done_reason": "stop"},
            thinking="a" * 4321,
        )
        text = filepath.read_text()
        assert "**Thinking:** 4321 chars" in text
        assert "**Done reason:** stop" in text
        assert "the real answer" in text
        assert "a" * 4321 in text

    def test_no_thinking_block_is_written_when_there_was_none(self, tmp_path):
        """
        Purpose:
            Pin that no reasoning section is written to the transcript when there was no reasoning.

        Parameters:
            tmp_path: Directory the transcript is written into.
        """
        prov = _ollama_provider(api_keys=["k"])
        filepath = tmp_path / "log.md"

        class _OutputManager:
            """
            Purpose:
                An output manager that points the transcript at one fixed file.
            """
            def get_llm_log_path(self, unused_provider_label, unused_ts):
                """
                Purpose:
                    Return the fixed transcript path.

                Parameters:
                    unused_provider_label: The provider name, unused here.
                    unused_ts: The timestamp, unused here.

                Returns:
                    The path the transcript is written to.
                """
                return filepath

        prov.verbose = True
        prov.output_manager = _OutputManager()
        prov.log_exchange(
            "system", "prompt", "answer",
            elapsed=0.5, metrics={"eval_count": 10, "done_reason": "stop"},
            thinking="",
        )
        assert "## Thinking" not in filepath.read_text()


class TestParseActionFromThinking:
    """
    Purpose:
        Salvaging a decision out of a reasoning trace that ran out of room before producing one.
    """
    def _fn(self):
        """
        Purpose:
            Resolve the salvage helper.

        Returns:
            The helper function.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import (
            _parse_action_from_thinking)

        return _parse_action_from_thinking

    def test_recovers_the_last_valid_action_in_the_trace(self):
        """
        Purpose:
            Pin that a decision embedded in prose is recovered and unrelated structures around it are ignored.
        """
        parse = self._fn()
        thinking = (
            'Let me think... maybe {"foo": "bar"} is relevant. '
            'Actually the right move is '
            '{"action":"read_file","path":"sources/A.java"}'
        )
        result = parse(thinking)
        assert result == {"action": "read_file", "path": "sources/A.java"}

    def test_an_early_draft_action_is_not_preferred_over_a_later_real_one(self):
        """
        Purpose:
            Pin that when the trace holds several decisions, the last one is taken.

        Implementation notes:
            A reasoning trace shows the model changing its mind, so an earlier candidate is a draft it has already rejected.
        """
        parse = self._fn()
        thinking = (
            'First I thought {"action":"list_files","path":""} but no, '
            'I should instead {"action":"report","vulnerabilities":[]}'
        )
        result = parse(thinking)
        assert result["action"] == "report"

    def test_prose_with_no_json_at_all_yields_nothing(self):
        """
        Purpose:
            Pin that a trace holding no structure at all yields nothing.
        """
        parse = self._fn()
        assert parse("just reasoning, no structure here whatsoever") is None

    def test_a_stray_object_that_is_not_an_action_is_skipped(self):
        """
        Purpose:
            Pin that a structure that is not a decision is not mistaken for one.
        """
        parse = self._fn()
        assert parse('{"not": "an action"}') is None

    def test_empty_and_none_are_handled(self):
        """
        Purpose:
            Pin that an empty or absent trace yields nothing rather than raising.
        """
        parse = self._fn()
        assert parse("") is None
        assert parse(None) is None


class TestActionRecoveryEndToEnd:
    """
    Purpose:
        That the agent loop actually uses the salvage and the inline retry, rather than only the helpers existing.
    """
    def test_empty_content_with_a_decision_buried_in_thinking_is_recovered(
            self, tmp_path):
        """
        Purpose:
            Pin that a turn with no answer but a decision in its reasoning is recovered without spending another call.

        Parameters:
            tmp_path: The source tree the loop runs over.

        Implementation notes:
            The call count is asserted at one, so a recovery that worked only by asking again would fail here; spending a second full-size call is the cost this exists to avoid.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import (
            run_agent_analysis)

        (tmp_path / "A.java").write_text("class A {}\n")

        class _Provider:
            """
            Purpose:
                A provider whose first turn ran out of room mid-reasoning, leaving its decision only in the trace.

            Attributes:
                calls: How many turns were requested.
            """
            def __init__(self):
                """
                Purpose:
                    Build the provider with no calls recorded.
                """
                self.calls = 0

            def analyze(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Return an empty answer with a decision in the reasoning on the first turn, and a plain decision afterwards.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    The turn's response.

                Side effects:
                    Increments the call count.
                """
                self.calls += 1
                if self.calls == 1:
                    return {
                        "response": "",
                        "thinking": 'reasoning... '
                                   '{"action":"report","vulnerabilities":[]}',
                    }
                return {"response":
                       '{"action":"report","vulnerabilities":[]}'}

        prov = _Provider()
        vulns, completed_ok, _ = run_agent_analysis(prov, str(tmp_path), verbose=False)
        assert completed_ok is True
        assert prov.calls == 1

    def test_empty_content_and_empty_thinking_still_falls_through_normally(
            self, tmp_path):
        """
        Purpose:
            Pin that a turn with nothing to salvage falls through to the ordinary unparseable handling rather than being swallowed.

        Parameters:
            tmp_path: The source tree the loop runs over.

        Implementation notes:
            Three calls are expected: the empty turn and its immediate inline retry, which is still empty and costs the step, then the real decision.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import (
            run_agent_analysis)

        (tmp_path / "A.java").write_text("class A {}\n")

        class _Provider:
            """
            Purpose:
                A provider whose first two turns return nothing at all.

            Attributes:
                calls: How many turns were requested.
            """
            def __init__(self):
                """
                Purpose:
                    Build the provider with no calls recorded.
                """
                self.calls = 0

            def analyze(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Return an empty answer and empty reasoning on the first two turns, and a decision afterwards.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    The turn's response.

                Side effects:
                    Increments the call count.
                """
                self.calls += 1
                if self.calls <= 2:
                    return {"response": "", "thinking": ""}
                return {"response": '{"action":"report","vulnerabilities":[]}'}

        prov = _Provider()
        vulns, completed_ok, _ = run_agent_analysis(prov, str(tmp_path), verbose=False)
        assert completed_ok is True
        assert prov.calls == 3

    def test_an_unparseable_response_is_recovered_on_the_inline_retry(self, tmp_path):
        """
        Purpose:
            Pin that a single malformed response is retried immediately, costs no step, and is still counted.

        Parameters:
            tmp_path: The source tree the loop runs over.

        Implementation notes:
            One bad sample is usually noise. A real scan lost two full steps to malformed responses immediately after a throttle with nothing attempted to salvage them, so when the very next call is well formed this has to cost no step at all.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis

        (tmp_path / "A.java").write_text("class A {}\n")

        class _Provider:
            """
            Purpose:
                A provider whose first turn is malformed and whose second is a decision, counting both turns and salvage notifications.

            Attributes:
                calls: How many turns were requested.
                unparseable_calls: How many malformed responses were reported back.
            """
            def __init__(self):
                """
                Purpose:
                    Build the provider with no calls and no notifications recorded.
                """
                self.calls = 0
                self.unparseable_calls = 0

            def record_unparseable(self):
                """
                Purpose:
                    Record that the loop reported a malformed response.

                Side effects:
                    Increments the notification count.
                """
                self.unparseable_calls += 1

            def analyze(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Return text that is not a decision on the first turn, and a decision afterwards.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    The turn's response.

                Side effects:
                    Increments the call count.
                """
                self.calls += 1
                if self.calls == 1:
                    return {"response": "not json at all"}
                return {"response": '{"action":"report","vulnerabilities":[]}'}

        prov = _Provider()
        vulns, completed_ok, _ = run_agent_analysis(prov, str(tmp_path), verbose=False)
        assert completed_ok is True
        assert prov.calls == 2
        assert prov.unparseable_calls == 1


class _ConcurrencyProvider(BaseAIProvider):
    """
    Purpose:
        A provider that records the highest number of calls that were ever in flight at once.

    Attributes:
        name: The provider name the base class requires.
        hold: How long each call occupies its slot.
        lock: Guards the active count and the peak.
        active: How many calls are in flight now.
        concurrent_peak: The highest number in flight at any point.
    """
    name = "test"

    def __init__(self, *a, hold=0.05, **kw):
        """
        Purpose:
            Build the provider with an empty record.

        Parameters:
            hold: How long each call occupies its slot.
            a: Positional arguments passed to the base class.
            kw: Keyword arguments passed to the base class, such as the configuration.
        """
        super().__init__(*a, **kw)
        self.hold = hold
        self.lock = threading.Lock()
        self.active = 0
        self.concurrent_peak = 0

    def analyze(self, *a, **kw):
        """
        Purpose:
            Occupy a slot for the hold time and answer successfully.

        Parameters:
            a: Positional arguments, ignored.
            kw: Keyword arguments, ignored.

        Returns:
            A response holding an empty finding list.

        Side effects:
            Raises and lowers the active count and updates the recorded peak.
        """
        with self.lock:
            self.active += 1
            self.concurrent_peak = max(self.concurrent_peak, self.active)
        try:
            time.sleep(self.hold)
            return {"response": "[]"}
        finally:
            with self.lock:
                self.active -= 1

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


class TestConcurrencyGate:
    """
    Purpose:
        The cap on how many calls a provider may have in flight at once.
    """
    def test_calls_never_exceed_max_concurrent_requests(self):
        """
        Purpose:
            Pin that with a width of two, six concurrent callers never put more than two calls in flight, and that the gate is not accidentally fully serial.

        Implementation notes:
            The base class's own analyse does not take the gate; each concrete provider takes it at the top of its own. The fake here stands in for the work a provider does under the gate, so the call site wraps it the same way rather than expecting the base to do it.
        """
        prov = _ConcurrencyProvider(
            config={"max_concurrent_requests": 2}, api_key="k", hold=0.05)
        gate = prov._request_gate

        def gated_call():
            """
            Purpose:
                Take a permit and do one call's worth of work under it.

            Side effects:
                Occupies a gate permit for the duration of the call.
            """
            with gate:
                prov.analyze()

        threads = [threading.Thread(target=gated_call) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert prov.concurrent_peak <= 2
        assert prov.concurrent_peak > 1

    def test_default_width_is_two_when_unconfigured(self):
        """
        Purpose:
            Pin the default width when nothing is configured.
        """
        prov = _ConcurrencyProvider(api_key="k")
        assert prov._request_gate._value == 2

    def test_a_configured_width_is_honoured(self):
        """
        Purpose:
            Pin that a configured width is the one the gate uses.
        """
        prov = _ConcurrencyProvider(
            config={"max_concurrent_requests": 5}, api_key="k")
        assert prov._request_gate._value == 5

    def test_a_malformed_config_value_falls_back_to_the_default(self):
        """
        Purpose:
            Pin that a non-numeric configured width falls back to the default rather than failing at construction.

        Implementation notes:
            The value comes from a settings file the user can edit by hand, and failing here would leave them with a tool that will not start over a single bad character.
        """
        prov = _ConcurrencyProvider(
            config={"max_concurrent_requests": "not a number"}, api_key="k")
        assert prov._request_gate._value == 2

    def test_ollama_actually_serialises_through_the_gate(self, monkeypatch):
        """
        Purpose:
            Pin that the real provider, not merely the base class, holds five concurrent callers to a width of two.

        Parameters:
            monkeypatch: Removes the backoff delay.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        lock = threading.Lock()
        state = {"active": 0, "peak": 0}

        class _SlowClient:
            """
            Purpose:
                A client that holds its slot long enough for overlap to be observable, recording the peak.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Occupy a slot briefly, recording the peak, then yield a complete answer.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk.

                Side effects:
                    Raises and lowers the active count and updates the recorded peak.
                """
                with lock:
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                time.sleep(0.05)
                with lock:
                    state["active"] -= 1
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov = _ollama_provider(
            config={"mode": "cloud", "max_concurrent_requests": 2},
            api_keys=["k"])
        prov._client = _SlowClient()

        threads = [threading.Thread(
            target=lambda: prov.analyze("p", system_message="s"))
            for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert state["peak"] <= 2


class TestAdaptiveGate:
    """
    Purpose:
        Narrowing the concurrency width when the account itself says the configured one is too wide.

    Implementation notes:
        A configured width of two still collided on an account whose real limit is one: measured against the cloud provider, two calls each ran twelve to fourteen minutes while the sibling region was refused for the entire window. The configured width is a starting estimate, and a refusal is the actual measurement.
    """
    def test_the_first_throttle_narrows_the_gate_to_one(self, monkeypatch):
        """
        Purpose:
            Pin that the first refusal narrows the gate so that a second caller queues instead of running alongside the first.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            The narrowing is asserted by observing real concurrency afterwards rather than by reading the width, because the width and the permits actually available can disagree if the absorption went wrong.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        prov = _ollama_provider(
            config={"mode": "cloud", "max_concurrent_requests": 2},
            api_keys=["k"])

        calls = {"n": 0}

        class _ThrottlesOnce:
            """
            Purpose:
                A client that is refused once and then answers.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Report a refusal on the first call and answer on any later one.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk, after the first call.

                Raises:
                    Exception: On the first call, carrying a rate-limit message.

                Side effects:
                    Records the attempt.
                """
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Exception("rate limit exceeded")
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov._client = _ThrottlesOnce()
        prov.analyze("p", system_message="s")
        assert prov._gate_shrunk_done.wait(timeout=5)

        state = {"active": 0, "peak": 0}
        lock = threading.Lock()

        def gated_call():
            """
            Purpose:
                Take a permit and hold it briefly, recording the peak number held at once.

            Side effects:
                Occupies a gate permit and updates the recorded peak.
            """
            with prov._request_gate:
                with lock:
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                time.sleep(0.05)
                with lock:
                    state["active"] -= 1

        threads = [threading.Thread(target=gated_call) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert state["peak"] == 1

    def test_shrinking_is_idempotent_and_never_over_releases(self, monkeypatch):
        """
        Purpose:
            Pin that repeated refusals narrow the gate only once and that resetting returns exactly the permits that were absorbed.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            Returning more permits than were taken raises out of the primitive, so the absorbed count is asserted back to zero rather than only the width being asserted back to its original value.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        prov = _ollama_provider(
            config={"mode": "cloud", "max_concurrent_requests": 3},
            api_keys=["k"])

        for _ in range(5):
            prov.on_throttled(blocked_s=0.01)
        assert prov._gate_shrunk_done.wait(timeout=5)

        prov.reset_circuit()
        assert prov._request_gate._value == 3
        assert prov._absorbed == 0

    def test_a_thread_holding_a_permit_does_not_deadlock_the_shrink(self, monkeypatch):
        """
        Purpose:
            Pin that a caller which observes a refusal while holding a permit does not deadlock against itself.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            This is the specific hazard the design carries: the thread that sees the refusal is itself inside the gate, so the absorption has to happen off that thread or it waits for a permit it is holding.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        prov = _ollama_provider(
            config={"mode": "cloud", "max_concurrent_requests": 2},
            api_keys=["k"])

        done = threading.Event()

        def holds_a_permit_and_throttles():
            """
            Purpose:
                Take a permit, report a refusal from inside it, and wait for the narrowing to finish.

            Side effects:
                Occupies a gate permit and signals completion.
            """
            with prov._request_gate:
                prov.on_throttled(blocked_s=0.01)
                assert prov._gate_shrunk_done.wait(timeout=5)
            done.set()

        thread = threading.Thread(target=holds_a_permit_and_throttles)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert done.is_set()

    def test_a_narrowed_gate_survives_a_second_throttle(self, monkeypatch):
        """
        Purpose:
            Pin that a second refusal after the gate has narrowed neither hangs nor raises, and is still counted.

        Parameters:
            monkeypatch: Removes the backoff delay.

        Implementation notes:
            There is only one surplus permit to take and it was already taken, so a second absorption attempt would wait forever for a permit that does not exist.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        prov = _ollama_provider(
            config={"mode": "cloud", "max_concurrent_requests": 2},
            api_keys=["k"])
        prov.on_throttled(blocked_s=0.01)
        assert prov._gate_shrunk_done.wait(timeout=5)
        prov.on_throttled(blocked_s=0.01)
        assert prov.usage["throttled_attempts"] == 2


class TestThrottleTelemetry:
    """
    Purpose:
        That throttling and malformed responses are counted honestly.

    Implementation notes:
        A real scan that logged four refusals and two malformed responses reported zero failures in its usage summary, which is the one number a user would look at to decide whether the provider layer was healthy.
    """
    def test_a_throttle_that_later_succeeds_is_still_counted(self, monkeypatch):
        """
        Purpose:
            Pin that a refusal followed by a successful retry is still recorded as a refusal, a retry, and time spent blocked.

        Parameters:
            monkeypatch: Removes the backoff delay.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        calls = {"n": 0}

        class _ThrottlesOnce:
            """
            Purpose:
                A client that is refused once and then answers.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Report a refusal on the first call and answer on any later one.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk, after the first call.

                Raises:
                    Exception: On the first call, carrying a rate-limit message.

                Side effects:
                    Records the attempt.
                """
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Exception("rate limit exceeded")
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _ThrottlesOnce()
        result = prov.analyze("p", system_message="s")

        assert result["response"] == "ok"
        assert prov.usage["throttled_attempts"] == 1
        assert prov.usage["retried_calls"] == 1
        assert prov.usage["blocked_seconds"] > 0

    def test_blocked_seconds_measures_the_stall_not_the_backoff(self, monkeypatch):
        """
        Purpose:
            Pin that the time recorded as blocked is the time the refused attempt stalled for, not the delay waited afterwards.

        Parameters:
            monkeypatch: Removes the backoff delay and replaces the clock with a fabricated one.

        Implementation notes:
            The sleep being replaced belongs to the standard library module, so replacing it silences every sleep in the process including a fake client's own. A fabricated clock is therefore the only way to give the failing attempt a known duration without a real, slow and flaky wall-clock wait. The clock returns zero for the first two readings, which are the whole-call timer and the first attempt's start, and the stall duration for every reading after, so later attempts measure no time of their own, which this test does not look at.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        monkeypatch.setattr(op.time, "sleep", lambda _: None)
        state = {"n": 0}

        def _clock():
            """
            Purpose:
                A fabricated monotonic clock that jumps forward after the first two readings.

            Returns:
                Zero for the first two readings and the stall duration thereafter.

            Side effects:
                Counts the readings taken.
            """
            state["n"] += 1
            return 0.0 if state["n"] <= 2 else 300.0

        monkeypatch.setattr(op.time, "monotonic", _clock)
        calls = {"n": 0}

        class _Throttle:
            """
            Purpose:
                A client that is refused once and then answers.
            """
            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Report a refusal on the first call and answer on any later one.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk, after the first call.

                Raises:
                    Exception: On the first call, carrying a rate-limit message.

                Side effects:
                    Records the attempt.
                """
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Exception("rate limit exceeded")
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _Throttle()
        prov.analyze("p", system_message="s")
        assert prov.usage["blocked_seconds"] >= 300.0

    def test_unparseable_responses_are_counted_when_the_hook_is_used(self):
        """
        Purpose:
            Pin that reported malformed responses accumulate in the usage summary.
        """
        prov_like = _ollama_provider(api_keys=["k"])
        prov_like.record_unparseable()
        prov_like.record_unparseable()
        assert prov_like.usage["unparseable_responses"] == 2

    def test_a_provider_without_the_hook_still_drives_the_loop(self, tmp_path):
        """
        Purpose:
            Pin that a provider offering none of the telemetry hooks still runs the loop to completion.

        Parameters:
            tmp_path: The source tree the loop runs over.

        Implementation notes:
            Callers guard each hook before using it, and this holds that guarding in place so a provider written before the hooks existed keeps working.
        """
        (tmp_path / "A.java").write_text("class A {}\n")
        from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis

        class _Bare:
            """
            Purpose:
                A provider offering nothing beyond a single answer.
            """
            def analyze(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Return a decision to finish immediately.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A response holding a report with no findings.
                """
                return {"response": '{"action":"report","vulnerabilities":[]}'}

        vulns, completed_ok, _ = run_agent_analysis(
            _Bare(), str(tmp_path), verbose=False)
        assert completed_ok is True


class _FakeHeaders(dict):
    """
    Purpose:
        A header mapping whose lookup is case-sensitive, matching what the real client exposes.

    Implementation notes:
        Case sensitivity is the point: the code under test has to try both spellings itself rather than relying on the mapping to fold them.
    """
    def get(self, key, default=None):
        """
        Purpose:
            Look up a header by its exact name.

        Parameters:
            key: The header name, matched exactly.
            default: What to return when the name is absent.

        Returns:
            The header value, or the default.
        """
        return dict.get(self, key, default)


class _FakeResponse:
    """
    Purpose:
        A response carrying headers and a status code.

    Attributes:
        headers: The response headers.
        status_code: The response status.
    """
    def __init__(self, headers=None, status_code=429):
        """
        Purpose:
            Build the response.

        Parameters:
            headers: The response headers, or None for none.
            status_code: The response status.
        """
        self.headers = headers or {}
        self.status_code = status_code


class _FakeHttpError(Exception):
    """
    Purpose:
        An error carrying a response, shaped the way an HTTP client's error is.

    Attributes:
        response: The response the error carries.
    """
    def __init__(self, response=None):
        """
        Purpose:
            Build the error.

        Parameters:
            response: The response to carry, or None for none.
        """
        super().__init__("too many requests")
        self.response = response


class TestRetryAfter:
    """
    Purpose:
        Reading a retry delay out of a refusal, and what happens when none is offered.
    """
    def test_reads_an_integer_retry_after_header(self):
        """
        Purpose:
            Pin that a numeric delay header is read as that many seconds.
        """
        exc = _FakeHttpError(_FakeResponse({"Retry-After": "30"}))
        assert retry_after_for(exc) == 30.0

    def test_is_case_insensitive_on_the_header_name(self):
        """
        Purpose:
            Pin that the header is found whichever way its name is capitalised.

        Implementation notes:
            Header names are case-insensitive on the wire but the mapping here is not, so both spellings have to be tried by the code rather than by the container.
        """
        exc = _FakeHttpError(_FakeResponse({"retry-after": "12"}))
        assert retry_after_for(exc) == 12.0

    def test_missing_header_is_none(self):
        """
        Purpose:
            Pin that a response without the header yields no delay.
        """
        exc = _FakeHttpError(_FakeResponse({}))
        assert retry_after_for(exc) is None

    def test_no_response_at_all_is_none(self):
        """
        Purpose:
            Pin that an error carrying no response yields no delay rather than raising.
        """
        assert retry_after_for(Exception("plain")) is None

    def test_a_non_numeric_value_is_none_rather_than_raising(self):
        """
        Purpose:
            Pin that a date-formatted delay, which is legal but not handled, yields no delay rather than raising.
        """
        exc = _FakeHttpError(_FakeResponse({"Retry-After": "Wed, 21 Oct 2026"}))
        assert retry_after_for(exc) is None

    def test_a_negative_value_is_clamped_to_zero(self):
        """
        Purpose:
            Pin that a negative delay becomes zero rather than a negative wait.
        """
        exc = _FakeHttpError(_FakeResponse({"Retry-After": "-5"}))
        assert retry_after_for(exc) == 0.0

    def test_ollamas_actual_exception_type_never_carries_it(self):
        """
        Purpose:
            Pin that the cloud provider's own error type carries no delay, documenting a real constraint rather than a defect.

        Implementation notes:
            That error is constructed deep inside the client from the response body and status alone, so the response object and its headers never reach this project's code. This is why that provider's refusal path falls back to a flat delay, and it is not a fault in the reader.
        """
        from ollama import ResponseError

        exc = ResponseError("too many requests", 429)
        assert retry_after_for(exc) is None

    def test_ollama_throttle_uses_retry_after_when_the_exception_carries_one(
            self, monkeypatch):
        """
        Purpose:
            Pin that when a refusal does carry a delay, that delay is what is waited.

        Parameters:
            monkeypatch: Records what was waited instead of waiting.

        Implementation notes:
            Proven with an error shaped the way an HTTP-based provider's is, since the mechanism is provider-agnostic even though today's client cannot supply the header.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        sleeps = []
        monkeypatch.setattr(op.time, "sleep", lambda s: sleeps.append(s))

        class _ThrottledWithHeader:
            """
            Purpose:
                A client refused once with a delay header, then answering.

            Attributes:
                n: How many attempts were made.
            """
            def __init__(self):
                """
                Purpose:
                    Build the client with no attempts recorded.
                """
                self.n = 0

            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Fail with a delay-carrying refusal on the first attempt and answer afterwards.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk, after the first attempt.

                Raises:
                    _FakeHttpError: On the first attempt, carrying a delay header.

                Side effects:
                    Increments the attempt count.
                """
                self.n += 1
                if self.n < 2:
                    raise _FakeHttpError(_FakeResponse({"Retry-After": "42"}))
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov = _ollama_provider(api_keys=["k"])
        client = _ThrottledWithHeader()
        prov._client = client

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "ok"
        assert sleeps == [42.0]

    def test_ollama_throttle_falls_back_to_the_flat_delay_without_a_header(
            self, monkeypatch):
        """
        Purpose:
            Pin that a refusal with no delay header waits the configured flat delay.

        Parameters:
            monkeypatch: Records what was waited instead of waiting.
        """
        import lu77U_MobileSec.ai.ollama_provider as op

        sleeps = []
        monkeypatch.setattr(op.time, "sleep", lambda s: sleeps.append(s))

        class _ThrottledNoHeader:
            """
            Purpose:
                A client refused once with no delay header, then answering.

            Attributes:
                n: How many attempts were made.
            """
            def __init__(self):
                """
                Purpose:
                    Build the client with no attempts recorded.
                """
                self.n = 0

            def chat(self, *unused_args, **unused_kwargs):
                """
                Purpose:
                    Fail with a plain refusal on the first attempt and answer afterwards.

                Parameters:
                    unused_args: Positional arguments, ignored.
                    unused_kwargs: Keyword arguments, ignored.

                Returns:
                    A single complete final chunk, after the first attempt.

                Raises:
                    Exception: On the first attempt, carrying a rate-limit message.

                Side effects:
                    Increments the attempt count.
                """
                self.n += 1
                if self.n < 2:
                    raise Exception("rate limit exceeded")
                yield _chunk("ok", done=True, done_reason="stop", eval_count=1)

        prov = _ollama_provider(api_keys=["k"])
        prov._client = _ThrottledNoHeader()

        result = prov.analyze("p", system_message="s")
        assert result["response"] == "ok"
        assert sleeps == [op.THROTTLE_RETRY_DELAY]


class TestThrottleRegression:
    """
    Purpose:
        That a refusal is still neither fatal nor a reason to change key.
    """
    def test_a_throttled_error_does_not_open_the_circuit(self):
        """
        Purpose:
            Pin that a refusal leaves the circuit closed and stays on the current key.

        Implementation notes:
            A refusal is about pacing rather than about the credential, so rotating on one would spend the whole pool during a busy minute and leave nothing for a key that genuinely runs out.
        """
        prov = _ollama_provider(api_keys=["k1", "k2"])
        assert prov._handle_exception(Exception("rate limit exceeded")) is None
        assert prov.unavailable is None
        assert prov.api_key == "k1"
