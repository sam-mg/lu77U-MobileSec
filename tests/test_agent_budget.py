#!/usr/bin/env python3
"""
Module: test_agent_budget

Purpose:
    The ceiling on the phase-1 agent, and what it reports when it stops.

Responsibilities:
    Pin the step budget, the time budget, the crediting of time lost to throttling, the interaction between a budget stop and an already-dead provider, the validation of the stored budget setting, and how the fan-out shares one budget across parallel regions.

Dependencies:
    pytest, the agent loop, the budget module, the fan-out, the user settings store and the cancellation exception.

Implementation notes:
    The loop was once unbounded by default and no caller passed a step limit, so on an app of 13,398 files the only thing that ended a scan was the provider's own account limit: 93 minutes, 244 model calls, a spent cloud quota, and neither region ever submitting a report. Nothing in the output told that apart from a scan the model had finished, which is why the stop reason is asserted here as well as the stopping itself.
"""

import time

import pytest

from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis
from lu77U_MobileSec.config import user_settings
from lu77U_MobileSec.utils.cancellation import ScanCancelled

_VEC = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_LIST = '{"action":"list_files","path":""}'


def _finding(title, file, line):
    """
    Purpose:
        Build one finding as the model would return it, as a JSON fragment.

    Parameters:
        title: The finding title.
        file: The file the finding is attributed to.
        line: The line the finding is attributed to.

    Returns:
        The finding as a JSON object string, ready to embed in a scripted response.
    """
    return (f'{{"title":"{title}","file":"{file}","line":"{line}",'
            f'"description":"demo","cvss_vector":"{_VEC}"}}')


class _Provider:
    """
    Purpose:
        A provider that answers every turn with a file listing, so the loop never ends on its own and only a budget can stop it.

    Attributes:
        calls: How many times the loop asked the provider for a turn.
        script: Responses handed out in order before falling back to the listing action.
    """
    def __init__(self, script=None, unavailable=None):
        """
        Purpose:
            Build the provider, optionally with a scripted sequence of responses and a simulated unavailability.

        Parameters:
            script: Responses to return in order, or None to always return the listing action.
            unavailable: The reason the provider reports itself unusable, or None when it is healthy.
        """
        self.calls = 0
        self.script = list(script or [])
        self._unavailable = unavailable

    @property
    def unavailable(self):
        """
        Purpose:
            Report why the provider is unusable, matching the real provider's circuit-breaker attribute.

        Returns:
            The reason string, or None when the provider is healthy.
        """
        return self._unavailable

    def analyze(self, *args_unused, **kwargs_unused):
        """
        Purpose:
            Answer one turn and count the call.

        Parameters:
            args_unused: The prompt and any other positional arguments the loop calls with, ignored.
            kwargs_unused: The system message, schema, images, token limit and session key the loop calls with, ignored.

        Returns:
            The next scripted response, or the listing action once the script is spent.

        Side effects:
            Increments the call count and consumes one scripted response.
        """
        self.calls += 1
        if self.script:
            return {"response": self.script.pop(0)}
        return {"response": _LIST}


@pytest.fixture
def tree(tmp_path):
    """
    Purpose:
        Build a minimal decompiled source tree with one Java file in it.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The root the agent loop is pointed at.
    """
    src = tmp_path / "sources" / "com" / "x"
    src.mkdir(parents=True)
    (src / "A.java").write_text("class A {}\n")
    return tmp_path


@pytest.fixture(autouse=True)
def isolated_user_settings(tmp_path, monkeypatch):
    """
    Purpose:
        Point the user settings store at a throwaway file for every test in this module.

    Parameters:
        tmp_path: Temporary directory holding the throwaway settings file.
        monkeypatch: Redirects the settings path and clears the cache.

    Returns:
        Nothing; the fixture yields once and then clears the cache again.

    Side effects:
        Replaces the settings path and resets the module cache before and after each test.

    Implementation notes:
        Several tests read the agent budget, directly or through the fan-out, and the real settings file is the user's live machine-specific configuration. Reading a value they set, such as an intentional unbounded budget left in place while working on something else, would make the outcome depend on their machine, and writing to it from a test run would change their configuration. Redirecting the path lets the real load and save logic run against an empty file instead of being stubbed out.

    Security considerations:
        Keeps the test run from reading or overwriting the user's stored configuration, which sits alongside their credentials.
    """
    from lu77U_MobileSec.config import user_settings

    monkeypatch.setattr(
        user_settings, "get_settings_path", lambda: tmp_path / "settings.json")
    monkeypatch.setattr(user_settings, "_cache", None)
    yield
    monkeypatch.setattr(user_settings, "_cache", None)


class TestStepBudget:
    """
    Purpose:
        The limit on how many turns one region's agent may take.
    """
    def test_the_loop_stops_at_the_step_budget(self, tree):
        """
        Purpose:
            Pin that a loop which never self-terminates stops at the step budget and says so.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            The expected call count is the budget plus one, because a budget stop is followed by a single forced call asking the model for its final report rather than discarding the work done so far.
        """
        provider = _Provider()
        telemetry = {}
        run_agent_analysis(provider, tree, max_steps=5, telemetry=telemetry)
        assert provider.calls == 6
        assert telemetry["stop_reason"] == "budget_steps"
        assert telemetry["steps"] == 5

    def test_findings_recorded_before_the_budget_ran_out_survive(self, tree):
        """
        Purpose:
            Pin that findings recorded before the budget expired are returned rather than discarded with the run.

        Parameters:
            tree: The decompiled source tree.
        """
        provider = _Provider(script=[
            '{"action":"add_finding","vulnerabilities":['
            + _finding("Recorded early", "A.java", "3") + "]}",
            _LIST, _LIST,
        ])
        findings, ok, _ = run_agent_analysis(provider, tree, max_steps=3)
        assert ok
        assert [f["title"] for f in findings] == ["Recorded early"]

    def test_a_model_that_reports_is_not_cut_short(self, tree):
        """
        Purpose:
            Pin that a model which submits its report stops for that reason and not for the budget.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            The stop reason is what the coverage summary shows the user, so a completed scan attributed to the budget would read as truncated.
        """
        provider = _Provider(script=[
            '{"action":"report","vulnerabilities":['
            + _finding("Done", "A.java", "1") + "]}"])
        telemetry = {}
        run_agent_analysis(provider, tree, max_steps=50, telemetry=telemetry)
        assert telemetry["stop_reason"] == "reported"


class TestTimeBudget:
    """
    Purpose:
        The wall-clock limit on one region's agent.
    """
    def test_a_deadline_in_the_past_stops_before_any_model_call(self, tree):
        """
        Purpose:
            Pin that an already-expired deadline spends no exploration turns at all.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            The single call the provider does see is the forced final report; an expired budget must not buy even one turn of exploration.
        """
        provider = _Provider()
        telemetry = {}
        run_agent_analysis(provider, tree, deadline=time.monotonic() - 1,
                           telemetry=telemetry)
        assert provider.calls == 1
        assert telemetry["stop_reason"] == "budget_time"

    def test_a_deadline_in_the_future_does_not_interfere(self, tree):
        """
        Purpose:
            Pin that a deadline with time left on it lets the model finish normally.

        Parameters:
            tree: The decompiled source tree.
        """
        provider = _Provider(script=[
            '{"action":"report","vulnerabilities":[]}'])
        telemetry = {}
        run_agent_analysis(provider, tree, deadline=time.monotonic() + 300,
                           telemetry=telemetry)
        assert telemetry["stop_reason"] == "reported"


class TestDeadlineCrediting:
    """
    Purpose:
        Crediting back the time an agent spent blocked on a throttle rather than working.

    Implementation notes:
        On a real scan 1,235 seconds of self-inflicted rate-limit backoff came straight out of a 45-minute budget, and both regions stopped on time with steps still unused. Time spent waiting on a throttle is not coverage the user chose to spend, so it is credited back rather than silently lost.
    """
    def test_a_bare_float_deadline_still_works(self, tree):
        """
        Purpose:
            Pin that a plain timestamp is still accepted as a deadline.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            The regression guard for every caller predating the deadline object: the expiry check must not require one.
        """
        provider = _Provider()
        telemetry = {}
        run_agent_analysis(provider, tree, deadline=time.monotonic() - 1,
                           telemetry=telemetry)
        assert telemetry["stop_reason"] == "budget_time"

    def test_a_deadline_object_with_no_credits_behaves_like_the_float(self, tree):
        """
        Purpose:
            Pin that an expired deadline object stops the loop exactly as an expired timestamp does.

        Parameters:
            tree: The decompiled source tree.
        """
        from lu77U_MobileSec.analyzers.agent.budget import Deadline

        provider = _Provider()
        telemetry = {}
        run_agent_analysis(provider, tree, deadline=Deadline(-1),
                           telemetry=telemetry)
        assert telemetry["stop_reason"] == "budget_time"

    def test_credited_time_extends_the_budget(self):
        """
        Purpose:
            Pin that crediting a deadline adds that much time to what remains.

        Implementation notes:
            The base budget is large enough that the cap on total credit is not what is under test here, which the next test covers on its own. The remaining time is read directly rather than waiting for an expiry, because timing a real expiry would make the test race against wall-clock scheduling.
        """
        from lu77U_MobileSec.analyzers.agent.budget import Deadline

        deadline = Deadline(100)
        before = deadline.remaining
        deadline.credit(10)
        after = deadline.remaining
        assert after - before == pytest.approx(10, abs=0.5)

    def test_crediting_is_capped_at_half_the_original_budget(self):
        """
        Purpose:
            Pin that total credit cannot exceed the fixed fraction of the original budget.

        Implementation notes:
            Without a cap a provider throttling continuously would extend the budget indefinitely, turning the user's time limit into no limit at all.
        """
        from lu77U_MobileSec.analyzers.agent.budget import Deadline, MAX_CREDIT_FRACTION

        deadline = Deadline(100)
        deadline.credit(1000)
        assert deadline.credited == pytest.approx(100 * MAX_CREDIT_FRACTION)

    def test_a_closed_deadline_ignores_late_credits(self):
        """
        Purpose:
            Pin that a deadline closed after its run cannot be revived by a credit arriving afterwards.

        Implementation notes:
            Throttle notifications can arrive from a provider's background retry after the region has already finished, and honouring one then would reopen a budget nothing is using.
        """
        from lu77U_MobileSec.analyzers.agent.budget import Deadline

        deadline = Deadline(0.01)
        deadline.close()
        time.sleep(0.02)
        deadline.credit(60)
        assert deadline.expired() is True

    def test_an_unbounded_deadline_ignores_credits_too(self):
        """
        Purpose:
            Pin that crediting an unbounded deadline neither raises nor turns it into a bounded one.
        """
        from lu77U_MobileSec.analyzers.agent.budget import Deadline

        deadline = Deadline(None)
        deadline.credit(60)
        assert deadline.expired() is False
        assert deadline.remaining is None

    def test_a_throttle_observer_credits_the_deadline_through_the_provider_hook(self):
        """
        Purpose:
            Pin that a provider's throttle notification credits the deadline through the real observer hook.

        Implementation notes:
            Exercised end to end on the hook the fan-out actually wires up, rather than on the deadline in isolation, because the wiring is the part that has broken before.
        """
        from lu77U_MobileSec.ai.base_provider import BaseAIProvider
        from lu77U_MobileSec.analyzers.agent.budget import Deadline

        class _Prov(BaseAIProvider):
            """
            Purpose:
                A minimal real provider subclass, used so the throttle hook under test is the base class's own rather than a stub.

            Attributes:
                name: The provider name the base class requires.
            """
            name = "test"

            def analyze(self, *args_unused, **kwargs_unused):
                """
                Purpose:
                    Answer any turn with an empty finding list.

                Parameters:
                    args_unused: Positional arguments, ignored.
                    kwargs_unused: Keyword arguments, ignored.

                Returns:
                    A response holding an empty JSON list.
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

        provider = _Prov(api_key="k")
        deadline = Deadline(0.01)
        provider.add_throttle_observer(deadline.credit)
        provider.on_throttled(blocked_s=60)
        assert deadline.expired() is False


class TestBudgetDoesNotFeedADeadProvider:
    """
    Purpose:
        What the loop does when its budget runs out against a provider that has already stopped answering.
    """
    def test_a_budget_stop_skips_the_forced_report_when_the_circuit_is_open(self, tree):
        """
        Purpose:
            Pin that the forced final report is not sent to a provider whose circuit breaker is already open.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            The forced report is itself a full-size model call, so making it against a provider that has refused everything spends a large prompt to receive the same error back. The call count is asserted at the budget with no extra turn on top.
        """
        provider = _Provider(unavailable="fatal_quota: session usage limit")
        telemetry = {}
        findings, ok, _ = run_agent_analysis(
            provider, tree, max_steps=3, telemetry=telemetry)
        assert provider.calls == 3, "the forced report was sent to a dead provider"
        assert ok
        assert telemetry["stop_reason"] == "budget_steps"

    def test_cancellation_still_wins_over_the_budget(self, tree):
        """
        Purpose:
            Pin that a cancelled scan raises and is recorded as cancelled rather than as a budget stop.

        Parameters:
            tree: The decompiled source tree.

        Implementation notes:
            Cancellation is the user's own action, so reporting it as a budget stop would tell them the tool ran out of time when in fact they stopped it.
        """
        provider = _Provider()
        telemetry = {}
        with pytest.raises(ScanCancelled):
            run_agent_analysis(provider, tree, max_steps=50,
                               is_cancelled=lambda: True, telemetry=telemetry)
        assert telemetry["stop_reason"] == "cancelled"


class TestBudgetSetting:
    """
    Purpose:
        The stored agent budget setting and its validation.
    """
    def test_defaults_are_bounded(self):
        """
        Purpose:
            Pin that the shipped defaults are finite in both steps and minutes.

        Implementation notes:
            An unbounded default is the original failure this module exists for, so it is asserted directly rather than inferred from the loop's behaviour.
        """
        budget = user_settings.get_agent_budget()
        assert budget["max_steps_per_region"] > 0
        assert budget["max_minutes"] > 0

    @pytest.mark.parametrize("field,value", [
        ("max_steps_per_region", -1),
        ("max_steps_per_region", 10_000),
        ("max_minutes", 10_000),
        ("nonsense", 5),
    ])
    def test_out_of_range_values_are_rejected(self, field, value):
        """
        Purpose:
            Pin that a negative, oversized or unknown budget field is refused.

        Parameters:
            field: The budget field being set.
            value: The value being rejected.

        Security considerations:
            These values arrive from the settings endpoint, so refusing them here is what stops a request from setting an effectively unlimited budget on the user's machine.
        """
        with pytest.raises(ValueError):
            user_settings.set_agent_budget(field, value)

    def test_a_corrupt_stored_value_falls_back_to_the_default(self, monkeypatch):
        """
        Purpose:
            Pin that a stored budget of the wrong type falls back to the default instead of propagating.

        Parameters:
            monkeypatch: Returns a settings mapping holding a non-numeric budget.

        Implementation notes:
            A hand-edited or partially-written settings file is the realistic source of this, and letting the bad value through would fail every scan at the point the budget is first compared.
        """
        monkeypatch.setattr(
            user_settings, "load",
            lambda *args_unused, **kwargs_unused: {
                "agent_budget": {"max_steps_per_region": "lots"}})
        budget = user_settings.get_agent_budget()
        assert budget["max_steps_per_region"] == (
            user_settings.DEFAULT_SETTINGS["agent_budget"]["max_steps_per_region"])


class TestFanoutBudget:
    """
    Purpose:
        How one budget is shared across the regions the fan-out runs in parallel, and what the coverage summary records about each.
    """
    def test_every_region_gets_the_same_deadline(self, monkeypatch):
        """
        Purpose:
            Pin that every region receives one shared deadline and a step budget of its own.

        Parameters:
            monkeypatch: Replaces the agent loop with a recorder.

        Implementation notes:
            The deadline is shared rather than divided because the regions run at the same time; dividing one time budget between them would cut each region to a fraction of the limit the user actually set.
        """
        from lu77U_MobileSec.analyzers.agent import fanout
        from lu77U_MobileSec.analyzers.agent.profiles import JAVA_KOTLIN
        from test_fanout import _graph

        seen = []

        def _recorder(*args_unused, max_steps=None, deadline=None, telemetry=None,
                      **kwargs_unused):
            """
            Purpose:
                Stand in for the agent loop and record the budgets each region was given.

            Parameters:
                args_unused: The provider, source root and static signals the fan-out passes positionally, ignored.
                max_steps: The step budget the fan-out handed this region.
                deadline: The time budget the fan-out handed this region.
                telemetry: The mapping the loop reports its outcome through.
                kwargs_unused: The code graph, profile, cancellation callback and verbosity flag the fan-out passes by keyword, ignored.

            Returns:
                An empty finding list, a success flag and an empty error string.

            Side effects:
                Appends the budgets to the recorded list and reports a completed region through the telemetry mapping.
            """
            seen.append((max_steps, deadline))
            if telemetry is not None:
                telemetry.update({"stop_reason": "reported", "steps": 1, "findings": 0})
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", _recorder)
        fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin")

        assert len(seen) > 1
        assert len({deadline for _, deadline in seen}) == 1
        assert all(max_steps for max_steps, _ in seen)

    def test_coverage_records_why_each_region_stopped(self, monkeypatch):
        """
        Purpose:
            Pin that a run where every region stopped early is reported as incomplete, with the reason carried per region.

        Parameters:
            monkeypatch: Replaces the agent loop with a recorder reporting an unavailable provider.

        Implementation notes:
            This is what keeps a truncated scan from reading as a clean result: the coverage summary is the only place the user sees that the regions did not finish.
        """
        from lu77U_MobileSec.analyzers.agent import fanout
        from lu77U_MobileSec.analyzers.agent.profiles import JAVA_KOTLIN
        from test_fanout import _graph

        def _recorder(*args_unused, telemetry=None, **kwargs_unused):
            """
            Purpose:
                Stand in for the agent loop and report every region as stopped by an unavailable provider.

            Parameters:
                args_unused: The provider, source root and static signals the fan-out passes positionally, ignored.
                telemetry: The mapping the loop reports its outcome through.
                kwargs_unused: The code graph, profile, cancellation callback, verbosity flag, step budget and deadline the fan-out passes by keyword, ignored.

            Returns:
                An empty finding list, a success flag and an empty error string.

            Side effects:
                Reports the stop reason and step count through the telemetry mapping.
            """
            if telemetry is not None:
                telemetry.update({"stop_reason": "provider_unavailable",
                                  "steps": 105, "findings": 0})
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", _recorder)
        coverage = {}
        fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin", coverage=coverage)

        assert coverage["complete"] is False
        assert coverage["regions_incomplete"] == coverage["regions_total"]
        assert coverage["degraded_reason"]
        assert all(r["stop_reason"] == "provider_unavailable"
                   for r in coverage["regions"])

    def test_a_finished_scan_is_marked_complete(self, monkeypatch):
        """
        Purpose:
            Pin that a run where every region reported is marked complete with no degradation reason.

        Parameters:
            monkeypatch: Replaces the agent loop with a recorder reporting a finished region.
        """
        from lu77U_MobileSec.analyzers.agent import fanout
        from lu77U_MobileSec.analyzers.agent.profiles import JAVA_KOTLIN
        from test_fanout import _graph

        def _recorder(*args_unused, telemetry=None, **kwargs_unused):
            """
            Purpose:
                Stand in for the agent loop and report every region as having submitted its report.

            Parameters:
                args_unused: The provider, source root and static signals the fan-out passes positionally, ignored.
                telemetry: The mapping the loop reports its outcome through.
                kwargs_unused: The code graph, profile, cancellation callback, verbosity flag, step budget and deadline the fan-out passes by keyword, ignored.

            Returns:
                An empty finding list, a success flag and an empty error string.

            Side effects:
                Reports the stop reason, step count and finding count through the telemetry mapping.
            """
            if telemetry is not None:
                telemetry.update({"stop_reason": "reported", "steps": 12,
                                  "findings": 1})
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", _recorder)
        coverage = {}
        fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin", coverage=coverage)

        assert coverage["complete"] is True
        assert coverage["degraded_reason"] is None
