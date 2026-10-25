#!/usr/bin/env python3
"""
Module: test_quota_resume

Purpose:
    Pausing on a provider outage and continuing afterwards, rather than replaying the region from the start or treating it as finished.

Responsibilities:
    Pin the flag that marks a region continuable, that continuing actually spends more turns and keeps the findings from before, that a genuinely finished region is still replayed for free, that the fan-out's own reuse check reads the same flag, the shared definition of an exhausted quota, and an unreachable provider treated as an outage rather than as a model that cannot drive the loop.

Dependencies:
    pytest, the agent loop and the analysis service.

Implementation notes:
    Every non-crash exit used to be recorded as finished, with no way to tell the model having completed its work apart from the provider having died mid-investigation. A checkpoint written at a quota trip was therefore indistinguishable from a completed region and was replayed forever, permanently capping that region's findings at whatever it had when the quota ran out. Nothing here touches the network, a real model, or a live quota.
"""

import pytest

from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis
from lu77U_MobileSec.ai.errors import is_unreachable
from lu77U_MobileSec.web.services.analysis_service import provider_outage, quota_exhausted

_VEC = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _finding(title, file, line):
    """
    Purpose:
        Build one finding as the model would return it, as a JSON fragment.

    Parameters:
        title: The finding title.
        file: The file the finding is attributed to.
        line: The line the finding is attributed to.

    Returns:
        The finding as a JSON object string.
    """
    return (f'{{"title":"{title}","file":"{file}","line":"{line}",'
            f'"description":"demo","cvss_vector":"{_VEC}"}}')


def _add_finding(title, file, line):
    """
    Purpose:
        Build a turn that records one finding without ending the investigation.

    Parameters:
        title: The finding title.
        file: The file the finding is attributed to.
        line: The line the finding is attributed to.

    Returns:
        The action as a JSON object string.
    """
    return f'{{"action":"add_finding","vulnerabilities":[{_finding(title, file, line)}]}}'


_REPORT = '{"action":"report","vulnerabilities":[' + _finding("H", "a.java", "1") + "]}"
_EMPTY_REPORT = '{"action":"report","vulnerabilities":[]}'
_LIST = '{"action":"list_files","path":""}'


class QuotaTrippingProvider:
    """
    Purpose:
        A provider that plays a scripted sequence of turns and then fails exactly as one whose account quota has run out.

    Attributes:
        actions: The turns still to be played before the failure.
        calls: How many turns were requested.

    Implementation notes:
        The failure shape is the real one: a fatal error naming the quota class, together with a reason on the unavailability attribute, which the loop reads the same way for every provider whether it is backed by a subscription CLI or not.
    """
    def __init__(self, actions_before_trip):
        """
        Purpose:
            Build the provider with the turns to play before failing.

        Parameters:
            actions_before_trip: The turns to play in order before the quota runs out.
        """
        self.actions = list(actions_before_trip)
        self.calls = 0
        self._fatal = None

    @property
    def unavailable(self):
        """
        Purpose:
            Report why the provider is unusable.

        Returns:
            The reason once the quota has run out, and None before that.
        """
        return self._fatal

    def analyze(self, _, **__):
        """
        Purpose:
            Play the next scripted turn, or report the quota as spent once the script is finished.

        Parameters:
            _: The turn prompt, ignored.
            __: The turn's keyword arguments (system_message, schema, images, max_tokens, session_key), ignored.

        Returns:
            The next scripted response, or the fatal quota error.

        Side effects:
            Increments the call count and, on the failing call, marks the provider unusable.
        """
        self.calls += 1
        if self.actions:
            return {"response": self.actions.pop(0)}
        self._fatal = "fatal_quota: usage limit reached. Your limit will reset at 8pm."
        return {"error": self._fatal, "fatal": True, "error_class": "fatal_quota"}


class ScriptedProvider:
    """
    Purpose:
        A healthy provider that plays back a fixed script, standing in for the quota window having reopened.

    Attributes:
        actions: The turns still to be played.
        calls: How many turns were requested.
        unavailable: Always absent, marking the provider as healthy.
    """
    def __init__(self, actions):
        """
        Purpose:
            Build the provider with its script.

        Parameters:
            actions: The turns to play in order.
        """
        self.actions = list(actions)
        self.calls = 0
        self.unavailable = None

    def analyze(self, _, **__):
        """
        Purpose:
            Play the next scripted turn, falling back to a harmless listing action once the script is spent.

        Parameters:
            _: The turn prompt, ignored.
            __: The turn's keyword arguments (system_message, schema, images, max_tokens, session_key), ignored.

        Returns:
            The next scripted response, or a listing action.

        Side effects:
            Increments the call count.
        """
        self.calls += 1
        action = self.actions.pop(0) if self.actions else _LIST
        return {"response": action}


@pytest.fixture
def src(tmp_path):
    """
    Purpose:
        Build a minimal source tree with one file in it.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "a.java").write_text("class A {}\n")
    return tmp_path


class TestSnapshotResumableFlag:
    """
    Purpose:
        The flag on a checkpoint that says whether the region can be continued.

    Implementation notes:
        Everything downstream branches on this one flag: the loop's own short-circuit on resume and the fan-out's separate reuse check both read it off the same saved state.
    """
    def test_a_provider_outage_is_marked_resumable(self, src):
        """
        Purpose:
            Pin that a region cut short by the provider keeps its findings, is still reported as successful, and is marked continuable with the reason it stopped.

        Parameters:
            src: The source tree.

        Implementation notes:
            A provider dying part way through with real progress already made is still a successful region as far as the caller's contract goes, because the findings it recorded are real and are kept. What must be distinguishable is the way it ended, which is what the stop reason and the flag carry.
        """
        provider = QuotaTrippingProvider([
            _add_finding("Hardcoded secret", "a.java", "3"),
            _add_finding("SQL injection", "a.java", "9"),
        ])
        checkpoints = []
        vulns, completed_ok, _ = run_agent_analysis(
            provider, str(src), verbose=False,
            on_checkpoint=lambda snap: checkpoints.append(dict(snap)))

        assert completed_ok is True
        assert len(vulns) == 2
        final = checkpoints[-1]
        assert final["done"] is True
        assert final["stop_reason"] == "provider_unavailable"
        assert final["resumable"] is True

    @pytest.mark.parametrize("actions,expected_stop_reason", [
        ([_REPORT], "reported"),
    ])
    def test_a_genuine_report_is_not_resumable(self, src, actions, expected_stop_reason):
        """
        Purpose:
            Pin that a region whose model submitted its report is not marked continuable.

        Parameters:
            src: The source tree.
            actions: The turns the provider plays.
            expected_stop_reason: The reason the region is expected to record.
        """
        provider = ScriptedProvider(actions)
        checkpoints = []
        run_agent_analysis(
            provider, str(src), verbose=False,
            on_checkpoint=lambda snap: checkpoints.append(dict(snap)))
        final = checkpoints[-1]
        assert final["stop_reason"] == expected_stop_reason
        assert final["resumable"] is False

    def test_a_step_budget_exit_is_not_resumable(self, src):
        """
        Purpose:
            Pin that a region that ran out of steps is not marked continuable.

        Parameters:
            src: The source tree.

        Implementation notes:
            Such a region ran out of what it was allowed to do rather than being stopped by anything outside it, so replaying it on resume is the correct behaviour, unlike a quota trip that cut the same region off part way through.
        """
        provider = ScriptedProvider([_LIST] * 10)
        checkpoints = []
        run_agent_analysis(
            provider, str(src), max_steps=3, verbose=False,
            on_checkpoint=lambda snap: checkpoints.append(dict(snap)))
        final = checkpoints[-1]
        assert final["stop_reason"] == "budget_steps"
        assert final["resumable"] is False


class TestResumeContinuesRatherThanReplays:
    """
    Purpose:
        The behaviour a user actually experiences: hit the limit, keep the findings so far, and have a resume pick the same region back up.
    """
    def test_resuming_a_quota_trip_spends_more_turns_not_zero(self, src):
        """
        Purpose:
            Pin that resuming a region cut short by a quota spends further turns, keeps the earlier findings, records new ones, and does not rewalk the turns already spent.

        Parameters:
            src: The source tree.

        Implementation notes:
            This is the specific regression the whole mechanism exists to prevent. Before the fix the loop's own resume check short-circuited here and handed the first run's findings straight back having made no calls at all, forever. The call count is asserted from both sides: above zero so it really continued, and within the script so it did not start over.
        """
        first_provider = QuotaTrippingProvider([
            _add_finding("Hardcoded secret", "a.java", "3"),
            _add_finding("SQL injection", "a.java", "9"),
        ])
        snapshots = []
        vulns1, completed_ok1, transcript1 = run_agent_analysis(
            first_provider, str(src), verbose=False,
            on_checkpoint=lambda snap: snapshots.append(dict(snap)))
        assert completed_ok1 is True
        assert len(vulns1) == 2
        resume_state = snapshots[-1]
        assert resume_state["resumable"] is True
        assert "steps_taken" in resume_state

        second_provider = ScriptedProvider([
            _add_finding("Path traversal", "a.java", "20"),
            _EMPTY_REPORT,
        ])
        vulns2, completed_ok2, transcript2 = run_agent_analysis(
            second_provider, str(src), verbose=False, resume_state=resume_state)

        assert completed_ok2 is True
        assert second_provider.calls > 0
        titles = {v.get("title") for v in vulns2}
        assert "Hardcoded secret" in titles
        assert "SQL injection" in titles
        assert "Path traversal" in titles
        assert len(vulns2) == 3
        assert second_provider.calls <= 2

    def test_a_genuinely_finished_region_is_still_reused_with_zero_calls(self, src):
        """
        Purpose:
            Pin that a region that genuinely reported is replayed on resume with no model calls at all.

        Parameters:
            src: The source tree.

        Implementation notes:
            The control case for the test above: only a region stopped by the provider gets further turns, and everything else is still reused for free.
        """
        provider = ScriptedProvider([_REPORT])
        snapshots = []
        run_agent_analysis(
            provider, str(src), verbose=False,
            on_checkpoint=lambda snap: snapshots.append(dict(snap)))
        resume_state = snapshots[-1]
        assert resume_state["resumable"] is False

        second_provider = ScriptedProvider([_REPORT])
        vulns2, completed_ok2, _ = run_agent_analysis(
            second_provider, str(src), verbose=False, resume_state=resume_state)
        assert completed_ok2 is True
        assert second_provider.calls == 0
        assert len(vulns2) == 1


class TestFanoutReuseGate:
    """
    Purpose:
        That the fan-out's own reuse check reads the same flag as the loop's.

    Implementation notes:
        The two checks mirror each other, so fixing one without the other would silently reintroduce the bug for whichever path a given scan happens to take.
    """
    def test_resumable_region_is_not_short_circuited_by_the_fanout_module(self):
        """
        Purpose:
            Pin that the fan-out's reuse of a checkpointed region is conditioned on that region not being continuable.

        Implementation notes:
            Asserted against the module's source rather than by running a fan-out, because reproducing the condition end to end would need a whole scan's worth of setup to check a single condition. The trade-off is that a rewording of that line fails this test without anything being broken, which is the cheaper of the two failure modes.
        """
        import inspect
        from lu77U_MobileSec.analyzers.agent import fanout

        source = inspect.getsource(fanout)
        assert 'saved.get("done") and saved.get("completed_ok") and not saved.get("resumable")' in source


class TestQuotaExhaustedDetection:
    """
    Purpose:
        The single shared definition of an exhausted quota.

    Implementation notes:
        The job runner and the analysis service both read the same helper, so the decision to pause and the cleanup guard that keeps the application file on disk for that pause can never disagree about what triggered them.
    """
    def test_no_analyzer_details_is_not_exhausted(self):
        """
        Purpose:
            Pin that a result carrying no provider details is not read as an exhausted quota.
        """
        assert quota_exhausted({}) is False
        assert quota_exhausted({"analyzer_details": {}}) is False

    def test_fatal_quota_is_exhausted(self):
        """
        Purpose:
            Pin that a result reporting a spent quota is read as exhausted.
        """
        result = {"analyzer_details": {"llm_usage": {
            "unavailable": "fatal_quota: usage limit reached"}}}
        assert quota_exhausted(result) is True

    def test_fatal_auth_is_not_treated_as_a_quota_pause(self):
        """
        Purpose:
            Pin that a rejected credential is not read as an exhausted quota.

        Implementation notes:
            Waiting cannot fix a rejected or missing login, so pausing and retrying automatically would fail again on the same broken credential and leave the user watching a scan that never progresses.
        """
        result = {"analyzer_details": {"llm_usage": {
            "unavailable": "fatal_auth: not signed in"}}}
        assert quota_exhausted(result) is False

    def test_a_normal_completion_is_not_exhausted(self):
        """
        Purpose:
            Pin that a healthy provider at the end of a scan is not read as exhausted.
        """
        result = {"analyzer_details": {"llm_usage": {"unavailable": None}}}
        assert quota_exhausted(result) is False


class UnreachableProvider:
    """
    Purpose:
        A provider whose host cannot be resolved, failing every turn while still reporting itself available.

    Attributes:
        calls: How many turns were requested.
        unavailable: Always absent: an unreachable host is a transient failure, not a tripped circuit.
    """
    def __init__(self):
        """
        Purpose:
            Build the provider.
        """
        self.calls = 0
        self.unavailable = None

    def analyze(self, _, **__):
        """
        Purpose:
            Fail as a call whose every attempt could not resolve the host.

        Parameters:
            _: The turn prompt, ignored.
            __: The turn's keyword arguments, ignored.

        Returns:
            The provider's error result.
        """
        self.calls += 1
        return {"error": "Ollama failed after 3 attempts: [Errno 8] nodename nor servname provided, or not known"}


class TestUnreachableProvider:
    """
    Purpose:
        A provider host that cannot be reached, as when the machine is offline.

    Implementation notes:
        A real resumed scan ran with the network down: its region had spent sixteen steps before the pause, every new turn failed to resolve the host, and the loop reported that the model could not drive it at all. The analyzer then discarded everything and the scan was recorded as completed with no findings.
    """
    def test_a_resumed_region_keeps_its_place_when_the_host_is_down(self, src):
        """
        Purpose:
            Pin that a region resumed with steps already spent ends as having driven the loop, keeping its restored findings, when the provider cannot be reached.

        Parameters:
            src: The source tree.
        """
        resume_state = {"steps_taken": 16, "accumulated": [], "transcript": ["[Step 16] read a.java"],
                        "done": True, "resumable": True, "stop_reason": "provider_error"}
        vulns, completed_ok, _ = run_agent_analysis(
            UnreachableProvider(), str(src), verbose=False, resume_state=resume_state)
        assert completed_ok is True and vulns == []

    @pytest.mark.parametrize("message, expected", [
        ("[Errno 8] nodename nor servname provided, or not known", True),
        ("[Errno -2] Name or service not known", True),
        ("[Errno 61] Connection refused", True),
        ("You reached the Free usage limit (status code: 429)", False),
        ("Internal Server Error (status code: 500)", False),
    ])
    def test_unreachable_failures_are_recognised(self, message, expected):
        """
        Purpose:
            Pin which failure messages mean the host could not be reached.

        Parameters:
            message: A provider failure message.
            expected: Whether it means the host is unreachable.
        """
        assert is_unreachable(message) is expected

    def test_an_unreachable_provider_is_an_outage_and_quota_takes_precedence(self):
        """
        Purpose:
            Pin that a scan whose provider was unreachable when it stopped is an outage, and that an exhausted quota is reported as such first.
        """
        unreachable = {"analyzer_details": {"llm_usage": {"unreachable": "nodename nor servname"}}}
        both = {"analyzer_details": {"llm_usage": {"unreachable": "x",
                                                   "unavailable": "fatal_quota: limit"}}}
        assert provider_outage(unreachable) == "provider_unreachable"
        assert provider_outage(both) == "provider_quota"
        assert provider_outage({"analyzer_details": {"llm_usage": {}}}) == ""

    def test_the_provider_marker_clears_on_the_next_success(self):
        """
        Purpose:
            Pin that a provider remembers an unreachable host until a call succeeds, and reports it in its usage summary.
        """
        from lu77U_MobileSec.ai.ollama_provider import OllamaProvider

        provider = OllamaProvider(config={"mode": "local"})
        provider.note_reachability(OSError("[Errno 8] nodename nor servname provided, or not known"))
        assert provider.usage_summary()["unreachable"]
        provider.record_usage(1.0, ok=False)
        assert provider.usage_summary()["unreachable"]
        provider.record_usage(1.0, ok=True)
        assert provider.usage_summary()["unreachable"] is None
