#!/usr/bin/env python3
"""
Module: test_agent_loop

Purpose:
    The phase-one agent loop: how many turns it takes, how it is stopped, how findings recorded along the way survive, and what it says while it runs.

Responsibilities:
    Pin the unbounded default and the opt-in step limit, cancellation, the handling of findings recorded mid-investigation, the conversation session a capable provider keeps, the one-shot prompt that asks the model to record as it goes, the turn numbers the log reports, and the narration of every request and response.

Dependencies:
    pytest, the agent loop, the agent tool surface, the verbose helpers and the cancellation exception.

Implementation notes:
    The loop has no fixed call ceiling by default; it runs until the model reports, the provider fails, or the scan is cancelled. Every provider here is a scripted fake, so nothing reaches the network or a real model.
"""

import hmac

import pytest

from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis
from lu77U_MobileSec.utils.cancellation import ScanCancelled

_VEC = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_LIST = '{"action":"list_files","path":""}'


def _constant_time_contains(haystack, needle):
    """
    Purpose:
        Check whether needle is a substring of haystack by comparing every candidate window with hmac.compare_digest instead of a short-circuiting `in`, since the prompts and transcripts under test are built from provider-turn text CodeQL treats as carrying a sensitive token, and flags a plain membership check on it as a non-constant-time comparison.

    Parameters:
        haystack: The text to search within.
        needle: The literal substring to look for.

    Returns:
        True when needle appears in haystack, False otherwise.
    """
    width = len(needle)
    return any(hmac.compare_digest(haystack[i:i + width], needle)
               for i in range(len(haystack) - width + 1))


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

    Implementation notes:
        The file, line and description are all present because the response parser drops any finding missing them, so a fixture without them would test the parser rather than the loop.
    """
    return (f'{{"title":"{title}","file":"{file}","line":"{line}",'
            f'"description":"demo","cvss_vector":"{_VEC}"}}')


_REPORT = '{"action":"report","vulnerabilities":[' + _finding("H", "a.java", "1") + "]}"


def _action(name, findings):
    """
    Purpose:
        Build a turn carrying a list of findings.

    Parameters:
        name: The action, either recording findings or submitting the report.
        findings: The findings as JSON fragments.

    Returns:
        The action as a JSON object string.
    """
    return f'{{"action":"{name}","vulnerabilities":[{",".join(findings)}]}}'


class ScriptedProvider:
    """
    Purpose:
        A provider that plays queued turns and, once they run out, keeps asking to list files so it never reports on its own.

    Attributes:
        actions: The turns still to be played.
        calls: How many turns were requested.
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

    def analyze(self, prompt, system_message=None, schema=None, max_tokens=None, session_key=None):
        """
        Purpose:
            Play the next scripted turn, falling back to a listing action once the script is spent.

        Parameters:
            prompt: The turn prompt.
            system_message: The system prompt, unused here.
            schema: The requested response schema, unused here.
            max_tokens: The response limit, unused here.
            session_key: The conversation key, which marks the region this turn belongs to.

        Returns:
            The turn's response.

        Side effects:
            Increments the call count.
        """
        self.calls += 1
        action = self.actions.pop(0) if self.actions else _LIST
        return {"response": action}


class SessionAwareScriptedProvider(ScriptedProvider):
    """
    Purpose:
        A scripted provider that also keeps a conversation session the way a subscription-CLI provider does, and records every prompt it was sent.

    Attributes:
        prompts: Every prompt received, in order.

    Implementation notes:
        It implements the session interface itself rather than merely accepting the session argument, so the loop's behaviour is exercised against something that really holds a conversation. The recorded prompts are what let a test show that the first turn carries the full context and later turns do not.
    """
    def __init__(self, actions):
        """
        Purpose:
            Build the provider with its script, no recorded prompts and no open sessions.

        Parameters:
            actions: The turns to play in order.
        """
        super().__init__(actions)
        self.prompts = []
        self._sessions = set()

    def has_session(self, session_key):
        """
        Purpose:
            Report whether a conversation is open for a region.

        Parameters:
            session_key: The region's conversation key.

        Returns:
            True while that conversation is open.
        """
        return session_key in self._sessions

    def close_session(self, session_key):
        """
        Purpose:
            Close a region's conversation.

        Parameters:
            session_key: The region's conversation key.

        Side effects:
            Forgets that conversation.
        """
        self._sessions.discard(session_key)

    def analyze(self, prompt, system_message=None, schema=None, max_tokens=None, session_key=None):
        """
        Purpose:
            Record the prompt, open the region's conversation if it is not already open, and play the next scripted turn.

        Parameters:
            prompt: The turn prompt.
            system_message: The system prompt, unused here.
            schema: The requested response schema, unused here.
            max_tokens: The response limit, unused here.
            session_key: The conversation key, which marks the region this turn belongs to.

        Returns:
            The turn's response.

        Side effects:
            Records the prompt and may open a conversation.
        """
        self.prompts.append(prompt)
        if session_key:
            self._sessions.add(session_key)
        return super().analyze(prompt, system_message, schema, max_tokens, session_key)


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


def test_loop_runs_past_the_old_30_call_cap(src):
    """
    Purpose:
        Pin that the loop runs well past the ceiling it once had and returns on the model's own report.

    Parameters:
        src: The source tree.

    Implementation notes:
        The exact call count distinguishes the two outcomes: the model's own report on its turn, rather than a forced report the loop asked for after cutting it off.
    """
    prov = ScriptedProvider([_LIST] * 35 + [_REPORT])
    vulns, completed_ok, _ = run_agent_analysis(prov, str(src), verbose=False)
    assert completed_ok is True
    assert prov.calls == 36
    assert isinstance(vulns, list)


def test_explicit_max_steps_still_caps_and_forces_a_report(src):
    """
    Purpose:
        Pin that an explicit step limit still stops the loop and spends one further call asking for a report.

    Parameters:
        src: The source tree.

    Implementation notes:
        The forced call is what keeps a cut-off region from returning nothing at all when the model had found things it had not yet written up.
    """
    prov = ScriptedProvider([_LIST] * 100)
    vulns, completed_ok, _ = run_agent_analysis(
        prov, str(src), max_steps=5, verbose=False)
    assert completed_ok is True
    assert prov.calls == 6
    assert isinstance(vulns, list)


def test_cancellation_interrupts_the_unbounded_loop(src):
    """
    Purpose:
        Pin that a model which never reports is still stoppable, and stops promptly.

    Parameters:
        src: The source tree.

    Implementation notes:
        With no step limit this is the only thing that ends such a run, so the call count is asserted as well as the exception: a loop that raised only after a hundred more turns would be no use to someone who pressed stop.
    """
    prov = ScriptedProvider([_LIST] * 100000)
    checks = {"n": 0}

    def is_cancelled():
        """
        Purpose:
            Report the scan as cancelled after a few polls.

        Returns:
            False for the first few calls and True afterwards.

        Side effects:
            Counts the polls.
        """
        checks["n"] += 1
        return checks["n"] > 3

    with pytest.raises(ScanCancelled):
        run_agent_analysis(prov, str(src), is_cancelled=is_cancelled, verbose=False)
    assert prov.calls <= 4


def test_add_finding_survives_hitting_the_budget_with_no_report(src):
    """
    Purpose:
        Pin that a finding recorded mid-investigation survives the budget running out, and that no extra call is spent trying to reconstruct it.

    Parameters:
        src: The source tree.

    Implementation notes:
        This is the failure seen on a real application: the model records a real finding part way through and then never submits a clean report before the budget ends. A region that already has recorded findings skips the forced report entirely, because that path used to ask the model to reconstruct them blind from a transcript that never held the finding bodies.
    """
    add = _action("add_finding", [_finding("BridgeLeak", "a.java", "1")])
    prov = ScriptedProvider([add] + [_LIST] * 20)
    vulns, completed_ok, _ = run_agent_analysis(
        prov, str(src), max_steps=4, verbose=False)
    assert completed_ok is True
    titles = [(v.get("title") or v.get("vulnerability_type")) for v in vulns]
    assert "BridgeLeak" in titles
    assert prov.calls == 4


def test_add_finding_then_report_merges_and_dedups(src):
    """
    Purpose:
        Pin that a finding recorded during the run and repeated in the final report is kept once, while new ones in the report are added.

    Parameters:
        src: The source tree.
    """
    add = _action("add_finding", [_finding("A", "a.java", "1")])
    report = _action("report", [_finding("A", "a.java", "1"), _finding("B", "b.java", "2")])
    prov = ScriptedProvider([add, report])
    vulns, completed_ok, _ = run_agent_analysis(prov, str(src), verbose=False)
    assert completed_ok is True
    titles = sorted((v.get("title") or v.get("vulnerability_type")) for v in vulns)
    assert titles == ["A", "B"]


def test_inspected_native_library_counts_as_read_for_its_findings(src):
    """
    Purpose:
        Pin that a finding citing a native library the agent inspected is stamped as citing a file it read, while one citing an unopened file is not.

    Parameters:
        src: The source tree.

    Implementation notes:
        inspect_native is the only way the agent can open a library. Before this, every native finding was stamped unread and the evidence gate capped it as unconfirmed, even when the agent had read the library's decompiled code and cited the exact line.
    """
    lib = src / "lib" / "libx.so"
    lib.parent.mkdir()
    lib.write_bytes(b"\x7fELF fake")
    inspect = '{"action":"inspect_native","path":"lib/libx.so"}'
    report = _action("report", [_finding("Native overflow", "lib/libx.so", "12"),
                                _finding("Elsewhere", "b.java", "3")])
    prov = ScriptedProvider([inspect, report])
    vulns, completed_ok, _ = run_agent_analysis(prov, str(src), verbose=False)
    assert completed_ok is True
    stamped = {(v.get("title") or v.get("vulnerability_type")): v.get("cited_file_read") for v in vulns}
    assert stamped == {"Native overflow": True, "Elsewhere": False}

def test_add_finding_does_not_end_the_loop(src):
    """
    Purpose:
        Pin that recording a finding keeps the investigation going and only the report ends it.

    Parameters:
        src: The source tree.
    """
    add = _action("add_finding", [_finding("A", "a.java", "1")])
    prov = ScriptedProvider([add, add, _REPORT])
    vulns, completed_ok, _ = run_agent_analysis(prov, str(src), verbose=False)
    assert completed_ok is True
    assert prov.calls == 3
    titles = {(v.get("title") or v.get("vulnerability_type")) for v in vulns}
    assert titles == {"A", "H"}


class TestSessionAwareProviders:
    """
    Purpose:
        What the loop sends to a provider that can hold the region's conversation itself.

    Implementation notes:
        Such a provider already has the opening context and every earlier turn once its conversation is open, so re-sending them on every later turn would undo the entire point of keeping one.
    """
    def test_only_the_first_turn_carries_the_full_context(self, src):
        """
        Purpose:
            Pin that the opening turn carries the full context and the turns after it do not.

        Parameters:
            src: The source tree.

        Implementation notes:
            The first turn has no conversation to resume yet, so it must carry the real context, which for this fixture is the file tree since no code graph is built.
        """
        prov = SessionAwareScriptedProvider([_LIST, _LIST, _REPORT])
        run_agent_analysis(prov, str(src), verbose=False)
        assert len(prov.prompts) == 3
        assert _constant_time_contains(prov.prompts[0], "Decompiled file tree")
        assert not _constant_time_contains(prov.prompts[1], "Decompiled file tree")
        assert not _constant_time_contains(prov.prompts[2], "Decompiled file tree")

    def test_a_provider_with_no_session_support_gets_full_context_every_turn(self, src):
        """
        Purpose:
            Pin that a provider without a conversation is driven exactly as before.

        Parameters:
            src: The source tree.

        Implementation notes:
            Every provider but the subscription-CLI ones takes this path, so it is the behaviour that must not change.
        """
        prov = ScriptedProvider([_LIST, _LIST, _REPORT])
        run_agent_analysis(prov, str(src), verbose=False)
        assert prov.calls == 3

    def test_the_session_is_closed_when_the_region_finishes(self, src):
        """
        Purpose:
            Pin that the region's conversation is closed once it is done.

        Parameters:
            src: The source tree.

        Implementation notes:
            A conversation left open holds the whole region's context on the provider's side, and a scan runs several regions.
        """
        prov = SessionAwareScriptedProvider([_LIST, _REPORT])
        run_agent_analysis(prov, str(src), verbose=False)
        assert prov.has_session("single") is False

    def test_a_resumed_turn_is_just_the_latest_observation_plus_the_tail(self, src):
        """
        Purpose:
            Pin that a resumed turn carries only the newest observation and the closing instruction, without the framing that introduces a full transcript.

        Parameters:
            src: The source tree.

        Implementation notes:
            That framing only makes sense when the whole transcript is being re-sent, which is exactly what a resumed turn avoids.
        """
        prov = SessionAwareScriptedProvider([_LIST, _LIST, _REPORT])
        run_agent_analysis(prov, str(src), verbose=False)
        assert not _constant_time_contains(prov.prompts[1], "## Investigation so far")
        assert _constant_time_contains(prov.prompts[1], "Respond with the next action JSON")


class TestAddFindingNudge:
    """
    Purpose:
        The one-shot prompt that asks a model to record findings as it goes rather than saving them all for the end.

    Implementation notes:
        A real scan recorded nothing in 57 turns and produced all six of its findings through the forced report at the end, which is fragile: a long scan's rolling transcript drops its oldest turns, so a finding confirmed early and never recorded can disappear entirely.
    """
    def test_a_one_shot_nudge_fires_after_several_reads_with_nothing_recorded(self, src):
        """
        Purpose:
            Pin that the prompt appears once after several turns with nothing recorded, and not once per turn thereafter.

        Parameters:
            src: The source tree.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _ADD_FINDING_NUDGE_AFTER

        prov = ScriptedProvider([_LIST] * (_ADD_FINDING_NUDGE_AFTER + 2) + [_REPORT])
        _, completed_ok, transcript = run_agent_analysis(prov, str(src), verbose=False)
        assert completed_ok is True
        assert (_constant_time_contains(transcript, "add_finding")
                and _constant_time_contains(transcript, "SYSTEM NUDGE"))
        assert transcript.count("You have investigated several files") == 1

    def test_no_nudge_once_a_finding_has_been_recorded(self, src):
        """
        Purpose:
            Pin that a model already recording findings is not prompted.

        Parameters:
            src: The source tree.
        """
        add_action = _action("add_finding", [_finding("H", "a.java", "1")])
        prov = ScriptedProvider([add_action] + [_LIST] * 10 + [_REPORT])
        _, _, transcript = run_agent_analysis(prov, str(src), verbose=False)
        assert not _constant_time_contains(transcript, "You have investigated several files")

    def test_no_nudge_for_a_short_investigation(self, src):
        """
        Purpose:
            Pin that a short investigation is not prompted.

        Parameters:
            src: The source tree.

        Implementation notes:
            A model a few turns in has usually not seen enough to record anything, so prompting there would just spend context telling it to do something premature.
        """
        prov = ScriptedProvider([_LIST] * 2 + [_REPORT])
        _, _, transcript = run_agent_analysis(prov, str(src), verbose=False)
        assert not _constant_time_contains(transcript, "You have investigated several files")


class TestStepLoggingIsOneBased:
    """
    Purpose:
        That the turn numbers in the log are the ones a reader would count.

    Implementation notes:
        A real scan's log reported each event one turn short of what had actually happened, because the internal counter starts at zero and, for a resumed region, does not include the turns a previous run already spent.
    """
    def test_the_add_finding_nudge_reports_the_turn_it_fired_on(self, src, capsys):
        """
        Purpose:
            Pin that the prompt is logged against the turn it actually fired on.

        Parameters:
            src: The source tree.
            capsys: Captures the printed output.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _ADD_FINDING_NUDGE_AFTER

        prov = ScriptedProvider([_LIST] * _ADD_FINDING_NUDGE_AFTER + [_REPORT])
        run_agent_analysis(prov, str(src), verbose=True)
        out = capsys.readouterr().out
        assert f"Add-finding nudge at step {_ADD_FINDING_NUDGE_AFTER}:" in out

    def test_agent_finished_reports_the_number_of_turns_actually_taken(self, src, capsys):
        """
        Purpose:
            Pin that the closing line reports as many turns as the provider was actually asked for.

        Parameters:
            src: The source tree.
            capsys: Captures the printed output.
        """
        prov = ScriptedProvider([_LIST, _LIST, _REPORT])
        run_agent_analysis(prov, str(src), verbose=True)
        out = capsys.readouterr().out
        assert f"Agent finished at step {prov.calls} with" in out


class TestActionNarration:
    """
    Purpose:
        What each turn says in the live log.

    Implementation notes:
        The log is the only window into a run that can spend twenty minutes waiting on a model, so every turn states what was asked for and what was handed back.
    """
    def test_each_action_reads_as_a_sentence(self):
        """
        Purpose:
            Pin the exact wording for each kind of request.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_request

        assert _describe_request("read_file", "sources/a/B.java", [], "", None) == (
            "The LLM is requesting to read `sources/a/B.java`.")
        assert _describe_request("list_files", "sources", [], "", None) == (
            "The LLM is requesting to list all the files in `sources` directory.")
        assert _describe_request("search_code", "", [], "loadUrl", None) == (
            "The LLM is requesting to search the code for `loadUrl`.")
        assert _describe_request("inspect_native", "lib/x.so", [], "", None) == (
            "The LLM is requesting to inspect the native library `lib/x.so`.")

    def test_a_batched_read_names_the_first_files_and_counts_the_rest(self):
        """
        Purpose:
            Pin that a request for several files names the first few and counts the remainder.

        Implementation notes:
            A batch can name dozens of files, and listing them all would push everything else in the log off the screen.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_request

        line = _describe_request("read_file", "", ["a", "b", "c", "d", "e"], "", None)
        assert "`a`, `b`, `c`" in line and "2 other files" in line

    def test_a_paged_read_says_where_it_resumes(self):
        """
        Purpose:
            Pin that a continued read says which line it resumes from.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_request

        assert "from line 200" in _describe_request("read_file", "A.java", [], "", 200)

    def test_the_response_says_what_was_handed_over(self):
        """
        Purpose:
            Pin that a response line states how much was handed to the model.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_response

        assert _describe_response("read_file", "A.java", [], "l1\nl2\nl3") == (
            "Giving read access to `A.java` (3 lines sent to the LLM).")
        assert "1 entry)" in _describe_response("list_files", "sources", [], "one")

    def test_an_error_is_stated_not_swallowed(self):
        """
        Purpose:
            Pin that a failed request is reported with the reason it failed.

        Implementation notes:
            A failed read that logged nothing looks exactly like a file the model chose not to use, which hides a whole class of wasted turn.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_response

        line = _describe_response("read_file", "nope", [], "ERROR: not a file: nope")
        assert line.startswith("Could not satisfy that request")
        assert "not a file: nope" in line

    def test_an_error_names_its_reason_without_quoting_the_tool(self):
        """
        Purpose:
            Pin that a failed request is logged with its reason and the requested path, and nothing else the tool wrote.

        Security considerations:
            Tool text can hold exception messages with the analyst's absolute paths, the model's own search terms, or a native summary listing credential candidates, and this line reaches the terminal and the shareable dashboard feed. The key-shaped value here is invented.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _describe_response

        line = _describe_response(
            "read_file", "A.java", [],
            "ERROR: could not read A.java: [Errno 13] Permission denied: "
            "'/Users/analyst/cases/acme/A.java'")
        assert line == "Could not satisfy that request: could not read: A.java"
        unknown = _describe_response("search_code", "", [], "ERROR: AKIAINVENTED0000 broke")
        assert unknown == "Could not satisfy that request: the tool reported an error"

    def test_every_tool_error_has_a_named_reason(self, tmp_path):
        """
        Purpose:
            Pin that each error the agent tools can return is named by its reason rather than falling to the generic wording.

        Parameters:
            tmp_path: The source root for a real tool surface, used to provoke the sandbox refusal.

        Implementation notes:
            The reasons are a fixed list so no tool text is copied into the log, which means a new error message added to the tools reads as a generic failure until it is listed. The literal messages are read from the tools' source, and the refusal built from an exception is provoked for real, so a new message fails here instead of quietly losing its reason.
        """
        import pathlib
        import re as _re

        from lu77U_MobileSec.analyzers.agent import tools as tools_module
        from lu77U_MobileSec.analyzers.agent.agent_loop import (
            _TOOL_ERROR_REASONS, _describe_response)
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools

        source = pathlib.Path(tools_module.__file__).read_text()
        phrases = {m.strip() for m in _re.findall(r"ERROR: ([a-z][^{\"'.:(]*)", source)}
        assert phrases
        for phrase in phrases:
            assert any(phrase.startswith(r) for r in _TOOL_ERROR_REASONS), phrase

        refusal = AgentTools(tmp_path).read_file("../../etc/passwd")
        line = _describe_response("read_file", "../../etc/passwd", [], refusal)
        assert "path escapes sandbox" in line

    def test_the_loop_narrates_every_turn(self, tmp_path):
        """
        Purpose:
            Pin end to end that the loop narrates each request and each response through the real logging path.

        Parameters:
            tmp_path: Directory the source tree is written into.

        Side effects:
            Registers a log sink for the duration of the test and removes it afterwards.
        """
        import json
        from lu77U_MobileSec.analyzers.agent.agent_loop import run_agent_analysis
        from lu77U_MobileSec.utils import verbose as vmod

        (tmp_path / "sources").mkdir()
        (tmp_path / "sources" / "A.java").write_text("class A {}\n")

        lines = []
        vmod.register_sink(lines.append)
        try:
            steps = [{"action": "list_files", "path": "sources"},
                     {"action": "read_file", "path": "sources/A.java"},
                     {"action": "report", "vulnerabilities": []},
                     {"action": "report", "vulnerabilities": []}]

            class P:
                """
                Purpose:
                    A provider that plays a fixed sequence of turns, repeating the last one once the sequence is spent.

                Attributes:
                    i: How many turns have been played.
                """
                def __init__(self):
                    """
                    Purpose:
                        Build the provider at the start of the sequence.
                    """
                    self.i = 0

                def analyze(self, *args_unused, **kwargs_unused):
                    """
                    Purpose:
                        Play the next turn in the sequence, or repeat the last one once it is spent.

                    Parameters:
                        args_unused: Positional arguments, ignored.
                        kwargs_unused: Keyword arguments, ignored.

                    Returns:
                        The turn's response.

                    Side effects:
                        Advances through the sequence.
                    """
                    s = steps[min(self.i, len(steps) - 1)]; self.i += 1
                    return {"response": json.dumps(s)}

            run_agent_analysis(P(), tmp_path, {"framework": "Java/Kotlin"})
        finally:
            vmod.unregister_sink(lines.append)

        assert any("requesting to list all the files" in l for l in lines)
        assert any("requesting to read `sources/A.java`" in l for l in lines)
        assert any("Giving read access" in l for l in lines)

    def test_walking_the_tree_emits_no_per_file_noise(self, tmp_path):
        """
        Purpose:
            Pin that walking the tree logs nothing per file.

        Parameters:
            tmp_path: Directory the source tree is written into.

        Side effects:
            Registers a log sink for the duration of the test and removes it afterwards.

        Implementation notes:
            The framework check used to log twice for every candidate file on every walk, which is hundreds of lines that drowned the scan log, and it appeared even with verbose output off because sinks receive regardless.
        """
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools
        from lu77U_MobileSec.utils import verbose as vmod

        src = tmp_path / "sources" / "com" / "app"
        src.mkdir(parents=True)
        for i in range(50):
            (src / f"C{i}.java").write_text("class C {}\n")

        lines = []
        vmod.register_sink(lines.append)
        try:
            tools = AgentTools(tmp_path)
            found = tools.search_code("class")
            tools.file_tree()
            _ = tools.app_source_files()
        finally:
            vmod.unregister_sink(lines.append)

        assert not [l for l in lines if "is_framework_layout_file" in l
                    or "is app-specific" in l], lines[:5]
        assert found.count("\n") + 1 == 50

    def test_a_java_path_skips_the_resource_only_checks(self):
        """
        Purpose:
            Pin that a source path is not put through the checks that can only match resources, while a resource path still is.

        Implementation notes:
            Those checks can only ever match under the resource directory, so running them over every decompiled source file was pure waste on a tree of thousands.
        """
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools

        tools = AgentTools("/nonexistent")
        assert not tools._is_framework("sources/com/app/abc_MainActivity.java")
        assert tools._is_framework("resources/res/layout/abc_action_bar.xml")


class TestPluralisation:
    """
    Purpose:
        That counts in log lines read as English.
    """
    def test_counts_read_as_english(self):
        """
        Purpose:
            Pin the singular and plural forms, including a word whose plural is irregular.
        """
        from lu77U_MobileSec.utils.verbose import plural

        assert plural(1, "finding") == "1 finding"
        assert plural(0, "finding") == "0 findings"
        assert plural(3, "finding") == "3 findings"
        assert plural(1, "class", "classes") == "1 class"
        assert plural(19, "class", "classes") == "19 classes"

    def test_no_shipped_log_line_still_says_s_in_brackets(self):
        """
        Purpose:
            Pin that no shipped log line, progress message or title writes a plural as a bracketed suffix.

        Implementation notes:
            A bracketed plural in the middle of a sentence reads like a form field rather than a report, and the helper above exists precisely so none is needed.
        """
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[1] / "lu77U_MobileSec"
        offenders = []
        for path in root.rglob("*.py"):
            for n, line in enumerate(path.read_text(encoding="utf-8",
                                                    errors="ignore").splitlines(), 1):
                if re.search(r"\(e?s\)", line) and re.search(
                        r"verbose_print|progress\(|title=f|f\"", line):
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, offenders


class PromptRecordingProvider(ScriptedProvider):
    """
    Purpose:
        A scripted provider without a session that records every prompt, so a test can see the context the loop rebuilt for each turn.

    Attributes:
        prompts: Every prompt received, in order.
    """
    def __init__(self, actions):
        """
        Purpose:
            Build the provider with its script and no recorded prompts.

        Parameters:
            actions: The turns to play in order.
        """
        super().__init__(actions)
        self.prompts = []

    def analyze(self, prompt, system_message=None, schema=None, max_tokens=None, session_key=None):
        """
        Purpose:
            Record the prompt, then play the next scripted turn.

        Parameters:
            prompt: The turn prompt.
            system_message: The system prompt, passed through.
            schema: The requested response schema, passed through.
            max_tokens: The response limit, passed through.
            session_key: The conversation key, passed through.

        Returns:
            The turn's response.
        """
        self.prompts.append(prompt)
        return super().analyze(prompt, system_message=system_message, schema=schema,
                               max_tokens=max_tokens, session_key=session_key)


class TestCoverageAfterCompaction:
    """
    Purpose:
        The record of what has been examined, restated once compaction has dropped the turns that showed it.

    Implementation notes:
        A real React Native scan on a mid-size model dropped 221 turns and then re-read the same handful of files for over a hundred steps without reporting, because nothing left in its prompt said which files it had already opened or that none were left.
    """
    def test_note_appears_only_after_turns_are_dropped(self, src, monkeypatch):
        """
        Purpose:
            Pin that the coverage note is absent while the history is whole, then names the files read and the flagged files left once turns are dropped.

        Parameters:
            src: The source tree.
            monkeypatch: Shrinks the transcript budget so compaction happens within a few turns.
        """
        from lu77U_MobileSec.analyzers.agent import agent_loop

        (src / "b.java").write_text("class B {}\n")
        monkeypatch.setattr(agent_loop, "_MAX_TRANSCRIPT_CHARS", 600)
        monkeypatch.setattr(agent_loop, "_MIN_TRANSCRIPT_CHARS", 300)
        read_a = '{"action":"read_file","path":"a.java"}'
        prov = PromptRecordingProvider([read_a] + [_LIST] * 12 + [_REPORT])
        run_agent_analysis(prov, str(src), verbose=False)
        assert not _constant_time_contains(prov.prompts[1], "## Coverage")
        last = prov.prompts[-1]
        assert _constant_time_contains(last, "earlier turns dropped")
        assert _constant_time_contains(last, "Already examined (1): a.java")
        assert _constant_time_contains(last, "Flagged and not yet examined (1): b.java")

    def test_note_says_when_everything_is_examined(self):
        """
        Purpose:
            Pin the closing instruction when nothing flagged is left, and the bound on a long list.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _COVERAGE_NOTE_CHARS, _coverage_note

        done = _coverage_note({"a.java", "b.java"}, [], [])
        assert _constant_time_contains(done, "Every flagged file has been examined")
        assert _constant_time_contains(done, "Already examined (2): a.java, b.java")
        many = _coverage_note(set(), [f"app_modules/{n}.js" for n in range(2000)], ["lib/x.so"])
        assert _constant_time_contains(many, "not yet examined (2001)")
        assert len(many) < _COVERAGE_NOTE_CHARS + 400


class _FlakyProvider(ScriptedProvider):
    """
    Purpose:
        A scripted provider whose script can hold a failed request, as a dict, in place of a reply.

    Attributes:
        unavailable: Set to a reason to mark the provider as having stopped serving.
    """
    unavailable = None

    def analyze(self, prompt, system_message=None, schema=None, max_tokens=None, session_key=None):
        """
        Purpose:
            Play the next scripted turn, returning a failed request when the script holds one.

        Parameters:
            prompt: The turn prompt.
            system_message: The system prompt, unused here.
            schema: The requested response schema, unused here.
            max_tokens: The response limit, unused here.
            session_key: The conversation key, unused here.

        Returns:
            The turn's response or error.
        """
        self.calls += 1
        action = self.actions.pop(0) if self.actions else _LIST
        return action if isinstance(action, dict) else {"response": action}


_LOST = {"error": "Ollama response truncated at the 4000-token output cap after 3 attempts"}


class TestFailedTurns:
    """
    Purpose:
        A failed request costs a step, not the region, unless it keeps happening or the provider is gone.
    """

    def test_one_lost_reply_is_survived(self, src):
        """
        Purpose:
            Pin that a single failed turn is noted and the region carries on to its own report.

        Parameters:
            src: The source tree.
        """
        prov = _FlakyProvider([_LOST, _REPORT])
        telemetry = {}
        vulns, completed_ok, transcript = run_agent_analysis(prov, str(src), verbose=False, telemetry=telemetry)
        assert completed_ok is True and telemetry["stop_reason"] == "reported"
        assert [v["title"] for v in vulns] == ["H"]
        assert _constant_time_contains(transcript, "your reply to this step was lost")

    def test_repeated_failures_end_the_region_keeping_its_findings(self, src):
        """
        Purpose:
            Pin that failures past the tolerance end the region as a provider error, with what was already recorded kept.

        Parameters:
            src: The source tree.
        """
        prov = _FlakyProvider([_action("add_finding", [_finding("Kept", "a.java", "1")]),
                               _LOST, _LOST, _LOST, _REPORT])
        telemetry = {}
        vulns, _ok, _transcript = run_agent_analysis(prov, str(src), verbose=False, telemetry=telemetry)
        assert telemetry["stop_reason"] == "provider_error"
        assert [v["title"] for v in vulns] == ["Kept"]
        assert prov.calls == 4

    def test_an_unavailable_provider_is_not_retried(self, src):
        """
        Purpose:
            Pin that a provider that has stopped serving ends the region at the first failure.

        Parameters:
            src: The source tree.
        """
        prov = _FlakyProvider([_LOST, _REPORT])
        prov.unavailable = "fatal_quota: usage limit reached"
        run_agent_analysis(prov, str(src), verbose=False)
        assert prov.calls == 1
