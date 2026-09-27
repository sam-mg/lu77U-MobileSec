#!/usr/bin/env python3
"""
Module: test_agent_parsing

Purpose:
    The layers that turn unreliable model output into an action or a report.

Responsibilities:
    Pin thinking removal, JSON extraction, report coercion, action parsing and finding salvage.

Dependencies:
    The agent loop's parsing helpers.
"""

from lu77U_MobileSec.analyzers.agent.agent_loop import (
    _coerce_report, _extract_first_json_object, _parse_action, _salvage_findings,
    _strip_thinking_tokens,
)

class TestStripThinking:
    """
    Purpose:
        Removing a model's reasoning trace before anything is parsed.
    """
    def test_paired_block_is_removed(self):
        """
        Purpose:
            Pin that a complete reasoning block is stripped.
        """
        assert _strip_thinking_tokens("<think>reasoning</think>answer") == "answer"

    def test_lone_closing_tag_keeps_only_the_answer(self):
        """
        Purpose:
            Pin that an unpaired closing tag leaves only what followed it.

        Implementation notes:
            A draft action inside the reasoning must not win over the real one, and a truncated response frequently leaves exactly this shape.
        """
        raw = '{"action":"read_file","path":"a.java"}</think>{"action":"report"}'
        assert _strip_thinking_tokens(raw) == '{"action":"report"}'

    def test_last_closing_tag_wins(self):
        """
        Purpose:
            Pin that with several closing tags, only the text after the last survives.
        """
        assert _strip_thinking_tokens("a</think>b</think>c") == "c"

    def test_plain_text_is_untouched(self):
        """
        Purpose:
            Pin that a response with no reasoning markup passes through unchanged.
        """
        assert _strip_thinking_tokens('{"action":"report"}') == '{"action":"report"}'

class TestExtractJson:
    """
    Purpose:
        Finding the first complete JSON object in a response.
    """
    def test_first_balanced_object(self):
        """
        Purpose:
            Pin that an object embedded in surrounding noise is extracted.
        """
        assert _extract_first_json_object('noise {"a": 1} tail') == '{"a": 1}'

    def test_nested_braces(self):
        """
        Purpose:
            Pin that a nested object is extracted whole rather than cut at the inner brace.
        """
        text = '{"a": {"b": 2}}'
        assert _extract_first_json_object("x" + text) == text

    def test_braces_inside_strings_do_not_confuse_it(self):
        """
        Purpose:
            Pin that braces inside a string value do not end the object early.

        Implementation notes:
            This is why brace counting alone is not enough: agent actions carry search patterns and code excerpts, which contain braces routinely.
        """
        text = '{"a": "} not the end {"}'
        assert _extract_first_json_object(text) == text

    def test_duplicate_objects_return_only_the_first(self):
        """
        Purpose:
            Pin that only the first object is returned when several are present.
        """
        assert _extract_first_json_object('{"a":1} junk {"a":2}') == '{"a":1}'

    def test_no_object(self):
        """
        Purpose:
            Pin that text with no object yields nothing.
        """
        assert _extract_first_json_object("no braces here") is None

class TestCoerceReport:
    """
    Purpose:
        Recognising a report the model sent without the expected wrapper.
    """
    def test_bare_list_becomes_a_report(self):
        """
        Purpose:
            Pin that a bare findings list is understood as a report.

        Implementation notes:
            Models finishing an investigation frequently send the array directly, and rejecting it would discard a complete set of findings over a formatting detail.
        """
        out = _coerce_report([{"title": "x"}])
        assert out == {"action": "report", "vulnerabilities": [{"title": "x"}]}

    def test_findings_key_without_action(self):
        """
        Purpose:
            Pin that an object carrying findings under a plausible key is understood as a report.
        """
        assert _coerce_report({"findings": [{"title": "x"}]})["action"] == "report"

    def test_normal_action_is_unchanged(self):
        """
        Purpose:
            Pin that an ordinary action passes through untouched.

        Implementation notes:
            The coercion must not rewrite a legitimate action into a report, which would end an investigation early.
        """
        obj = {"action": "read_file", "path": "a.java"}
        assert _coerce_report(obj) == obj

class TestParseAction:
    """
    Purpose:
        Parsing one agent response into an action.
    """
    def test_fenced_json(self):
        """
        Purpose:
            Pin that an action inside a code fence is parsed.
        """
        assert _parse_action('```json\n{"action":"report"}\n```')["action"] == "report"

    def test_surrounding_prose(self):
        """
        Purpose:
            Pin that an action embedded in prose is parsed.
        """
        assert _parse_action('Sure. {"action":"list_files","path":""} ok')["action"] == "list_files"

    def test_empty_input(self):
        """
        Purpose:
            Pin that an empty response yields no action.
        """
        assert _parse_action("") is None

    def test_unparseable_input(self):
        """
        Purpose:
            Pin that prose with no action yields nothing rather than a guess.

        Implementation notes:
            Guessing here would have the loop perform an action the model never asked for.
        """
        assert _parse_action("I could not complete this task.") is None

class TestSalvage:
    """
    Purpose:
        Recovering findings from a report that will not parse.
    """
    def test_recovers_findings_from_malformed_json(self):
        """
        Purpose:
            Pin that findings are recovered from output with unquoted and malformed field values.

        Implementation notes:
            This runs after a long and expensive investigation, where the alternative to salvage is losing everything the agent found because its final message was malformed.
        """
        raw = """{"vulnerabilities": [
          {"title": "Exported provider", "severity": "High",
           "file": "sources/a/B.java", "line": 76-80 (manifest export),
           "description": "no permission"},
          {"title": "Hardcoded key", "severity": "Medium",
           "file": "sources/a/C.java", "line": "12", 22-23}
        ]}"""
        found = _salvage_findings(raw)
        assert [f["title"] for f in found] == ["Exported provider", "Hardcoded key"]
        assert found[0]["file"] == "sources/a/B.java"

    def test_skips_objects_without_a_title(self):
        """
        Purpose:
            Pin that an object with no title is not recovered as a finding.

        Implementation notes:
            An untitled finding cannot be reported, so recovering one would put an unusable entry into the results.
        """
        assert _salvage_findings('{"foo": {"bar": 1}}') == []

    def test_requires_a_file_or_severity(self):
        """
        Purpose:
            Pin that a title alone is not enough to be recovered.

        Implementation notes:
            Without a location or a severity there is nothing to act on, and prose that happens to look object-shaped would otherwise become a finding.
        """
        assert _salvage_findings('{"title": "lonely"}') == []
