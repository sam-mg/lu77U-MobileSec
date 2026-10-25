#!/usr/bin/env python3
"""
Module: test_parsing_and_detection_fixes

Purpose:
    Parser and detector defects found by auditing a real scan's raw transcripts.

Responsibilities:
    Pin the line span read out of a location, the composite location a finding carries, the recovery of a repeated key in a model's response, the provenance tag on every finding, what the normaliser logs, the severity and wording of the injection rule family, and what a wrong path costs the agent.

Dependencies:
    pytest, the response schema, the JSON helpers, the response parser, the fan-out, the validator, the injection detector and the agent tool surface.

Implementation notes:
    Each of these lost or mislabelled information silently, with no exception, no log line, and a plausible-looking value in the report. That is precisely the failure a hand review of the output cannot catch, which is why they are pinned rather than simply fixed.
"""

import pytest

from lu77U_MobileSec.ai.schema import parse_line_span
from lu77U_MobileSec.utils.json_utils import loads_richest
from lu77U_MobileSec.utils.response_parser import ResponseParser

_VEC = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestLineSpanFromAPath:
    """
    Purpose:
        Reading a line number out of a location that also carries a path.

    Implementation notes:
        Obfuscated source is full of digits and none of them are line numbers. The location now carries the file as well as the line, and the span reader used to take the first two integers it found anywhere in the string, so a path holding two short obfuscated names parsed as a line range taken from those names and the report highlighted the wrong lines of the right file.
    """
    @pytest.mark.parametrize("value,expected", [
        ("sources/d6/B1.java:41", (41, 41)),
        ("sources/co/hyperverge/SignatureHelper.java:41", (41, 41)),
        ("a/b.java:6-7", (6, 7)),
        ("sources/y0/c9.java:120", (120, 120)),
    ])
    def test_only_the_trailing_line_number_counts(self, value, expected):
        """
        Purpose:
            Pin that only the number after the path is read, across paths whose own names contain digits.

        Parameters:
            value: The location to read.
            expected: The line span it must yield.
        """
        assert parse_line_span(value) == expected

    def test_a_bare_path_has_no_line_span(self):
        """
        Purpose:
            Pin that a path with no line attached yields no span rather than digits taken out of the path.
        """
        assert parse_line_span("sources/d6/B1.java") is None

    @pytest.mark.parametrize("value,expected", [
        ("8", (8, 8)),
        ("line 8", (8, 8)),
        ("6-7", (6, 7)),
        ("lines 6 to 9", (6, 9)),
        (8, (8, 8)),
        ("7-6", (6, 7)),
        ("application tag", None),
        (None, None),
    ])
    def test_every_previously_accepted_form_is_unchanged(self, value, expected):
        """
        Purpose:
            Pin that every form the reader accepted before still reads the same way, including a reversed range and a value that is not a line at all.

        Parameters:
            value: The value to read.
            expected: The line span it must yield, or nothing.
        """
        assert parse_line_span(value) == expected


class TestLocationCarriesTheFile:
    """
    Purpose:
        The composite location a normalised finding carries.
    """
    def test_location_is_file_and_line(self):
        """
        Purpose:
            Pin that the location names the file and the line, and that the line is also available on its own.

        Implementation notes:
            It used to hold only the line, which duplicated a field the finding already had and left out the one thing a reader needs in order to find the code.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "Hardcoded RSA test public key",
            "file": "sources/co/hyperverge/SignatureHelper.java",
            "line": "41", "description": "demo", "cvss_vector": _VEC})
        assert out["location"] == "sources/co/hyperverge/SignatureHelper.java:41"
        assert out["line_number"] == 41

    def test_a_range_is_preserved(self):
        """
        Purpose:
            Pin that a line range survives into the location rather than collapsing to a single line.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "X", "file": "a/B.java", "line": "6-7",
            "description": "demo", "cvss_vector": _VEC})
        assert out["location"] == "a/B.java:6-7"

    def test_the_round_trip_recovers_the_same_lines(self):
        """
        Purpose:
            Pin that the composite location can be read back into the same line span.

        Implementation notes:
            The report falls back to the location when a finding carries no separate line, so a form the reader cannot parse is a silent corruption rather than a visible failure.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "X", "file": "sources/d6/B1.java", "line": "41",
            "description": "demo", "cvss_vector": _VEC})
        assert parse_line_span(out["location"]) == (41, 41)

    def test_a_finding_with_no_line_falls_back_to_the_file(self):
        """
        Purpose:
            Pin that a finding with no line carries just the file as its location.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "X", "file": "AndroidManifest.xml",
            "description": "demo", "cvss_vector": _VEC})
        assert out["location"] == "AndroidManifest.xml"


class TestDuplicateJsonKeys:
    """
    Purpose:
        Recovering the useful value when a model repeats a key in its response.

    Implementation notes:
        Seen in a real transcript: a finding carried its description twice, the real one first and then a short restatement of the title. Standard parsing keeps the last of the two, so what reached the report was the useless copy, with nothing anywhere to notice it.
    """
    def test_the_longer_value_wins(self):
        """
        Purpose:
            Pin that where a key is repeated, the fuller value is the one kept.
        """
        raw = ('{"title":"Hardcoded RSA test public key",'
               '"description":"A 2048-bit RSA public key labelled TEST is compiled '
               'into SignatureHelper and used to verify KYC payload signatures.",'
               f'"cvss_vector":"{_VEC}",'
               '"description":"Hardcoded RSA test public key"}')
        assert loads_richest(raw)["description"].startswith("A 2048-bit RSA")

    def test_order_does_not_matter(self):
        """
        Purpose:
            Pin that the fuller value wins whichever position it appears in.
        """
        raw = '{"a":"short","a":"a considerably longer value"}'
        assert loads_richest(raw)["a"] == "a considerably longer value"
        raw = '{"a":"a considerably longer value","a":"short"}'
        assert loads_richest(raw)["a"] == "a considerably longer value"

    def test_a_populated_value_is_not_displaced_by_an_empty_one(self):
        """
        Purpose:
            Pin that a real value is not replaced by an absent or empty one of the same key.
        """
        assert loads_richest('{"line":"41","line":null}')["line"] == "41"
        assert loads_richest('{"tags":["a"],"tags":[]}')["tags"] == ["a"]

    def test_ordinary_json_is_untouched(self):
        """
        Purpose:
            Pin that a response with no repeated keys parses exactly as it normally would.

        Implementation notes:
            This is the assertion that keeps the recovery from being a second, subtly different parser applied to every response.
        """
        raw = '{"a":1,"b":[1,2],"c":{"d":"e"}}'
        import json
        assert loads_richest(raw) == json.loads(raw)

    def test_the_parser_recovers_it_end_to_end(self):
        """
        Purpose:
            Pin that a repeated key is recovered through the real response parsing path rather than only through the helper.
        """
        raw = ('[{"title":"Hardcoded RSA test public key","file":"a/B.java",'
               '"line":"41","description":"The long and accurate description of '
               'what this key actually is and why it matters.",'
               f'"cvss_vector":"{_VEC}",'
               '"description":"Hardcoded RSA test public key"}]')
        out = ResponseParser().parse_json_response(raw)
        assert out and out[0]["description"].startswith("The long and accurate")


class TestFindingProvenance:
    """
    Purpose:
        The tag saying which pass produced a finding.

    Implementation notes:
        It was empty on every finding the agent produced. A pattern match on a concatenated query and a model's inference about a biometric prompt need very different review effort, and the report gave a triager no field to tell them apart.
    """
    def test_the_fanout_merge_tags_agent_findings(self):
        """
        Purpose:
            Pin that merging a region's results tags each finding as the agent's and names the region it came from.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import (
            _SurfaceResult, merge_surface_findings)
        from lu77U_MobileSec.analyzers.agent.partition import Region

        result = _SurfaceResult(Region(key="region-1-a", members=set(), seeds=[],
                                       families=[]))
        result.findings = [{"title": "Found by the model", "file": "A.java",
                            "line": "1"}]
        merged = merge_surface_findings([result])
        assert merged[0]["source"] == "agent"
        assert merged[0]["surface"] == "region-1-a"

    def test_a_scanner_source_is_not_overwritten(self):
        """
        Purpose:
            Pin that a finding already attributed to a scanner keeps that attribution through the merge.

        Implementation notes:
            The deterministic findings pass through the same merge, so tagging unconditionally would relabel every one of them as the agent's work.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import (
            _SurfaceResult, merge_surface_findings)
        from lu77U_MobileSec.analyzers.agent.partition import Region

        result = _SurfaceResult(Region(key="region-1-a", members=set(), seeds=[],
                                       families=[]))
        result.findings = [{"title": "From the scanner", "file": "A.java",
                            "line": "1", "source": "static-analyzer"}]
        assert merge_surface_findings([result])[0]["source"] == "static-analyzer"

    def test_source_survives_normalization(self):
        """
        Purpose:
            Pin that the provenance and the region survive normalisation.

        Implementation notes:
            The parser builds its output from an explicit list of fields and drops anything not on it, so tagging the finding upstream is only half the change.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "X", "file": "a/B.java", "line": "1", "description": "demo",
            "cvss_vector": _VEC, "source": "agent", "surface": "region-1-a"})
        assert out["source"] == "agent"
        assert out["surface"] == "region-1-a"

    def test_related_findings_survive_normalization(self):
        """
        Purpose:
            Pin that a finding's cross-references survive normalisation.
        """
        out = ResponseParser().normalize_vulnerability({
            "title": "X", "file": "a/B.java", "line": "1", "description": "demo",
            "cvss_vector": _VEC,
            "related_findings": [{"pattern": "CHAIN-01", "confirmed": False,
                                  "reason": "candidate", "with": {}}]})
        assert len(out["related_findings"]) == 1

    def test_agent_source_does_not_route_findings_into_code_verification(self):
        """
        Purpose:
            Pin that an agent-produced finding is not routed into the pass that re-checks a scanner's pattern match against the code.

        Implementation notes:
            That pass asks whether the code supports the claim, which the agent has already done by reading it, so sending agent findings there would spend a model call to repeat work and risk discarding a correct finding.
        """
        from lu77U_MobileSec.validation.validator import is_rule_finding

        assert not is_rule_finding({"source": "agent"})
        assert is_rule_finding({"source": "static-analyzer"})


class TestNormalizedVulnerabilityLogging:
    """
    Purpose:
        What the normaliser writes to the log.

    Implementation notes:
        A real verbose log printed the literal source text of its summary line rather than the values, because every brace in the formatted string had been doubled, which escapes to a literal brace instead of substituting. Separately, a key the model invented and a fall back to the default severity both disappeared without trace, dropped by the field list with nothing logged.
    """
    def test_the_summary_line_interpolates_real_values(self, capsys):
        """
        Purpose:
            Pin that the summary line carries the finding's actual values and not the text of the expression that was meant to produce them.

        Parameters:
            capsys: Captures the printed output.
        """
        p = ResponseParser()
        p.verbose = True
        p.normalize_vulnerability({"title": "SQL Injection", "file": "a/B.java",
                                   "line": "1", "description": "demo",
                                   "severity": "High"})
        out = capsys.readouterr().out
        assert "vulnerability_type='SQL Injection'" in out
        assert "file='a/B.java'" in out
        assert "severity='High'" in out
        assert "normalized['vulnerability_type']" not in out

    def test_an_unrecognized_key_is_logged_not_silently_dropped(self, capsys):
        """
        Purpose:
            Pin that a key the normaliser does not recognise is still dropped from the output but is named in the log.

        Parameters:
            capsys: Captures the printed output.

        Implementation notes:
            Keeping it would let a model invent report fields, and dropping it silently is how a finding can lose information nobody knows it had.
        """
        p = ResponseParser()
        p.verbose = True
        out = p.normalize_vulnerability({
            "title": "X", "file": "a/B.java", "line": "1", "description": "demo",
            "title2": "a model-invented duplicate field"})
        assert "title2" not in out
        logged = capsys.readouterr().out
        assert "title2" in logged

    def test_a_missing_severity_is_distinguished_from_an_unrecognized_one(self, capsys):
        """
        Purpose:
            Pin that no severity at all and a severity that is not recognised are logged as two different things.

        Parameters:
            capsys: Captures the printed output.

        Implementation notes:
            Both end up at the default, so without the distinction a model consistently emitting a severity nobody parses looks exactly like a model emitting none.
        """
        p = ResponseParser()
        p.verbose = True
        p.normalize_vulnerability({"title": "X", "file": "a/B.java", "line": "1",
                                   "description": "demo"})
        assert "No severity provided" in capsys.readouterr().out

        p.normalize_vulnerability({"title": "X", "file": "a/B.java", "line": "1",
                                   "description": "demo", "severity": "Severe"})
        assert "Unrecognized severity" in capsys.readouterr().out


class TestSqlRuleFamily:
    """
    Purpose:
        One defect, one title, and a severity driven by whether the value is actually reachable.

    Implementation notes:
        The same concatenation was reported as High or Medium under three different titles depending on which pattern matched it first, which read as unrelated issues scored inconsistently.
    """
    def _findings(self, tmp_path, source):
        """
        Purpose:
            Run the injection detector over one source file and return its query-building findings.

        Parameters:
            tmp_path: The tree root.
            source: The source to analyse.

        Returns:
            The findings of the query-building class.

        Implementation notes:
            The file is always written to the same path, so a test needing two independent cases has to put both in this one file and keep their operand names distinct.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.injection import (
            analyze_injection)

        src = tmp_path / "sources" / "com" / "x"
        src.mkdir(parents=True)
        (src / "Db.java").write_text(source)
        return [f for f in analyze_injection(tmp_path)
                if f.vuln_class == "CODE-01"]

    def test_attacker_controlled_input_scores_high(self, tmp_path):
        """
        Purpose:
            Pin that a value arriving from outside the application scores high.

        Parameters:
            tmp_path: The tree root.
        """
        findings = self._findings(tmp_path, """
class Db {
  void load() {
    String name = getIntent().getStringExtra("q");
    db.rawQuery("SELECT * FROM users WHERE name='" + name + "'", null);
  }
}
""")
        assert findings and findings[0].severity == "High"

    def test_a_compile_time_constant_is_not_reported(self, tmp_path):
        """
        Purpose:
            Pin that a statement built only from values fixed at compile time is not reported.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            Nothing can be injected into a value the attacker cannot influence. This used to be reported at Low; a fixed Ghera app's `"DELETE FROM " + Table.TABLE_NAME` then counted as its SQL injection still being there, so a statement whose every operand is a constant is now dropped, as a command made only of constants already was.
        """
        findings = self._findings(tmp_path, """
class Db {
  void load() {
    String table = "users";
    db.rawQuery("SELECT * FROM " + table, null);
  }
}
""")
        assert findings == []

    def test_unknown_provenance_stays_medium(self, tmp_path):
        """
        Purpose:
            Pin that a value whose origin cannot be determined stays in the middle.

        Parameters:
            tmp_path: The tree root.
        """
        findings = self._findings(tmp_path, """
class Db {
  void load(String name) {
    db.rawQuery("SELECT * FROM users WHERE name='" + name + "'", null);
  }
}
""")
        assert findings and findings[0].severity == "Medium"

    def test_a_content_provider_does_not_inflate_a_constant_identifier(self, tmp_path):
        """
        Purpose:
            Pin that a fixed table name in a component reachable from other applications is still treated as a constant, and so, being the statement's only operand, not reported at all.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            This case used to be scored at the top severity purely because the class extended that component type, which short-circuited the scoring entirely, so a file merely mentioning it made every query hit in it critical regardless of what was actually concatenated. A fixed table name is not reachable by an attacker however the query is invoked; only a value position or an externally tainted operand still escalates in such a component.
        """
        findings = self._findings(tmp_path, """
class Db extends ContentProvider {
  public Cursor query(Uri uri, String sel) {
    String table = "users";
    return db.rawQuery("SELECT * FROM " + table, null);
  }
}
""")
        assert findings == []

    def test_every_sql_finding_is_grammatical(self, tmp_path):
        """
        Purpose:
            Pin that no finding in this family reads ungrammatically.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            These titles used to come from one shared template, which is what produced the grammar fault it was meant to prevent: two of the four sinks are already noun phrases carrying their own article, so the template produced a doubled one. Titles now vary by what kind of element was concatenated into, which is a real difference in the underlying defect, so the invariant worth holding is the grammar rather than a single literal template.
        """
        import re

        findings = self._findings(tmp_path, """
class Db {
  void a(String v) { db.rawQuery("SELECT * FROM t WHERE x='" + v + "'", null); }
  void b(String v) { db.execSQL("DELETE FROM t WHERE x='" + v + "'"); }
  void c(String v) { String selection = "x='" + v + "'"; }
}
""")
        assert len(findings) >= 3
        assert all(not re.search(r"\bSQL (a|an) ", f.title) for f in findings)

    def test_confidence_reflects_whether_provenance_was_determined(self, tmp_path):
        """
        Purpose:
            Pin that confidence follows whether the value's origin could be determined, not only how precise the pattern match was.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            Confidence used to be high for any precise pattern match regardless of what could be said about where the value came from. A finding whose origin is unknown carries no more signal than a guess about whether it is exploitable, and presenting that as high confidence misrepresents it: low confidence is what lets the mechanical gate treat it as a lead to verify rather than as a confirmed issue. Both cases live in one file because the helper writes to a fixed path, and they use different operand names because the origin search looks for an assignment by name across the whole file rather than within a scope, so a shared name would let one method's assignment answer for the other's unrelated parameter.
        """
        findings = self._findings(tmp_path, """
class Db {
  void a() {
    String v = getIntent().getStringExtra("q");
    db.rawQuery("SELECT * FROM t WHERE x='" + v + "'", null);
  }
  void b(String input) {
    db.rawQuery("SELECT * FROM t WHERE x='" + input + "'", null);
  }
}
""")
        resolved = next(f for f in findings if f.line == 5)
        unresolved = next(f for f in findings if f.line == 8)
        assert resolved.extra["operand_provenance"] == "external"
        assert resolved.confidence == "HIGH"
        assert unresolved.extra["operand_provenance"] == "unknown"
        assert unresolved.confidence == "LOW"


class TestAgentPathMisses:
    """
    Purpose:
        What the agent gets back when it asks for a path that does not exist.

    Implementation notes:
        A wrong path used to cost a whole turn and return nothing usable. A real scan spent fifteen round trips on paths that do not exist, nine of them asking for the manifest, which is not a file in a decompiled tree and was already supplied pre-rendered in the very same prompt.
    """
    @pytest.fixture
    def tools(self, tmp_path):
        """
        Purpose:
            Build a tool surface over a small decompiled tree.

        Parameters:
            tmp_path: Directory the tree is written into.

        Returns:
            The tool surface.
        """
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools

        src = tmp_path / "sources" / "y0"
        src.mkdir(parents=True)
        (src / "c.java").write_text("class C {}\n")
        return AgentTools(tmp_path)

    def test_the_manifest_gets_an_explanation_not_a_dead_end(self, tools):
        """
        Purpose:
            Pin that asking for the manifest explains that it was already supplied rather than simply failing.

        Parameters:
            tools: The tool surface.
        """
        out = tools.read_file("AndroidManifest.xml")
        assert "already rendered" in out
        assert "Do not" not in out or "read the components" in out.lower()

    def test_a_near_miss_suggests_the_real_path(self, tools):
        """
        Purpose:
            Pin that a path close to a real one suggests the real one.

        Parameters:
            tools: The tool surface.

        Implementation notes:
            Obfuscated directory names differ by a single character, so a near miss is the common case rather than a rare one, and suggesting the right path turns two wasted turns into one.
        """
        out = tools.read_file("sources/y/c.java")
        assert "Did you mean" in out
        assert "sources/y0/c.java" in out

    def test_a_directory_is_listed_rather_than_refused(self, tools):
        """
        Purpose:
            Pin that asking to read a directory lists its contents instead of returning an error.

        Parameters:
            tools: The tool surface.
        """
        out = tools.read_file("sources/y0")
        assert "c.java" in out
        assert not out.startswith("ERROR")

    def test_a_genuinely_absent_file_still_errors(self, tools):
        """
        Purpose:
            Pin that a path resembling nothing in the tree is still reported as an error.

        Parameters:
            tools: The tool surface.

        Implementation notes:
            The helpfulness above must not become a reader that never admits a file is missing, which would leave the agent believing it had read something.
        """
        out = tools.read_file("sources/y0/NoSuchThing.java")
        assert out.startswith("ERROR")

    def test_a_real_file_is_unaffected(self, tools):
        """
        Purpose:
            Pin that an ordinary read still returns the file's contents.

        Parameters:
            tools: The tool surface.
        """
        assert "class C {}" in tools.read_file("sources/y0/c.java")

    def test_the_sandbox_still_holds(self, tools):
        """
        Purpose:
            Pin that none of the added helpfulness opened a way out of the source root.

        Parameters:
            tools: The tool surface.

        Security considerations:
            The suggestion and directory-listing paths both resolve a path the model supplied, so each is a new place the sandbox could have been bypassed.
        """
        assert tools.read_file("../../../etc/passwd").startswith("ERROR")
