#!/usr/bin/env python3
"""
Module: test_file_review

Purpose:
    The file-by-file review pass that follows the agent, and the Blutter disassembly digest it reads compiled Dart through.

Responsibilities:
    Pin which files the pass reviews and in what order, how files are numbered, digested, packed and split into requests, how findings are tagged and pinned to the files a request showed, how failures, the request budget and cancellation are handled, and that the base analyzer adds the pass's findings without ever losing the agent's.

Dependencies:
    pytest, the file review module, the agent tool surface and profiles, the Flutter recovery helpers, the base analyzer.

Implementation notes:
    No model is called: a stub provider records each request and replies with canned JSON, which is enough to pin everything this pass decides for itself. The disassembly fixture is hand-written in Blutter's real output format, as in the Flutter recovery tests.
"""

import json
from types import SimpleNamespace

import pytest

from lu77U_MobileSec.analyzers.agent import file_review
from lu77U_MobileSec.analyzers.agent.file_review import (
    ORIGIN, build_parts, render_for_review, review_targets, run_file_review)
from lu77U_MobileSec.analyzers.agent.profiles import FLUTTER, JAVA_KOTLIN, REACT_NATIVE
from lu77U_MobileSec.analyzers.agent.tools import AgentTools
from lu77U_MobileSec.analyzers.flutter import recovered
from lu77U_MobileSec.analyzers.flutter.recovered import digest_disassembly
from lu77U_MobileSec.utils.cancellation import ScanCancelled

ASM = '''// lib: , url: package:vault/notes.dart

// class id: 7, size: 0x8
class _NotesState extends State<dynamic> {

  _ _search(/* No info */) async {
    // ** addr: 0x3000, size: 0x100
    // 0x3000: EnterFrame
    //     0x3000: stp             fp, lr, [SP, #-0x10]!
    // 0x3004: r16 = "SELECT * FROM notes WHERE title LIKE '%"
    // 0x3008: mov             x1, x0
    // 0x300c: r0 = _interpolate()
    //     0x300c: bl              #0x7000  ; [dart:core] _StringBase::_interpolate
    // 0x3010: r0 = rawQuery()
    //     0x3010: bl              #0x7300  ; [package:sqflite_common/src/database_mixin.dart] _MixinApplication1&Object&SqfliteDatabaseExecutorMixin::rawQuery
    // 0x3014: r0 = Await()
    //     0x3014: bl              #0x7400  ; AwaitStub
    // 0x3018: r1 = true
    // 0x301c: r1 = true
    // 0x3020: r2 = Instance_Text
    // 0x3024: r1 = 4
  }
}
'''


class _Provider:
    """
    Purpose:
        Stand in for an AI provider, recording each request and replying from a script.

    Attributes:
        replies: Responses handed out in order; the last one repeats.
        prompts: Every prompt received.
        systems: Every system message received.
    """

    def __init__(self, *replies):
        """
        Purpose:
            Store the scripted replies.

        Parameters:
            replies: Response dicts, handed out in request order.
        """
        self.replies = list(replies) or [{"response": "[]"}]
        self.prompts = []
        self.systems = []

    def analyze(self, prompt, system_message=None, **unused_options):
        """
        Purpose:
            Record a request and return the next scripted reply.

        Parameters:
            prompt: The request text.
            system_message: The system prompt.
            unused_options: The response schema and output cap, which a stub has no use for.

        Returns:
            The scripted reply.
        """
        self.prompts.append(prompt)
        self.systems.append(system_message)
        index = min(len(self.prompts) - 1, len(self.replies) - 1)
        return self.replies[index]


def _write(root, files):
    """
    Purpose:
        Write a decompiled tree.

    Parameters:
        root: The analysis root.
        files: Relative path to text.

    Returns:
        The analysis root.
    """
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _graph(nodes, native=()):
    """
    Purpose:
        Build a minimal stand-in for a code graph.

    Parameters:
        nodes: (file, role, flagged) for each node.
        native: Native library paths.

    Returns:
        An object with the nodes and native_libs attributes the review reads.
    """
    return SimpleNamespace(
        nodes={f: SimpleNamespace(file=f, role=role, flagged=flagged, source_available=True)
               for f, role, flagged in nodes},
        native_libs=[SimpleNamespace(path=p) for p in native])


class TestDigest:
    """
    Purpose:
        The Blutter digest keeps what a security reading needs, at the file's real line numbers.
    """

    def test_keeps_literals_calls_and_declarations_at_real_lines(self):
        """
        Purpose:
            Pin that string loads, resolved calls, booleans, constants and declarations survive with their own line numbers.
        """
        lines = ASM.splitlines()
        rows = dict(row.split(": ", 1) for row in digest_disassembly(ASM).splitlines())
        sql_line = str(next(i for i, l in enumerate(lines, 1) if "SELECT" in l))
        assert rows[sql_line].startswith('"SELECT * FROM notes')
        query_line = str(next(i for i, l in enumerate(lines, 1) if "r0 = rawQuery()" in l))
        assert rows[query_line] == "call SqfliteDatabaseExecutorMixin::rawQuery (sqflite_common)"
        assert any(v.startswith("fn _ _search") for v in rows.values())
        assert any(v.startswith("class _NotesState") for v in rows.values())
        assert "Instance_Text" in rows.values()

    def test_drops_plumbing_and_collapses_repeats(self):
        """
        Purpose:
            Pin that frame setup, register moves, async plumbing and integer immediates are dropped and a repeated row is kept once.
        """
        condensed = digest_disassembly(ASM)
        kept = condensed.splitlines()
        assert not [row for row in kept if row.split(": ", 1)[1] in ("EnterFrame", "Await", "4")]
        assert not [row for row in kept if row.split(": ", 1)[1].startswith("mov")]
        assert condensed.count(": true") == 1


RICH_ASM = '''// lib: , url: package:vault/transfer.dart

class _TransferState extends State<dynamic> {

  _ initState(/* No info */) {
    // ** addr: 0x5000, size: 0x40
    // 0x5004: r0 = Instance_HomePage
    //     0x5004: add             x0, PP, #0xa, lsl #12  ; [pp+0xaa20] Obj!HomePage@47c2c1
    // 0x5008: r1 = Function '<anonymous closure>':.
    //     0x5008: add             x1, PP, #0x15, lsl #12  ; [pp+0x15a40] AnonymousClosure: (0x6000), in [package:vault/transfer.dart] _TransferState::initState (0x5000)
    // 0x500c: r16 = 142
    // 0x5010: StoreField: r0->field_f = r16
    // 0x5014: r16 = 154
    // 0x5018: StoreField: r0->field_13 = r16
    // 0x501c: r16 = 132
    // 0x5020: StoreField: r0->field_17 = r16
    // 0x5024: r16 = 144
    // 0x5028: StoreField: r0->field_1b = r16
    // 0x502c: r16 = 248
    // 0x5030: StoreField: r0->field_1f = r16
    // 0x5034: r16 = 210
    // 0x5038: StoreField: r0->field_23 = r16
    // 0x503c: eor             x4, x1, #3
    // 0x503e: r2 = const [Instance of 'ListTile', Instance of 'ListTile']
    //     0x503e: add             x2, PP, #0x14, lsl #12  ; [pp+0x14f18] List<Widget>(2)
    // 0x5040: ret
    //     0x5040: ret
    // 0x5044: sub             SP, fp, #0x60
    // 0x5048: r0 = _HttpClient()
    //     0x5048: bl              #0x33ac3c  ; [dart:_http] _HttpClient::_HttpClient
  }

  [closure] void <anonymous closure>(dynamic, Duration) {
    // ** addr: 0x6000, size: 0x20
    // 0x6004: r0 = _send()
    //     0x6004: bl              #0x7000  ; [package:vault/transfer.dart] _TransferState::_send
  }
}
'''


class TestRichDigest:
    """
    Purpose:
        The digest rows added after review transcripts showed what a reader could not see.
    """

    def _rows(self):
        """
        Purpose:
            Digest the fixture with an object dump holding a const page's secret.

        Returns:
            The digest rows by line number.
        """
        from lu77U_MobileSec.analyzers.flutter.recovered import PoolEntry
        objects = {"47c2c1": ["FLAG{demo_flag}", "FLAG{demo_flag}"],
                   "586011": ["Debug API key", "demo_debug_key_0123"], "585ed1": ["Gateway secret"]}
        pool = {"0x14f18": PoolEntry(offset="0x14f18",
                                     header="List<Widget>(2) [Obj!ListTile@586011, Obj!ListTile@585ed1]")}
        condensed = digest_disassembly(RICH_ASM, objects, pool)
        return dict(row.split(": ", 1) for row in condensed.splitlines())

    def _line(self, marker):
        """
        Purpose:
            Find a fixture line.

        Parameters:
            marker: Text on the line.

        Returns:
            Its 1-based number as text.
        """
        return str(next(i for i, l in enumerate(RICH_ASM.splitlines(), 1) if marker in l))

    def test_const_object_strings_and_closure_bodies(self):
        """
        Purpose:
            Pin that a loaded const object shows its strings once, and a closure names its line, its frame-callback nature and the app call it makes.
        """
        rows = self._rows()
        assert rows[self._line("r0 = Instance_HomePage")] == 'Instance_HomePage {"FLAG{demo_flag}"}'
        closure = rows[self._line("Function '<anonymous closure>'")]
        assert closure.startswith(f"closure -> line {self._line('[closure] void')}")
        assert "frame callback" in closure and closure.endswith("_TransferState::_send (vault)")

    def test_a_const_list_shows_what_its_objects_hold(self):
        """
        Purpose:
            Pin that a const list loaded from a pool slot is followed to the objects the slot lists, and their strings shown.
        """
        rows = self._rows()
        assert rows[self._line("r2 = const [Instance of")] == (
            'const list of 2 objects {"Debug API key", "demo_debug_key_0123", "Gateway secret"}')

    def test_integer_arrays_xor_returns_and_handlers(self):
        """
        Purpose:
            Pin that a run of integer stores becomes one array row with its characters, and that XOR, return and the exception handler's entry are kept.
        """
        rows = self._rows()
        assert rows[self._line("r16 = 142")] == 'int array (6): 71, 77, 66, 72, 124, 105 chars "GMBH|i"'
        assert rows[self._line("eor ")] == "xor with #3"
        assert rows[self._line("0x5040: ret")] == "return"
        assert rows[self._line("sub             SP")] == "catch: exception handler starts here"


@pytest.mark.parametrize("values, expected", [
    ([75, 81, 70, 76, 128, 109, 116, 116, 112, 110, 115, 108, 100, 117, 113, 102, 121, 107,
      116, 119, 114, 100, 104, 116, 105, 106, 130], 'decodes (minus 5) as "FLAG{hooking_platform_code}"'),
    ([71, 77, 66, 72, 124, 105, 112, 112, 108, 106, 111, 104, 96, 101, 98, 115, 117, 96, 100,
      112, 101, 102, 126], 'decodes (minus 1) as "FLAG{hooking_dart_code}"'),
    ([ord(c) ^ 0x2A for c in "secret_admin_key"], 'decodes (xor 0x2a) as "secret_admin_key"'),
    ([ord(c) for c in "plain_text_key_123"], None),
    (list(range(20)), None),
    ([203, 17, 88, 241, 3, 156, 77, 190, 64, 222], None),
])
def test_an_encoded_integer_array_is_decoded(values, expected):
    """
    Purpose:
        Pin that an integer array hiding text behind a constant shift or a one-byte XOR is shown decoded, and that readable text, a counter and random bytes are not.

    Parameters:
        values: The array's values.
        expected: The decoding fragment the row must carry, or None when it must carry none.

    Implementation notes:
        A lab app's flag was stored shifted by five; two of its codes fell above printable ASCII, so the array was shown as bare numbers and the flag went unreported, while a sibling shifted by one kept readable-looking characters and was found.
    """
    row = recovered._int_array_row(values)
    if expected is None:
        assert "decodes" not in row
    else:
        assert row.endswith(expected)


class TestTargets:
    """
    Purpose:
        Which files the pass reviews, and in what order.
    """

    def test_leads_first_then_entry_points_then_the_rest(self, tmp_path):
        """
        Purpose:
            Pin the priority order and that native libraries and other extensions are left out.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = _write(tmp_path, {
            "sources/com/app/A.java": "class A {}\n", "sources/com/app/B.java": "class B {}\n",
            "sources/com/app/Entry.java": "class Entry {}\n", "lib/arm64-v8a/libx.so": "x",
        })
        graph = _graph([("sources/com/app/A.java", "class", True),
                        ("sources/com/app/B.java", "class", True),
                        ("sources/com/app/Entry.java", "exported-activity", True),
                        ("sources/com/app/Quiet.java", "class", False)],
                       native=["lib/arm64-v8a/libx.so"])
        leads = [SimpleNamespace(file="sources/com/app/B.java")]
        tools = AgentTools(root, profile=JAVA_KOTLIN)
        assert review_targets(graph, tools, leads) == [
            "sources/com/app/B.java", "sources/com/app/Entry.java", "sources/com/app/A.java"]

    def test_cross_platform_plugin_java_is_left_out(self, tmp_path):
        """
        Purpose:
            Pin that a Flutter app's platform-layer Java is reviewed only under the app's own package.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = _write(tmp_path, {
            "asm/vault/notes.dart": ASM,
            "platform/sources/com/vault/app/MainActivity.java": "class MainActivity {}\n",
            "platform/sources/com/plugin/Lib.java": "class Lib {}\n",
            "platform/sources/G0/C0.java": "class C0 {}\n",
            "platform/resources/AndroidManifest.xml":
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.vault.app">'
                "<application/></manifest>\n",
        })
        graph = _graph([("asm/vault/notes.dart", "app-class", True),
                        ("platform/sources/com/vault/app/MainActivity.java", "class", True),
                        ("platform/sources/com/plugin/Lib.java", "class", True),
                        ("platform/sources/G0/C0.java", "class", True)])
        targets = review_targets(graph, AgentTools(root, profile=FLUTTER), [])
        assert targets == ["asm/vault/notes.dart", "platform/sources/com/vault/app/MainActivity.java"]

    def test_without_a_graph_the_app_files_are_used(self, tmp_path):
        """
        Purpose:
            Pin the fallback to the tool surface's app file list when no graph was built.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = _write(tmp_path, {"app_modules/1_App.js": "export default 1;\n"})
        assert review_targets(None, AgentTools(root, profile=REACT_NATIVE), []) == ["app_modules/1_App.js"]


class TestParts:
    """
    Purpose:
        Rendering and packing files into requests.
    """

    def test_source_is_numbered_and_disassembly_digested(self):
        """
        Purpose:
            Pin line numbering for source and the switch to the digest for Blutter output.
        """
        text, condensed = render_for_review("app_modules/1.js", "a();\nb();\n")
        assert text.splitlines() == ["1: a();", "2: b();"] and condensed is False
        text, condensed = render_for_review("asm/vault/notes.dart", ASM)
        assert condensed is True and "rawQuery" in text and "EnterFrame" not in text

    def test_small_files_share_and_large_files_split(self):
        """
        Purpose:
            Pin greedy packing of small files and line-boundary splitting of a large one, in order.
        """
        big = "\n".join(f"{i}: x" * 3 for i in range(1, 200))
        parts = build_parts([("a", "1: a", False), ("b", "1: b", False), ("big", big, False)], limit=300)
        assert [rel for rel, _t, _d in parts[0]][:2] == ["a", "b"]
        pieces = [t for part in parts for rel, t, _d in part if rel == "big"]
        assert len(pieces) > 1 and "\n".join(pieces) == big
        assert all(sum(len(t) for _r, t, _d in part) <= 300 for part in parts[1:])


class TestRun:
    """
    Purpose:
        Running the pass end to end against a stub provider.
    """

    @pytest.fixture
    def tree(self, tmp_path):
        """
        Purpose:
            Write a two-module React Native tree and its graph.

        Parameters:
            tmp_path: Directory the tree is written into.

        Returns:
            The root and the graph.
        """
        root = _write(tmp_path, {"app_modules/1_Login.js": "save(token);\n",
                                 "app_modules/2_Home.js": "render();\n"})
        graph = _graph([("app_modules/1_Login.js", "class", True), ("app_modules/2_Home.js", "class", True)])
        return root, graph

    def test_findings_are_tagged_and_pinned_to_a_shown_file(self, tree):
        """
        Purpose:
            Pin the provenance fields and that a basename-only citation is mapped to the file the request showed.

        Parameters:
            tree: The fixture tree and graph.
        """
        root, graph = tree
        reply = [{"title": "Token stored in plain storage", "file": "1_Login.js", "line": "1",
                  "description": "The token is written in plain text.",
                  "cvss_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 {"title": "Elsewhere", "file": "Other.js", "line": "3", "description": "Elsewhere."}]
        provider = _Provider({"response": json.dumps(reply)})
        telemetry = {}
        found = run_file_review(provider, root, REACT_NATIVE, graph, "React Native", telemetry=telemetry)
        assert len(provider.prompts) == 1
        assert "### app_modules/1_Login.js" in provider.prompts[0]
        assert "# Reference skills" in provider.systems[0]
        first, second = found
        assert first["file"] == "app_modules/1_Login.js" and first["cited_file_read"] is True
        assert first["agent_origin"] == ORIGIN and first["region_files_read"] == 2
        assert second["cited_file_read"] is False
        assert telemetry == {"files": 2, "parts": 1, "parts_skipped": 0, "parts_failed": 0, "findings": 2}

    def test_failed_parts_are_counted_and_the_budget_cuts_from_the_end(self, tree, monkeypatch):
        """
        Purpose:
            Pin that a failed request costs only its part and that the request budget drops the lowest-priority parts.

        Parameters:
            tree: The fixture tree and graph.
            monkeypatch: Shrinks the part size so each file is its own part.
        """
        root, graph = tree
        monkeypatch.setattr(file_review, "PART_CHARS", 10)
        provider = _Provider({"error": "down"})
        telemetry = {}
        assert run_file_review(provider, root, REACT_NATIVE, graph, "RN", max_parts=1, telemetry=telemetry) == []
        assert len(provider.prompts) == 1 and "1_Login.js" in provider.prompts[0]
        assert telemetry["parts_skipped"] == 1 and telemetry["parts_failed"] == 1

    def test_cancellation_stops_the_pass(self, tree):
        """
        Purpose:
            Pin that a stop request raises instead of reviewing.

        Parameters:
            tree: The fixture tree and graph.
        """
        root, graph = tree
        provider = _Provider()
        with pytest.raises(ScanCancelled):
            run_file_review(provider, root, REACT_NATIVE, graph, "RN", is_cancelled=lambda: True)
        assert provider.prompts == []


class TestBaseAnalyzerHook:
    """
    Purpose:
        The base analyzer adds the review's findings and never loses the agent's.
    """

    def _analyzer(self, provider):
        """
        Purpose:
            Build a bare analyzer object carrying only what the hook reads.

        Parameters:
            provider: The AI provider to attach.

        Returns:
            The analyzer.
        """
        from lu77U_MobileSec.analyzers.react_native_analyzer import ReactNativeAnalyzer
        analyzer = object.__new__(ReactNativeAnalyzer)
        analyzer.ai_provider = provider
        analyzer.profile = REACT_NATIVE
        analyzer.verbose = False
        analyzer.agent_coverage = {}
        analyzer.is_cancelled = lambda: False
        analyzer._progress = lambda *unused_a, **unused_kw: None
        return analyzer

    def test_review_findings_follow_the_agents(self, tmp_path):
        """
        Purpose:
            Pin that the review's findings are appended after the agent's and its telemetry recorded.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = _write(tmp_path, {"app_modules/1_App.js": "x();\n"})
        provider = _Provider({"response": json.dumps([{"title": "Issue", "line": "1", "description": "Found."}])})
        analyzer = self._analyzer(provider)
        out = analyzer._with_file_review([{"title": "Agent"}], root, None, "RN", [])
        assert [f["title"] for f in out] == ["Agent", "Issue"]
        assert analyzer.agent_coverage["file_review"]["findings"] == 1

    def test_an_unavailable_provider_or_a_failure_changes_nothing(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an unavailable provider is not asked again and that a failing pass leaves the agent's findings as they were.

        Parameters:
            tmp_path: Directory the tree is written into.
            monkeypatch: Makes the review raise.
        """
        agent = [{"title": "Agent"}]
        down = self._analyzer(SimpleNamespace(unavailable=True))
        assert down._with_file_review(agent, tmp_path, None, "RN", []) is agent

        def broken(*unused_a, **unused_kw):
            """
            Purpose:
                Fail the way an unexpected bug in the pass would.

            Parameters:
                unused_a: Ignored positional arguments.
                unused_kw: Ignored keyword arguments.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("boom")

        monkeypatch.setattr(file_review, "run_file_review", broken)
        analyzer = self._analyzer(_Provider())
        assert analyzer._with_file_review(agent, tmp_path, None, "RN", []) == agent


def _native_skill_title():
    """
    Purpose:
        Read the native skill's own title line, which only appears in a system prompt that loaded the skill.

    Returns:
        The title line.
    """
    from lu77U_MobileSec.analyzers.agent.skills_loader import skill_path
    return skill_path("native_library_analysis").read_text(encoding="utf-8").splitlines()[0]


class TestNativeReview:
    """
    Purpose:
        The native libraries the app loads are reviewed too, first, as the agent's decompiled view.
    """

    def test_native_libraries_come_first_with_the_native_skill(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a graph's native library is reviewed ahead of the source files, numbered as the decompiled view, with the native guidance loaded only then.

        Parameters:
            tmp_path: Directory the tree is written into.
            monkeypatch: Replaces the decompiled view with a fixed one.
        """
        root = _write(tmp_path, {"app_modules/1_App.js": "x();\n", "lib/arm64-v8a/libdemo.so": "ELF"})
        monkeypatch.setattr(AgentTools, "native_view",
                            lambda self, unused_rel: ["// ---- Java_demo_check", 'strcpy(local_48,__src);'])
        graph = _graph([("app_modules/1_App.js", "class", True)], native=["lib/arm64-v8a/libdemo.so"])
        provider = _Provider()
        run_file_review(provider, root, REACT_NATIVE, graph, "RN")
        prompt = provider.prompts[0]
        assert prompt.index("### lib/arm64-v8a/libdemo.so - native library") < prompt.index("### app_modules/1_App.js")
        assert "2: strcpy(local_48,__src);" in prompt
        assert _native_skill_title() in provider.systems[0]

    def test_without_native_libraries_the_skill_is_not_loaded(self, tmp_path):
        """
        Purpose:
            Pin that a pass with no native library does not carry the native guidance.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = _write(tmp_path, {"app_modules/1_App.js": "x();\n"})
        provider = _Provider()
        run_file_review(provider, root, REACT_NATIVE, _graph([("app_modules/1_App.js", "class", True)]), "RN")
        assert _native_skill_title() not in provider.systems[0]



@pytest.mark.parametrize("path,profile,expected", [
    ("AndroidManifest.xml", JAVA_KOTLIN, True),
    ("resources/AndroidManifest.xml", REACT_NATIVE, True),
    ("flutter_scan_overview.txt", FLUTTER, True),
    ("rn_scan_overview.txt", REACT_NATIVE, True),
    ("sources/com/app/Main.java", JAVA_KOTLIN, False),
])
def test_summary_files_count_as_read(path, profile, expected):
    """
    Purpose:
        Pin that the manifest and a profile's overview file count as read, since every opening context and review request shows them.

    Parameters:
        path: The cited file.
        profile: The framework profile.
        expected: Whether it counts as read.
    """
    from lu77U_MobileSec.analyzers.agent.agent_loop import context_file
    assert context_file(path, profile) is expected


def test_a_review_finding_citing_the_manifest_is_not_unread(tmp_path):
    """
    Purpose:
        Pin that a review finding citing the manifest is not marked as citing an unread file.

    Parameters:
        tmp_path: Directory the tree is written into.
    """
    root = _write(tmp_path, {"app_modules/1_App.js": "x();\n"})
    reply = [{"title": "Exported provider without permission", "file": "AndroidManifest.xml", "line": "3",
              "description": "Any app can read it."}]
    found = run_file_review(_Provider({"response": json.dumps(reply)}), root, REACT_NATIVE,
                            _graph([("app_modules/1_App.js", "class", True)]), "RN")
    assert found[0]["cited_file_read"] is True
