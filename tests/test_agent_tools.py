#!/usr/bin/env python3
"""
Module: test_agent_tools

Purpose:
    The phase-1 tool surface the agent reads a decompiled tree through: the sandbox, the paged reader, the noise filtering and the search.

Responsibilities:
    Pin that no path escapes the source root, that reading pages through a large file rather than truncating it, that decompiler diagnostics are hidden without shifting any line number, that searching behaves on malformed patterns, and that the inventory leaves generated files out.

Dependencies:
    pytest and the agent tool surface.

Security considerations:
    Every path here arrives from the model, so the sandbox is the control that keeps a prompt-driven read inside the decompiled tree rather than reaching the analyst's own filesystem.
"""

import pytest

from lu77U_MobileSec.analyzers.agent.tools import (
    AgentTools, MAX_READ_CHARS, MIN_NATIVE_STRING_LEN,
    _extract_native_strings, _native_signal_summary)

@pytest.fixture
def tree(tmp_path):
    """
    Purpose:
        Build a decompiled tree with application source, resources, a manifest, and a file at the root outside the usual directories.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "sources" / "com" / "app").mkdir(parents=True)
    (tmp_path / "resources" / "res" / "values").mkdir(parents=True)
    (tmp_path / "sources" / "com" / "app" / "Main.java").write_text(
        "package com.app;\nclass Main {\n  String key = \"abc123\";\n}\n")
    (tmp_path / "resources" / "AndroidManifest.xml").write_text("<manifest/>")
    (tmp_path / "resources" / "res" / "values" / "strings.xml").write_text("<resources/>")
    (tmp_path / "secret_outside.txt").write_text("should stay reachable, it is in the root")
    return tmp_path

@pytest.fixture
def tools(tree):
    """
    Purpose:
        Build the tool surface over the tree.

    Parameters:
        tree: The decompiled tree.

    Returns:
        The tool surface.
    """
    return AgentTools(tree)

class TestSandbox:
    """
    Purpose:
        That no path reaches outside the source root.
    """
    @pytest.mark.parametrize("path", [
        "../etc/passwd",
        "../../../../etc/passwd",
        "sources/../../outside.txt",
    ])
    def test_escape_attempts_are_refused(self, tools, path):
        """
        Purpose:
            Pin that a traversing path is refused by both the reader and the lister.

        Parameters:
            tools: The tool surface.
            path: A path attempting to climb out of the root.

        Security considerations:
            Both entry points are asserted, because a sandbox closed on one tool and open on the other is no sandbox at all.
        """
        assert tools.read_file(path).startswith("ERROR")
        assert tools.list_files(path).startswith("ERROR")

    def test_absolute_path_outside_the_root_is_refused(self, tools):
        """
        Purpose:
            Pin that an absolute path naming a real file outside the root is refused.

        Parameters:
            tools: The tool surface.
        """
        assert tools.read_file("/etc/passwd").startswith("ERROR")

    def test_paths_inside_the_root_resolve(self, tools):
        """
        Purpose:
            Pin that an ordinary path inside the root reads its file, so the sandbox is not simply refusing everything.

        Parameters:
            tools: The tool surface.
        """
        assert "class Main" in tools.read_file("sources/com/app/Main.java")

    def test_leading_slash_is_treated_as_relative(self, tools):
        """
        Purpose:
            Pin that a path written with a leading separator is read relative to the root rather than as absolute.

        Parameters:
            tools: The tool surface.

        Implementation notes:
            Models write paths both ways, and refusing the leading separator would cost a step every time on a path that is otherwise perfectly valid.
        """
        assert "class Main" in tools.read_file("/sources/com/app/Main.java")

class TestReadFile:
    """
    Purpose:
        The reader, including how it pages through a file too large for one window.
    """
    def test_line_gutter_is_one_based(self, tools):
        """
        Purpose:
            Pin that the line numbers shown start at one.

        Parameters:
            tools: The tool surface.

        Implementation notes:
            Findings are reported by line number against what the model was shown, so an off-by-one here shifts every finding in the scan.
        """
        first = tools.read_file("sources/com/app/Main.java").splitlines()[0]
        assert first.strip().startswith("1| package com.app;")

    def test_missing_file(self, tools):
        """
        Purpose:
            Pin that reading a file that does not exist returns an error the agent can read.

        Parameters:
            tools: The tool surface.
        """
        assert tools.read_file("nope.java").startswith("ERROR")

    def test_large_file_pages_instead_of_truncating(self, tree):
        """
        Purpose:
            Pin that a large file is served in windows within the size budget, with the next read continuing where the first stopped.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            The budget applies to the file's own content, and the line-number gutter adds a few characters per line on top of it, so the assertion measures the content rather than the rendered output. Paging rather than truncating is what lets the agent reach the end of a large class at all.
        """
        body = "\n".join(f"int x{i} = {i};" for i in range(4000))
        (tree / "Big.java").write_text(body)
        tools = AgentTools(tree)

        first = tools.read_file("Big.java")
        assert "read_file again" in first
        content = sum(len(line.split("| ", 1)[-1]) + 1
                      for line in first.splitlines() if "| " in line)
        assert content <= MAX_READ_CHARS

        second = tools.read_file("Big.java")
        assert second != first
        assert "int x0 = 0;" not in second

    def test_start_line_jumps(self, tree):
        """
        Purpose:
            Pin that an explicit starting line moves the window there rather than to the top.

        Parameters:
            tree: The decompiled tree.
        """
        (tree / "Lines.java").write_text("\n".join(f"line{i}" for i in range(1, 21)))
        tools = AgentTools(tree)
        out = tools.read_file("Lines.java", start_line=15)
        assert "line15" in out and "line1\n" not in out

    def test_a_small_exhausted_file_is_re_served_from_the_top(self, tree):
        """
        Purpose:
            Pin that re-reading a file that fits in one window returns its content again rather than a note saying it was already read.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            A read whose cursor was already past the end used to return a dead note even for a tiny file, including when a batch read had consumed the cursor without ever appearing in the log as a read of its own. A file that fits in one window costs nothing to serve again, so a plain re-read gets the content back instead of spending a turn on a refusal.
        """
        (tree / "Tiny.java").write_text("one line")
        tools = AgentTools(tree)
        first = tools.read_file("Tiny.java")
        second = tools.read_file("Tiny.java")
        assert second == first
        assert "one line" in second
        assert not second.startswith("NOTE:")

    def test_reading_past_the_end_of_a_large_file_says_so(self, tree):
        """
        Purpose:
            Pin that a genuinely paged file whose cursor is spent returns an explicit note rather than starting over.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            Re-serving a large file from the top would spend the budget the paging exists to protect, so the two cases deliberately behave differently.
        """
        body = "\n".join(f"int x{i} = {i};" for i in range(4000))
        (tree / "Big.java").write_text(body)
        tools = AgentTools(tree)
        total_lines = len(body.splitlines())
        tools.read_file("Big.java", start_line=total_lines)
        assert tools.read_file("Big.java").startswith("NOTE: already read to the end")


class TestJadxNoiseCollapsing:
    """
    Purpose:
        Hiding the decompiler's own diagnostics from what the reader shows the model.

    Implementation notes:
        A real scan cited a decompiler stack trace as evidence of hardcoded credentials; the line it quoted was a bare stack frame from the decompiler's own internals. These pin that such blocks are stripped out of what the model sees without shifting any other line's number.
    """
    def _multiline_block(self):
        """
        Purpose:
            Build a source file holding a multi-line decompiler error block with real code after it.

        Returns:
            The file's contents.
        """
        return (
            "class C {\n"
            "  /*  JADX ERROR: Error in decompile pass: KotlinMetadataDecompile\n"
            "      java.lang.UnsupportedOperationException\n"
            "      \tat jadx.plugins.kotlin.metadata.pass."
            "KotlinMetadataDecompilePass.visit(KotlinMetadataDecompilePass.kt:33)\n"
            "  */\n"
            "  void real() { int x = 1; }\n"
            "}\n"
        )

    def test_the_stack_trace_is_not_shown(self, tree):
        """
        Purpose:
            Pin that neither the stack frame nor the exception name reaches the model.

        Parameters:
            tree: The decompiled tree.
        """
        (tree / "C.java").write_text(self._multiline_block())
        tools = AgentTools(tree)
        out = tools.read_file("C.java")
        assert "KotlinMetadataDecompilePass.visit" not in out
        assert "UnsupportedOperationException" not in out

    def test_a_marker_replaces_the_block(self, tree):
        """
        Purpose:
            Pin that the hidden block is replaced by a marker saying what it was.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            Silently blanking it would leave the model to guess why a stretch of the file is empty; the marker tells it the gap is the decompiler's output rather than the application's code.
        """
        (tree / "C.java").write_text(self._multiline_block())
        tools = AgentTools(tree)
        assert "decompiler output, not app code" in tools.read_file("C.java")

    def test_line_numbers_after_the_block_are_unchanged(self, tree):
        """
        Purpose:
            Pin that code following a collapsed block keeps the line number it has in the real file.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            Collapsing has to blank lines rather than remove them, because every finding's line number is reported against what the model was shown and would otherwise point at the wrong place in the file on disk.
        """
        (tree / "C.java").write_text(self._multiline_block())
        tools = AgentTools(tree)
        out = tools.read_file("C.java")
        real_line = next(l for l in out.splitlines() if "void real()" in l)
        assert real_line.strip().startswith("6|")

    def test_a_single_line_jadx_warn_comment_is_collapsed(self, tree):
        """
        Purpose:
            Pin that a one-line decompiler warning is collapsed the same way, with the line numbers after it unchanged.

        Parameters:
            tree: The decompiled tree.
        """
        (tree / "C.java").write_text(
            "class C {\n"
            "  /* JADX WARN: Removed duplicated region for block: B:32:0x008a "
            "A[Catch: Exception -> 0x0071] */\n"
            "  void real() { int x = 1; }\n"
            "}\n"
        )
        tools = AgentTools(tree)
        out = tools.read_file("C.java")
        assert "Removed duplicated region" not in out
        assert "decompiler output, not app code" in out
        real_line = next(l for l in out.splitlines() if "void real()" in l)
        assert real_line.strip().startswith("3|")

    def test_ordinary_code_is_unaffected(self, tools):
        """
        Purpose:
            Pin that an ordinary file is shown in full with no marker added.

        Parameters:
            tools: The tool surface.
        """
        out = tools.read_file("sources/com/app/Main.java")
        assert "abc123" in out
        assert "decompiler output" not in out

    def test_an_unterminated_block_blanks_to_the_end_without_crashing(self, tree):
        """
        Purpose:
            Pin that a diagnostic block the file never closes is blanked to the end rather than raising.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            A file cut short mid-block is exactly what a failed decompile leaves behind, so this is the ordinary case rather than a malformed one.
        """
        (tree / "C.java").write_text(
            "class C {\n"
            "  /* JADX ERROR: something failed\n"
            "  and the comment never closes\n"
        )
        tools = AgentTools(tree)
        out = tools.read_file("C.java")
        assert "decompiler output, not app code" in out
        assert "never closes" not in out


class TestSearch:
    """
    Purpose:
        Searching the tree for a pattern.
    """
    def test_matches_include_file_and_line(self, tools):
        """
        Purpose:
            Pin that a match reports the file and the line it was found on.

        Parameters:
            tools: The tool surface.
        """
        out = tools.search_code("key")
        assert "Main.java:3:" in out

    def test_empty_pattern(self, tools):
        """
        Purpose:
            Pin that an empty pattern is refused rather than matching everything.

        Parameters:
            tools: The tool surface.
        """
        assert tools.search_code("").startswith("ERROR")

    def test_invalid_regex_falls_back_to_literal(self, tree):
        """
        Purpose:
            Pin that a pattern which is not valid as an expression is searched for literally instead.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            A model often searches for a fragment of code containing brackets, which is not a valid expression, and refusing would cost a step on what is obviously a literal search.
        """
        (tree / "Odd.java").write_text("value = a[unclosed;\n")
        out = AgentTools(tree).search_code("[unclosed")
        assert "Odd.java:1:" in out

    def test_no_matches(self, tools):
        """
        Purpose:
            Pin that a pattern with no matches says so plainly rather than returning nothing at all.

        Parameters:
            tools: The tool surface.
        """
        assert tools.search_code("zzzz-not-present") == "(no matches)"

class TestInventory:
    """
    Purpose:
        The listings the agent uses to orient itself in the tree.
    """
    def test_app_source_files_skips_generated(self, tree):
        """
        Purpose:
            Pin that generated classes are left out of the source listing while real ones are kept.

        Parameters:
            tree: The decompiled tree.

        Implementation notes:
            Those files are produced by the build rather than written by anyone, and reading them spends steps out of a tight budget on code nobody wrote.
        """
        (tree / "sources" / "com" / "app" / "R.java").write_text("class R {}")
        (tree / "sources" / "com" / "app" / "BuildConfig.java").write_text("class BuildConfig {}")
        tools = AgentTools(tree)
        names = [p.rsplit("/", 1)[-1] for p in tools.app_source_files()]
        assert "Main.java" in names
        assert "R.java" not in names and "BuildConfig.java" not in names

    def test_app_resource_files_lists_strings(self, tools):
        """
        Purpose:
            Pin that resource XML appears in the resource listing.

        Parameters:
            tools: The tool surface.
        """
        assert any("strings.xml" in entry for entry in tools.app_resource_files())

    def test_manifest_summary(self, tools):
        """
        Purpose:
            Pin that the manifest's contents reach the summary.

        Parameters:
            tools: The tool surface.
        """
        assert "<manifest/>" in tools.manifest_summary()

    def test_manifest_missing(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no manifest yields a summary saying so rather than raising.

        Parameters:
            tmp_path: An empty tree root.

        Implementation notes:
            The summary is placed in the agent's opening prompt, so a failure here would end the scan before the first turn.
        """
        assert AgentTools(tmp_path).manifest_summary() == "(AndroidManifest.xml not found)"


class TestNativeStringExtraction:
    """
    Purpose:
        The pure-Python printable-run extractor behind native inspection.
    """
    def test_short_runs_are_dropped_and_long_runs_kept(self):
        """
        Purpose:
            Pin that only runs of at least the minimum length survive, split on non-printable bytes.
        """
        blob = b"ab\x00" + b"A" * MIN_NATIVE_STRING_LEN + b"\x00\x01" + b"hello world\x00"
        out = _extract_native_strings(blob)
        assert "A" * MIN_NATIVE_STRING_LEN in out
        assert "hello world" in out
        assert "ab" not in out

    def test_runs_are_deduplicated(self):
        """
        Purpose:
            Pin that a string repeated in the bytes appears once.
        """
        out = _extract_native_strings(b"repeated_token\x00\x00repeated_token\x00")
        assert out.count("repeated_token") == 1


class TestNativeSignalSummary:
    """
    Purpose:
        The signal sections derived from a native library's symbols and strings.
    """
    def test_risky_symbols_match_the_exact_name_not_a_substring(self):
        """
        Purpose:
            Pin that a risky import is surfaced by exact symbol name while a longer name containing it is not.

        Implementation notes:
            filesystem contains system; matching by substring would misreport it as a command-execution import.
        """
        symbols = ("0 g DF .text 0 Base system@GLIBC_2.2.5\n"
                   "0 g DF .text 0 Base filesystem\n"
                   "0 g DF .text 0 Base dlopen\n")
        out = _native_signal_summary(symbols, [])
        assert "Risky imported/exported symbols" in out
        assert "  system" in out
        assert "  dlopen" in out
        assert "filesystem" not in out

    def test_jni_entry_points_come_from_symbols_and_strings(self):
        """
        Purpose:
            Pin that JNI functions are recovered from either the symbol table or the extracted strings.
        """
        out = _native_signal_summary("0 g DF .text 0 Base Java_com_app_A_native\n",
                                     ["Java_com_app_B_other", "not a jni name"])
        assert "JNI entry points" in out
        assert "Java_com_app_A_native" in out
        assert "Java_com_app_B_other" in out

    def test_endpoints_and_secrets_are_summarised_with_values_withheld(self):
        """
        Purpose:
            Pin that an embedded URL is listed and a private credential is named without its value, while a public identifier keeps its value.
        """
        strings = ["http://evil.example/api/login",
                   "AIza" + "A" * 35,
                   "https://myapp.firebaseio.com"]
        out = _native_signal_summary("", strings)
        assert "http://evil.example/api/login" in out
        assert "[cleartext]" in out
        assert "Google API Key (value withheld)" in out
        assert "AIza" + "A" * 35 not in out
        assert "public identifier" in out


class TestInspectNative:
    """
    Purpose:
        The native-library inspection tool end to end.
    """
    def _write_so(self, root, rel, data):
        """
        Purpose:
            Write a fake native library into the tree.

        Parameters:
            root: The tree root.
            rel: The library's path relative to the root.
            data: The bytes to write.

        Returns:
            The path written.
        """
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_non_so_suffix_is_refused(self, tools, tree):
        """
        Purpose:
            Pin that a file without a .so suffix is rejected.

        Parameters:
            tools: The tool surface.
            tree: The tree root.
        """
        (tree / "notes.txt").write_bytes(b"plain")
        assert tools.inspect_native("notes.txt").startswith("ERROR: not a native library")

    def test_missing_file_is_refused(self, tools):
        """
        Purpose:
            Pin that a missing library path is rejected rather than raising.

        Parameters:
            tools: The tool surface.
        """
        assert tools.inspect_native("lib/absent.so").startswith("ERROR: not a file")

    def test_string_signals_are_surfaced_without_objdump(self, tree):
        """
        Purpose:
            Pin that the endpoint, JNI, and credential signals derived from the library's strings appear even when the symbol dump is empty.

        Parameters:
            tree: The tree root.

        Implementation notes:
            objdump on a non-ELF fake produces no usable symbols, so this exercises the string-derived path that does not depend on it.
        """
        blob = (b"Java_com_app_Foo_bar\x00"
                b"http://evil.example/api\x00"
                b"AIza" + b"A" * 35 + b"\x00")
        self._write_so(tree, "lib/libx.so", blob)
        out = AgentTools(tree).inspect_native("lib/libx.so")
        assert "http://evil.example/api" in out
        assert "Java_com_app_Foo_bar" in out
        assert "Credential candidates" in out
        assert "Google API Key (value withheld)" in out
