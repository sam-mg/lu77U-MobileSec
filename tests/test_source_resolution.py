#!/usr/bin/env python3
"""
Module: test_source_resolution

Purpose:
    Turning a filename a model reported into a real path in a decompiled tree full of files sharing the same name.

Responsibilities:
    Pin exact and prefixed resolution, refusal when a bare filename is ambiguous, disambiguation by the construct the finding claims, how enrichment marks what could not be resolved, and the repair of paths the decompiler renamed as it wrote them.

Dependencies:
    pytest, the Java/Kotlin analyzer, the code graph and the decompiler wrapper.

Implementation notes:
    A real decompiled tree held 50 files named one letter and 162 named another, because obfuscated class names collide constantly. The old fallback returned whichever twin the filesystem happened to list first, which is not even stable between two runs over the same tree. The rule these pin is to refuse rather than guess, and to use the construct the finding claims when that identifies exactly one twin.
"""

import re

import pytest

from lu77U_MobileSec.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer


@pytest.fixture
def analyzer():
    """
    Purpose:
        Provide the analyzer whose resolution is under test.

    Returns:
        The analyzer.
    """
    return JavaKotlinAnalyzer()


def _write(tmp_path, rel, text=""):
    """
    Purpose:
        Write one source file into the decompiled tree, creating the directories it needs.

    Parameters:
        tmp_path: The tree root.
        rel: The path under the source directory.
        text: The file's contents.

    Returns:
        The path written to.
    """
    path = tmp_path / "sources" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class TestExactAndPrefixResolution:
    """
    Purpose:
        Resolution when the reported path identifies the file on its own.
    """
    def test_an_exact_relative_path_wins_over_a_basename_twin(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a full relative path resolves to that exact file even when another file shares its name.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        one = _write(tmp_path, "A/D.java", "class D {}")
        _write(tmp_path, "B/D.java", "class D {}")
        resolved = analyzer.resolve_source_path(tmp_path, "sources/A/D.java")
        assert resolved == one

    def test_a_prefix_is_tried_when_the_bare_path_misses(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a path missing the tree's leading directory is still resolved.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            A model reports the path it read, which is relative to the source directory rather than to the tree root, so the prefix has to be supplied here or every path would miss.
        """
        one = _write(tmp_path, "com/app/Main.java", "class Main {}")
        resolved = analyzer.resolve_source_path(tmp_path, "com/app/Main.java")
        assert resolved == one


class TestBasenameDisambiguation:
    """
    Purpose:
        Resolution when only a bare filename was reported and several files carry it.
    """
    def test_a_single_basename_match_still_resolves(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a bare filename with exactly one match resolves to it.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        one = _write(tmp_path, "A/Unique.java", "class Unique {}")
        resolved = analyzer.resolve_source_path(tmp_path, "Unique.java")
        assert resolved == one

    def test_a_partial_path_suffix_resolves_without_scanning_twins(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a partial path identifies one file among several sharing its name.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        target = _write(tmp_path, "A/D.java", "class D {}")
        _write(tmp_path, "B/D.java", "class D {}")
        _write(tmp_path, "C/D.java", "class D {}")
        resolved = analyzer.resolve_source_path(tmp_path, "A/D.java")
        assert resolved == target

    def test_fifty_same_basename_files_are_refused_rather_than_guessed(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a bare filename matching many files resolves to nothing.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            Refusing is the whole point. A guess attaches a finding's code excerpt to a file that has nothing to do with it, which reads to the user as a confident report about the wrong class.
        """
        for i in range(50):
            _write(tmp_path, f"pkg{i}/D.java", "class D { int x; }")
        assert analyzer.resolve_source_path(tmp_path, "D.java") is None

    def test_the_claimed_construct_picks_the_right_twin(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that the construct a finding claims picks out the one file that contains it.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        target = _write(
            tmp_path, "A/D.java",
            'SecretKeySpec key = new SecretKeySpec(bytes, "AES");')
        for i in range(49):
            _write(tmp_path, f"pkg{i}/D.java", "class D { int x; }")
        resolved = analyzer.resolve_source_path(
            tmp_path, "D.java", claim_terms=["aes"])
        assert resolved == target

    def test_two_twins_both_containing_the_construct_are_refused(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that when the claimed construct appears in more than one file, resolution still refuses.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            The construct narrows the candidates rather than choosing between them, so two survivors is still ambiguity and picking either one would be the guess this exists to prevent.
        """
        _write(tmp_path, "A/D.java", 'new SecretKeySpec(bytes, "AES");')
        _write(tmp_path, "B/D.java", 'new SecretKeySpec(bytes, "AES");')
        resolved = analyzer.resolve_source_path(
            tmp_path, "D.java", claim_terms=["aes"])
        assert resolved is None

    def test_no_basename_match_at_all_is_none(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a filename nothing in the tree carries resolves to nothing.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        assert analyzer.resolve_source_path(tmp_path, "Nope.java") is None

    def test_resolution_is_stable_across_calls(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that repeated resolutions of an ambiguous name all refuse identically.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            The regression guarded here is a different file winning between runs, not simply some file winning, and refusing every time is exactly as stable as returning one fixed path would be.
        """
        for i in range(10):
            _write(tmp_path, f"pkg{i}/Twin.java", "class Twin {}")
        results = {analyzer.resolve_source_path(tmp_path, "Twin.java") for _ in range(5)}
        assert results == {None}

    def test_a_disambiguated_resolution_is_stable_across_calls(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that repeated resolutions disambiguated by a claimed construct all return the same file.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        target = _write(tmp_path, "A/Twin.java", 'MessageDigest.getInstance("SHA-1")')
        for i in range(9):
            _write(tmp_path, f"pkg{i}/Twin.java", "class Twin {}")
        results = {analyzer.resolve_source_path(tmp_path, "Twin.java", claim_terms=["sha1"])
                  for _ in range(5)}
        assert results == {target}


class TestEnrichmentMarksUnresolvedFindings:
    """
    Purpose:
        What enrichment attaches to a finding, and what it marks when it cannot.
    """
    def test_an_unresolved_finding_is_marked_and_left_untouched(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a finding whose file could not be resolved is marked as such and given no excerpt.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            The mark is what lets the report say the location is uncertain rather than presenting a guessed one as fact.
        """
        for i in range(50):
            _write(tmp_path, f"pkg{i}/D.java", "class D { int x; }")
        vulns = [{"title": "Hardcoded AES key in D.java", "file": "D.java",
                 "line_number": 1}]
        analyzer.enrich_vulnerabilities(vulns, tmp_path)
        assert vulns[0]["source_unresolved"] is True
        assert "code_context" not in vulns[0]
        assert "code_snippet" not in vulns[0] or not vulns[0].get("code_snippet")

    def test_a_resolved_finding_is_enriched_normally(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a finding whose file resolved is given its excerpt with the right line highlighted and carries no mark.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
        """
        _write(tmp_path, "A/Main.java", "class Main {\n  int x = 1;\n}\n")
        vulns = [{"title": "Something", "file": "A/Main.java", "line_number": 2}]
        analyzer.enrich_vulnerabilities(vulns, tmp_path)
        assert "source_unresolved" not in vulns[0]
        assert vulns[0]["code_context"]["highlight_start"] == 2

    def test_a_binary_file_gets_no_fabricated_snippet(self, tmp_path, analyzer):
        """
        Purpose:
            Pin that a finding pointing at a binary is given no excerpt and is not marked unresolved either.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.

        Implementation notes:
            A real scan resolved a native library, since the decompiler writes those into the tree and the analyzer searches that directory as a prefix, and shipped its raw bytes into the report as an unreadable excerpt. The finding itself is real and only its excerpt would be rubbish, so the excerpt is left off rather than the finding being downgraded as though its location were unknown.
        """
        lib_dir = tmp_path / "resources" / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libdivajni.so").write_bytes(
            b"\x7fELF" + b"\x00" * 12 + b"\x02\x00\xb7\x00" + bytes(range(200)))
        vulns = [{"title": "Native buffer overflow",
                 "file": "resources/lib/arm64-v8a/libdivajni.so", "line_number": 1}]
        analyzer.enrich_vulnerabilities(vulns, tmp_path)
        assert "code_context" not in vulns[0]
        assert "code_snippet" not in vulns[0] or not vulns[0].get("code_snippet")
        assert "source_unresolved" not in vulns[0]


    def test_a_native_finding_takes_its_excerpt_from_the_decompiled_view(self, tmp_path, analyzer, monkeypatch):
        """
        Purpose:
            Pin that a finding citing a native library is given the decompiled line it cited, with the whole function as context and labelled as Ghidra pseudo-C, when Ghidra produced code for that library.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
            monkeypatch: Supplies a decompilation in place of running Ghidra.

        Implementation notes:
            The agent cites native findings by the line numbers of the inspect_native view, so the excerpt must come from that same view. The line number used here is found from the view itself rather than hard-coded, which keeps the test about the mapping rather than about the view's layout.
        """
        from lu77U_MobileSec.analyzers.agent import tools as agent_tools
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools
        from lu77U_MobileSec.decompiler.ghidra_runner import NativeDecompilation, NativeFunction

        lib_dir = tmp_path / "resources" / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libdivajni.so").write_bytes(
            b"\x7fELF" + b"\x00" * 12 + b"\x02\x00\xb7\x00" + bytes(range(200)))
        code = ("void Java_a_B_launch(long *param_1,long param_2,long param_3)\n\n{\n"
                "  char local_18 [24];\n  strcpy(local_18,__src);\n}")
        decompiled = NativeDecompilation(
            language="AARCH64:LE:64:v8A", pointer_size=8, function_count=1,
            functions=[NativeFunction(name="Java_a_B_launch", entry="00100100", size=40,
                                      calls=["strcpy"], code=code)])
        monkeypatch.setattr(agent_tools, "decompile_native_library",
                            lambda path: decompiled if path.suffix == ".so" else None)
        rel = "resources/lib/arm64-v8a/libdivajni.so"
        view = AgentTools(tmp_path).native_view(rel)
        cited = next(i for i, line in enumerate(view, 1) if re.search(r"strcpy\(local_18", line))

        vulns = [{"title": "Unbounded strcpy into a stack buffer", "file": rel, "line_number": cited}]
        analyzer.enrich_vulnerabilities(vulns, tmp_path)
        assert vulns[0]["code_snippet"].strip() == "strcpy(local_18,__src);"
        assert vulns[0]["code_context"]["highlight_start"] == cited
        context = vulns[0]["code_context"]
        assert context["origin"].startswith("Ghidra decompilation (pseudo-C)")
        assert context["lines"][0].startswith("// Ghidra decompilation (pseudo-C) of Java_a_B_launch @ 00100100")
        assert any(re.search(r"void Java_a_B_launch\(", line) for line in context["lines"])
        assert "source_unresolved" not in vulns[0]

    def test_a_native_finding_citing_an_address_is_repaired(self, tmp_path, analyzer, monkeypatch):
        """
        Purpose:
            Pin that a native finding whose line field holds the function's entry address still gets the decompiled call it describes, not the symbol table at the end of the view.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
            monkeypatch: Supplies a decompilation in place of running Ghidra.

        Implementation notes:
            This is what a real DIVA scan produced: "line": "001005e0". The parser turned it into a number far past the end of the view, and the excerpt clamped onto the last lines, which are symbols.
        """
        from lu77U_MobileSec.analyzers.agent import tools as agent_tools
        from lu77U_MobileSec.decompiler.ghidra_runner import NativeDecompilation, NativeFunction

        lib_dir = tmp_path / "resources" / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libdivajni.so").write_bytes(
            b"\x7fELF" + b"\x00" * 12 + b"\x02\x00\xb7\x00" + bytes(range(200)))
        code = ("void Java_a_B_initiateLaunchSequence(long *param_1,long param_2,long param_3)\n\n{\n"
                "  char local_18 [24];\n  strcpy(local_18,__src);\n}")
        decompiled = NativeDecompilation(
            language="AARCH64:LE:64:v8A", pointer_size=8, function_count=1,
            functions=[NativeFunction(name="Java_a_B_initiateLaunchSequence", entry="001005e0",
                                      size=40, calls=["strcpy"], code=code)])
        monkeypatch.setattr(agent_tools, "decompile_native_library",
                            lambda path: decompiled if path.suffix == ".so" else None)

        vulns = [{"title": "Stack buffer overflow via unbounded strcpy",
                  "description": "initiateLaunchSequence strcpy's the Java string into 24 bytes",
                  "file": "resources/lib/arm64-v8a/libdivajni.so",
                  "line": "001005e0", "line_number": 1005}]
        analyzer.enrich_vulnerabilities(vulns, tmp_path)
        assert vulns[0]["code_snippet"].strip() == "strcpy(local_18,__src);"

    def test_a_native_finding_naming_its_function_survives_the_claim_gate(self, tmp_path, analyzer, monkeypatch):
        """
        Purpose:
            Pin that a native finding whose title names its JNI method is not refuted when the defect sits well below the function's signature.

        Parameters:
            tmp_path: The tree root.
            analyzer: The analyzer under test.
            monkeypatch: Supplies a decompilation in place of running Ghidra.

        Implementation notes:
            A real DIVA scan refuted "Stack overflow via unbounded strcpy in initiateLaunchSequence JNI fn": the excerpt was the strcpy line with four lines either side, the signature naming initiateLaunchSequence was nine lines above, and the API-claim gate found the named method nowhere in the evidence. Showing the whole function is what keeps the name in the evidence.
        """
        from lu77U_MobileSec.analyzers.agent import tools as agent_tools
        from lu77U_MobileSec.decompiler.ghidra_runner import NativeDecompilation, NativeFunction
        from lu77U_MobileSec.validation.gates import apply_gates

        lib_dir = tmp_path / "resources" / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libdivajni.so").write_bytes(
            b"\x7fELF" + b"\x00" * 12 + b"\x02\x00\xb7\x00" + bytes(range(200)))
        locals_ = "\n".join(f"  int iVar{i};" for i in range(10))
        code = ("bool Java_jakhar_aseem_diva_DivaJni_initiateLaunchSequence\n"
                "               (long *param_1,undefined8 param_2,undefined8 param_3)\n\n{\n"
                f"{locals_}\n  char local_18 [24];\n\n"
                "  strcpy(local_18,__src);\n  return 0;\n}")
        decompiled = NativeDecompilation(
            language="AARCH64:LE:64:v8A", pointer_size=8, function_count=1,
            functions=[NativeFunction(name="Java_jakhar_aseem_diva_DivaJni_initiateLaunchSequence",
                                      entry="001005e0", size=108, calls=["strcpy"], code=code)])
        monkeypatch.setattr(agent_tools, "decompile_native_library",
                            lambda path: decompiled if path.suffix == ".so" else None)
        rel = "resources/lib/arm64-v8a/libdivajni.so"
        view = agent_tools.AgentTools(tmp_path).native_view(rel)
        cited = next(i for i, line in enumerate(view, 1) if re.search(r"strcpy\(local_18", line))
        signature = next(i for i, line in enumerate(view, 1) if re.match(r"bool Java_", line))
        assert cited - signature > 4

        vuln = {"title": "Stack overflow via unbounded strcpy in initiateLaunchSequence JNI fn",
                "description": "The JNI string is copied into a 24-byte stack buffer.",
                "file": rel, "line": str(cited), "line_number": cited, "severity": "High",
                "confidence": "HIGH", "source": "agent"}
        analyzer.enrich_vulnerabilities([vuln], tmp_path)
        assert vuln["code_snippet"].strip() == "strcpy(local_18,__src);"
        result = apply_gates(vuln)
        assert result.mechanically_refuted is False
        assert result.verdict != "FALSE_POSITIVE"

class TestJadxRenameResolution:
    """
    Purpose:
        Repairing paths the decompiler changed as it wrote them.

    Implementation notes:
        The decompiler renames anything it cannot write verbatim. On a filesystem that ignores letter case, two obfuscated names differing only in case cannot share a directory, so the name recorded in the bytecode stops predicting the file that was emitted. On one real application that left 69 of 198 graph nodes pointing at files that were not there.
    """
    def test_a_renamed_package_is_undone(self):
        """
        Purpose:
            Pin that a renamed package is reduced to its original name and that packages which merely resemble the renamed form are left alone.

        Implementation notes:
            The rename prefix is a single letter followed by digits, which is also how several ordinary package names begin, so the untouched cases are as load-bearing as the reversed ones.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _original_package

        assert _original_package("p012aa") == "aa"
        assert _original_package("p151n9") == "n9"
        assert _original_package("com.example.app") == "com.example.app"
        assert _original_package("payments.core") == "payments.core"
        assert _original_package("p2p.client") == "p2p.client"

    def test_the_index_resolves_both_rename_kinds(self, tmp_path):
        """
        Purpose:
            Pin that the source index maps the original name to the emitted file for a renamed package, for a renamed class, and for a file that was not renamed at all.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            The two rename kinds leave different evidence: a renamed package shows only in the declaration inside the file, while a renamed class is recorded in a note the decompiler writes above it, so the index has to read both.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _build_source_index

        src = tmp_path / "sources"
        (src / "p012aa").mkdir(parents=True)
        (src / "p012aa" / "B.java").write_text(
            "package p012aa;\n\npublic interface B {\n}\n", encoding="utf-8")
        (src / "oa").mkdir(parents=True)
        (src / "oa" / "AbstractC0891b.java").write_text(
            "package oa;\n\n"
            "/* JADX INFO: renamed from: oa.b, reason: case insensitive filesystem */\n"
            "public abstract class AbstractC0891b {\n}\n", encoding="utf-8")
        (src / "com" / "example").mkdir(parents=True)
        (src / "com" / "example" / "Main.java").write_text(
            "package com.example;\n\npublic class Main {\n}\n", encoding="utf-8")

        index = _build_source_index(tmp_path)
        assert index["aa.B"] == "sources/p012aa/B.java"
        assert index["oa.b"] == "sources/oa/AbstractC0891b.java"
        assert index["com.example.Main"] == "sources/com/example/Main.java"

    def test_a_node_pointing_at_a_renamed_file_is_repaired_not_dropped(self, tmp_path):
        """
        Purpose:
            Pin that a graph node whose path was renamed is repaired to the emitted path and reported as readable.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            Dropping the node instead would remove a class from the graph entirely, which is invisible in the output and simply means the agent never looks at it.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import (
            CodeNode, _verify_source_paths)

        src = tmp_path / "sources" / "p012aa"
        src.mkdir(parents=True)
        (src / "B.java").write_text("package p012aa;\npublic interface B {}\n",
                                    encoding="utf-8")
        node = CodeNode(cls="B", file="sources/aa/B.java", descriptor="Laa/B;")
        stats = _verify_source_paths({"Laa/B;": node}, tmp_path, verbose=False)

        assert stats["repaired"] == 1 and stats["missing"] == 0
        assert node.file == "sources/p012aa/B.java"
        assert node.source_available is True

    def test_a_class_the_decompiler_never_emitted_is_marked_unreadable(self, tmp_path):
        """
        Purpose:
            Pin that a node with no emitted file behind it is counted as missing and marked unreadable rather than repaired.

        Parameters:
            tmp_path: The tree root.

        Implementation notes:
            The mark is what stops the agent spending a step trying to read a file that does not exist.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import (
            CodeNode, _verify_source_paths)

        (tmp_path / "sources").mkdir()
        node = CodeNode(cls="Gone", file="sources/x/Gone.java", descriptor="Lx/Gone;")
        stats = _verify_source_paths({"Lx/Gone;": node}, tmp_path, verbose=False)

        assert stats["missing"] == 1 and stats["repaired"] == 0
        assert node.source_available is False

    def test_case_sensitivity_is_probed_not_assumed(self, tmp_path):
        """
        Purpose:
            Pin that the filesystem's treatment of letter case is measured by probing it, and that the probe leaves nothing behind.

        Parameters:
            tmp_path: The directory to probe.

        Implementation notes:
            The operating system's name does not answer the question: a case-sensitive volume can be mounted on a system that usually is not, and the reverse is equally common.
        """
        from lu77U_MobileSec.decompiler.java_kotlin_decompiler import JavaKotlinDecompiler

        result = JavaKotlinDecompiler._filesystem_is_case_sensitive(tmp_path)
        assert isinstance(result, bool)
        assert not list(tmp_path.glob(".jadx_case_probe*"))
