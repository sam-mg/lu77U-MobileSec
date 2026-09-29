#!/usr/bin/env python3
"""
Module: test_flutter_graph

Purpose:
    The Flutter code graph, built defensively from the disassembly tree and object pool a recovery tool produces.

Responsibilities:
    Pin node construction, role and signal detection, object-pool string recovery, and the degrade paths.

Dependencies:
    pytest, and the Flutter graph builder.
"""

import pytest

from lu77U_MobileSec.analyzers.flutter.graph import build_flutter_graph

@pytest.fixture
def blutter_out(tmp_path):
    """
    Purpose:
        Build a synthetic recovered-output tree with disassembly units and an object pool.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.

    Implementation notes:
        The pool deliberately mixes a credential, an endpoint and an innocuous string, so the tests can prove filtering keeps the first two and drops the third rather than simply capturing everything.
    """
    asm = tmp_path / "asm"
    asm.mkdir()
    (asm / "MainActivity.asm").write_text(
        "// class MainActivity\nvoid main() {\n  print('starting');\n}\n")
    (asm / "NetworkClient.asm").write_text(
        "class NetworkClient {\n"
        "  void fetch() { HttpClient client = HttpClient(); }\n"
        "  void weak() { HttpOverrides.global = MyOverrides(); }\n"
        "}\n")
    (asm / "NativeBridge.asm").write_text(
        "import 'dart:ffi';\nfinal lib = DynamicLibrary.open('libcustom.so');\n")
    (tmp_path / "pp.txt").write_text(
        '"api_key_prod_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"\n'
        '"just a normal string"\n'
        '"https://backend.example.com/v1/login"\n')
    (tmp_path / "objs.txt").write_text("nested pool dump, not parsed\n")
    return tmp_path

class TestBuildFlutterGraph:
    """
    Purpose:
        Graph construction from recovered Flutter output.
    """
    def test_returns_none_for_missing_directory(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist yields no graph.

        Parameters:
            tmp_path: Temporary directory used to build a missing path.
        """
        assert build_flutter_graph(tmp_path / "does-not-exist") is None

    def test_returns_none_when_nothing_recoverable(self, tmp_path):
        """
        Purpose:
            Pin that an empty output directory yields no graph.

        Parameters:
            tmp_path: Temporary directory holding the empty output.
        """
        empty = tmp_path / "empty_out"
        empty.mkdir()
        assert build_flutter_graph(empty) is None

    def test_builds_one_node_per_asm_file(self, blutter_out):
        """
        Purpose:
            Pin that each disassembly unit becomes exactly one node.

        Parameters:
            blutter_out: The synthetic recovered-output tree.
        """
        graph = build_flutter_graph(blutter_out)
        assert graph is not None
        asm_nodes = {n.cls for n in graph.nodes.values() if n.file.endswith(".asm")}
        assert asm_nodes == {"MainActivity", "NetworkClient", "NativeBridge"}

    def test_main_file_flagged_entry_point(self, blutter_out):
        """
        Purpose:
            Pin that the unit holding the entry function is given the entry-point role.

        Parameters:
            blutter_out: The synthetic recovered-output tree.

        Implementation notes:
            Entry points are what the partitioner seeds regions from, so a missed one leaves that part of the app without an agent focused on it.
        """
        graph = build_flutter_graph(blutter_out)
        node = next(n for n in graph.nodes.values() if n.cls == "MainActivity")
        assert node.role == "entry-point"

    def test_network_and_tls_sinks_detected(self, blutter_out):
        """
        Purpose:
            Pin that a unit reaching both the network and transport configuration carries both signals.

        Parameters:
            blutter_out: The synthetic recovered-output tree.
        """
        graph = build_flutter_graph(blutter_out)
        node = next(n for n in graph.nodes.values() if n.cls == "NetworkClient")
        assert "network" in node.signals
        assert "tls" in node.signals

    def test_ffi_role_detected(self, blutter_out):
        """
        Purpose:
            Pin that a unit loading a native library is given the native-bridge role and the foreign-interface signal.

        Parameters:
            blutter_out: The synthetic recovered-output tree.

        Implementation notes:
            Native interop is where a Flutter app leaves the Dart snapshot entirely, so it has to be visible to the agent rather than silently absent.
        """
        graph = build_flutter_graph(blutter_out)
        node = next(n for n in graph.nodes.values() if n.cls == "NativeBridge")
        assert node.role == "native-bridge"
        assert "ffi" in node.signals

    def test_object_pool_secrets_recovered(self, blutter_out):
        """
        Purpose:
            Pin that credential-shaped and endpoint strings are recovered from the pool while ordinary text is dropped.

        Parameters:
            blutter_out: The synthetic recovered-output tree.

        Implementation notes:
            With the code reduced to disassembly, the pool is where hardcoded keys and URLs remain plainly readable, which makes it the highest-value node in a Flutter graph. Keeping every string would bury that in noise.
        """
        graph = build_flutter_graph(blutter_out)
        pool = graph.nodes.get("ObjectPool")
        assert pool is not None
        assert any("api_key_prod" in s for s in pool.strings)
        assert "https://backend.example.com/v1/login" in pool.strings
        assert not any("just a normal string" in s for s in pool.strings)

    def test_pp_txt_with_no_secrets_produces_no_pool_node(self, tmp_path):
        """
        Purpose:
            Pin that a pool holding nothing notable produces no pool node at all.

        Parameters:
            tmp_path: Temporary directory the output tree is written into.

        Implementation notes:
            An empty pool node would send the agent to read a file with nothing in it, spending a step out of a tight budget.
        """
        asm = tmp_path / "asm"
        asm.mkdir()
        (asm / "Foo.asm").write_text("void foo() {}\n")
        (tmp_path / "pp.txt").write_text('"harmless"\n"another harmless one"\n')
        graph = build_flutter_graph(tmp_path)
        assert graph is not None
        assert "ObjectPool" not in graph.nodes

    def test_pool_only_when_no_asm_dir(self, tmp_path):
        """
        Purpose:
            Pin that a pool with notable strings still produces a graph when no disassembly was recovered.

        Parameters:
            tmp_path: Temporary directory the output tree is written into.

        Implementation notes:
            Recovery partly failing is common, and the pool alone still carries the credentials worth reporting, so it must not depend on the disassembly succeeding.
        """
        (tmp_path / "pp.txt").write_text('"password123456789012345"\n')
        graph = build_flutter_graph(tmp_path)
        assert graph is not None
        assert "ObjectPool" in graph.nodes

    def test_file_paths_are_relative_and_readable(self, blutter_out):
        """
        Purpose:
            Pin that a node's recorded path actually resolves to a readable file.

        Parameters:
            blutter_out: The synthetic recovered-output tree.

        Implementation notes:
            The agent opens files by the path the graph gives it, so a path that does not resolve wastes a step and looks to the agent like a missing file.
        """
        graph = build_flutter_graph(blutter_out)
        node = next(n for n in graph.nodes.values() if n.cls == "MainActivity")
        target = blutter_out / node.file
        assert target.is_file()

    def test_flagged_files_include_signalled_and_pool_nodes(self, blutter_out):
        """
        Purpose:
            Pin that both a signalled unit and the object pool appear among the files worth examining.

        Parameters:
            blutter_out: The synthetic recovered-output tree.
        """
        graph = build_flutter_graph(blutter_out)
        flagged = graph.flagged_files()
        assert any(f.endswith("NetworkClient.asm") for f in flagged)
        assert any(f.endswith("pp.txt") for f in flagged)

    def test_unreadable_asm_file_is_skipped_not_fatal(self, blutter_out):
        """
        Purpose:
            Pin that an unreadable entry in the disassembly tree is skipped rather than failing the build.

        Parameters:
            blutter_out: The synthetic recovered-output tree.

        Implementation notes:
            The graph is an enhancement; losing it to one odd directory entry would cost the agent its structure for the whole app.
        """
        (blutter_out / "asm" / "weird_dir").mkdir()
        graph = build_flutter_graph(blutter_out)
        assert graph is not None
