#!/usr/bin/env python3
"""
Module: test_rn_graph

Purpose:
    The React Native code graph over both bundle shapes: an unpacked module directory and a single Hermes bundle.

Responsibilities:
    Pin vendor exclusion, module and entry detection, the sink and secret signals, the per-function split applied to single-file bundles, and the cases that must yield no graph at all.

Dependencies:
    pytest and the React Native graph builder.

Implementation notes:
    Both shapes reach the same builder, because what a React Native decompile produces depends on which tool ran: the decompiler leaves a directory of numbered modules, while Hermes disassembly leaves one bundle the builder has to split itself.
"""

import pytest

from lu77U_MobileSec.analyzers.react_native.graph import build_rn_graph

@pytest.fixture
def module_dir(tmp_path):
    """
    Purpose:
        Build an unpacked React Native module directory with a vendor module, an entry module, a storage sink with a secret, and a network sink that requires another module.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The directory root to build a graph from.

    Security considerations:
        The API key in the fixture is invented for this test and matches no real credential.
    """
    (tmp_path / "node_modules" / "react-native").mkdir(parents=True)
    (tmp_path / "node_modules" / "react-native" / "index.js").write_text("// vendor code\n")
    (tmp_path / "0.js").write_text(
        "import { AppRegistry } from 'react-native';\n"
        "AppRegistry.registerComponent('App', () => App);\n")
    (tmp_path / "1.js").write_text(
        "const AsyncStorage = require('AsyncStorage');\n"
        "function saveToken(t) { AsyncStorage.setItem('token', t); }\n"
        "const apiKey = 'not-a-real-secret-abc123';\n")
    (tmp_path / "2.js").write_text(
        "const one = require('./1.js');\n"
        "fetch('https://api.example.com/data');\n")
    return tmp_path

@pytest.fixture
def single_file(tmp_path):
    """
    Purpose:
        Build a single-file Hermes-shaped bundle holding three named functions, one of them with network and eval sinks and one of them the entry point.

    Parameters:
        tmp_path: Temporary directory the bundle is written into.

    Returns:
        The directory holding the bundle.
    """
    content = (
        "function global() {\n"
        "  console.log('boot');\n"
        "}\n"
        "function loginUser(u, p) {\n"
        "  fetch('https://api.example.com/login', {method: 'POST'});\n"
        "  eval('dangerous');\n"
        "}\n"
        "function AppEntry() {\n"
        "  AppRegistry.registerComponent('App', () => AppEntry);\n"
        "}\n"
    )
    (tmp_path / "bundle.js").write_text(content)
    return tmp_path

class TestModuleDirectory:
    """
    Purpose:
        Graph building over an unpacked module directory.
    """
    def test_vendor_modules_excluded(self, module_dir):
        """
        Purpose:
            Pin that a module under node_modules does not become a node.

        Parameters:
            module_dir: The unpacked module directory.

        Implementation notes:
            A React Native bundle is mostly framework and library code, so including it would bury the application's own modules and spend the agent's budget reading code the developer never wrote.
        """
        graph = build_rn_graph(module_dir)
        assert graph is not None
        clss = {n.cls for n in graph.nodes.values()}
        assert "index" not in clss

    def test_app_modules_present(self, module_dir):
        """
        Purpose:
            Pin that every application module in the directory becomes a node.

        Parameters:
            module_dir: The unpacked module directory.
        """
        graph = build_rn_graph(module_dir)
        clss = {n.cls for n in graph.nodes.values()}
        assert {"0", "1", "2"} <= clss

    def test_entry_module_detected(self, module_dir):
        """
        Purpose:
            Pin that the module registering the root component is marked as the entry.

        Parameters:
            module_dir: The unpacked module directory.
        """
        graph = build_rn_graph(module_dir)
        node = next(n for n in graph.nodes.values() if n.cls == "0")
        assert node.role == "entry-module"

    def test_storage_sink_and_secret_detected(self, module_dir):
        """
        Purpose:
            Pin that a module writing to storage carries the storage signal and that its embedded key is captured as a string.

        Parameters:
            module_dir: The unpacked module directory.
        """
        graph = build_rn_graph(module_dir)
        node = next(n for n in graph.nodes.values() if n.cls == "1")
        assert "storage" in node.signals
        assert any("not-a-real-secret" in s for s in node.strings)

    def test_network_sink_and_require_ref(self, module_dir):
        """
        Purpose:
            Pin that a module making a request carries the network signal and that its require of another module is recorded as a reference.

        Parameters:
            module_dir: The unpacked module directory.

        Implementation notes:
            The references are what let the agent follow a call from one module to the next; without them each module reads as isolated and no chain can be built across them.
        """
        graph = build_rn_graph(module_dir)
        node = next(n for n in graph.nodes.values() if n.cls == "2")
        assert "network" in node.signals
        assert any("1.js" in r for r in node.refs)

class TestSingleFileHermes:
    """
    Purpose:
        Graph building over a single-file bundle, where the builder has to split the file itself before there is anything to graph.
    """
    def test_splits_into_per_function_files(self, single_file):
        """
        Purpose:
            Pin that a single bundle is split into one file per named function.

        Parameters:
            single_file: The directory holding the bundle.

        Implementation notes:
            The split is what makes the bundle navigable: a single node covering a whole bundle would be far larger than any context window, so the agent could never read the code behind it.
        """
        graph = build_rn_graph(single_file)
        assert graph is not None
        assert (single_file / "functions").is_dir()
        split_files = list((single_file / "functions").glob("*.js"))
        assert len(split_files) == 3

    def test_function_nodes_have_real_readable_files(self, single_file):
        """
        Purpose:
            Pin that the file a function node points at exists and holds that function's body.

        Parameters:
            single_file: The directory holding the bundle.

        Implementation notes:
            The node's file path is what the agent's read tool is given, so a path that does not resolve or holds the wrong body wastes a step and returns nothing.
        """
        graph = build_rn_graph(single_file)
        node = next(n for n in graph.nodes.values() if n.cls == "loginUser")
        target = single_file / node.file
        assert target.is_file()
        assert "fetch(" in target.read_text()

    def test_eval_and_network_sinks_detected(self, single_file):
        """
        Purpose:
            Pin that a split function carries both the sinks its body contains.

        Parameters:
            single_file: The directory holding the bundle.
        """
        graph = build_rn_graph(single_file)
        node = next(n for n in graph.nodes.values() if n.cls == "loginUser")
        assert "network" in node.signals
        assert "eval" in node.signals

    def test_entry_function_detected(self, single_file):
        """
        Purpose:
            Pin that the split function registering the root component is marked as the entry.

        Parameters:
            single_file: The directory holding the bundle.
        """
        graph = build_rn_graph(single_file)
        node = next(n for n in graph.nodes.values() if n.cls == "AppEntry")
        assert node.role == "entry-module"

    def test_no_function_headers_falls_back_to_one_node(self, tmp_path):
        """
        Purpose:
            Pin that a bundle with no named function headers yields a single node carrying the whole file's signals rather than no graph.

        Parameters:
            tmp_path: Temporary directory holding a bundle written entirely as arrow functions.

        Implementation notes:
            Minified or arrow-only bundles have nothing to split on, and degrading to one node keeps the sinks visible instead of losing the file entirely.
        """
        (tmp_path / "bundle.js").write_text(
            "const x = () => { fetch('https://api.example.com'); };\nx();\n")
        graph = build_rn_graph(tmp_path)
        assert graph is not None
        assert list(graph.nodes.keys()) == ["bundle"]
        assert "network" in graph.nodes["bundle"].signals

class TestFailureModes:
    """
    Purpose:
        The inputs that must yield no graph.

    Implementation notes:
        Returning nothing is the contract, because the caller falls back to a non-graph analysis path; an empty graph would instead be treated as a real result and reported as an application with no code in it.
    """
    def test_missing_directory_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist yields no graph.

        Parameters:
            tmp_path: Temporary directory the missing path is named under.
        """
        assert build_rn_graph(tmp_path / "nope") is None

    def test_empty_directory_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that a directory with no files in it yields no graph.

        Parameters:
            tmp_path: Temporary directory the empty directory is created under.
        """
        empty = tmp_path / "empty"
        empty.mkdir()
        assert build_rn_graph(empty) is None

    def test_only_vendor_files_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that a directory holding nothing but vendor code yields no graph.

        Parameters:
            tmp_path: Temporary directory the vendor tree is created under.

        Implementation notes:
            Vendor exclusion runs before the emptiness check, so a tree of framework code must read as having nothing to analyse rather than as a graph of library internals.
        """
        vendor = tmp_path / "node_modules" / "react-native"
        vendor.mkdir(parents=True)
        (vendor / "index.js").write_text("// vendor only\n")
        assert build_rn_graph(tmp_path) is None
