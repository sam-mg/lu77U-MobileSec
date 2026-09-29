#!/usr/bin/env python3
"""
Module: test_cordova_graph

Purpose:
    The Cordova code graph, built over an extracted web asset tree.

Responsibilities:
    Pin which files become nodes, which signals are detected, and when no graph is produced.

Dependencies:
    pytest, and the Cordova graph builder.
"""

import pytest

from lu77U_MobileSec.analyzers.cordova.graph import build_cordova_graph


@pytest.fixture
def www(tmp_path):
    """
    Purpose:
        Build a small Cordova web tree holding an app page, an app script, an app plugin and framework noise.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.

    Implementation notes:
        The noise is deliberate: the runtime and a vendored library are included so the tests can prove they are filtered out rather than merely that the app files are found.
    """
    (tmp_path / "js").mkdir()
    (tmp_path / "plugins" / "com.app.storage" / "www").mkdir(parents=True)
    (tmp_path / "config.xml").write_text(
        '<?xml version="1.0"?><widget id="com.app"><access origin="*"/></widget>')
    (tmp_path / "index.html").write_text(
        "<html><head><script src='cordova.js'></script>"
        "<script src='js/index.js'></script></head>"
        "<body onload='deviceready'></body></html>")
    (tmp_path / "js" / "index.js").write_text(
        "var h = location.hash;\n"
        "document.getElementById('out').innerHTML = h;\n"
        "fetch('http://api.example.com/data?token=abcdef1234567890abcdef');\n")
    (tmp_path / "plugins" / "com.app.storage" / "www" / "Storage.js").write_text(
        "cordova.exec(ok, fail, 'Storage', 'save', [key, value]);\n")
    (tmp_path / "cordova.js").write_text("// cordova runtime\ncordova.exec = function(){};")
    (tmp_path / "js" / "jquery.min.js").write_text("// jQuery\n$('#x').html(evil);")
    return tmp_path


def test_builds_graph_with_app_nodes_only(www):
    """
    Purpose:
        Pin that the app's own files become nodes and the runtime and vendored library do not.

    Parameters:
        www: The synthetic Cordova tree.

    Implementation notes:
        Filtering is what makes the graph usable. A bundled library dwarfs the app's own code, and an agent handed it would spend its budget on code the app owner cannot change.
    """
    g = build_cordova_graph(www)
    assert g is not None
    files = {n.file for n in g.nodes.values()}
    assert "index.html" in files
    assert "js/index.js" in files
    assert "plugins/com.app.storage/www/Storage.js" in files
    assert "cordova.js" not in files
    assert "js/jquery.min.js" not in files


def test_dom_xss_and_network_sinks_flagged(www):
    """
    Purpose:
        Pin that a script reaching both a DOM sink and the network is flagged with both signals.

    Parameters:
        www: The synthetic Cordova tree.
    """
    g = build_cordova_graph(www)
    index = next(n for n in g.nodes.values() if n.file == "js/index.js")
    assert "dom_xss" in index.signals
    assert "network" in index.signals
    assert index.flagged


def test_cordova_bridge_flagged_on_plugin(www):
    """
    Purpose:
        Pin that a plugin calling the native bridge carries the bridge signal.

    Parameters:
        www: The synthetic Cordova tree.

    Implementation notes:
        The bridge is where a Cordova app crosses from web content into native code, so the signal is what makes the agent treat the plugin as an attack surface.
    """
    g = build_cordova_graph(www)
    plugin = next(n for n in g.nodes.values() if n.file.endswith("Storage.js"))
    assert "cordova_exec" in plugin.signals


def test_secret_string_extracted(www):
    """
    Purpose:
        Pin that a credential-bearing URL in a script is captured on the node.

    Parameters:
        www: The synthetic Cordova tree.
    """
    g = build_cordova_graph(www)
    index = next(n for n in g.nodes.values() if n.file == "js/index.js")
    assert "http://api.example.com/data?token=abcdef1234567890abcdef" in index.strings


def test_html_entry_page_role(www):
    """
    Purpose:
        Pin that an HTML file is given the entry-page role and that its script references become node references.

    Parameters:
        www: The synthetic Cordova tree.

    Implementation notes:
        The references are what let the agent follow a page to the scripts it loads, which is how a Cordova investigation gets from the entry point to the logic.
    """
    g = build_cordova_graph(www)
    page = next(n for n in g.nodes.values() if n.file == "index.html")
    assert page.role == "entry-page"
    assert "js/index.js" in page.refs


def test_empty_or_missing_tree_returns_none(tmp_path):
    """
    Purpose:
        Pin that an empty directory and a path that is not a directory both yield no graph.

    Parameters:
        tmp_path: Temporary directory used as the empty tree and to build a missing path.
    """
    assert build_cordova_graph(tmp_path) is None
    assert build_cordova_graph(tmp_path / "nope") is None


def test_only_noise_returns_none(tmp_path):
    """
    Purpose:
        Pin that a tree containing only framework files yields no graph.

    Parameters:
        tmp_path: Temporary directory the runtime files are written into.

    Implementation notes:
        Returning an empty graph rather than none would send an agent to investigate an app whose own code was never extracted.
    """
    (tmp_path / "cordova.js").write_text("// runtime only")
    (tmp_path / "cordova_plugins.js").write_text("module.exports = [];")
    assert build_cordova_graph(tmp_path) is None
