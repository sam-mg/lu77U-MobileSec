#!/usr/bin/env python3
"""
Module: test_code_graph_js_bridge

Purpose:
    The JavaScript-bridge annotation scan in the Java and Kotlin code graph.

Responsibilities:
    Cover the source-tree scan that flags classes exposing methods to web content.

Dependencies:
    The code graph's node type and its bridge-flagging pass.

Implementation notes:
    A class exposing annotated methods is the real data-exposure surface of a hybrid WebView, and androguard does not surface per-method annotations, so the graph scans the decompiled source for them instead. These tests cover that scan with a synthetic tree, which needs neither androguard nor a real APK.
"""

from lu77U_MobileSec.analyzers.agent.code_graph import CodeNode, _flag_js_bridges


def _jadx_tree(tmp_path):
    """
    Purpose:
        Build a decompiled-source tree holding one bridge class and one ordinary class.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.

    Implementation notes:
        The bridge class uses the fully-qualified annotation, which is how the decompiler renders it, and includes an unannotated method so the test can prove only the exposed ones are recorded.
    """
    (tmp_path / "sources" / "oa").mkdir(parents=True)
    (tmp_path / "sources" / "plain").mkdir(parents=True)
    (tmp_path / "sources" / "oa" / "Bridge.java").write_text(
        "package oa;\n"
        "public class Bridge {\n"
        "    @android.webkit.JavascriptInterface\n"
        "    public void copyTextToClipboard(String text) { }\n"
        "    @android.webkit.JavascriptInterface\n"
        "    public String getSessionToken() { return t; }\n"
        "    public void notExposed() { }\n"
        "}\n")
    (tmp_path / "sources" / "plain" / "Helper.java").write_text(
        "package plain;\npublic class Helper { public void f() {} }\n")
    return tmp_path


def _nodes():
    """
    Purpose:
        Build the graph nodes matching the synthetic source tree.

    Returns:
        The nodes, keyed by class name.
    """
    return {
        "Bridge": CodeNode(cls="Bridge", file="sources/oa/Bridge.java"),
        "Helper": CodeNode(cls="Helper", file="sources/plain/Helper.java"),
    }


def test_bridge_class_is_flagged_with_its_exposed_methods(tmp_path):
    """
    Purpose:
        Pin that a bridge class is flagged, and that exactly the annotated methods are recorded.

    Parameters:
        tmp_path: Temporary directory holding the synthetic source tree.

    Implementation notes:
        The unannotated method must be absent from the signal, because an agent told a method is web-reachable when it is not would chase an attack path that does not exist. The flagged assertion matters separately: it is what makes the agent read the class before it finishes.
    """
    root = _jadx_tree(tmp_path)
    nodes = _nodes()
    _flag_js_bridges(str(root), nodes, verbose=False)

    bridge = nodes["Bridge"]
    assert "js_bridge" in bridge.signals
    assert set(bridge.signals["js_bridge"]) == {"copyTextToClipboard", "getSessionToken"}
    assert "notExposed" not in bridge.signals["js_bridge"]
    assert bridge.flagged


def test_non_bridge_class_is_not_flagged(tmp_path):
    """
    Purpose:
        Pin that an ordinary class is left alone by the scan.

    Parameters:
        tmp_path: Temporary directory holding the synthetic source tree.
    """
    root = _jadx_tree(tmp_path)
    nodes = _nodes()
    _flag_js_bridges(str(root), nodes, verbose=False)
    assert "js_bridge" not in nodes["Helper"].signals


def test_short_annotation_form_is_recognized(tmp_path):
    """
    Purpose:
        Pin that the unqualified annotation form is recognised as well as the fully-qualified one.

    Parameters:
        tmp_path: Temporary directory the source tree is written into.

    Implementation notes:
        The decompiler emits either form depending on the imports it recovered, so matching only the qualified spelling would miss bridges in half of real apps.
    """
    (tmp_path / "sources" / "x").mkdir(parents=True)
    (tmp_path / "sources" / "x" / "B.java").write_text(
        "package x;\npublic class B {\n"
        "    @JavascriptInterface\n"
        "    public void ping() { }\n}\n")
    nodes = {"B": CodeNode(cls="B", file="sources/x/B.java")}
    _flag_js_bridges(str(tmp_path), nodes, verbose=False)
    assert nodes["B"].signals.get("js_bridge") == ["ping"]


def test_missing_or_bad_dir_is_a_noop(tmp_path):
    """
    Purpose:
        Pin that an absent or unreadable source tree leaves the nodes untouched instead of raising.

    Parameters:
        tmp_path: Temporary directory used to build a path that does not exist.

    Implementation notes:
        Graph construction runs when decompilation may have failed, so this pass has to degrade rather than take the whole graph down with it.
    """
    nodes = _nodes()
    _flag_js_bridges(None, nodes, verbose=False)
    _flag_js_bridges(str(tmp_path / "does-not-exist"), nodes, verbose=False)
    assert all("js_bridge" not in n.signals for n in nodes.values())
