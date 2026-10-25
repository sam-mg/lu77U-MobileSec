#!/usr/bin/env python3
"""
Module: test_flutter_recovery

Purpose:
    The Flutter recovery path: Dart source recovered from a debug build's kernel, the parsing of Blutter's release-build output, the Dart-to-Java platform-channel map, the graph built over all of it, the overview the agent reads first, and the analyzer's choice between build modes.

Responsibilities:
    Pin that a kernel source table is read exactly and safely, that SDK and package code is told apart from the app, that the Flutter framework stays out of the graph while the app's own code is always flagged, that channel calls are attributed to the right function and offset, that Java handlers are found by their string literals and framework noise is not, and that a debug build is analysed without Blutter while a release build still needs it.

Dependencies:
    pytest, the kernel extractor, the Flutter recovery helpers, graph and analyzer.

Implementation notes:
    The Blutter fixtures are hand-written in Blutter's real output format (library header, '** addr:' lines, annotated call targets, pool entries with object fields), modelled on real recoveries, so the parsers are tested against the shapes they meet rather than a simplified stand-in. Nothing here runs Blutter, JADX or a model.
"""

import hmac
import zipfile
from pathlib import Path

import pytest

from lu77U_MobileSec.analyzers import flutter_analyzer as fa_mod
from lu77U_MobileSec.analyzers.flutter import recovered
from lu77U_MobileSec.analyzers.flutter.graph import build_flutter_graph, write_flutter_overview
from lu77U_MobileSec.analyzers.flutter_analyzer import FlutterAnalyzer
from lu77U_MobileSec.decompiler import dart_kernel
from lu77U_MobileSec.decompiler.dart_kernel import (
    KERNEL_MEMBER, classify_uri, extract_kernel_sources, is_debug_build, parse_kernel_sources)

CREDENTIAL = "sk_" + "live_0123456789abcdefABCDEF0123"


def _contains(haystack, needle):
    """
    Purpose:
        Check whether needle occurs in haystack by comparing every window with hmac.compare_digest, since the overview text under test carries credential-shaped values and CodeQL flags a plain membership check on such text as a non-constant-time comparison.

    Parameters:
        haystack: The text to search within.
        needle: The literal substring to look for.

    Returns:
        True when needle appears in haystack.
    """
    width = len(needle)
    return any(hmac.compare_digest(haystack[i:i + width], needle)
               for i in range(len(haystack) - width + 1))


def _has(items, value):
    """
    Purpose:
        Check whether value is one of items with a constant-time comparison per item, for the same reason as _contains.

    Parameters:
        items: The strings to look through.
        value: The string to look for.

    Returns:
        True when value is among items.
    """
    return any(hmac.compare_digest(item, value) for item in items)


def _kuint(value):
    """
    Purpose:
        Encode an integer the way the Dart kernel format does.

    Parameters:
        value: The integer.

    Returns:
        One, two or four bytes.
    """
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    return bytes([0xC0 | ((value >> 24) & 0x3F), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _entry(uri, source):
    """
    Purpose:
        Build one source-table entry: a length-prefixed URI followed by length-prefixed source.

    Parameters:
        uri: The URI, as text.
        source: The source, as text or bytes.

    Returns:
        The entry's bytes.
    """
    uri_bytes = uri.encode()
    data = source if isinstance(source, bytes) else source.encode()
    return _kuint(len(uri_bytes)) + uri_bytes + _kuint(len(data)) + data


APP_MAIN = "file:///home/dev/demo/lib/main.dart"
LONG_URI = "file:///home/dev/demo/lib/" + "a" * 150 + ".dart"
BIG_URI = "file:///home/dev/demo/lib/big.dart"
BIG_SOURCE = "var x = 1;\n" * 2000


def _kernel_bytes():
    """
    Purpose:
        Build a kernel blob mixing real entries with the decoys the parser must reject.

    Returns:
        The blob.

    Implementation notes:
        The decoys are the shapes that occur in a real kernel: the same URI as an unprefixed reference, a package: import alias with a non-source payload, a binary payload, a later duplicate of a file, and SDK and pub-cache files that must be classified rather than treated as app code.
    """
    return b"".join([
        b"\x90\xab\xcd\xef\x00\x00",
        _entry(APP_MAIN, f"void main() {{ runApp(App()); }}\n// key {CREDENTIAL}\n"),
        b"\x07" + APP_MAIN.encode().replace(b"main", b"other"),
        _entry("package:demo/main.dart", "579=@BFIKNQT"),
        _entry("file:///home/dev/.pub-cache/hosted/pub.dev/http-1.2.0/lib/http.dart", "library http;\n"),
        _entry("file:///opt/flutter/packages/flutter/lib/material.dart", "library material;\n"),
        _entry("org-dartlang-sdk:///lib/core/core.dart", "library dart.core;\n"),
        _entry(LONG_URI, "class Long {}\n"),
        _entry(BIG_URI, BIG_SOURCE),
        _entry("file:///home/dev/demo/lib/../../../../tmp/evil.dart", "class Evil {}\n"),
        _entry("file:///home/dev/demo/lib/binary.dart", b"\xff\xfe;{\x00"),
        _entry(APP_MAIN, "void main() { replaced(); }\n"),
    ])


def _apk(tmp_path, members):
    """
    Purpose:
        Write a zip standing in for an APK.

    Parameters:
        tmp_path: Directory to write into.
        members: Archive name to bytes.

    Returns:
        The APK path.
    """
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


class TestKernelSourceTable:
    """
    Purpose:
        Reading the source table out of a kernel blob.
    """
    def test_entries_are_found_and_decoys_rejected(self):
        """
        Purpose:
            Pin which entries are accepted, that the first copy of a URI wins, and that every length encoding is decoded.
        """
        found = dict(parse_kernel_sources(_kernel_bytes()))
        assert found[APP_MAIN].startswith("void main() { runApp")
        assert hmac.compare_digest(found[LONG_URI], "class Long {}\n")
        assert hmac.compare_digest(found[BIG_URI], BIG_SOURCE)
        assert not _has(found, "package:demo/main.dart")
        assert not _has(found, "file:///home/dev/demo/lib/binary.dart")
        assert not any(uri.endswith("other.dart") for uri in found)

    @pytest.mark.parametrize("uri,kind,package,rel", [
        (APP_MAIN, "app", "", "dart_source/lib/main.dart"),
        ("file:///home/dev/.pub-cache/hosted/pub.dev/http-1.2.0/lib/src/client.dart",
         "package", "http", "dart_packages/http/lib/src/client.dart"),
        ("file:///home/dev/.pub-cache/git/my_plugin-abc123/lib/p.dart",
         "package", "my_plugin", "dart_packages/my_plugin/lib/p.dart"),
        ("file:///opt/flutter/packages/flutter/lib/widgets.dart", "sdk", "", ""),
        ("file:///opt/flutter/bin/cache/pkg/sky_engine/lib/ui/ui.dart", "sdk", "", ""),
        ("org-dartlang-sdk:///lib/core/core.dart", "sdk", "", ""),
        ("org-dartlang-app:///lib/screens/login.dart", "app", "", "dart_source/lib/screens/login.dart"),
    ])
    def test_classification(self, uri, kind, package, rel):
        """
        Purpose:
            Pin how each kind of URI is classified and where it is written.

        Parameters:
            uri: The kernel URI.
            kind: The expected classification.
            package: The expected package name.
            rel: The expected relative output path.
        """
        source = classify_uri(uri)
        assert (source.kind, source.package, source.rel_path) == (kind, package, rel)

    def test_traversal_components_are_dropped(self):
        """
        Purpose:
            Pin that a URI climbing out of the project is rewritten inside the output tree.
        """
        source = classify_uri("file:///home/dev/demo/lib/../../../../tmp/evil.dart")
        assert ".." not in source.rel_path.split("/")
        assert source.rel_path.startswith("dart_source/")


class TestKernelExtraction:
    """
    Purpose:
        Writing a debug build's recovered source to disk.
    """
    def test_debug_build_detection(self, tmp_path):
        """
        Purpose:
            Pin that the kernel's presence, and only that, marks a debug build.

        Parameters:
            tmp_path: Directory for the fake APKs.
        """
        debug = _apk(tmp_path, {KERNEL_MEMBER: b"x"})
        assert is_debug_build(debug)
        (tmp_path / "app.apk").unlink()
        release = _apk(tmp_path, {"lib/arm64-v8a/libapp.so": b"x"})
        assert not is_debug_build(release)
        assert not is_debug_build(tmp_path / "missing.apk")

    def test_extraction_writes_app_and_packages_inside_the_output(self, tmp_path):
        """
        Purpose:
            Pin what is written, where, and that nothing lands outside the output directory.

        Parameters:
            tmp_path: Directory for the APK and output.
        """
        apk = _apk(tmp_path, {KERNEL_MEMBER: _kernel_bytes()})
        out = tmp_path / "out"
        result = extract_kernel_sources(apk, out)
        assert result is not None
        assert "dart_source/lib/main.dart" in result.app_files
        assert result.packages == {"http": "1.2.0"}
        assert result.sdk_files == 2
        assert (out / "dart_source/lib/main.dart").read_text().startswith("void main() { runApp")
        assert (out / "dart_source/lib/tmp/evil.dart").is_file()
        for path in tmp_path.rglob("*.dart"):
            assert out.resolve() in path.resolve().parents

    def test_no_app_source_is_a_failure(self, tmp_path):
        """
        Purpose:
            Pin that a kernel holding only package code yields nothing.

        Parameters:
            tmp_path: Directory for the APK and output.
        """
        blob = _entry("file:///home/dev/.pub-cache/hosted/pub.dev/http-1.2.0/lib/http.dart", "library http;\n")
        apk = _apk(tmp_path, {KERNEL_MEMBER: blob})
        assert extract_kernel_sources(apk, tmp_path / "out") is None

    def test_oversized_kernel_is_refused(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin the size cap applied before the kernel is read.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Lowers the cap.
        """
        apk = _apk(tmp_path, {KERNEL_MEMBER: _kernel_bytes()})
        monkeypatch.setattr(dart_kernel, "MAX_KERNEL_BYTES", 16)
        assert extract_kernel_sources(apk, tmp_path / "out") is None


POOL = '''[pp+0x10] Obj!OptionalMethodChannel@1 : {
  off_8: "flutter/platform",
  off_c_Obj!JSONMethodCodec@2
}
[pp+0xa040] Obj!MethodChannel@3a7681 : {
  off_8: "com.demo/security",
  off_c_Obj!StandardMethodCodec@3a7821
}
[pp+0xa048] String: "isTrusted"
[pp+0x5b30] Obj!LicenseScreen@4b17a1 : {
  off_c: "%s"
}
[pp+0x5b38] String: "Welcome back"
[pp+0x9000] String: "framework only string_with_api_key_value_0123456789"
''' % CREDENTIAL

APP_ASM = '''// lib: , url: package:demo/main.dart

// class id: 1048595, size: 0x8
class :: {

  static void main() {
    // ** addr: 0x1000, size: 0x30
    // 0x1000: r0 = runApp()
    //     0x1000: bl              #0x9000  ; [package:flutter/src/widgets/binding.dart] ::runApp
  }
}

// class id: 1579, size: 0x10
class _HomeState extends State {

  _ build(/* No info */) {
    // ** addr: 0x1800, size: 0x40
    // 0x1804: r1 = Instance_LicenseScreen
    //     0x1804: ldr             x1, [PP, #0x5b30]  ; [pp+0x5b30] Obj!LicenseScreen@4b17a1
    // 0x1808: r2 = "Welcome back"
    //     0x1808: ldr             x2, [PP, #0x5b38]  ; [pp+0x5b38] "Welcome back"
  }

  _ _check(/* No info */) async {
    // ** addr: 0x2000, size: 0x80
    // 0x2004: r30 = Instance_MethodChannel
    //     0x2004: add             lr, PP, #0xa, lsl #12  ; [pp+0xa040] Obj!MethodChannel@3a7681
    // 0x2008: r16 = "isTrusted"
    //     0x2008: add             x16, PP, #0xa, lsl #12  ; [pp+0xa048] "isTrusted"
    // 0x200c: r0 = invokeMethod()
    //     0x200c: bl              #0x3000  ; [package:flutter/src/services/platform_channel.dart] MethodChannel::invokeMethod
    // 0x2010: r0 = check()
    //     0x2010: bl              #0x4000  ; [package:demo_plugin/guard.dart] Guard::check
  }

  [closure] void <anonymous closure>(dynamic) {
    // ** addr: 0x2100, size: 0x20
    // 0x2104: r0 = invokeMethod()
    //     0x2104: bl              #0x3000  ; [package:flutter/src/services/platform_channel.dart] MethodChannel::invokeMethod
  }
}
'''

PLUGIN_ASM = '''// lib: , url: package:demo_plugin/guard.dart

// class id: 200, size: 0x8
class Guard extends Object {

  static _ check(/* No info */) {
    // ** addr: 0x4000, size: 0x20
    // 0x4004: r0 = MethodChannel()
  }
}
'''

UTIL_ASM = '''// lib: , url: package:demo_util/strings.dart

class Strings extends Object {

  static _ pad(/* No info */) {
    // ** addr: 0x5000, size: 0x10
  }
}
'''

FRAMEWORK_ASM = '''// lib: , url: package:flutter/src/services/platform_channel.dart

class MethodChannel extends Object {

  _ invokeMethod(/* No info */) {
    // ** addr: 0x3000, size: 0x10
    // 0x3004: r16 = "isTrusted"
    // 0x3008: r0 = invokeMethod()
    //     0x3008: bl              #0x3000  ; [package:flutter/src/services/platform_channel.dart] MethodChannel::invokeMethod
  }
}
'''


@pytest.fixture
def release_tree(tmp_path):
    """
    Purpose:
        Build a Blutter-shaped release recovery with an app, a plugin, a utility package, the framework, a pool and a platform layer.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The analysis root.
    """
    root = tmp_path / "out"
    files = {
        "asm/demo/main.dart": APP_ASM,
        "asm/demo_plugin/guard.dart": PLUGIN_ASM,
        "asm/demo_util/strings.dart": UTIL_ASM,
        "asm/flutter/src/services/platform_channel.dart": FRAMEWORK_ASM,
        "pp.txt": POOL,
        "objs.txt": "nested dump\n",
        "platform/sources/com/demo/MainActivity.java":
            'class MainActivity {\n  String CH = "com.demo/security";\n'
            '  void on(String m) { if (m.equals("isTrusted")) {} }\n}\n',
        "platform/sources/io/flutter/plugin/common/MethodChannel.java":
            'class MethodChannel { String x = "isTrusted"; }\n',
        "platform/resources/AndroidManifest.xml": "<manifest/>\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


class TestBlutterParsing:
    """
    Purpose:
        Reading structure out of Blutter's output.
    """
    def test_pool_entries_keep_object_field_strings(self):
        """
        Purpose:
            Pin that an object's field strings belong to the object's pool entry.
        """
        pool = recovered.parse_object_pool(POOL)
        assert len(pool["0x5b30"].strings) == 1 and _has(pool["0x5b30"].strings, CREDENTIAL)
        assert pool["0xa048"].strings == ["isTrusted"]

    def test_channel_objects_resolve_to_names(self):
        """
        Purpose:
            Pin the channel id-to-name map, including the framework's own channel.
        """
        channels = recovered.channel_names_by_object(recovered.parse_object_pool(POOL))
        assert channels["3a7681"] == ("MethodChannel", "com.demo/security")
        assert channels["1"] == ("OptionalMethodChannel", "flutter/platform")

    def test_functions_and_offsets(self):
        """
        Purpose:
            Pin function spans, owners, offsets and the closure name.
        """
        functions = recovered.parse_functions(APP_ASM.splitlines())
        assert [(f.owner, f.name, f.addr) for f in functions] == [
            ("::", "main", "0x1000"), ("_HomeState", "build", "0x1800"),
            ("_HomeState", "_check", "0x2000"), ("_HomeState", "<anonymous closure>", "0x2100")]
        assert all(a.end_line < b.start_line for a, b in zip(functions, functions[1:]))

    def test_channel_calls_are_attributed_per_function(self):
        """
        Purpose:
            Pin that a call takes the channel and method loaded in its own function, and that a call in the next function does not inherit them.
        """
        channels = recovered.channel_names_by_object(recovered.parse_object_pool(POOL))
        calls = recovered.asm_channel_calls("asm/demo/main.dart", APP_ASM, channels)
        first, second = calls
        assert (first.channel, first.method, first.function, first.addr) == (
            "com.demo/security", "isTrusted", "_HomeState::_check", "0x200c")
        assert (second.channel, second.method) == ("?", "?")

    def test_app_package_and_kinds(self, release_tree):
        """
        Purpose:
            Pin that the package owning main() is the app and the rest are classified.

        Parameters:
            release_tree: The recovery fixture.
        """
        groups = recovered.asm_packages(release_tree / "asm")
        apps = recovered.find_app_packages(groups)
        assert apps == {"demo"}
        assert recovered.package_kind("flutter", apps) == "sdk"
        assert recovered.package_kind("demo_plugin", apps) == "package"
        assert recovered.package_kind("", apps) == "unknown"

    def test_app_pool_strings_follow_references(self, release_tree):
        """
        Purpose:
            Pin that only strings the app's code references are collected, including object fields.

        Parameters:
            release_tree: The recovery fixture.
        """
        pool = recovered.parse_object_pool(POOL)
        found = recovered.app_pool_strings([release_tree / "asm/demo/main.dart"], pool)
        assert _has(found, CREDENTIAL) and _has(found, "Welcome back")
        assert not any("framework only" in value for value in found)

    def test_java_hits_skip_framework_noise(self, release_tree):
        """
        Purpose:
            Pin that a literal is found in app Java and not in io.flutter.

        Parameters:
            release_tree: The recovery fixture.
        """
        hits = recovered.java_literal_hits(release_tree / "platform", release_tree, ["isTrusted", "?"])
        assert hits == {"isTrusted": ["platform/sources/com/demo/MainActivity.java:3"]}

    def test_source_channel_calls(self):
        """
        Purpose:
            Pin channel declarations and calls read from Dart source.
        """
        text = ("const ch = MethodChannel('com.demo/net');\n"
                "Future<bool?> f() => ch.invokeMethod<bool>('ping');\n")
        declared, calls = recovered.source_channel_calls("dart_source/lib/a.dart", text)
        assert declared == [("MethodChannel", "com.demo/net", 1)]
        assert [(c.channel, c.method, c.line) for c in calls] == [("com.demo/net", "ping", 2)]


class TestFlutterGraph:
    """
    Purpose:
        The graph over a package-laid-out recovery.
    """
    def test_framework_out_app_in(self, release_tree):
        """
        Purpose:
            Pin that the framework is left out, the app is always flagged, a plugin the app calls stays in the graph linked from the app but is not flagged even though it touches a sink, and a package the app never calls is left out.

        Parameters:
            release_tree: The recovery fixture.

        Implementation notes:
            On a real recovery the old graph flagged dozens of framework files and not the app's main.dart at all; on a lab app, flagging the plugins that touch a sink sent a third of the agent's steps into plugin internals.
        """
        graph = build_flutter_graph(release_tree)
        assert not any(key.startswith("asm/flutter/") for key in graph.nodes)
        flagged = set(graph.flagged_files())
        assert "asm/demo/main.dart" in flagged
        assert graph.nodes["asm/demo/main.dart"].role == "app-entry"
        assert graph.nodes["asm/demo_plugin/guard.dart"].role == "dart-package"
        assert "asm/demo_plugin/guard.dart" not in flagged
        assert "asm/demo_plugin/guard.dart" in graph.nodes["asm/demo/main.dart"].refs
        assert "asm/demo_util/strings.dart" not in graph.nodes

    def test_unreached_package_with_a_sink_stays_out(self, release_tree):
        """
        Purpose:
            Pin that a package library the app never reaches is left out even when it matches a sink pattern.

        Parameters:
            release_tree: The recovery fixture.

        Implementation notes:
            On a real app, scoring every package flagged 136 files of a crypto library's internals; the app reached 18 package libraries, the API entry points it calls.
        """
        internal = release_tree / "asm/deep_crypto/src/block_cipher.dart"
        internal.parent.mkdir(parents=True)
        internal.write_text("// lib: , url: package:deep_crypto/src/block_cipher.dart\n"
                            "class BlockCipher { _ init() { Cipher(); } }\n")
        graph = build_flutter_graph(release_tree)
        assert "asm/deep_crypto/src/block_cipher.dart" not in graph.nodes
        assert "asm/demo_plugin/guard.dart" in graph.nodes

    def test_app_node_strings_and_refs(self, release_tree):
        """
        Purpose:
            Pin that the app node carries the credential it loads through the pool and refers to the plugin it calls.

        Parameters:
            release_tree: The recovery fixture.
        """
        node = build_flutter_graph(release_tree).nodes["asm/demo/main.dart"]
        assert _has(node.strings, CREDENTIAL)
        assert node.refs == ["asm/demo_plugin/guard.dart"]

    def test_pool_node_holds_only_app_strings(self, release_tree):
        """
        Purpose:
            Pin that the pool node is built from the app's references, not the whole pool.

        Parameters:
            release_tree: The recovery fixture.
        """
        pool = build_flutter_graph(release_tree).nodes["ObjectPool"]
        assert _has(pool.strings, CREDENTIAL)
        assert not any("framework only" in value for value in pool.strings)

    def test_platform_handler_node(self, release_tree):
        """
        Purpose:
            Pin that the Java file answering the app's channel becomes a flagged handler node and io.flutter does not.

        Parameters:
            release_tree: The recovery fixture.
        """
        graph = build_flutter_graph(release_tree)
        handler = graph.nodes["platform/sources/com/demo/MainActivity.java"]
        assert handler.role == "platform-channel-handler"
        assert handler.flagged
        assert not any("io/flutter" in key for key in graph.nodes)

    def test_debug_source_nodes(self, tmp_path):
        """
        Purpose:
            Pin the nodes built over recovered Dart source: app always flagged, a package only with a sink, an import becoming a ref.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = tmp_path / "out"
        app = root / "dart_source/lib/main.dart"
        app.parent.mkdir(parents=True)
        app.write_text("import 'package:guard/guard.dart';\nvoid main() {}\n")
        guard = root / "dart_packages/guard/lib/guard.dart"
        guard.parent.mkdir(parents=True)
        guard.write_text("final c = MethodChannel('g');\n")
        quiet = root / "dart_packages/quiet/lib/q.dart"
        quiet.parent.mkdir(parents=True)
        quiet.write_text("int add(int a, int b) => a + b;\n/// Use fingerprint(x) or print(x).\n")
        graph = build_flutter_graph(root)
        assert graph.nodes["dart_source/lib/main.dart"].role == "app-entry"
        assert graph.nodes["dart_source/lib/main.dart"].refs == ["dart_packages/guard/lib/guard.dart"]
        assert "dart_packages/quiet/lib/q.dart" not in graph.nodes


class TestOverview:
    """
    Purpose:
        The overview file the agent reads first.
    """
    def test_release_overview(self, release_tree):
        """
        Purpose:
            Pin the build mode, packages, the channel map with offset and Java location, and the app strings.

        Parameters:
            release_tree: The recovery fixture.
        """
        (release_tree / "blutter_info.txt").write_text("Dart version: 3.8.1, Snapshot: abc, Target: android arm64\n")
        path = write_flutter_overview(release_tree, "release")
        text = path.read_text()
        assert path.name == recovered.OVERVIEW_NAME
        assert _contains(text, "Build: RELEASE")
        assert _contains(text, "Dart version: 3.8.1")
        assert _contains(text, "App's own Dart packages: demo")
        assert _contains(text, "demo_plugin")
        assert _contains(text, 'channel "com.demo/security"')
        assert _contains(text, 'invokeMethod "isTrusted" at asm/demo/main.dart:')
        assert _contains(text, "in _HomeState::_check (libapp.so+0x200c)")
        assert _contains(text, "-> Java: platform/sources/com/demo/MainActivity.java:3")
        assert _contains(text, CREDENTIAL)
        assert not _contains(text, "flutter/platform")
        assert len(text) <= recovered.MAX_OVERVIEW_CHARS + 80

    def test_debug_overview(self, tmp_path):
        """
        Purpose:
            Pin the debug-build overview built from recovered source.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root = tmp_path / "out"
        app = root / "dart_source/lib/main.dart"
        app.parent.mkdir(parents=True)
        app.write_text("const c = MethodChannel('com.demo/x');\nvoid f() { c.invokeMethod('go'); }\n")
        text = write_flutter_overview(root, "debug", {"http": "1.2.0"}).read_text()
        assert _contains(text, "Build: DEBUG")
        assert _contains(text, "http 1.2.0")
        assert _contains(text, 'invokeMethod "go" at dart_source/lib/main.dart:2')

    def test_overview_is_bounded(self):
        """
        Purpose:
            Pin that a huge channel map stays within the limit and says how many call sites it left out.
        """
        calls = [recovered.ChannelCall(channel="c", method=f"m{i}" * 20, file="asm/a/b.dart", line=i)
                 for i in range(400)]
        text = recovered.render_overview(
            mode="release", root=Path("/nonexistent"), app_packages=["a"], packages={},
            calls=calls, declared_channels=[], java_hits={}, pool_strings=[], has_platform=False)
        assert len(text) <= recovered.MAX_OVERVIEW_CHARS + 80
        assert _contains(text, f"+{400 - recovered.MAX_CHANNEL_SITES} more call sites")


class TestOverviewPriorities:
    """
    Purpose:
        What the overview keeps when space is short: the app's channels, its native libraries and the strings its const objects hold.
    """
    def test_const_object_strings_come_from_the_object_dump(self, release_tree):
        """
        Purpose:
            Pin that a pool entry listing const objects yields the strings inside them, read from objs.txt.

        Parameters:
            release_tree: The recovery fixture.

        Implementation notes:
            A real app's developer menu held a gateway secret in a const SelectableText; the pool carried only the list of widgets, so the secret was invisible to a pool search.
        """
        (release_tree / "pp.txt").write_text(POOL + "[pp+0x7000] List<Widget>(2) [Obj!ListTile@5e01, Obj!ListTile@5e02]\n")
        (release_tree / "objs.txt").write_text(
            "Obj!ListTile@5e01 : {\n  off_10_Obj!Text@5d01 : {\n    off_c: \"Gateway secret\"\n  },\n"
            "  off_14_Obj!SelectableText@5f01 : {\n    off_c: \"gw_live_secret_value_123\"\n  }\n}\n"
            "Obj!ListTile@5e99 : {\n  off_c: \"never referenced\"\n}\n")
        app = release_tree / "asm/demo/main.dart"
        app.write_text(app.read_text() + "    //     0x9: add x2, PP, #0x7  ; [pp+0x7000] List<Widget>(2)\n")
        objects = recovered.parse_object_dump((release_tree / "objs.txt").read_text())
        assert objects["5e01"] == ["Gateway secret", "gw_live_secret_value_123"]
        pool = recovered.parse_object_pool((release_tree / "pp.txt").read_text())
        strings = recovered.app_pool_strings([app], pool, objects)
        assert "gw_live_secret_value_123" in strings and "never referenced" not in strings
        text = write_flutter_overview(release_tree, "release").read_text()
        assert _contains(text, "gw_live_secret_value_123")

    def test_app_channels_first_plugins_on_one_line(self):
        """
        Purpose:
            Pin that the app's channel calls are listed with their sites and a plugin's channels are collapsed into one line after the app's strings.

        Implementation notes:
            On a lab app the plugins' pigeon calls filled the bound and pushed the app's strings out of the overview entirely.
        """
        calls = [recovered.ChannelCall(channel="com.demo/device", method="isRooted", file="asm/demo/guard.dart", line=3)]
        calls += [recovered.ChannelCall(channel=f"dev.flutter.pigeon.plugin.Api.m{i}", method=f"m{i}",
                                        file="asm/some_plugin/api.g.dart", line=i) for i in range(200)]
        text = recovered.render_overview(
            mode="release", root=Path("/nonexistent"), app_packages=["demo"], packages={},
            calls=calls, declared_channels=[], java_hits={}, pool_strings=["app string"],
            has_platform=False, native_lines=["Native libraries:", "  lib/arm64-v8a/libcore.so  loaded by the app"])
        assert _contains(text, 'invokeMethod "isRooted" at asm/demo/guard.dart:3')
        assert not _contains(text, "invokeMethod \"m1\"")
        order = [text.index(marker) for marker in
                 ("com.demo/device", "Native libraries:", "app string", "Plugin channels")]
        assert order == sorted(order)
        assert _contains(text, "(+185 more)")

    def test_graph_and_overview_name_the_ffi_library(self, release_tree):
        """
        Purpose:
            Pin that a library the app's Dart opens through dart:ffi is named in the overview and is a graph target.

        Parameters:
            release_tree: The recovery fixture.
        """
        app = release_tree / "asm/demo/main.dart"
        app.write_text(app.read_text() + '    // 0x40: r16 = "libcore.so"\n')
        for name in ("libcore.so", "libflutter.so", "libapp.so"):
            lib = release_tree / "platform/resources/lib/arm64-v8a" / name
            lib.parent.mkdir(parents=True, exist_ok=True)
            lib.write_bytes(b"\x7fELF")
        graph = build_flutter_graph(release_tree)
        assert [lib.path for lib in graph.native_libs] == ["platform/resources/lib/arm64-v8a/libcore.so"]
        text = write_flutter_overview(release_tree, "release").read_text()
        assert _contains(text, "libcore.so  loaded by the app at asm/demo/main.dart:")


class TestAnalyzerBuildModes:
    """
    Purpose:
        The analyzer's choice between debug and release handling.
    """
    def test_preflight(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a debug build needs no Blutter and a release build still does.

        Parameters:
            tmp_path: Directory for the fake APKs.
            monkeypatch: Reports Blutter as unconfigured.
        """
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.blutter_checker.check_blutter_configured",
            lambda **_: False)
        debug_dir = tmp_path / "d"
        debug_dir.mkdir()
        release_dir = tmp_path / "r"
        release_dir.mkdir()
        debug = _apk(debug_dir, {KERNEL_MEMBER: _kernel_bytes()})
        release = _apk(release_dir, {"lib/arm64-v8a/libapp.so": b"x"})
        assert FlutterAnalyzer().preflight(str(debug)) == (True, "")
        ready, reason = FlutterAnalyzer().preflight(str(release))
        assert ready is False and "Blutter" in reason

    def test_debug_build_is_analysed_from_source(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin the debug path end to end without Blutter: source recovered, overview written, graph built over it, and the agent given the debug label.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Stubs the provider, the agent, the scanners, JADX and the output location.
        """
        apk = _apk(tmp_path, {KERNEL_MEMBER: _kernel_bytes()})
        analyzer = FlutterAnalyzer()
        out = tmp_path / "out"
        seen = {}

        def fake_agent(source_root, code_graph, **kwargs):
            """
            Purpose:
                Record what the agent would have been given.

            Parameters:
                source_root: The analysis root.
                code_graph: The graph.
                kwargs: The label and checkpoint.

            Returns:
                No findings, success, and an empty transcript.
            """
            seen.update(root=Path(source_root), graph=code_graph, label=kwargs.get("framework_label"))
            return [], True, ""

        monkeypatch.setattr(fa_mod, "get_active_provider", lambda **_: object())
        monkeypatch.setattr(analyzer, "run_agent", fake_agent)
        monkeypatch.setattr(analyzer, "run_sast", lambda *_, **__: [])
        monkeypatch.setattr(analyzer.output_manager, "create_output_directory", lambda *_: tmp_path)
        monkeypatch.setattr(analyzer.output_manager, "get_flutter_lib_dir", lambda: tmp_path / "libs")
        monkeypatch.setattr(analyzer.output_manager, "get_flutter_output_dir", lambda: out)
        monkeypatch.setattr("lu77U_MobileSec.tools_checker.jadx_checker.check_jadx_configured",
                            lambda **_: False)
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.blutter_checker.check_blutter_configured",
            lambda **_: False)

        result = analyzer.analyze(str(apk), defer_cleanup=True)
        assert result["success"] is True
        assert seen["root"] == out
        assert "debug build" in seen["label"]
        assert "dart_source/lib/main.dart" in seen["graph"].flagged_files()
        assert _contains((out / recovered.OVERVIEW_NAME).read_text(), "Build: DEBUG")

    def test_release_without_blutter_fails_with_reason(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a release build reaching analyze without Blutter fails with a reason naming it.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Stubs the provider and the output location, and reports Blutter unconfigured.
        """
        apk = _apk(tmp_path, {"lib/arm64-v8a/libapp.so": b"x"})
        analyzer = FlutterAnalyzer()
        monkeypatch.setattr(fa_mod, "get_active_provider", lambda **_: object())
        monkeypatch.setattr(analyzer.output_manager, "create_output_directory", lambda *_: tmp_path)
        monkeypatch.setattr(analyzer.output_manager, "get_flutter_lib_dir", lambda: tmp_path / "libs")
        monkeypatch.setattr(analyzer.output_manager, "get_flutter_output_dir", lambda: tmp_path / "out")
        monkeypatch.setattr(
            "lu77U_MobileSec.tools_checker.blutter_checker.check_blutter_configured",
            lambda **_: False)
        result = analyzer.analyze(str(apk), defer_cleanup=True)
        assert result["success"] is False
        assert "Blutter is not configured" in result["error"]


class TestFlutterBuildRule:
    """
    Purpose:
        The deterministic debug-build finding.
    """
    def test_debug_tree_yields_one_build_finding(self, tmp_path):
        """
        Purpose:
            Pin that recovered app source produces one BUILD-01 finding citing main.dart, and a release tree produces none.

        Parameters:
            tmp_path: Directory the trees are written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.flutter_build import analyze_flutter_build
        debug = tmp_path / "debug"
        (debug / "dart_source/lib/screens").mkdir(parents=True)
        (debug / "dart_source/lib/screens/a.dart").write_text("class A {}\n")
        (debug / "dart_source/lib/main.dart").write_text("void main() {}\n")
        (findings,) = analyze_flutter_build(debug)
        assert findings.vuln_class == "BUILD-01"
        assert (findings.file, findings.line) == ("dart_source/lib/main.dart", 1)
        release = tmp_path / "release"
        (release / "asm/demo").mkdir(parents=True)
        assert analyze_flutter_build(release) == []

    def test_flutter_profile_runs_the_build_rule(self, tmp_path):
        """
        Purpose:
            Pin that the Flutter rule set includes the build rule.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        from lu77U_MobileSec.analyzers.sast.runner import run_sast
        (tmp_path / "dart_source/lib").mkdir(parents=True)
        (tmp_path / "dart_source/lib/main.dart").write_text("void main() {}\n")
        assert any(f.detector == "flutter-build" for f in run_sast(tmp_path, "flutter"))


class TestFlutterAgentTools:
    """
    Purpose:
        Agent tool behaviour that matters on a Flutter analysis root.
    """
    def test_search_with_a_path_covers_the_manifest(self, release_tree):
        """
        Purpose:
            Pin that a search scoped to the manifest searches it, rather than answering no matches because it is a resource file.

        Parameters:
            release_tree: The recovery fixture.

        Implementation notes:
            On a real scan the agent searched the manifest for 'exported', was told there were no matches although there were four, and went on as if the app exported nothing.
        """
        from lu77U_MobileSec.analyzers.agent.profiles import FLUTTER
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools
        manifest = release_tree / "platform/resources/AndroidManifest.xml"
        manifest.write_text('<manifest>\n  <activity android:exported="true"/>\n</manifest>\n')
        tools = AgentTools(release_tree, profile=FLUTTER)
        found = tools.search_code("exported", "platform/resources/AndroidManifest.xml")
        assert _contains(found, "AndroidManifest.xml:2")
        assert _contains(tools.search_code("exported", "platform/resources"), "AndroidManifest.xml:2")

    def test_entry_points_without_a_call_graph_guides_instead_of_failing(self, release_tree):
        """
        Purpose:
            Pin that a Flutter entry-point request names the main library, the channel map and the manifest instead of returning an error.

        Parameters:
            release_tree: The recovery fixture.
        """
        from lu77U_MobileSec.analyzers.agent.profiles import FLUTTER, JAVA_KOTLIN
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools
        answer = AgentTools(release_tree, profile=FLUTTER).entry_points()
        assert not answer.startswith("ERROR")
        assert _contains(answer, "asm/demo/main.dart")
        assert _contains(answer, "platform/resources/AndroidManifest.xml")
        assert AgentTools(release_tree, profile=JAVA_KOTLIN).entry_points().startswith("ERROR")


class TestManifestSummary:
    """
    Purpose:
        The manifest section of the Flutter overview.
    """
    def test_exported_components_flags_and_schemes(self, tmp_path):
        """
        Purpose:
            Pin the flags line, that explicitly and implicitly exported components are listed with their actions, schemes and permission, and that private ones are not.

        Parameters:
            tmp_path: Directory the manifest is written into.
        """
        from lu77U_MobileSec.analyzers.sast.extractors.manifest import summarise_manifest
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">\n'
            '  <uses-sdk android:targetSdkVersion="30"/>\n'
            '  <application android:debuggable="true">\n'
            '    <activity android:name="com.demo.Main" android:exported="true">\n'
            '      <intent-filter><action android:name="android.intent.action.VIEW"/>'
            '<data android:scheme="demoapp"/></intent-filter>\n'
            '    </activity>\n'
            '    <receiver android:name="com.demo.Implicit">\n'
            '      <intent-filter><action android:name="com.demo.PING"/></intent-filter>\n'
            '    </receiver>\n'
            '    <service android:name="com.demo.Private" android:exported="false"/>\n'
            '    <provider android:name="com.demo.Guarded" android:exported="true" '
            'android:permission="com.demo.READ"/>\n'
            '  </application>\n</manifest>\n')
        lines = summarise_manifest(manifest)
        assert lines[0] == ("Manifest: package com.demo, targetSdk 30, debuggable=true, "
                            "allowBackup=true (default)")
        assert "  exported activity com.demo.Main actions: VIEW schemes: demoapp" in lines
        assert "  exported receiver com.demo.Implicit actions: PING" in lines
        assert "  exported provider com.demo.Guarded (permission com.demo.READ)" in lines
        assert not any("Private" in line for line in lines)
        assert summarise_manifest(tmp_path / "missing.xml") == []

    def test_overview_carries_the_manifest(self, release_tree):
        """
        Purpose:
            Pin that the overview includes the manifest section when the platform layer was decompiled.

        Parameters:
            release_tree: The recovery fixture.
        """
        (release_tree / "platform/resources/AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">'
            '<application><activity android:name="com.demo.Main" android:exported="true"/>'
            '</application></manifest>')
        text = write_flutter_overview(release_tree, "release").read_text()
        assert _contains(text, "Manifest: package com.demo")
        assert _contains(text, "exported activity com.demo.Main")


VAULT_MAIN_ASM = '''// lib: , url: package:vault/main.dart

// class id: 1, size: 0x8
class :: {

  static void main() {
    // ** addr: 0x1000, size: 0x30
    // 0x1000: r0 = runApp()
    //     0x1000: bl              #0x9000  ; [package:flutter/src/widgets/binding.dart] ::runApp
  }
}
'''

VAULT_DEV_ASM = '''// lib: , url: package:vault/dev_menu.dart

class DevMenu extends StatelessWidget {

  _ build(/* No info */) {
    // ** addr: 0x2000, size: 0x80
    // 0x2004: r16 = "Developer Options"
    // 0x2008: r16 = Instance_Card
    //     0x2008: add             x16, PP, #0x13, lsl #12  ; [pp+0x139e0] Obj!Card@575c61
    // 0x200c: r2 = const [Obj!ListTile@585ed1]
    //     0x200c: add             x2, PP, #0x14, lsl #12  ; [pp+0x14f18] List<Widget>(1) [Obj!ListTile@585ed1]
  }
}
'''

VAULT_OBJS = '''Obj!Card@575c61 : {
  off_c: Obj!_InfoRow@575de1 : {
    off_c: "Debug API Key",
    off_10: "AKIA-DEMO-0000-1111"
  }
}
Obj!ListTile@585ed1 : {
  off_c: "Gateway secret",
  off_10: "gw_demo_secret_0123456789"
}
'''

VAULT_POOL = '''[pp+0x139e0] Obj!Card@575c61 : {
}
[pp+0x14f18] List<Widget>(1) [Obj!ListTile@585ed1]
'''


@pytest.fixture
def pool_tree(tmp_path):
    """
    Purpose:
        Build a release recovery whose secrets sit in const objects that one screen loads.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The analysis root.
    """
    for rel, text in {"asm/vault/main.dart": VAULT_MAIN_ASM, "asm/vault/dev_menu.dart": VAULT_DEV_ASM,
                      "objs.txt": VAULT_OBJS, "pp.txt": VAULT_POOL}.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


class TestPoolCitations:
    """
    Purpose:
        Finding the app code that loads a value Blutter's pool or object dump holds.
    """

    def _line(self, marker):
        """
        Purpose:
            Find a line of the developer-menu fixture.

        Parameters:
            marker: Text on the line.

        Returns:
            Its 1-based number.
        """
        return next(i for i, l in enumerate(VAULT_DEV_ASM.splitlines(), 1) if marker in l)

    def test_direct_literals_objects_and_pool_lists_are_found(self, pool_tree):
        """
        Purpose:
            Pin the three ways code loads a value - a literal, a const object holding it, a pool list naming that object - each resolved to the summary line.

        Parameters:
            pool_tree: The fixture tree.
        """
        locator = recovered.LiteralLocator(pool_tree)
        assert locator.locate("Developer Options") == ("asm/vault/dev_menu.dart", self._line('"Developer Options"'))
        assert locator.locate("AKIA-DEMO-0000-1111") == ("asm/vault/dev_menu.dart", self._line("Instance_Card"))
        assert locator.locate("gw_demo_secret_0123456789") == ("asm/vault/dev_menu.dart", self._line("const [Obj"))
        assert locator.locate("never-loaded-value") is None
        assert locator.locate("abc") is None
        assert locator.complete("gw_demo_secr") == "gw_demo_secret_0123456789"
        assert locator.complete("gw_d") is None

    def test_the_analyzer_recites_pool_findings(self, pool_tree):
        """
        Purpose:
            Pin that a finding citing the object dump is moved to the screen that loads the value, keeping where it was first cited.

        Parameters:
            pool_tree: The fixture tree.
        """
        analyzer = FlutterAnalyzer()
        vulns = [{"title": "Hardcoded key 'AKIA-DEMO-0000-1111'", "file": "objs.txt", "line": "4"},
                 {"title": "Hardcoded gateway secret 'gw_demo_secr...'", "file": "pp.txt", "line": "65"},
                 {"title": "Hardcoded value 'not-in-the-app'", "file": "pp.txt", "line": "1"},
                 {"title": "Elsewhere", "file": "asm/vault/main.dart", "line": "7"}]
        analyzer._recite_pool_findings(vulns, pool_tree)
        assert (vulns[0]["file"], vulns[0]["line"]) == ("asm/vault/dev_menu.dart", str(self._line("Instance_Card")))
        assert vulns[0]["pool_reference"] == "objs.txt:4"
        assert (vulns[1]["file"], vulns[1]["line"]) == ("asm/vault/dev_menu.dart", str(self._line("const [Obj")))
        assert (vulns[2]["file"], vulns[3]["file"]) == ("pp.txt", "asm/vault/main.dart")
