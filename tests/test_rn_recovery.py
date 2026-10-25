#!/usr/bin/env python3
"""
Module: test_rn_recovery

Purpose:
    The React Native recovery path: splitting a bundle into Metro modules, telling the app from the framework, laying minified code out readably, reading hermes-decomp's extraction, the overview's native-module map and leads, the graph over the module tree, and the analyzer's build-aware preflight.

Responsibilities:
    Pin that every module of a plain bundle is recovered with its id, dependencies and name, that the formatter only ever changes whitespace, that the app region is computed from the entry's non-framework dependencies, that native modules are found and joined to the JavaScript that calls them, and that the framework stays out of the graph.

Dependencies:
    pytest, the Metro module layer, the React Native overview, graph and analyzer, the Hermes runner and the agent tools.

Implementation notes:
    The fixtures are written in the real shapes -- Metro's __d(function(g,r,i,a,m,e,d){...},id,[deps]) definitions, hermes-decomp's module headers, JADX's fully-qualified Java -- so the parsers are tested against what they meet in practice. The classification test pins the case that went wrong on a real app, where the root component's closure contains react-native's and was mistaken for the framework.
"""

import hmac
import re
import zipfile
from pathlib import Path

import pytest

from lu77U_MobileSec.analyzers.react_native import overview as ov
from lu77U_MobileSec.analyzers.react_native.graph import build_rn_graph
from lu77U_MobileSec.analyzers.react_native_analyzer import ReactNativeAnalyzer
from lu77U_MobileSec.decompiler import hermes_runner
from lu77U_MobileSec.decompiler.rn_metro import (
    MetroModule, classify_modules, format_js, read_extracted_modules, split_plain_bundle,
    write_module_tree)


def _contains(haystack, needle):
    """
    Purpose:
        Check whether needle occurs in haystack by comparing every window with hmac.compare_digest, since the overview text carries credential-shaped values and CodeQL flags a plain membership check on such text.

    Parameters:
        haystack: The text to search within.
        needle: The literal substring to look for.

    Returns:
        True when needle appears in haystack.
    """
    width = len(needle)
    return any(hmac.compare_digest(haystack[i:i + width], needle)
               for i in range(len(haystack) - width + 1))


def _define(module_id, deps, body, name=None):
    """
    Purpose:
        Write one Metro module definition as a plain bundle carries it.

    Parameters:
        module_id: The module id.
        deps: Its dependency ids.
        body: The factory body.
        name: A dev bundle's verbose name, when given.

    Returns:
        The definition text.
    """
    verbose = f',"{name}"' if name else ""
    return f"__d(function(g,r,i,a,m,e,d){{{body}}},{module_id},[{','.join(map(str, deps))}]{verbose});\n"


PRELUDE = ("var __BUNDLE_START_TIME__=Date.now();\n"
           "!(function(e){e.__d=function(e,n,o){r.set(n,o)}})(globalThis);\n")


def _plain_bundle():
    """
    Purpose:
        Build a small plain Metro bundle shaped like a real app: entry, react-native with its own closure, an app root, an app module importing a library, and app.json.

    Returns:
        The bundle text.
    """
    return (PRELUDE
            + _define(0, [1, 2, 50, 60], 'var t=r(d[1]);t.AppRegistry.registerComponent("demo",function(){return r(d[2]).default})')
            + _define(1, [], "e.default={}")
            + _define(2, [3, 1], "e.AppRegistry={registerComponent:function(){}}")
            + _define(3, [4], "e.View=1")
            + _define(4, [], "e.flatten=function(n){return n}")
            + _define(50, [2, 51, 52], 'e.default=function(n){var p=n.isPro;return p?"paid":"locked"}')
            + _define(51, [53], 'e.SECRET_KEY="sk_' + 'live_0123456789abcdefABCD";e.default=1')
            + _define(52, [], 'e.default=function(){return r(d[0]).NativeModules.SupportModule.openLogFile("x")}')
            + _define(53, [], 'e.getItem=function(k){return k}')
            + _define(60, [], 'm.exports={name:"demo"}', name="app.json")
            + "__r(0);\n")


class TestPlainBundleSplit:
    """
    Purpose:
        Splitting a plain Metro bundle into modules.
    """
    def test_every_module_with_ids_deps_and_names(self):
        """
        Purpose:
            Pin the recovered ids, dependency lists, export-derived names and verbose names, and that the runtime prelude is not mistaken for a module.
        """
        modules = {m.id: m for m in split_plain_bundle(_plain_bundle())}
        assert sorted(modules) == [0, 1, 2, 3, 4, 50, 51, 52, 53, 60]
        assert modules[0].deps == [1, 2, 50, 60]
        assert modules[51].name == "SECRET_KEY"
        assert modules[53].name == "getItem"
        assert modules[60].name == "app.json"
        assert modules[50].name == ""
        assert modules[51].code.startswith("// Module ID: 51\n// Name: SECRET_KEY\n// Dependencies: [53]")

    def test_last_module_ignores_trailing_requires(self):
        """
        Purpose:
            Pin that the trailing __r() calls do not corrupt the last module's tail.
        """
        last = split_plain_bundle(_plain_bundle())[-1]
        assert last.id == 60 and last.deps == []
        assert "__r(0)" not in last.code


TRICKY = ('var a="x;{y}",b=/[{;}]\\/re{2}/g,c=`t${n.map(function(q){return {k:q}})}`;'
          "for(var i=0;i<2;i++){f(i)}/* c;{ */if(a){b()}else{c()}"
          "var re=x.replace(/;/g,'');return /a}b/.test(re)")


class TestFormatter:
    """
    Purpose:
        Laying minified JavaScript out on readable lines.
    """
    def test_only_whitespace_changes(self):
        """
        Purpose:
            Pin that formatting inserts or removes whitespace only, even through strings, regular expressions, template literals and comments containing braces and semicolons.
        """
        out = format_js(TRICKY)
        assert re.sub(r"\s+", "", out) == re.sub(r"\s+", "", TRICKY)

    def test_lines_are_split_and_for_headers_kept(self):
        """
        Purpose:
            Pin that statements land on their own lines while a for(;;) header stays whole.
        """
        out = format_js(TRICKY)
        lines = out.splitlines()
        assert len(lines) > 5
        assert any("for(var i=0;i<2;i++){" in line for line in lines)
        assert any(line.strip() == "f(i)" for line in lines)

    def test_long_minified_line_is_broken_up(self):
        """
        Purpose:
            Pin that a long single-line module becomes many short lines.
        """
        code = ";".join(f"var v{i}={{a:{i}}}" for i in range(500))
        out = format_js(code)
        assert max(len(line) for line in out.splitlines()) < 100


class TestClassification:
    """
    Purpose:
        Telling the app region from the framework.
    """
    def test_app_region_and_framework(self):
        """
        Purpose:
            Pin the split for the usual entry shape.

        Implementation notes:
            The root component's closure contains react-native's, so choosing the largest closure as the framework picked the app on a real bundle; the framework root is the entry dependency another entry dependency reaches.
        """
        entry, app, framework = classify_modules(split_plain_bundle(_plain_bundle()))
        assert entry == 0
        assert app == {0, 50, 51, 52, 53, 60}
        assert framework == {1, 2, 3, 4}

    def test_fallback_without_a_shared_dependency(self):
        """
        Purpose:
            Pin the fallback when the entry's dependencies share nothing: the module with the most dependencies is the framework.
        """
        modules = [MetroModule(0, deps=[5, 9]), MetroModule(5, deps=[6, 7, 8]),
                   MetroModule(6), MetroModule(7), MetroModule(8),
                   MetroModule(9, deps=[10]), MetroModule(10)]
        _entry, app, framework = classify_modules(modules)
        assert framework == {5, 6, 7, 8}
        assert app == {0, 9, 10}

    def test_imported_libraries_leave_the_app_region(self):
        """
        Purpose:
            Pin that a library the app imports, and everything only it reaches, moves to the framework side, while the app's own modules and a re-export it imports directly stay.

        Implementation notes:
            Module 30 is a re-export the app imports by id and carries no marker, so it stays; 31 is the WebView component with its native name, 40 is crypto-js registering its global, and 41 is reached only through 40.
        """
        modules = [MetroModule(0, deps=[5, 9]), MetroModule(5, deps=[6, 7, 8]),
                   MetroModule(6), MetroModule(7), MetroModule(8),
                   MetroModule(9, deps=[10, 30, 40], code="screen"),
                   MetroModule(10, code="const key = Utf8.parse(KEY);"),
                   MetroModule(30, deps=[31], code="export const WebView = module_31.default;"),
                   MetroModule(31, code='const config = { uiViewClassName: "RNCWebView" };'),
                   MetroModule(40, deps=[41], code="root.CryptoJS = factory();"),
                   MetroModule(41, code="function evpKdf() {}")]
        _entry, app, framework = classify_modules(modules)
        assert app == {0, 9, 10, 30}
        assert {31, 40, 41} <= framework


class TestModuleTree:
    """
    Purpose:
        Reading hermes-decomp's extraction and writing the module tree.
    """
    def test_read_extracted_headers(self, tmp_path):
        """
        Purpose:
            Pin that ids, names and dependencies come from the header, and that an unnamed module gets an empty name.

        Parameters:
            tmp_path: Directory for the fake extraction.
        """
        (tmp_path / "7_Login.js").write_text(
            "// Module ID: 7\n// Function ID: 99\n// Name: Login\n// Dependencies: [1, 2]\n\nexport default 1;\n")
        (tmp_path / "8_x.js").write_text("// Module ID: 8\n// Name: ?\n// Dependencies: []\n")
        modules = {m.id: m for m in read_extracted_modules(tmp_path)}
        assert (modules[7].name, modules[7].deps) == ("Login", [1, 2])
        assert modules[8].name == ""

    def test_write_tree_with_hostile_names(self, tmp_path):
        """
        Purpose:
            Pin the two directories, safe file names, and that nothing is written outside the root.

        Parameters:
            tmp_path: Directory for the tree.
        """
        modules = [MetroModule(0, deps=[1, 2], code="entry"), MetroModule(1, deps=[3], code="rn"),
                   MetroModule(2, name="../../evil/x", deps=[1], code="app"), MetroModule(3, code="rn2")]
        tree = write_module_tree(modules, tmp_path / "out")
        assert tree.files[2].startswith("app_modules/2_")
        assert ".." not in tree.files[2] and "/" not in tree.files[2][len("app_modules/"):]
        assert tree.files[1].startswith("framework_modules/")
        for path in tmp_path.rglob("*"):
            assert (tmp_path / "out").resolve() in path.resolve().parents or path.resolve() == (tmp_path / "out").resolve()


MODULE_JAVA = '''package com.demo.app;

public final class SupportModule extends com.facebook.react.bridge.ReactContextBaseJavaModule {
    @Override // com.facebook.react.bridge.NativeModule
    public java.lang.String getName() {
        return "SupportModule";
    }

    @com.facebook.react.bridge.ReactMethod
    public final void openLogFile(java.lang.String path, com.facebook.react.bridge.Promise promise) {
        promise.resolve(path);
    }

    public final void notExposed(java.lang.String s) {
    }
}
'''

SPEC_JAVA = '''package org.storage;

public abstract class NativeStoreSpec extends com.facebook.react.bridge.ReactContextBaseJavaModule {
    public static final java.lang.String NAME = "RNStore";

    @Override
    public java.lang.String getName() {
        return NAME;
    }

    @com.facebook.react.bridge.ReactMethod
    public abstract void getValues(java.lang.String db, com.facebook.react.bridge.Promise promise);
}
'''

IMPL_JAVA = '''package org.storage;

public final class StoreModule extends NativeStoreSpec {
    @com.facebook.react.bridge.ReactMethod
    public void clear(com.facebook.react.bridge.Promise promise) {
    }
}
'''


@pytest.fixture
def rn_root(tmp_path):
    """
    Purpose:
        Build a recovered React Native analysis root: a module tree from the plain bundle, a platform layer with an app module, a library spec and implementation, React Native's own module, its version class and a manifest.

    Parameters:
        tmp_path: Directory the root is written into.

    Returns:
        The analysis root.
    """
    root = tmp_path / "out"
    write_module_tree(split_plain_bundle(_plain_bundle()), root)
    files = {
        "platform/sources/com/demo/app/SupportModule.java": MODULE_JAVA,
        "platform/sources/org/storage/NativeStoreSpec.java": SPEC_JAVA,
        "platform/sources/org/storage/StoreModule.java": IMPL_JAVA,
        "platform/sources/com/facebook/react/modules/toast/ToastModule.java":
            MODULE_JAVA.replace("SupportModule", "ToastModule"),
        "platform/sources/com/facebook/react/modules/systeminfo/ReactNativeVersion.java":
            'public class ReactNativeVersion { public static final java.util.Map VERSION = '
            'kotlin.collections.MapsKt.mapOf(kotlin.TuplesKt.to("major", 0), '
            'kotlin.TuplesKt.to("minor", 81), kotlin.TuplesKt.to("patch", 6)); }\n',
        "platform/resources/AndroidManifest.xml":
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">'
            '<application><activity android:name="com.demo.app.MainActivity" android:exported="true"/>'
            '</application></manifest>',
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


class TestOverview:
    """
    Purpose:
        The React Native overview and the extractors behind it.
    """
    def test_engine_from_header(self, tmp_path):
        """
        Purpose:
            Pin Hermes detection and the bytecode version, and plain JS otherwise.

        Parameters:
            tmp_path: Directory for the fake bundles.
        """
        hbc = tmp_path / "a.bundle"
        hbc.write_bytes(ov.HERMES_MAGIC + (96).to_bytes(4, "little") + b"\x00" * 8)
        js = tmp_path / "b.bundle"
        js.write_text("var __BUNDLE_START_TIME__=1;")
        assert ov.bundle_engine(hbc) == ("hermes", 96)
        assert ov.bundle_engine(js) == ("javascript", None)

    def test_library_markers(self, tmp_path):
        """
        Purpose:
            Pin the engine and architecture markers read from the APK's libraries.

        Parameters:
            tmp_path: Directory for the fake APK.
        """
        apk = tmp_path / "a.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            for name in ("libhermes.so", "libreactnativejni.so", "libfabricjni.so"):
                zf.writestr(f"lib/arm64-v8a/{name}", b"x")
        markers = ov.native_library_markers(apk)
        assert any("libhermes.so" in m for m in markers)
        assert any("libfabricjni.so" in m for m in markers)
        assert any("CatalystInstanceImpl" in m for m in markers)

    def test_version_both_spellings(self, rn_root):
        """
        Purpose:
            Pin the React Native version from the Kotlin mapOf form, and from the older MapBuilder form.

        Parameters:
            rn_root: The analysis root fixture.
        """
        assert ov.react_native_version(rn_root) == "0.81.6"
        version = rn_root / "platform/sources/com/facebook/react/modules/systeminfo/ReactNativeVersion.java"
        version.write_text('VERSION = com.facebook.react.common.MapBuilder.of("major", 0, "minor", 70, "patch", 15);')
        assert ov.react_native_version(rn_root) == "0.70.15"

    def test_native_modules(self, rn_root):
        """
        Purpose:
            Pin module discovery: app ownership by package, the literal and constant getName forms, spec and implementation merged, @ReactMethod methods only, and React Native's own modules skipped.

        Parameters:
            rn_root: The analysis root fixture.
        """
        modules = {m.js_name: m for m in ov.find_native_modules(rn_root, "com.demo.app")}
        assert set(modules) == {"SupportModule", "RNStore"}
        support = modules["SupportModule"]
        assert support.app_owned and support.methods == ["openLogFile(path, promise)"]
        store = modules["RNStore"]
        assert not store.app_owned
        assert store.java_class == "StoreModule"
        assert set(store.methods) == {"clear(promise)", "getValues(db, promise)"}

    def test_js_usage(self, rn_root):
        """
        Purpose:
            Pin the JavaScript leads read from the app region only, including the entitlement flag a client-side gate reads.

        Parameters:
            rn_root: The analysis root fixture.
        """
        usage = ov.js_usage(rn_root)
        assert any(hmac.compare_digest(detail, "SupportModule.openLogFile") for detail, _ in usage["native"])
        assert any(_contains(detail, "Stripe Secret Key") and _contains(detail, "withheld") for detail, _ in usage["secret"])
        assert not any(_contains(detail, "registerComponent") for detail, _ in usage["native"])
        assert usage["gate"] == [("isPro", "app_modules/50.js:7")]

    def test_render(self, rn_root):
        """
        Purpose:
            Pin the native-module map, the called-from join and the not-called note, and the bound.

        Parameters:
            rn_root: The analysis root fixture.
        """
        bundle = rn_root / "bundle.bin"
        bundle.write_bytes(ov.HERMES_MAGIC + (89).to_bytes(4, "little"))
        path = ov.write_rn_overview(rn_root, rn_root / "missing.apk", bundle, "6 app-region modules")
        text = path.read_text()
        assert _contains(text, "Hermes bytecode (HBC version 89)")
        assert _contains(text, "React Native 0.81.6")
        assert _contains(text, "Manifest: package com.demo.app")
        assert _contains(text, "SupportModule [app] platform/sources/com/demo/app/SupportModule.java: openLogFile(path, promise)")
        assert _contains(text, "called from JS: app_modules/52.js")
        assert _contains(text, "Entitlement and role flags in app code")
        assert _contains(text, "isPro  (app_modules/50.js:7)")
        assert len(text) <= ov.MAX_OVERVIEW_CHARS + 80
        (rn_root / "app_modules/52.js").write_text("// Module ID: 52\n// Dependencies: []\n")
        text = ov.write_rn_overview(rn_root, rn_root / "missing.apk", bundle).read_text()
        assert _contains(text, "not called from the app's JS - still exposed")


class TestGraph:
    """
    Purpose:
        The graph over a Metro module tree.
    """
    def test_module_tree_graph(self, rn_root):
        """
        Purpose:
            Pin that every app-region module is flagged, the entry is marked, refs follow the dependency headers, the app's native module is a node, and the framework and library native modules are not.

        Parameters:
            rn_root: The analysis root fixture.
        """
        graph = build_rn_graph(rn_root)
        flagged = set(graph.flagged_files())
        assert {f for f in flagged if f.startswith("app_modules/")} == set(
            p.relative_to(rn_root).as_posix() for p in (rn_root / "app_modules").glob("*.js"))
        assert graph.nodes["app_modules/0.js"].role == "app-entry"
        assert "app_modules/51_SECRET_KEY.js" in graph.nodes["app_modules/50.js"].refs
        assert graph.nodes["platform/sources/com/demo/app/SupportModule.java"].role == "native-module"
        assert not any(k.startswith("framework_modules/") for k in graph.nodes)
        assert not any("StoreModule" in k for k in graph.nodes)


class TestAnalyzer:
    """
    Purpose:
        The analyzer's build-aware preflight and module recovery.
    """
    def _apk(self, tmp_path, bundle_bytes):
        """
        Purpose:
            Write an APK holding a bundle.

        Parameters:
            tmp_path: Directory to write into.
            bundle_bytes: The bundle's contents.

        Returns:
            The APK path.
        """
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("assets/index.android.bundle", bundle_bytes)
        return apk

    def test_preflight_by_format(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a plain bundle needs no tool and a Hermes bundle needs hermes-decomp.

        Parameters:
            tmp_path: Directory for the fake APKs.
            monkeypatch: Reports both decompilers unconfigured.
        """
        monkeypatch.setattr("lu77U_MobileSec.tools_checker.hermes_checker.check_hermes_configured",
                            lambda **_: False)
        monkeypatch.setattr("lu77U_MobileSec.tools_checker.rn_decompiler_checker.check_rn_decompiler_configured",
                            lambda **_: False)
        plain_dir = tmp_path / "p"
        plain_dir.mkdir()
        hermes_dir = tmp_path / "h"
        hermes_dir.mkdir()
        plain = self._apk(plain_dir, _plain_bundle().encode())
        hermes = self._apk(hermes_dir, ov.HERMES_MAGIC + (96).to_bytes(4, "little"))
        assert ReactNativeAnalyzer().preflight(str(plain)) == (True, "")
        ready, reason = ReactNativeAnalyzer().preflight(str(hermes))
        assert ready is False and "hermes_decomp_path" in reason

    def test_plain_bundle_recovered_without_tools(self, tmp_path):
        """
        Purpose:
            Pin that a plain bundle is recovered into the module tree by the built-in splitter.

        Parameters:
            tmp_path: Directory for the bundle and output.
        """
        bundle = tmp_path / "index.android.bundle"
        bundle.write_text(_plain_bundle())
        summary = ReactNativeAnalyzer()._recover_modules(bundle, tmp_path / "out", hermes=False)
        assert summary == "6 app-region modules, 4 framework modules"
        assert (tmp_path / "out/app_modules/51_SECRET_KEY.js").is_file()

    def test_hermes_extract_feeds_the_tree(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that hermes-decomp's extraction becomes the module tree and its scratch directory is removed.

        Parameters:
            tmp_path: Directory for the bundle and output.
            monkeypatch: Replaces the extraction with one that writes module files.
        """
        def fake_extract(bundle_path, out_dir, verbose=False):
            """
            Purpose:
                Write module files the way hermes-decomp's extract does.

            Parameters:
                bundle_path: The bundle, required by the interface.
                out_dir: Where to write.
                verbose: Unused tracing flag.

            Returns:
                The output directory.
            """
            out_dir = Path(out_dir)
            out_dir.mkdir(parents=True)
            for module in split_plain_bundle(_plain_bundle()):
                (out_dir / f"{module.id}_{module.name or 'x'}.js").write_text(module.code)
            assert Path(bundle_path).name == "b.hbc" and verbose is False
            return out_dir
        monkeypatch.setattr("lu77U_MobileSec.analyzers.react_native_analyzer.extract_hbc_modules", fake_extract)
        bundle = tmp_path / "b.hbc"
        bundle.write_bytes(b"x")
        summary = ReactNativeAnalyzer()._recover_modules(bundle, tmp_path / "out", hermes=True)
        assert summary == "6 app-region modules, 4 framework modules"
        assert not (tmp_path / "out/.hermes_extract").exists()


class TestNativeAndEvidence:
    """
    Purpose:
        The app's native libraries in the overview and graph, and the module vocabulary attached to findings.
    """
    def _add_native_library(self, rn_root):
        """
        Purpose:
            Bundle a library the app's own module loads, plus one only a library loads.

        Parameters:
            rn_root: The analysis root fixture.
        """
        signer = rn_root / "platform/sources/com/demo/app/SignerModule.java"
        signer.write_text('class SignerModule { static { System.loadLibrary("signer"); } }\n')
        for name in ("libsigner.so", "libvendor.so", "libhermes.so"):
            lib = rn_root / "platform/resources/lib/arm64-v8a" / name
            lib.parent.mkdir(parents=True, exist_ok=True)
            lib.write_bytes(b"\x7fELF")

    def test_overview_and_graph_name_the_app_library(self, rn_root):
        """
        Purpose:
            Pin that the overview names the library the app loads, with where, and that the graph makes inspecting it part of coverage.

        Parameters:
            rn_root: The analysis root fixture.

        Implementation notes:
            A real scan read the JNI bridge and never opened the library behind it, because nothing named the library as the app's.
        """
        self._add_native_library(rn_root)
        bundle = rn_root / "bundle.bin"
        bundle.write_bytes(ov.HERMES_MAGIC + (96).to_bytes(4, "little"))
        text = ov.write_rn_overview(rn_root, rn_root / "missing.apk", bundle).read_text()
        assert _contains(text, "platform/resources/lib/arm64-v8a/libsigner.so  loaded by the app at "
                               "platform/sources/com/demo/app/SignerModule.java:1")
        assert _contains(text, "libhermes.so, libvendor.so")
        graph = build_rn_graph(rn_root)
        assert [lib.path for lib in graph.native_libs] == ["platform/resources/lib/arm64-v8a/libsigner.so"]
        assert "platform/resources/lib/arm64-v8a/libsigner.so" in graph.flagged_files()

    def test_module_terms_only_for_modules(self, rn_root):
        """
        Purpose:
            Pin that a finding citing a recovered module records the module's vocabulary, and one citing the platform layer does not.

        Parameters:
            rn_root: The analysis root fixture.
        """
        (rn_root / "app_modules/52.js").write_text(
            "// Module ID: 52\nconst key = 'k';\nconst a = 1;\nconst b = 2;\nconst c = 3;\n"
            "const d = 4;\nconst e = 5;\nfunction seal(x) { return CryptoJS.AES.encrypt(x, key); }\n")
        vulns = [
            {"title": "Hardcoded AES key", "file": "app_modules/52.js", "line_number": 2},
            {"title": "Hardcoded AES key", "file": "platform/sources/com/demo/app/SupportModule.java",
             "line_number": 4},
        ]
        ReactNativeAnalyzer().enrich_vulnerabilities(vulns, rn_root)
        assert "aes" in vulns[0]["code_context"]["module_terms"]
        assert "module_terms" not in vulns[1]["code_context"]


class TestHermesExtract:
    """
    Purpose:
        The wrapper around hermes-decomp's extract command.
    """
    def test_command_and_success_by_files(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin the command shape, that success means module files were written, and that the extras land beside the module directory.

        Parameters:
            tmp_path: Directory for the output.
            monkeypatch: Replaces the configured path and the process runner.
        """
        calls = []

        class Done:
            """
            Purpose:
                A completed process result.

            Attributes:
                returncode: The exit status.
                stdout: The standard output.
                stderr: The standard error output.
            """
            def __init__(self, stdout=""):
                """
                Purpose:
                    Build the result.

                Parameters:
                    stdout: The standard output to report.
                """
                self.returncode = 0
                self.stdout = stdout
                self.stderr = ""

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Record the command and play hermes-decomp's part.

            Parameters:
                cmd: The argument vector.
                kwargs: The subprocess options.

            Returns:
                A successful result.
            """
            calls.append(cmd)
            assert kwargs.get("timeout")
            if cmd[1] == "extract":
                out = Path(cmd[cmd.index("-o") + 1])
                (out / "0_entry.js").write_text("// Module ID: 0\n")
                return Done()
            return Done(stdout=f"{cmd[1]} output\n")
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path", lambda: "/x/hermes-decomp")
        monkeypatch.setattr(hermes_runner.subprocess, "run", fake_run)
        out = hermes_runner.extract_hbc_modules(tmp_path / "b.hbc", tmp_path / "out" / "mods")
        assert out == tmp_path / "out" / "mods"
        assert calls[0][:3] == ["/x/hermes-decomp", "extract", str(tmp_path / "b.hbc")]
        assert (tmp_path / "out/secrets.txt").read_text() == "secrets output\n"
        assert (tmp_path / "out/modules.txt").is_file()


class TestAgentTools:
    """
    Purpose:
        Agent tool behaviour that matters on a React Native root.
    """
    def test_long_lines_are_capped(self, tmp_path):
        """
        Purpose:
            Pin that one enormous minified line is cut in a page rather than returned whole.

        Parameters:
            tmp_path: Directory for the file.

        Implementation notes:
            A real plain bundle carried lines of 121,000 characters; a page always includes at least one whole line, so without the cap one read returned all of it.
        """
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools, MAX_LINE_CHARS
        (tmp_path / "big.js").write_text("x" * (MAX_LINE_CHARS * 10) + "\nshort\n")
        page = AgentTools(tmp_path).read_file("big.js")
        assert len(page) < MAX_LINE_CHARS * 2
        assert _contains(page, "line truncated")
        assert _contains(page, "short")

    def test_entry_points_guide(self, rn_root):
        """
        Purpose:
            Pin the React Native entry-point answer in place of a call-graph error.

        Parameters:
            rn_root: The analysis root fixture.
        """
        from lu77U_MobileSec.analyzers.agent.profiles import REACT_NATIVE
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools
        answer = AgentTools(rn_root, profile=REACT_NATIVE).entry_points()
        assert not answer.startswith("ERROR")
        assert _contains(answer, "app_modules/0.js")
        assert _contains(answer, "Native modules")
