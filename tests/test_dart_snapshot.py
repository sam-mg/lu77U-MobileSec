#!/usr/bin/env python3
"""
Module: test_dart_snapshot

Purpose:
    The fallback for a Flutter release build Blutter cannot disassemble: libapp.so's strings recovered and filtered, the analyzer continuing on them with a stated limitation, and the graph and overview built over them.

Responsibilities:
    Pin the string extraction and the key-string filter, the choice of architecture slice, the analyzer falling back for an APK with no arm64 slice and for a Blutter failure while a missing Blutter and a missing libapp.so still fail, and the graph flagging the key strings and the app's own Java so they are read.

Dependencies:
    pytest, the snapshot string module, the Flutter analyzer, graph and recovery helpers.

Implementation notes:
    The fake libapp.so is a byte string with the shapes a real Dart snapshot carries side by side: an endpoint, SQL, a platform channel, a library hash-tagged private name, an engine keyboard key name, an elliptic-curve constant and a package URI. A real x86_64-only APK pulled from an emulator ended its scan in fourteen seconds with no findings and no visible reason, which is the behaviour these tests exist to keep from returning. Nothing here runs Blutter, JADX or a model.
"""

import zipfile
from pathlib import Path

from lu77U_MobileSec.analyzers import flutter_analyzer as fa_mod
from lu77U_MobileSec.analyzers.flutter import recovered
from lu77U_MobileSec.analyzers.flutter.graph import build_flutter_graph, write_flutter_overview
from lu77U_MobileSec.analyzers.flutter_analyzer import FlutterAnalyzer
from lu77U_MobileSec.decompiler.dart_snapshot import (
    ALL_STRINGS_NAME, KEY_STRINGS_NAME, SNAPSHOT_DIR, is_key_string, libapp_abi,
    snapshot_strings, write_snapshot_strings)

ENDPOINT = "https://api.example.test/v1/login"
QUERY = "SELECT * FROM users WHERE name = '"
CHANNEL = "com.example.app/bridge"
CURVE = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"

LIBAPP = b"\x00\x01".join(s.encode() for s in (
    ENDPOINT, QUERY, CHANNEL, "_checkLoaded@0150898", "UIKeyInputF10", "PinPToggle",
    CURVE, "package:pointycastle/block/aes.dart", "Reveal the admin flag", ENDPOINT,
    "libnative-guard.so", "short"))


def _apk(path, members):
    """
    Purpose:
        Write a minimal APK with the given members.

    Parameters:
        path: Directory to write into.
        members: Archive entry name to bytes.

    Returns:
        The APK path.
    """
    apk = Path(path) / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return apk


class TestSnapshotStrings:
    """
    Purpose:
        Reading strings out of libapp.so and choosing which ones a reviewer sees.
    """
    def test_distinct_strings_in_order(self):
        """
        Purpose:
            Pin that strings come out once each, in first-appearance order, and that short runs are skipped.
        """
        strings = snapshot_strings(LIBAPP)
        assert strings[0] == ENDPOINT
        assert strings.count(ENDPOINT) == 1
        assert "short" not in strings

    def test_key_strings_keep_what_findings_rest_on(self):
        """
        Purpose:
            Pin that endpoints, SQL, channels, native libraries and sensitive words are kept, and the app's package marks its identifiers.
        """
        for text in (ENDPOINT, QUERY, CHANNEL, "libnative-guard.so", "Reveal the admin flag"):
            assert is_key_string(text), text
        assert is_key_string("com.example.app.MainActivity", package="com.example.app")

    def test_key_strings_drop_framework_vocabulary(self):
        """
        Purpose:
            Pin that hash-tagged private names, engine keyboard keys, curve constants and package URIs are dropped, and that a sensitive word must be a whole word.
        """
        for text in ("_checkLoaded@0150898", "UIKeyInputF10", "PinPToggle", CURVE,
                     "package:pointycastle/block/aes.dart", "pinnedCertificates"):
            assert not is_key_string(text), text

    def test_digest_length_hex_is_kept(self):
        """
        Purpose:
            Pin that a SHA-256-length hex value with no long repeated run is kept, since it is what an app compares a PIN or password hash against.
        """
        assert is_key_string("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9")

    def test_slice_choice_prefers_arm64_and_accepts_x86_64(self, tmp_path):
        """
        Purpose:
            Pin the architecture slice chosen for reading, and None when no slice holds libapp.so.

        Parameters:
            tmp_path: Directory for the APKs.
        """
        both = tmp_path / "both"
        both.mkdir()
        only_x86 = tmp_path / "x86"
        only_x86.mkdir()
        none = tmp_path / "none"
        none.mkdir()
        assert libapp_abi(str(_apk(both, {"lib/x86_64/libapp.so": b"x",
                                          "lib/arm64-v8a/libapp.so": b"x"}))) == "arm64-v8a"
        assert libapp_abi(str(_apk(only_x86, {"lib/x86_64/libapp.so": b"x"}))) == "x86_64"
        assert libapp_abi(str(_apk(none, {"lib/x86_64/libflutter.so": b"x"}))) is None

    def test_both_lists_are_written(self, tmp_path):
        """
        Purpose:
            Pin that the full and the key list are written under the snapshot directory, with the counts reported.

        Parameters:
            tmp_path: Directory for the APK and output.
        """
        apk = _apk(tmp_path, {"lib/x86_64/libapp.so": LIBAPP})
        result = write_snapshot_strings(str(apk), tmp_path / "out")
        assert result.abi == "x86_64"
        assert result.all_path == tmp_path / "out" / SNAPSHOT_DIR / ALL_STRINGS_NAME
        key = result.key_path.read_text().splitlines()
        assert CHANNEL in key and "UIKeyInputF10" not in key
        assert "UIKeyInputF10" in result.all_path.read_text().splitlines()
        assert (result.total, result.key) == (len(snapshot_strings(LIBAPP)), len(key))


class TestAnalyzerFallback:
    """
    Purpose:
        The analyzer continuing on libapp.so's strings when Blutter cannot disassemble the build.
    """
    def _run(self, tmp_path, monkeypatch, members, blutter_configured=True):
        """
        Purpose:
            Run the analyzer over an APK with the agent, scanners, JADX and output location stubbed.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Applies the stubs.
            members: The APK's entries.
            blutter_configured: What the Blutter check reports.

        Returns:
            The result and what the agent was given.
        """
        apk = _apk(tmp_path, members)
        analyzer = FlutterAnalyzer()
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
        monkeypatch.setattr(analyzer.output_manager, "get_flutter_output_dir", lambda: tmp_path / "out")
        monkeypatch.setattr("lu77U_MobileSec.tools_checker.jadx_checker.check_jadx_configured",
                            lambda **_: False)
        monkeypatch.setattr("lu77U_MobileSec.tools_checker.blutter_checker.check_blutter_configured",
                            lambda **_: blutter_configured)
        return analyzer.analyze(str(apk), defer_cleanup=True), seen

    def test_x86_64_only_apk_is_analysed_from_strings(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an APK with only an x86_64 slice is analysed, with a limitation naming the slice and what was read instead.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Applies the stubs.
        """
        result, seen = self._run(tmp_path, monkeypatch, {"lib/x86_64/libapp.so": LIBAPP})
        assert result["success"] is True
        assert "arm64-v8a" in result["limitation"] and "x86_64" in result["limitation"]
        assert "Analysed instead" in result["limitation"]
        assert "no Dart disassembly" in seen["label"]
        assert f"{SNAPSHOT_DIR}/{KEY_STRINGS_NAME}" in seen["graph"].flagged_files()
        overview = (tmp_path / "out" / recovered.OVERVIEW_NAME).read_text()
        assert "could NOT be disassembled" in overview and CHANNEL in overview

    def test_blutter_failure_falls_back(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an arm64 build Blutter fails on is analysed from its strings rather than ending the scan.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Applies the stubs and makes Blutter fail.
        """
        monkeypatch.setattr(fa_mod, "run_blutter", lambda *_, **__: None)
        result, _ = self._run(tmp_path, monkeypatch, {"lib/arm64-v8a/libapp.so": LIBAPP})
        assert result["success"] is True
        assert "Blutter could not disassemble" in result["limitation"]

    def test_no_libapp_anywhere_still_fails_with_reason(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an APK whose slices hold no libapp.so fails, naming both why Blutter could not run and why there was nothing to fall back to.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Applies the stubs.
        """
        result, _ = self._run(tmp_path, monkeypatch, {"lib/x86_64/libflutter.so": b"engine"})
        assert result["success"] is False
        assert "arm64-v8a" in result["error"] and "No strings could be read" in result["error"]

    def test_missing_blutter_still_fails(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a release build with Blutter unconfigured still fails, since that is a setting the user can fix.

        Parameters:
            tmp_path: Directory for the APK and output.
            monkeypatch: Applies the stubs with Blutter unconfigured.
        """
        result, _ = self._run(tmp_path, monkeypatch, {"lib/x86_64/libapp.so": LIBAPP},
                              blutter_configured=False)
        assert result["success"] is False
        assert "Blutter is not configured" in result["error"]
        assert not result.get("limitation")


def test_strings_tree_graph_and_overview(tmp_path):
    """
    Purpose:
        Pin that, with only strings recovered, the graph flags the key strings and the app's own Java, maps a channel string to its Java handler, counts a native library named in the strings as the app's, and the overview says what could not be read.

    Parameters:
        tmp_path: Directory the analysis tree is written into.
    """
    root = tmp_path / "out"
    snap = root / SNAPSHOT_DIR
    snap.mkdir(parents=True)
    (snap / KEY_STRINGS_NAME).write_text(f"{CHANNEL}\n{ENDPOINT}\nlibnative-guard.so\n")
    (snap / ALL_STRINGS_NAME).write_text(f"{CHANNEL}\n{ENDPOINT}\nlibnative-guard.so\nUIKeyInputF10\n")
    resources = root / recovered.PLATFORM_DIR / "resources"
    resources.mkdir(parents=True)
    (resources / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.app"><application/></manifest>')
    (resources / "lib" / "x86_64").mkdir(parents=True)
    (resources / "lib" / "x86_64" / "libnative-guard.so").write_bytes(b"\x7fELF")
    java = root / recovered.PLATFORM_DIR / "sources" / "com" / "example" / "app"
    java.mkdir(parents=True)
    (java / "MainActivity.java").write_text(f'class MainActivity {{ String c = "{CHANNEL}"; }}\n')

    graph = build_flutter_graph(root)
    flagged = graph.flagged_files()
    assert f"{SNAPSHOT_DIR}/{KEY_STRINGS_NAME}" in flagged
    assert "platform/sources/com/example/app/MainActivity.java" in flagged
    assert [lib.path for lib in graph.native_libs] == ["platform/resources/lib/x86_64/libnative-guard.so"]

    write_flutter_overview(root, "strings")
    overview = (root / recovered.OVERVIEW_NAME).read_text()
    assert "could NOT be disassembled" in overview
    assert "(not recoverable without disassembly)" in overview
    assert "snapshot_strings/libapp_key_strings.txt" in overview
