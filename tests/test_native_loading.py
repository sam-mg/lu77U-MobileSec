#!/usr/bin/env python3
"""
Module: test_native_loading

Purpose:
    Finding the native libraries a cross-platform app's own code loads: the bundled index, the load calls in Java/Kotlin and Dart, and the overview section that names them.

Responsibilities:
    Pin that the arm64-v8a copy is preferred, that System.loadLibrary and a lib*.so literal both count, that only bundled libraries and only the app's own code count, that framework runtimes are skipped, and that the section names the app's libraries apart from the rest.

Dependencies:
    pytest and the native-loading helpers.

Implementation notes:
    The fixtures follow the layout JADX writes: libraries under platform/resources/lib/<abi>/, Java under platform/sources/<package path>/, and a manifest declaring the package.
"""

import pytest

from lu77U_MobileSec.analyzers.agent.native_loading import (
    app_code_files, app_loaded_libraries, bundled_libraries, manifest_package, render_native_section)


@pytest.fixture
def root(tmp_path):
    """
    Purpose:
        Build an analysis root with bundled libraries, the app's Java and Dart code, a library's Java, and a manifest.

    Parameters:
        tmp_path: Directory the root is written into.

    Returns:
        The analysis root.
    """
    files = {
        "platform/resources/AndroidManifest.xml":
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">'
            "<application/></manifest>",
        "platform/sources/com/demo/app/Signer.java":
            'class Signer { static { System.loadLibrary("signer"); } }\n',
        "platform/sources/org/vendor/Codec.java":
            'class Codec { static { System.loadLibrary("vendorcodec"); System.loadLibrary("c++_shared"); } }\n',
        "asm/demo/bridge.dart":
            '    //     0x3fe0: add x16, PP, #0xe  ; [pp+0xea08] "libcore.so"\n'
            '    // r16 = "libmissing.so"\n',
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for abi in ("x86_64", "arm64-v8a"):
        for name in ("libsigner.so", "libcore.so", "libvendorcodec.so", "libflutter.so"):
            lib = tmp_path / "platform/resources/lib" / abi / name
            lib.parent.mkdir(parents=True, exist_ok=True)
            lib.write_bytes(b"\x7fELF")
    return tmp_path


class TestNativeLoading:
    """
    Purpose:
        The helpers that tie a bundled library to the app code that loads it.
    """
    def test_bundled_prefers_arm64(self, root):
        """
        Purpose:
            Pin that each library is indexed once, at its arm64-v8a copy.

        Parameters:
            root: The analysis root fixture.
        """
        bundled = bundled_libraries(root)
        assert bundled["libsigner.so"] == "platform/resources/lib/arm64-v8a/libsigner.so"
        assert len(bundled) == 4

    def test_app_loads_only(self, root):
        """
        Purpose:
            Pin that the app's Java and Dart load calls are found, a library's own load call is not, a missing library is ignored, and runtimes are skipped.

        Parameters:
            root: The analysis root fixture.
        """
        assert manifest_package(root) == "com.demo.app"
        files = app_code_files(root, "com.demo.app", ("asm/demo",))
        libraries = app_loaded_libraries(root, files, skip={"libflutter.so"})
        assert [lib.name for lib in libraries] == ["libcore.so", "libsigner.so"]
        signer = libraries[1]
        assert signer.path.endswith("arm64-v8a/libsigner.so")
        assert signer.loaded_from == ["platform/sources/com/demo/app/Signer.java:1"]

    def test_section(self, root):
        """
        Purpose:
            Pin that the app's libraries are named with their load site and the rest are one line.

        Parameters:
            root: The analysis root fixture.
        """
        files = app_code_files(root, "com.demo.app", ("asm/demo",))
        lines = render_native_section(app_loaded_libraries(root, files), bundled_libraries(root))
        assert lines[0] == "Native libraries:"
        assert any("libsigner.so  loaded by the app at platform/sources/com/demo/app/Signer.java:1" in line
                   for line in lines)
        assert lines[-1].endswith("libflutter.so, libvendorcodec.so")
        assert render_native_section([], {}) == []
