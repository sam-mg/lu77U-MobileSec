#!/usr/bin/env python3
"""
Module: test_apk_payload

Purpose:
    Pulling the parts of an APK that a non-Java framework's code lives in: the JavaScript bundle, the native libraries and the Cordova web assets.

Responsibilities:
    Pin bundle discovery and its fallbacks, member extraction, the bytecode sniff that tells a compiled bundle from a plain one, native library selection across architectures, and the Cordova extraction including its containment.

Dependencies:
    pytest and the APK payload extractor.

Security considerations:
    An archive member's name is attacker-controlled, so the containment case here is what keeps a crafted application from writing outside the output directory during extraction.
"""

import zipfile

from lu77U_MobileSec.decompiler.apk_payload import (
    HERMES_MAGIC, available_native_abis, extract_cordova_www, extract_member,
    extract_native_libs, find_js_bundle, is_hermes,
)

def make_apk(path, members: dict):
    """
    Purpose:
        Build a minimal archive holding the given members.

    Parameters:
        path: Where to write the archive.
        members: A mapping of member name to contents.

    Returns:
        The path written to.
    """
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return path

class TestFindJsBundle:
    """
    Purpose:
        Locating the JavaScript bundle inside an archive.
    """
    def test_standard_bundle_name(self, tmp_path):
        """
        Purpose:
            Pin that the conventional bundle name is found.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = make_apk(tmp_path / "app.apk", {"assets/index.android.bundle": b"var x=1;"})
        assert find_js_bundle(str(apk)) == "assets/index.android.bundle"

    def test_falls_back_to_any_bundle_file(self, tmp_path):
        """
        Purpose:
            Pin that a differently-named bundle is still found.

        Parameters:
            tmp_path: Directory the fixture archive is written into.

        Implementation notes:
            A custom build can rename the bundle, and matching only the conventional name would report no JavaScript in an application that is entirely JavaScript.
        """
        apk = make_apk(tmp_path / "app.apk", {"assets/custom.bundle": b"var x=1;"})
        assert find_js_bundle(str(apk)) == "assets/custom.bundle"

    def test_no_bundle_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that an archive with no bundle yields nothing.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = make_apk(tmp_path / "app.apk", {"classes.dex": b"\x00"})
        assert find_js_bundle(str(apk)) is None

    def test_not_a_zip_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that a file that is not an archive yields nothing rather than raising.

        Parameters:
            tmp_path: Directory the malformed file is written into.
        """
        bad = tmp_path / "not_an_apk.apk"
        bad.write_bytes(b"not a zip file")
        assert find_js_bundle(str(bad)) is None

    def test_missing_file_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist yields nothing rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        assert find_js_bundle(str(tmp_path / "nope.apk")) is None

class TestExtractMember:
    """
    Purpose:
        Extracting one named member out of an archive.
    """
    def test_extracts_to_flat_filename(self, tmp_path):
        """
        Purpose:
            Pin that a member nested in the archive is written out under its bare filename with its contents intact.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {"assets/index.android.bundle": b"var x=1;"})
        dest = tmp_path / "out"
        result = extract_member(str(apk), "assets/index.android.bundle", dest)
        assert result == dest / "index.android.bundle"
        assert result.read_bytes() == b"var x=1;"

    def test_missing_member_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that asking for a member the archive does not hold yields nothing.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {"classes.dex": b"\x00"})
        assert extract_member(str(apk), "assets/index.android.bundle", tmp_path / "out") is None

class TestIsHermes:
    """
    Purpose:
        Telling a compiled bundle from a plain JavaScript one.

    Implementation notes:
        The two need entirely different tooling, and the file extension is the same either way, so the decision has to be made from the file's leading bytes.
    """
    def test_hermes_magic_detected(self, tmp_path):
        """
        Purpose:
            Pin that a file carrying the compiled bundle signature is recognised.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        f = tmp_path / "bundle.js"
        f.write_bytes(HERMES_MAGIC + b"\x00\x00\x00rest of hbc")
        assert is_hermes(f) is True

    def test_plain_js_is_not_hermes(self, tmp_path):
        """
        Purpose:
            Pin that ordinary JavaScript is not mistaken for a compiled bundle.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        f = tmp_path / "bundle.js"
        f.write_text("var x = require('y');")
        assert is_hermes(f) is False

    def test_missing_file(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist is reported as not compiled rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        assert is_hermes(tmp_path / "nope.js") is False

    def test_short_file(self, tmp_path):
        """
        Purpose:
            Pin that a file too short to hold the signature is reported as not compiled.

        Parameters:
            tmp_path: Directory the fixture is written into.
        """
        f = tmp_path / "tiny.js"
        f.write_bytes(b"\xc6\x1f")
        assert is_hermes(f) is False

class TestNativeLibs:
    """
    Purpose:
        Listing and extracting the native libraries an archive ships, per processor architecture.
    """
    def test_available_abis(self, tmp_path):
        """
        Purpose:
            Pin that every architecture present in the archive is listed.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "lib/arm64-v8a/libapp.so": b"\x7fELF",
            "lib/armeabi-v7a/libapp.so": b"\x7fELF",
        })
        assert available_native_abis(str(apk)) == ["arm64-v8a", "armeabi-v7a"]

    def test_no_native_libs(self, tmp_path):
        """
        Purpose:
            Pin that an archive shipping no native code lists no architectures.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = make_apk(tmp_path / "app.apk", {"classes.dex": b"\x00"})
        assert available_native_abis(str(apk)) == []

    def test_extracts_preferred_abi(self, tmp_path):
        """
        Purpose:
            Pin that every library of the requested architecture is extracted, and none of another.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            An application ships the same libraries built for several architectures, and mixing them in one output directory would leave two files with the same name and one silently overwriting the other.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "lib/arm64-v8a/libapp.so": b"AAAA",
            "lib/arm64-v8a/libflutter.so": b"BBBB",
            "lib/armeabi-v7a/libapp.so": b"CCCC",
        })
        out = extract_native_libs(str(apk), tmp_path / "libs", abis=("arm64-v8a",))
        assert out is not None
        names = {p.name for p in out.iterdir()}
        assert names == {"libapp.so", "libflutter.so"}
        assert (out / "libapp.so").read_bytes() == b"AAAA"

    def test_missing_preferred_abi_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that requesting an architecture the archive does not ship yields nothing.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {"lib/armeabi-v7a/libapp.so": b"CCCC"})
        assert extract_native_libs(str(apk), tmp_path / "libs", abis=("arm64-v8a",)) is None

    def test_falls_through_abi_list_in_order(self, tmp_path):
        """
        Purpose:
            Pin that a list of architectures is tried in order and the first one present is used.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            The order expresses a preference rather than a requirement, since the disassembly tooling works best on the newest architecture but an older application may ship only an older one.
        """
        apk = make_apk(tmp_path / "app.apk", {"lib/armeabi-v7a/libapp.so": b"CCCC"})
        out = extract_native_libs(str(apk), tmp_path / "libs",
                                  abis=("arm64-v8a", "armeabi-v7a"))
        assert out is not None
        assert (out / "libapp.so").read_bytes() == b"CCCC"

class TestExtractCordovaWww:
    """
    Purpose:
        Extracting a Cordova application's web assets and its configuration.
    """
    def test_extracts_www_tree_and_config(self, tmp_path):
        """
        Purpose:
            Pin that the asset tree is written out with its directory structure preserved, its enclosing prefix removed, the configuration lifted to the root, and nothing else included.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "assets/www/index.html": b"<html></html>",
            "assets/www/js/index.js": b"var x=1;",
            "assets/www/plugins/p/www/P.js": b"cordova.exec();",
            "res/xml/config.xml": b"<widget/>",
            "classes.dex": b"\x00",
        })
        out = extract_cordova_www(str(apk), tmp_path / "www")
        assert out is not None
        rels = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
        assert rels == {"index.html", "js/index.js", "plugins/p/www/P.js", "config.xml"}
        assert (out / "js/index.js").read_bytes() == b"var x=1;"

    def test_config_falls_back_to_root_member(self, tmp_path):
        """
        Purpose:
            Pin that a configuration stored at the archive root is found when it is not in the usual place.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "assets/www/index.html": b"<html></html>",
            "config.xml": b"<widget/>",
        })
        out = extract_cordova_www(str(apk), tmp_path / "www")
        assert (out / "config.xml").read_bytes() == b"<widget/>"

    def test_non_cordova_apk_returns_none(self, tmp_path):
        """
        Purpose:
            Pin that an archive with no web assets yields nothing.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = make_apk(tmp_path / "app.apk", {"classes.dex": b"\x00"})
        assert extract_cordova_www(str(apk), tmp_path / "www") is None

    def test_directory_entries_are_skipped(self, tmp_path):
        """
        Purpose:
            Pin that a directory entry in the archive does not disturb the extraction of the files around it.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            Some build tools write explicit directory entries and others do not, and treating one as a file would either fail or leave an empty file where a directory belongs.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "assets/www/": b"",
            "assets/www/index.html": b"<html></html>",
        })
        out = extract_cordova_www(str(apk), tmp_path / "www")
        assert out is not None
        assert (out / "index.html").is_file()

    def test_zip_slip_is_refused(self, tmp_path):
        """
        Purpose:
            Pin that a member whose name climbs out of the asset directory is skipped entirely while the legitimate members still extract.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Security considerations:
            Member names come from the archive being analysed. Joining one to the output directory without checking where it lands lets a crafted application write anywhere the process can, so the test asserts both that the escaping file exists nowhere under the temporary tree and that the extraction did not simply give up.
        """
        apk = make_apk(tmp_path / "app.apk", {
            "assets/www/../../../../tmp/evil.js": b"pwn",
            "assets/www/index.html": b"<html></html>",
        })
        out = extract_cordova_www(str(apk), tmp_path / "www")
        assert out is not None
        assert (out / "index.html").is_file()
        assert list(tmp_path.rglob("evil.js")) == []
