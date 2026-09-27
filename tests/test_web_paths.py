#!/usr/bin/env python3
"""
Module: test_web_paths

Purpose:
    Path handling across the web layer: static file serving, scan identifiers and upload filenames.

Responsibilities:
    Pin the containment controls that stop a request reaching outside its intended directory.

Dependencies:
    pytest, the scan store, and the static file resolver.

Security considerations:
    Every case here is a traversal or escape attempt. These are the controls that keep an unauthenticated local dashboard from serving arbitrary files or writing outside the output directory.
"""

import pytest

from lu77U_MobileSec.web import store
from lu77U_MobileSec.web.app import _static_file

class TestStaticFile:
    """
    Purpose:
        The static file resolver's containment behaviour.
    """
    @pytest.mark.parametrize("path", [
        "",
        "/",
        "../app.py",
        "../../etc/passwd",
        "/etc/passwd",
        "assets/../../app.py",
        "does-not-exist.js",
    ])
    def test_unresolvable_or_escaping_paths_return_none(self, path):
        """
        Purpose:
            Pin that empty, traversing, absolute and missing paths all resolve to nothing.

        Parameters:
            path: A path that must not resolve.

        Security considerations:
            Each case is a real traversal shape. A single one resolving would expose the filesystem through the dashboard.
        """
        assert _static_file(path) is None

    def test_real_file_resolves(self):
        """
        Purpose:
            Pin that a genuine static file still resolves, so the containment is not simply refusing everything.
        """
        resolved = _static_file("index.html")
        assert resolved is not None and resolved.name == "index.html"

    def test_symlinked_entry_is_refused(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a symlink inside the static directory pointing outside it is refused.

        Parameters:
            tmp_path: Temporary directory holding the link and its target.
            monkeypatch: Redirects the resolver at the temporary static directory.

        Security considerations:
            Resolving the path and comparing prefixes would accept this, because the link itself sits inside the directory. Refusing symlinks outright is what closes it.
        """
        target = tmp_path / "outside.txt"
        target.write_text("secret")
        static = tmp_path / "static"
        static.mkdir()
        (static / "link.txt").symlink_to(target)
        monkeypatch.setattr("lu77U_MobileSec.web.app.STATIC_DIR", static)
        assert _static_file("link.txt") is None

    def test_directory_is_not_a_file(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a directory does not resolve as a servable file.

        Parameters:
            tmp_path: Temporary directory holding the static tree.
            monkeypatch: Redirects the resolver at the temporary static directory.
        """
        static = tmp_path / "static"
        (static / "assets").mkdir(parents=True)
        monkeypatch.setattr("lu77U_MobileSec.web.app.STATIC_DIR", static)
        assert _static_file("assets") is None

class TestScanIds:
    """
    Purpose:
        Scan identifier validation.
    """
    @pytest.mark.parametrize("scan_id", ["9f2c1a7b4d0e", "000000000000"])
    def test_valid(self, scan_id):
        """
        Purpose:
            Pin that a well-formed identifier is accepted.

        Parameters:
            scan_id: An identifier in the permitted form.
        """
        store._validate_scan_id(scan_id)

    @pytest.mark.parametrize("scan_id", [
        "", None, "../../etc", "9F2C1A7B4D0E", "9f2c1a7b4d0", "9f2c1a7b4d0ee", "zzzzzzzzzzzz",
    ])
    def test_invalid(self, scan_id):
        """
        Purpose:
            Pin that anything outside the permitted form is rejected.

        Parameters:
            scan_id: An empty, absent, traversing, miscased or wrongly-sized identifier.

        Security considerations:
            Scan identifiers become directory names, so an unvalidated one lets a request name a path instead of a scan.
        """
        with pytest.raises(ValueError):
            store._validate_scan_id(scan_id)

class TestFilenameSanitising:
    """
    Purpose:
        Upload filename sanitising.
    """
    @pytest.mark.parametrize("raw,expected", [
        ("app.apk", "app.apk"),
        ("../../etc/passwd", "passwd.apk"),
        ("/absolute/path/app.apk", "app.apk"),
        ("we;rd$name.apk", "we_rd_name.apk"),
        ("no-extension", "no-extension.apk"),
        ("", "upload.apk"),
        (None, "upload.apk"),
    ])
    def test_sanitize(self, raw, expected):
        """
        Purpose:
            Pin that each dangerous or malformed filename reduces to a safe one.

        Parameters:
            raw: The client-supplied filename.
            expected: The safe name it must reduce to.

        Security considerations:
            The traversal and absolute-path cases are the ones that matter: both must collapse to a bare name, or an upload could be written outside the scan directory.
        """
        assert store.sanitize_filename(raw) == expected

    def test_result_has_no_separators(self):
        """
        Purpose:
            Pin that no path separator of either platform survives sanitising.
        """
        assert "/" not in store.sanitize_filename("a/b/c.apk")
        assert "\\" not in store.sanitize_filename("a\\b\\c.apk")
