#!/usr/bin/env python3
"""
Module: test_favicon

Purpose:
    Pin the favicon to every page the tool serves or writes, so a page cannot silently lose its icon.

Responsibilities:
    Check the inlined artwork against the file the frontend build ships, check that both HTML entry points and both report builders reference an icon, and check that the built static directory actually contains the files those entry points link to.

Dependencies:
    pytest, the branding constants, and the packaged web application.
"""

from pathlib import Path
from urllib.parse import unquote

import pytest

from lu77U_MobileSec.config.branding import (
    FAVICON_DATA_URI,
    FAVICON_LINK_TAG,
    FAVICON_SVG,
)

REPO = Path(__file__).resolve().parents[1]
PUBLIC = REPO / "lu77U_MobileSec" / "frontend" / "public"
STATIC = REPO / "lu77U_MobileSec" / "web" / "static"
SERVED_ICONS = ("favicon.svg", "favicon.ico", "apple-touch-icon.png")


def _normalise(markup: str) -> str:
    """
    Purpose:
        Reduce markup to a canonical form so that only real differences -- a changed path, colour or dimension -- make two spellings compare unequal.

    Parameters:
        markup: The markup to normalise.

    Returns:
        The markup with each whitespace run collapsed to one space and the whitespace between elements removed.

    Implementation notes:
        The file in the frontend sources is indented for a human reader while the inlined copy is written as one string, so whitespace between tags is formatting rather than content and is dropped before comparing.
    """
    return " ".join(markup.split()).replace("> <", "><")


class TestInlinedArtwork:
    """
    Purpose:
        Hold the inlined favicon to the artwork the frontend build ships.
    """

    def test_matches_the_frontend_source(self):
        """
        Purpose:
            Fail when the inlined copy drifts from lu77U_MobileSec/frontend/public/favicon.svg.

        Implementation notes:
            Skipped rather than failed when the frontend tree is absent, because the wheel prunes it and this check is only meaningful in a source checkout.
        """
        source = PUBLIC / "favicon.svg"
        if not source.exists():
            pytest.skip("frontend sources are not present in this installation")
        assert _normalise(FAVICON_SVG) == _normalise(source.read_text())

    def test_data_uri_round_trips(self):
        """
        Purpose:
            Fail when the data URI stops decoding back to the artwork it claims to carry.
        """
        assert FAVICON_DATA_URI.startswith("data:image/svg+xml,")
        decoded = unquote(FAVICON_DATA_URI.split(",", 1)[1])
        assert decoded == FAVICON_SVG
        assert "<svg" in decoded and "</svg>" in decoded


class TestServedPages:
    """
    Purpose:
        Check the pages the local server hands to a browser.
    """

    def test_spa_entry_points_link_every_icon(self):
        """
        Purpose:
            Fail when either HTML entry point loses an icon link, or when the demo stops using relative hrefs.

        Implementation notes:
            The demo is served from a GitHub Pages project subpath, so an absolute href would resolve against the domain root and 404; the packaged app is served from the domain root under a BrowserRouter, where a relative href would break on a deep route.
        """
        entries = {
            REPO / "lu77U_MobileSec" / "frontend" / "index.html": "/",
            REPO / "lu77U_MobileSec" / "frontend" / "demo" / "index.html": "./",
        }
        for path, prefix in entries.items():
            markup = path.read_text()
            for icon in SERVED_ICONS:
                assert f'href="{prefix}{icon}"' in markup, f"{path.name} lost {icon}"

    def test_built_static_directory_serves_what_the_page_links(self):
        """
        Purpose:
            Fail when the built app links icons that are not in the build directory.

        Implementation notes:
            Skipped when the frontend has not been built, which is a normal state in a source checkout.
        """
        if not (STATIC / "index.html").exists():
            pytest.skip("the frontend has not been built")
        for icon in SERVED_ICONS:
            assert (STATIC / icon).is_file(), f"{icon} missing from the build"

    def test_no_build_page_carries_an_inline_icon(self):
        """
        Purpose:
            Fail when the page shown before the frontend is built loses its icon.

        Implementation notes:
            This page is rendered precisely when no static directory exists, so its icon has to be inline rather than a link to a served file.
        """
        from lu77U_MobileSec.web.app import _no_build_response

        body = _no_build_response().body.decode()
        assert FAVICON_LINK_TAG in body
        assert "<head>" in body.replace("<head >", "<head>") or "<head" in body


class TestGeneratedReports:
    """
    Purpose:
        Check the standalone HTML reports the tool writes to disk.
    """

    @pytest.mark.parametrize(
        "module_name",
        [
            "lu77U_MobileSec.report_generator.comprehensive_html_builder",
            "lu77U_MobileSec.report_generator.html_content_builder",
        ],
    )
    def test_report_header_templates_inline_the_icon(self, module_name):
        """
        Purpose:
            Fail when a report builder stops inlining the icon into its document head.

        Parameters:
            module_name: The dotted path of the report builder to check.

        Implementation notes:
            A report is opened as a file off disk, with no server to fetch an icon from, so the artwork has to travel inside the document.
        """
        import importlib

        source = Path(importlib.import_module(module_name).__file__).read_text()
        assert "{FAVICON_LINK_TAG}" in source
        assert "from ..config.branding import FAVICON_LINK_TAG" in source
