#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.branding

Purpose:
    Hold the product's icon artwork in an inlineable form, so every page the tool serves or writes carries the same favicon.

Responsibilities:
    Declare the favicon artwork, its data-URI encoding and the link tag built from it. No logic beyond the encoding, no I/O.

Dependencies:
    urllib.parse, for percent-encoding the artwork into a data URI.

Implementation notes:
    The artwork is duplicated here from lu77U_MobileSec/frontend/public/favicon.svg rather than read from it, because that directory is a build input that is pruned from the wheel -- an installed copy of the package has no frontend tree to read. tests/test_favicon.py compares the two whenever the source checkout is present, so the duplicate cannot drift. A data URI rather than a served path is what makes this usable from a standalone report file opened off disk and from the no-build page, which is rendered precisely when no static directory exists to serve an icon from.
"""

from urllib.parse import quote

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" '
    'viewBox="0 0 512 512">'
    '<rect width="512" height="512" fill="#000000"/>'
    '<path d="M 86 118 L 230 118 L 230 172 L 160 394 L 92 394 L 162 176 L 86 176 Z" '
    'fill="#FFFFFF"/>'
    '<path d="M 282 118 L 426 118 L 426 172 L 356 394 L 288 394 L 358 176 L 282 176 Z" '
    'fill="#FFFFFF"/>'
    '<rect x="74" y="424" width="364" height="42" rx="21" fill="#F43F5E"/>'
    '</svg>'
)

FAVICON_DATA_URI = "data:image/svg+xml," + quote(FAVICON_SVG, safe="")

FAVICON_LINK_TAG = f'<link rel="icon" type="image/svg+xml" href="{FAVICON_DATA_URI}">'
