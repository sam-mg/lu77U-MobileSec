#!/usr/bin/env python3
"""
Module: lu77U_MobileSec._metadata

Purpose:
    Resolve the project's identity -- name, version, description, author, URLs -- from packaging data at import time, so that the version is stated in exactly one place (pyproject.toml) and cannot drift between the package, the CLI banner and the generated reports.

Responsibilities:
    Try pyproject.toml first, fall back to installed distribution metadata, and expose the result as plain module-level strings.

Dependencies:
    tomllib (standard library, Python 3.11+), importlib.metadata, pathlib.

Implementation notes:
    pyproject.toml is preferred over installed metadata because during development the checkout is the truth and the installed distribution is usually stale. The order flips in practice for an installed user: there is no pyproject.toml beside the package, so the distribution wins. Every lookup is defensive. Metadata resolution must never be the reason an analysis fails to start, so every failure degrades to a default rather than propagating.

Security considerations:
    EMAIL and AUTHOR come from packaging metadata and are embedded in generated reports. They are project identity, not user data, and no value here is ever read from the APK under analysis.
"""

import tomllib
from importlib import metadata as _importlib_metadata
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_TOP_LEVEL = __package__ or __name__.split(".")[0]

def _split_author(value: str) -> Tuple[str, str]:
    """
    Purpose:
        Split a packaging author field into a name and an email, tolerating the three shapes that appear in the wild.

    Parameters:
        value: Raw author string, typically Author-email from distribution metadata. None and empty are accepted.

    Returns:
        A (name, email) tuple. Either element may be an empty string when the input did not carry it; the function never returns None.

    Postconditions:
        Both elements are stripped, and surrounding double quotes are removed from the name.

    Implementation notes:
        Three shapes are handled in order: `Name <addr>` (RFC 5322 style, the common case for Author-email), a bare address recognised by containing @, and a bare name. The bare-address test runs after the bracket test because `Name <addr>` also contains @ and would otherwise be misclassified as an address with no name.
    """
    value = (value or "").strip()
    if not value:
        return "", ""
    if "<" in value and value.endswith(">"):
        name, _, email = value.partition("<")
        return name.strip().strip('"'), email[:-1].strip()
    if "@" in value:
        return "", value
    return value, ""

def _from_installed_distribution() -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Read project identity from installed distribution metadata, for the normal case where the package was pip-installed and no source tree is present.

    Returns:
        A dict with name, version, description, author, email and urls, or None when no candidate distribution could be read.

    Side effects:
        Reads installed package metadata from disk via importlib.metadata.

    Implementation notes:
        The distribution name and the import name differ here -- the package imports as lu77U_MobileSec but ships as lu77U-MobileSec -- so candidates covers both spellings. packages_distributions() is asked first because it maps an import name to whatever actually provides it, which is authoritative where the underscore/hyphen guess is only a convention. Project-URL entries arrive as a single `Label, URL` string per line and are split on the first comma; a URL containing a comma would still parse correctly because only the first separator is consumed. Both the packages_distributions() call and each metadata() call are wrapped broadly: importlib.metadata raises a variety of errors on a damaged or partially installed environment, and none of them should prevent the package from importing.
    """
    candidates = [_TOP_LEVEL.replace("_", "-"), _TOP_LEVEL]
    try:
        provided = _importlib_metadata.packages_distributions().get(_TOP_LEVEL)
    except Exception:
        provided = None
    if provided:
        candidates = list(provided) + candidates

    for candidate in candidates:
        try:
            md = _importlib_metadata.metadata(candidate)
        except _importlib_metadata.PackageNotFoundError:
            continue
        except Exception:
            continue

        urls: Dict[str, str] = {}
        for entry in md.get_all("Project-URL") or []:
            label, _, url = entry.partition(",")
            urls[label.strip()] = url.strip()

        name, email = _split_author(md.get("Author-email", ""))
        return {
            "name": md.get("Name", candidate),
            "version": md.get("Version", ""),
            "description": md.get("Summary", "") or "",
            "author": md.get("Author") or name,
            "email": email,
            "urls": urls,
        }
    return None

def _from_pyproject() -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Read project identity from pyproject.toml, for the development case where the checkout is more current than anything installed.

    Returns:
        A dict with name, version, description, author, email and urls, or None when no usable pyproject.toml was found.

    Side effects:
        Reads and parses pyproject.toml from disk.

    Implementation notes:
        Only two directory levels above this file are searched: the package directory and the repository root. Walking further up would let an unrelated pyproject.toml belonging to a parent project be picked up, which would silently rename the tool. A file that parses but declares no project.name is skipped rather than accepted, so a tooling-only pyproject.toml (one carrying just a [tool.*] section) does not shadow the real one. A file that fails to parse returns None immediately instead of continuing, because a broken pyproject.toml in the checkout is a real problem and silently falling through to stale installed metadata would hide it. authors defaults to [{}] so that the first-element access below is safe when the key is absent or empty.
    """
    for parent in Path(__file__).resolve().parents[:2]:
        candidate = parent / "pyproject.toml"
        if not candidate.is_file():
            continue
        try:
            project = tomllib.loads(candidate.read_text(encoding="utf-8")).get("project", {})
        except Exception:
            return None
        if not project.get("name"):
            continue
        authors = project.get("authors") or [{}]
        return {
            "name": project["name"],
            "version": project.get("version", ""),
            "description": project.get("description", ""),
            "author": authors[0].get("name", ""),
            "email": authors[0].get("email", ""),
            "urls": project.get("urls", {}) or {},
        }
    return None

_DATA: Dict[str, Any] = _from_pyproject() or _from_installed_distribution() or {}

NAME: str = _DATA.get("name") or _TOP_LEVEL.replace("_", "-")
VERSION: str = _DATA.get("version") or "0.0.0"
DESCRIPTION: str = _DATA.get("description") or ""
AUTHOR: str = _DATA.get("author") or ""
EMAIL: str = _DATA.get("email") or ""
URLS: Dict[str, str] = dict(_DATA.get("urls") or {})
HOMEPAGE: str = URLS.get("Homepage") or next(iter(URLS.values()), "")

__all__ = ["NAME", "VERSION", "DESCRIPTION", "AUTHOR", "EMAIL", "URLS", "HOMEPAGE"]
