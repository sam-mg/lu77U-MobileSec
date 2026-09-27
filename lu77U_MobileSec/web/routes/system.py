#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.routes.system

Purpose:
    Expose the endpoints the dashboard polls to know the server is alive, what version it is, and whether the tools a scan needs are configured.

Responsibilities:
    Serve health, version and readiness.

Dependencies:
    The tool readiness checker.

Implementation notes:
    These are deliberately trivial and side-effect free, since the dashboard polls them continuously -- the readiness endpoint in particular is what drives the setup prompts in the interface.
"""

from fastapi import APIRouter

from ..._metadata import NAME, VERSION
from ...tools_checker.analysis_checker import get_analysis_status

router = APIRouter(prefix="/api", tags=["system"])

@router.get("/health")
async def health():
    """
    Purpose:
        Report that the server is running.

    Parameters:
        None.

    Returns:
        The JSON response body.
    """
    return {"ok": True}

@router.get("/version")
async def version():
    """
    Purpose:
        Report the tool's name and version, so the interface can display it and detect a mismatch after an upgrade.

    Parameters:
        None.

    Returns:
        The JSON response body.
    """
    return {"name": NAME, "version": VERSION}

@router.get("/status")
async def status():
    """
    Purpose:
        Report which required and optional tools are configured, driving the dashboard's readiness panel.

    Parameters:
        None.

    Returns:
        The JSON response body.

    Implementation notes:
        Uses the non-interactive readiness check, which never blocks or prompts -- the interactive variant would hang a request.
    """
    return get_analysis_status()
