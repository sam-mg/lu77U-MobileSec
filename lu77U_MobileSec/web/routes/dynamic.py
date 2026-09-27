#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.routes.dynamic

Purpose:
    Expose the device-facing endpoints: which devices are attached, what is installed on them, and whether a device is ready for a dynamic run.

Responsibilities:
    Serve device listings and run the readiness checks off the event loop.

Dependencies:
    The device, instrumentation and interception managers.

Security considerations:
    The readiness check is not a passive probe: it deploys and starts the instrumentation server and performs a full interception check, which installs a CA on the device. It is exposed as an endpoint because the dashboard needs it before a run, but it changes device state.
"""

import asyncio
import threading

from fastapi import APIRouter, Request

from ...dynamic_analysis import ADBManager, FridaManager, MitmproxyManager

router = APIRouter(prefix="/api", tags=["dynamic"])

@router.get("/devices")
async def list_devices(request: Request):
    """
    Purpose:
        List the Android devices currently attached and ready.

    Parameters:
        request: The incoming request.

    Returns:
        The JSON response body.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"devices": ADBManager(verbose=verbose).list_devices()}

@router.get("/devices/{serial}/apps")
async def list_device_apps(request: Request, serial: str):
    """
    Purpose:
        List the third-party packages installed on a device, for the app chooser.

    Parameters:
        request: The incoming request.
        serial: Device serial.

    Returns:
        The JSON response body.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"packages": ADBManager(verbose=verbose).list_packages(serial)}

def _run_device_checks(serial: str, verbose: bool) -> dict:
    """
    Purpose:
        Run the instrumentation and interception readiness checks for a device.

    Parameters:
        serial: Device serial.
        verbose: Enables tracing.

    Returns:
        The outcome of each check.

    Side effects:
        Deploys and starts the instrumentation server, installs an interception CA, and reconfigures the device proxy.

    Implementation notes:
        Root is established once and passed into the instrumentation check, since both checks depend on it and probing twice would be wasted work on a slow link.

    Security considerations:
        These checks leave the device modified. The instrumentation server is stopped afterwards; the interception CA remains installed until removed.
    """
    adb = ADBManager(verbose=verbose)
    root_ok = adb.check_root(serial)

    results: dict = {}

    def _run_frida() -> None:
        """
        Purpose:
            Run the instrumentation readiness check and record its outcome.

        Side effects:
            Deploys and starts the instrumentation server, then stops it again.

        Implementation notes:
            The server is stopped after the check because this is a readiness probe rather than the start of a session; leaving it running would hold root on the device until something else tore it down.
        """
        frida = FridaManager(verbose=verbose)
        frida_ok, frida_message = frida.setup_and_verify(adb, serial, root_ok)
        try:
            frida.stop_server(adb, serial)
        except Exception:
            pass
        results["frida"] = {"ok": frida_ok, "message": frida_message}

    def _run_mitm() -> None:
        """
        Purpose:
            Run the interception readiness check and record its outcome.

        Side effects:
            Installs the interception CA and reconfigures the device proxy.

        Security considerations:
            A successful check leaves the device trusting the interception CA.
        """
        mitmproxy = MitmproxyManager(verbose=verbose)
        mitm_ok, mitm_message = mitmproxy.run_https_check(adb, serial)
        results["mitmproxy"] = {"ok": mitm_ok, "message": mitm_message}

    frida_thread = threading.Thread(target=_run_frida)
    mitm_thread = threading.Thread(target=_run_mitm)
    frida_thread.start()
    mitm_thread.start()
    frida_thread.join()
    mitm_thread.join()

    return {
        "root": {"ok": root_ok,
                 "message": "Root access available" if root_ok else "No root access detected"},
        "frida": results.get("frida", {"ok": False, "message": "Frida check did not complete"}),
        "mitmproxy": results.get(
            "mitmproxy", {"ok": False, "message": "HTTPS check did not complete"}),
    }

@router.get("/devices/{serial}/checks")
async def device_checks(request: Request, serial: str):
    """
    Purpose:
        Run the device readiness checks and return their outcomes.

    Parameters:
        request: The incoming request.
        serial: Device serial.

    Returns:
        The JSON response body.

    Implementation notes:
        The checks are run on a worker thread rather than on the event loop, because they spawn processes and wait on a device for tens of seconds -- doing that inline would block every other request.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return await asyncio.to_thread(_run_device_checks, serial, verbose)
