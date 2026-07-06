"""Device discovery and readiness-check endpoints."""

import asyncio
import threading

from fastapi import APIRouter, Request

from ...dynamic_analysis import ADBManager, FridaManager, MitmproxyManager

router = APIRouter(prefix="/api", tags=["dynamic"])

@router.get("/devices")
async def list_devices(request: Request):
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"devices": ADBManager(verbose=verbose).list_devices()}

@router.get("/devices/{serial}/apps")
async def list_device_apps(request: Request, serial: str):
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"packages": ADBManager(verbose=verbose).list_packages(serial)}

def _run_device_checks(serial: str, verbose: bool) -> dict:
    """Blocking: run real Root / Frida / HTTPS-intercept checks against a
    device. Always called via ``asyncio.to_thread`` — a real Frida push/
    start/verify plus a full HTTPS man-in-the-middle round trip (CA install,
    proxy, browser navigation) takes several seconds, which would otherwise
    freeze the whole server (including any in-progress scan's WebSocket)
    since this is a synchronous, subprocess-heavy call chain.

    Frida (``adb forward`` to a device-hashed local port) and the HTTPS check
    (``adb reverse`` on a fixed port, unrelated device files/settings) don't
    share any state, so they run concurrently on their own threads rather
    than back to back — total time is whichever is slower, not the sum.
    """
    adb = ADBManager(verbose=verbose)
    root_ok = adb.check_root(serial)

    results: dict = {}

    def _run_frida() -> None:
        frida = FridaManager(verbose=verbose)
        frida_ok, frida_message = frida.setup_and_verify(adb, serial, root_ok)
        try:
            frida.stop_server(adb, serial)
        except Exception:
            pass
        results["frida"] = {"ok": frida_ok, "message": frida_message}

    def _run_mitm() -> None:
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
    """Per-device readiness: Root, Frida, MitmProxy (HTTPS) — real functional
    checks against the device, not host tool presence.

    These mirror exactly what a real scan does (Frida push/start/verify via
    frida-ps, a full HTTPS interception round trip with CA installation), so
    a green check here means the same thing a green check in a completed
    scan's results does — at the cost of taking noticeably longer than a
    simple presence check.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return await asyncio.to_thread(_run_device_checks, serial, verbose)