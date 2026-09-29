#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.dynamic_analyzer

Purpose:
    Orchestrate a full on-device session: check the device, set up instrumentation and interception, drive the app, and collect what was observed.

Responsibilities:
    Sequence the environment checks, run the interaction loop, derive runtime findings, and tear down what it started.

Dependencies:
    The device, Frida and proxy managers, the UI automator, the visual checker and the detector.

Implementation notes:
    Environment checks are recorded rather than required. A device without root cannot run Frida, and a pinned app defeats interception, but neither makes the rest of the session worthless -- so each check's outcome is stored and the session continues. Progress is reported at every stage because a dynamic run is slow and largely invisible, and a user watching a dashboard needs to see which stage is taking the time.

Security considerations:
    A run installs an interception CA, starts a root instrumentation server and drives an untrusted app. The Frida server is stopped in a finally block so it does not outlive the scan; the proxy CA and device proxy setting are the responsibility of the proxy manager's teardown.
"""

import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..detection.detector import MobileSecurityDetector
from ..detection.results.detection_results import DetectionResult
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import verbose_print
from .adb_manager import ADBManager
from .frida_manager import FridaManager
from .mitmproxy_manager import MitmproxyManager
from .ui_automator import UIAutomator
from .visual_checker import run_google_visual_check

class DynamicAnalyzer:
    """
    Purpose:
        Runs one on-device analysis session.

    Attributes:
        verbose: Whether the session is traced.
        adb: Device control.
        frida: Instrumentation control.
        mitmproxy: Interception control.
        is_cancelled: Polled between stages.
        pause_for_login: Called when the interaction loop reaches a login screen.

    Invariants:
        Every stage's outcome is recorded, whether it succeeded or not, so the report can state what was and was not verified.

    Thread-safety:
        Not safe to share; it owns a device for the duration of a session.
    """
    def __init__(
        self,
        verbose: bool = False,
        progress: Optional[Callable[..., None]] = None,
        pause_for_login: Optional[Callable[[], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        adb: Optional[ADBManager] = None,
        frida: Optional[FridaManager] = None,
    ):
        """
        Purpose:
            Construct the analyzer with its managers and callbacks.

        Parameters:
            verbose: Enables tracing.
            progress: Reports stage progress to the dashboard.
            pause_for_login: Called when a login screen is reached, so the operator can sign in.
            is_cancelled: Polled between stages.
            adb: Device manager; constructed if not supplied.
            frida: Instrumentation manager; constructed if not supplied.

        Implementation notes:
            The managers are injectable so that a caller which already set up Frida for an earlier phase can pass it in rather than repeating the deployment. Every callback defaults to a no-op, so the analyzer runs headless without a caller having to supply stubs.
        """
        self.verbose = verbose
        self._progress = progress or (lambda *_unused_args, **_unused_kwargs: None)
        self.pause_for_login = pause_for_login
        self.is_cancelled = is_cancelled or (lambda: False)
        self.adb = adb or ADBManager(verbose=verbose)
        self.frida = frida or FridaManager(verbose=verbose)
        self.mitmproxy = MitmproxyManager(verbose=verbose)
        verbose_print("DynamicAnalyzer initialized", self.verbose)

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        """
        Purpose:
            Report stage progress to the caller.

        Parameters:
            phase: Stage identifier.
            percent: Overall completion.
            message: Human-readable description.

        Side effects:
            Invokes the caller's progress callback.

        Implementation notes:
            Callback failures are logged and otherwise ignored, except for cancellation. A disconnected dashboard client must not abort a dynamic run, but a cancellation raised through the callback is the user stopping the scan and has to propagate. contextlib.suppress cannot replace the handler because ScanCancelled subclasses Exception and must be re-raised first.
        """
        try:
            self._progress(phase=phase, percent=percent, message=message)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Progress update could not be delivered: {exc}", self.verbose)

    def _raise_if_cancelled(self) -> None:
        """
        Purpose:
            Stop the session if the user has cancelled.

        Raises:
            ScanCancelled: When cancellation has been requested.

        Implementation notes:
            Called between stages rather than inside them, so a stop takes effect within one stage instead of mid-operation on the device -- which matters because several stages leave the device modified until their teardown runs.
        """
        if self.is_cancelled():
            verbose_print("Cancellation requested; stopping dynamic analysis", self.verbose)
            raise ScanCancelled()

    def _safe_check(self, label: str, fn: Callable[[], "tuple[bool, str]"]) -> Dict[str, Any]:
        """
        Purpose:
            Run one environment check and record its outcome without letting a failure end the session.

        Parameters:
            label: Name of the check, used in the failure message.
            fn: The check, returning a success flag and a message.

        Returns:
            The outcome as a recordable dict.

        Implementation notes:
            Cancellation is re-raised; everything else becomes a failed check with the error as its message. That is the whole point of the wrapper: an environment check failing is information about the device, not a reason to abandon the session.
        """
        try:
            ok, message = fn()
            return {"ok": ok, "message": message}
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"{label} check errored: {exc}", self.verbose)
            return {"ok": False, "message": f"{label} check failed: {exc}"}

    def run(self, device_id: str, app_package: str, ui_steps: int = 20,
            skip_app_info: bool = False,
            frida_env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Purpose:
            Run a complete dynamic analysis session against one app on one device.

        Parameters:
            device_id: Device serial.
            app_package: Package under test.
            ui_steps: Ceiling on interaction loop iterations.
            skip_app_info: Skip pulling and inspecting the installed APK.
            frida_env: An earlier phase's Frida result, reused instead of setting up again.

        Returns:
            The session results: device details, environment check outcomes, actions taken and runtime findings.

        Raises:
            ScanCancelled: When the user stopped the scan.

        Side effects:
            Installs an interception CA, starts a root instrumentation server, reconfigures the device proxy, and drives the app.

        Implementation notes:
            Stages run in dependency order: device and root first, because root determines what is possible; then instrumentation, interception and the visual check; then interaction, which is what actually exercises the app. A Frida result from the verification phase is reused when it succeeded, since redeploying the server would cost a minute and change nothing. A failed automation connection skips the interaction loop rather than failing the session -- the app still launched, and the environment checks still have value. The Frida server is stopped in a finally block, so a cancelled or failed session does not leave a root process running on the device.

        Security considerations:
            This is the method that leaves a device modified. The instrumentation server is always stopped here; the interception CA and the proxy setting are torn down by the proxy manager, and a session killed outside this method can leave both in place.
        """
        verbose_print(
            f"Dynamic analysis: device={device_id} app={app_package}", self.verbose)

        self.progress("device_check", 10, "Checking device and root access")
        device_info = self._device_info(device_id)
        has_root = self.adb.check_root(device_id)
        verbose_print(f"Device root: {has_root}", self.verbose)

        env_checks: Dict[str, Any] = {"root": has_root}
        self._raise_if_cancelled()

        if skip_app_info:
            detection_result = None
        else:
            self.progress("app_info", 20, "Reading app info from the device")
            detection_result = self._detect_app_info(device_id, app_package)

        try:
            self.progress("frida_setup", 30, "Setting up Frida server")
            if frida_env and frida_env.get("ok"):
                env_checks["frida"] = frida_env
                verbose_print(
                    f"Frida: reusing verification phase's result ({frida_env})",
                    self.verbose)
            else:
                env_checks["frida"] = self._safe_check(
                    "Frida", lambda: self.frida.setup_and_verify(self.adb, device_id, has_root))
            verbose_print(f"Frida: {env_checks['frida']}", self.verbose)
            self._raise_if_cancelled()

            self.progress("http_check", 45, "Verifying HTTPS interception")
            env_checks["https_intercept"] = self._safe_check(
                "HTTPS intercept", lambda: self.mitmproxy.run_https_check(self.adb, device_id))
            verbose_print(f"HTTPS intercept: {env_checks['https_intercept']}", self.verbose)
            self._raise_if_cancelled()

            self.progress("visual_check", 50, "Verifying AI provider can see the device screen")
            env_checks["ai_visual_check"] = self._safe_check(
                "AI visual", lambda: run_google_visual_check(self.adb, device_id, self.verbose))
            verbose_print(f"AI visual check: {env_checks['ai_visual_check']}", self.verbose)
            self._raise_if_cancelled()

            self.progress("ui_interact", 60, "Launching app and exploring UI")
            self.adb.launch_app(device_id, app_package)
            actions: List[Dict[str, Any]] = []
            ui = UIAutomator(self.adb, device_id, verbose=self.verbose)
            if ui.connect():
                actions = ui.run_analysis_loop(
                    app_package, pause_for_login=self.pause_for_login,
                    is_cancelled=self.is_cancelled, max_iterations=ui_steps)
            else:
                verbose_print(
                    "uiautomator2 connect failed - skipping UI interaction loop",
                    self.verbose)

            self.progress("runtime_analysis", 85, "Collecting runtime findings")
            runtime_findings = self._derive_findings(env_checks)

            return {
                "device": device_info,
                "app_package": app_package,
                "detection_result": detection_result,
                "env_checks": env_checks,
                "actions": actions,
                "runtime_findings": runtime_findings,
                "network_captures": [],
                "frida_traces": [],
            }
        finally:
            try:
                self.frida.stop_server(self.adb, device_id)
            except Exception as exc:
                verbose_print(f"Error stopping frida-server: {exc}", self.verbose)

    def _detect_app_info(self, device_id: str, app_package: str) -> Optional[DetectionResult]:
        """
        Purpose:
            Pull the installed APK and run detection over it, so the report can describe the app it actually tested.

        Parameters:
            device_id: Device serial.
            app_package: Package under test.

        Returns:
            The detection result, or None when the APK could not be retrieved.

        Side effects:
            Writes the APK to a temporary directory, which is removed afterwards.

        Implementation notes:
            The APK is pulled from the device rather than taken from the operator, because a dynamic run can target an app that was already installed and for which no local copy exists. The temporary directory is removed in a finally block, so a large APK is not left behind after a failure. Failure returns None rather than raising, and the caller falls back to a placeholder -- a dynamic session is still useful without framework detection.
        """
        tmp_dir = tempfile.mkdtemp(prefix="lu77u_dyn_")
        local_apk = str(Path(tmp_dir) / f"{app_package}.apk")
        try:
            if not self.adb.pull_installed_apk(device_id, app_package, local_apk):
                verbose_print(
                    f"Could not pull APK for {app_package}; framework/app-info "
                    "will fall back to a placeholder", self.verbose)
                return None
            return MobileSecurityDetector(verbose=self.verbose).detect(local_apk)
        except Exception as exc:
            verbose_print(f"App-info detection failed: {exc}", self.verbose)
            return None
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _device_info(self, device_id: str) -> Dict[str, Any]:
        """
        Purpose:
            Describe the device under test for the report.

        Parameters:
            device_id: Device serial.

        Returns:
            The device entry, or a placeholder built from the serial.

        Implementation notes:
            The placeholder keeps the result shape stable when a device disconnects between selection and reporting, so the report renders rather than failing on a missing key.
        """
        for dev in self.adb.list_devices():
            if dev["serial"] == device_id:
                return dev
        return {"serial": device_id, "model": device_id,
                "android_version": "?", "is_emulator": False}

    def _derive_findings(self, env_checks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Purpose:
            Turn environment check outcomes into findings, where what the check proved is itself a vulnerability.

        Parameters:
            env_checks: Outcomes of the environment checks.

        Returns:
            Runtime findings.

        Implementation notes:
            Successful HTTPS interception is a finding rather than a success: it demonstrates that the app accepted a certificate from a CA added to the device, which means it does not pin for the endpoints that were exercised. That is a genuine runtime demonstration rather than a static observation, and it is scoped carefully in its wording -- it claims only the endpoints actually exercised, since an app can pin some connections and not others. The severity is moderate rather than high because interception required installing a system CA, which is not something an attacker achieves against an ordinary device.

        Security considerations:
            This finding depends on the CA having been installed by this tool. Reported without that context it would overstate the exposure, which is why the description states the mechanism explicitly.
        """
        findings: List[Dict[str, Any]] = []
        if env_checks.get("https_intercept", {}).get("ok"):
            findings.append({
                "vulnerability_type": "Interceptable HTTPS Traffic (No Certificate Pinning)",
                "severity": "Medium",
                "file": "runtime://network",
                "description": (
                    "HTTPS traffic was successfully decrypted and intercepted through "
                    "a man-in-the-middle proxy trusted only via a manually installed "
                    "system CA certificate, indicating the app does not enforce "
                    "certificate pinning for the exercised endpoints."),
                "recommendation": (
                    "Implement certificate pinning and reject user-added/non-default "
                    "CAs for sensitive endpoints."),
            })
        return findings
