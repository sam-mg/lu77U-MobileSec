"""Dynamic analysis orchestrator (UI-agnostic)."""

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
    def __init__(
        self,
        verbose: bool = False,
        progress: Optional[Callable[..., None]] = None,
        pause_for_login: Optional[Callable[[], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.verbose = verbose
        self._progress = progress or (lambda *a, **k: None)
        self.pause_for_login = pause_for_login
        self.is_cancelled = is_cancelled or (lambda: False)
        self.adb = ADBManager(verbose=verbose)
        self.frida = FridaManager(verbose=verbose)
        self.mitmproxy = MitmproxyManager(verbose=verbose)
        verbose_print("DynamicAnalyzer initialized", self.verbose)

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        try:
            self._progress(phase=phase, percent=percent, message=message)
        except ScanCancelled:
            raise
        except Exception:
            pass

    def _raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            verbose_print("Cancellation requested; stopping dynamic analysis", self.verbose)
            raise ScanCancelled()

    def _safe_check(self, label: str, fn: Callable[[], "tuple[bool, str]"]) -> Dict[str, Any]:
        """Run an optional, non-blocking environment check (Frida/HTTP intercept).

        These checks shell out to adb repeatedly and can hang or raise for
        reasons outside our control (a device with no route to the internet, an
        unexpected BusyBox build, etc.). Regardless of the cause, a failure here
        must degrade to ``{"ok": False, ...}`` rather than aborting the session.
        """
        try:
            ok, message = fn()
            return {"ok": ok, "message": message}
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"{label} check errored: {exc}", self.verbose)
            return {"ok": False, "message": f"{label} check failed: {exc}"}

    def run(self, device_id: str, app_package: str) -> Dict[str, Any]:
        """Run a dynamic-analysis session and return a structured result dict."""
        verbose_print(
            f"Dynamic analysis: device={device_id} app={app_package}", self.verbose)

        self.progress("device_check", 10, "Checking device and root access")
        device_info = self._device_info(device_id)
        has_root = self.adb.check_root(device_id)
        verbose_print(f"Device root: {has_root}", self.verbose)

        env_checks: Dict[str, Any] = {"root": has_root}
        self._raise_if_cancelled()

        self.progress("app_info", 20, "Reading app info from the device")
        detection_result = self._detect_app_info(device_id, app_package)

        try:
            self.progress("frida_setup", 30, "Setting up Frida server")
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
                    is_cancelled=self.is_cancelled)
            else:
                verbose_print(
                    "uiautomator2 connect failed — skipping UI interaction loop",
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
        """Pull the installed APK and run static detection on it (best-effort).

        Returns ``None`` (never raises) if the pull or detection fails — e.g. no
        root, a split-APK layout we can't resolve, or a transient adb error. The
        caller falls back to a generic placeholder in that case.
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
        for dev in self.adb.list_devices():
            if dev["serial"] == device_id:
                return dev
        return {"serial": device_id, "model": device_id,
                "android_version": "?", "is_emulator": False}

    def _derive_findings(self, env_checks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Turn environment observations into report-shaped runtime findings."""
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