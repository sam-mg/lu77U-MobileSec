"""ADB device management for dynamic analysis."""

import re
import subprocess
from typing import Dict, List, Optional

from ..utils.verbose import verbose_print

_ANDROID_PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
_SERIAL_RE = re.compile(r"^[a-zA-Z0-9.\-:_]{1,64}$")

class ADBManager:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.selected_device: Optional[str] = None
        verbose_print("ADBManager initialized", self.verbose)

    def run_adb(self, args: List[str], device: Optional[str] = None,
                timeout: int = 15) -> subprocess.CompletedProcess:
        """Run an adb command, optionally targeting a device with ``-s``."""
        if device and not _SERIAL_RE.match(device):
            raise ValueError(f"Invalid device serial: {device!r}")
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += args
        verbose_print(f"Running: {' '.join(cmd)}", self.verbose)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        verbose_print(f"adb rc={result.returncode}", self.verbose)
        if result.stdout.strip():
            verbose_print(f"adb stdout={result.stdout.strip()[:200]}", self.verbose)
        if result.stderr.strip():
            verbose_print(f"adb stderr={result.stderr.strip()[:200]}", self.verbose)
        return result

    def _device_serials(self) -> List[str]:
        """Parse ``adb devices`` into a list of serials in the ``device`` state."""
        try:
            result = self.run_adb(["devices"])
        except FileNotFoundError:
            verbose_print("adb binary not found on PATH", self.verbose)
            return []
        except subprocess.TimeoutExpired:
            verbose_print("adb devices timed out", self.verbose)
            return []

        serials: List[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of") or line.startswith("*"):
                continue
            if "\t" in line:
                serial, state = line.split("\t", 1)
                if state.strip() == "device":
                    serials.append(serial.strip())
                    verbose_print(f"Found device: {serial.strip()}", self.verbose)
                else:
                    verbose_print(
                        f"Skipping {serial.strip()} (state '{state.strip()}')",
                        self.verbose)
        return serials

    def list_devices(self) -> List[Dict[str, str]]:
        """Return attached devices as ``{serial, model, android_version, is_emulator}``."""
        verbose_print("Listing ADB devices", self.verbose)
        devices: List[Dict[str, str]] = []
        for serial in self._device_serials():
            model = self._getprop(serial, "ro.product.model") or serial
            release = self._getprop(serial, "ro.build.version.release") or "?"
            is_emulator = serial.startswith("emulator-") or serial.startswith("127.0.0.1")
            devices.append({
                "serial": serial,
                "model": model,
                "android_version": release,
                "is_emulator": is_emulator,
            })
        verbose_print(f"Total devices: {len(devices)}", self.verbose)
        return devices

    def _getprop(self, device: str, prop: str) -> Optional[str]:
        try:
            result = self.run_adb(["shell", "getprop", prop], device=device, timeout=10)
            value = result.stdout.strip()
            return value or None
        except Exception as exc:
            verbose_print(f"getprop {prop} failed: {exc}", self.verbose)
            return None

    def check_root(self, device: str) -> bool:
        """Return True if ``su -c id`` reports uid=0 on the device."""
        verbose_print(f"Checking root on {device}", self.verbose)
        try:
            result = self.run_adb(["shell", "su", "-c", "id"], device=device, timeout=10)
            is_root = result.returncode == 0 and "uid=0" in result.stdout
            verbose_print(f"Root: {is_root}", self.verbose)
            return is_root
        except subprocess.TimeoutExpired:
            verbose_print("Root check timed out", self.verbose)
            return False
        except Exception as exc:
            verbose_print(f"Root check error: {exc}", self.verbose)
            return False

    def get_architecture(self, device: str) -> Optional[str]:
        """Return the device's primary ABI (e.g. ``arm64-v8a``)."""
        verbose_print(f"Getting architecture for {device}", self.verbose)
        abi = self._getprop(device, "ro.product.cpu.abi")
        verbose_print(f"ABI: {abi}", self.verbose)
        return abi

    @staticmethod
    def abi_to_frida_arch(abi: str) -> Optional[str]:
        """Map an Android ABI to the Frida release arch name, or None if unknown."""
        return {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86_64": "x86_64",
            "x86": "x86",
        }.get((abi or "").strip())

    def shell(self, device: str, command: str,
              timeout: int = 30) -> subprocess.CompletedProcess:
        """Run an arbitrary shell command on the device."""
        verbose_print(f"shell[{device}]: {command}", self.verbose)
        return self.run_adb(["shell", command], device=device, timeout=timeout)

    def push(self, device: str, local_path: str, remote_path: str) -> bool:
        """Push a local file to the device. Returns True on success."""
        verbose_print(f"push {local_path} -> {remote_path} ({device})", self.verbose)
        try:
            result = self.run_adb(["push", local_path, remote_path],
                                  device=device, timeout=120)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"push failed: {exc}", self.verbose)
            return False

    def pull(self, device: str, remote_path: str, local_path: str) -> bool:
        """Pull a file from the device. Returns True on success."""
        verbose_print(f"pull {remote_path} -> {local_path} ({device})", self.verbose)
        try:
            result = self.run_adb(["pull", remote_path, local_path],
                                  device=device, timeout=120)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"pull failed: {exc}", self.verbose)
            return False

    def pull_installed_apk(self, device: str, package: str, local_path: str) -> bool:
        """Pull the installed base APK for ``package`` to ``local_path``.

        Used to run the same static framework/app-info detection used for
        uploaded APKs against an app already installed on the device, so
        dynamic-scan results report an accurate framework/name instead of a
        generic stand-in.
        """
        if not _ANDROID_PACKAGE_RE.match(package or ""):
            verbose_print(f"pull_installed_apk: invalid package rejected: {package!r}", self.verbose)
            return False
        try:
            result = self.shell(device, f"pm path {package}", timeout=15)
        except Exception as exc:
            verbose_print(f"pm path failed: {exc}", self.verbose)
            return False
        if result.returncode != 0 or not result.stdout.strip():
            verbose_print(f"pm path returned nothing for {package}", self.verbose)
            return False
        paths = [line[len("package:"):].strip() for line in result.stdout.splitlines()
                if line.startswith("package:")]
        if not paths:
            return False
        # Split-APK installs list multiple paths; base.apk carries the
        # manifest/DEX signals the framework detector needs.
        remote_path = next((p for p in paths if p.endswith("base.apk")), paths[0])
        return self.pull(device, remote_path, local_path)

    def install_apk(self, device: str, apk_path: str) -> tuple:
        """Install (reinstall + grant runtime perms) an APK. Returns ``(ok, message)``.

        ``-r`` reinstalls over an existing copy (keeping data), ``-g`` grants the
        runtime permissions up front so the dynamic-verification phase isn't
        blocked by permission dialogs it can't dismiss headlessly.
        """
        verbose_print(f"Installing {apk_path} on {device}", self.verbose)
        try:
            result = self.run_adb(["install", "-r", "-g", apk_path],
                                  device=device, timeout=180)
        except Exception as exc:
            return False, f"adb install failed: {exc}"
        out = (result.stdout + "\n" + result.stderr).strip()
        ok = result.returncode == 0 and "Success" in out
        if ok:
            return True, "Success"
        return False, (out[:400] or "adb install failed")

    def capture_screenshot(self, device: str, timeout: int = 15) -> Optional[bytes]:
        """Capture a PNG screenshot from the device. Returns raw PNG bytes or None.

        Uses ``exec-out`` (not ``shell``) because it streams stdout without the
        text/pty translation ``shell`` applies, which would corrupt binary data.
        """
        if not _SERIAL_RE.match(device):
            raise ValueError(f"Invalid device serial: {device!r}")
        cmd = ["adb", "-s", device, "exec-out", "screencap", "-p"]
        verbose_print(f"Running: {' '.join(cmd)}", self.verbose)
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except Exception as exc:
            verbose_print(f"Screenshot capture failed: {exc}", self.verbose)
            return None
        if result.returncode != 0 or not result.stdout:
            verbose_print(f"Screenshot capture failed (rc={result.returncode})", self.verbose)
            return None
        verbose_print(f"Captured screenshot: {len(result.stdout)} bytes", self.verbose)
        return result.stdout

    def open_url(self, device: str, url: str) -> bool:
        """Open ``url`` in the device's default browser via an intent."""
        verbose_print(f"Opening {url} on {device}", self.verbose)
        try:
            result = self.run_adb(
                ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url],
                device=device, timeout=15)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"open_url failed: {exc}", self.verbose)
            return False

    def list_packages(self, device: str) -> List[str]:
        """Return installed third-party package names (``pm list packages -3``)."""
        verbose_print(f"Listing third-party packages on {device}", self.verbose)
        try:
            result = self.shell(device, "pm list packages -3", timeout=20)
        except Exception as exc:
            verbose_print(f"pm list packages failed: {exc}", self.verbose)
            return []
        packages: List[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line[len("package:"):].strip())
        packages.sort()
        verbose_print(f"Found {len(packages)} third-party packages", self.verbose)
        return packages

    def launch_app(self, device: str, package: str) -> bool:
        """Start an app's launcher activity via monkey. Returns True on success."""
        if not _ANDROID_PACKAGE_RE.match(package or ""):
            verbose_print(f"launch_app: invalid package name rejected: {package!r}", self.verbose)
            return False
        verbose_print(f"Launching {package} on {device}", self.verbose)
        try:
            result = self.run_adb(
                ["shell", "monkey", "-p", package,
                 "-c", "android.intent.category.LAUNCHER", "1"],
                device=device, timeout=20)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"launch_app failed: {exc}", self.verbose)
            return False