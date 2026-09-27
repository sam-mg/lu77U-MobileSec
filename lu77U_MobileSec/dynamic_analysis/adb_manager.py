#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.adb_manager

Purpose:
    Drive a connected Android device through adb: enumerate devices, install and launch the app under test, move files, capture screenshots and run shell commands.

Responsibilities:
    Wrap adb invocation with validation and timeouts, and provide the device operations the dynamic pipeline needs.

Dependencies:
    subprocess, re.

Implementation notes:
    Every operation goes through one invocation helper, so validation, timeouts and tracing are applied uniformly rather than per call site.

Security considerations:
    Two values reach adb from outside this module and both are validated against strict patterns before use: the device serial and the package name. Everything is passed as an argument vector with no shell. Note that the shell helper sends a command string to the device's own shell, which does interpret it. Callers must not build that string from untrusted input -- the validated package-name path exists precisely so they do not have to. This module installs and runs an untrusted APK on a real device. That device should be one the operator owns and is prepared to wipe.
"""

import contextlib
import re
import subprocess
from typing import Dict, List, Optional

from ..utils.verbose import verbose_print

_ANDROID_PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
_SERIAL_RE = re.compile(r"^[a-zA-Z0-9.\-:_]{1,64}$")

_VERIFIER_BLOCKED_MARKERS = (
    "INSTALL_FAILED_VERIFICATION_FAILURE",
    "INSTALL_FAILED_VERIFICATION_TIMEOUT",
)

_VERIFIER_BYPASS_SETTINGS = {
    "verifier_verify_adb_installs": "0",
    "package_verifier_enable": "0",
    "package_verifier_user_consent": "-1",
    "upload_apk_enable": "0",
}

class ADBManager:
    """
    Purpose:
        Controls a connected Android device over adb.

    Attributes:
        verbose: Whether adb activity is traced.
        selected_device: The device chosen for this session, if any.

    Invariants:
        Device serials and package names are validated before reaching a command line.

    Thread-safety:
        adb itself serialises access per device, but two managers driving one device will interleave their operations.

    Security considerations:
        Every method here acts on a real device with a real user's data if pointed at the wrong one.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the manager.

        Parameters:
            verbose: Enables tracing of every adb invocation.
        """
        self.verbose = verbose
        self.selected_device: Optional[str] = None
        verbose_print("ADBManager initialized", self.verbose)

    def run_adb(self, args: List[str], device: Optional[str] = None,
                timeout: int = 15) -> subprocess.CompletedProcess:
        """
        Purpose:
            Run one adb command and capture its result.

        Parameters:
            args: Arguments after the adb binary and any device selector.
            device: Device serial to target, validated before use.
            timeout: Seconds to allow.

        Returns:
            The completed process.

        Raises:
            ValueError: When the device serial does not match the permitted pattern.
            subprocess.TimeoutExpired: When adb did not finish in time.
            FileNotFoundError: When adb is not on PATH.

        Side effects:
            Spawns adb and traces the command and its output.

        Implementation notes:
            Every adb call in this module funnels through here, which is what makes the serial validation and the timeout unavoidable rather than something each call site has to remember. Output is truncated in the trace, since a shell command can return a great deal of text and the log is for following progress. Timeouts and missing-binary errors propagate rather than being swallowed, so each caller decides whether that failure is fatal for it.

        Security considerations:
            The serial is validated against a strict pattern before it can become a command-line argument.
        """
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
        """
        Purpose:
            List the serials of devices that are connected and ready.

        Returns:
            Serials; empty when adb is missing, timed out, or nothing is connected.

        Implementation notes:
            Only devices in the ready state are returned. A device that is unauthorised or offline appears in the listing but cannot be driven, and returning it would produce a confusing failure later; the skip is traced so the user can see it was there. Header and annotation lines are skipped explicitly rather than by position, since adb's output preamble varies.
        """
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
        """
        Purpose:
            Describe every ready device, for the device chooser.

        Returns:
            One entry per device with serial, model, Android version and whether it is an emulator.

        Side effects:
            Queries each device for its properties.

        Implementation notes:
            The model and version make the chooser usable -- a serial alone is meaningless to someone with two phones attached. Each falls back to a placeholder rather than failing the listing. Emulator detection is by serial convention, covering both the local emulator naming and a loopback network connection.
        """
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
        """
        Purpose:
            Read one system property from a device.

        Parameters:
            device: Device serial.
            prop: Property name.

        Returns:
            The value, or None when unset or the query failed.

        Implementation notes:
            An empty result is normalised to None, since an unset property and a failed query are equivalent to every caller here.
        """
        try:
            result = self.run_adb(["shell", "getprop", prop], device=device, timeout=10)
            value = result.stdout.strip()
            return value or None
        except Exception as exc:
            verbose_print(f"getprop {prop} failed: {exc}", self.verbose)
            return None

    def check_root(self, device: str) -> bool:
        """
        Purpose:
            Determine whether the device gives root access.

        Parameters:
            device: Device serial.

        Returns:
            True when a root shell is available.

        Implementation notes:
            Tested by actually obtaining a root shell and checking the reported user id, rather than by looking for a binary. A device can have a su binary that refuses to grant root, and only the real attempt distinguishes the two.

        Security considerations:
            Root availability determines how much of the dynamic pipeline can run -- system-wide certificate installation and unrestricted instrumentation both need it. A device that grants root to adb is fully compromised by design, which is the expected state for a dedicated test device.
        """
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
        """
        Purpose:
            Read the device's primary CPU architecture.

        Parameters:
            device: Device serial.

        Returns:
            The ABI string, or None.

        Implementation notes:
            Needed to pick the matching Frida server build; a mismatched binary fails to start with an unhelpful error.
        """
        verbose_print(f"Getting architecture for {device}", self.verbose)
        abi = self._getprop(device, "ro.product.cpu.abi")
        verbose_print(f"ABI: {abi}", self.verbose)
        return abi

    @staticmethod
    def abi_to_frida_arch(abi: str) -> Optional[str]:
        """
        Purpose:
            Translate an Android ABI name into Frida's architecture naming.

        Parameters:
            abi: The ABI string from the device.

        Returns:
            Frida's name for that architecture, or None when unrecognised.

        Implementation notes:
            A small fixed mapping, because the two projects name the same architectures differently and getting it wrong means downloading a server binary that cannot run. An unknown ABI returns None rather than guessing, so the caller reports an unsupported device instead of failing obscurely later.
        """
        return {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86_64": "x86_64",
            "x86": "x86",
        }.get((abi or "").strip())

    def shell(self, device: str, command: str,
              timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Purpose:
            Run a shell command on the device.

        Parameters:
            device: Device serial.
            command: Command string, interpreted by the device's shell.
            timeout: Seconds to allow.

        Returns:
            The completed process.

        Security considerations:
            The command is a single string passed to the device's shell, which interprets metacharacters. Callers must construct it from trusted values only; anything derived from the APK must be validated first, as the package-name paths in this module do.
        """
        verbose_print(f"shell[{device}]: {command}", self.verbose)
        return self.run_adb(["shell", command], device=device, timeout=timeout)

    def push(self, device: str, local_path: str, remote_path: str) -> bool:
        """
        Purpose:
            Copy a local file onto the device.

        Parameters:
            device: Device serial.
            local_path: Source path.
            remote_path: Destination on the device.

        Returns:
            True when the copy succeeded.

        Implementation notes:
            A long timeout, since this moves the Frida server and other multi-megabyte payloads over a link that can be slow.
        """
        verbose_print(f"push {local_path} -> {remote_path} ({device})", self.verbose)
        try:
            result = self.run_adb(["push", local_path, remote_path],
                                  device=device, timeout=120)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"push failed: {exc}", self.verbose)
            return False

    def pull(self, device: str, remote_path: str, local_path: str) -> bool:
        """
        Purpose:
            Copy a file from the device to the local filesystem.

        Parameters:
            device: Device serial.
            remote_path: Source on the device.
            local_path: Destination path.

        Returns:
            True when the copy succeeded.
        """
        verbose_print(f"pull {remote_path} -> {local_path} ({device})", self.verbose)
        try:
            result = self.run_adb(["pull", remote_path, local_path],
                                  device=device, timeout=120)
            return result.returncode == 0
        except Exception as exc:
            verbose_print(f"pull failed: {exc}", self.verbose)
            return False

    def pull_installed_apk(self, device: str, package: str, local_path: str) -> bool:
        """
        Purpose:
            Retrieve the APK of a package already installed on the device, so an app can be analysed without a local copy.

        Parameters:
            device: Device serial.
            package: Package name, validated before use.
            local_path: Where to write the APK.

        Returns:
            True when the APK was retrieved.

        Implementation notes:
            The package's real path is asked of the package manager rather than assumed, since it varies by install source and Android version. A split APK reports several paths; the base is preferred because it carries the manifest and the primary DEX, which is what the analysis needs.

        Security considerations:
            The package name is validated against a strict pattern before it reaches the shell, because this method composes it into a command string.
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
        remote_path = next((p for p in paths if p.endswith("base.apk")), paths[0])
        return self.pull(device, remote_path, local_path)

    def install_apk(self, device: str, apk_path: str) -> tuple:
        """
        Purpose:
            Install an APK, working around the device's package verifier when it blocks the install.

        Parameters:
            device: Device serial.
            apk_path: Local path to the APK.

        Returns:
            A success flag and a message.

        Side effects:
            Installs the app, and temporarily changes device verification settings on the retry path.

        Implementation notes:
            The first attempt is plain. Only a failure whose message names a verifier block triggers the retry, so an ordinary install failure is reported as itself rather than being blamed on verification.

        Security considerations:
            The package verifier is Google Play Protect's check on sideloaded apps. Disabling it is exactly what an analyst needs -- the app under test is expected to be malicious and would otherwise be refused -- and exactly what must never be left disabled. The bypass is scoped to a context manager that restores the prior settings.
        """
        verbose_print(f"Installing {apk_path} on {device}", self.verbose)
        ok, message = self._install_once(device, apk_path)
        if ok or not any(marker in message for marker in _VERIFIER_BLOCKED_MARKERS):
            return ok, message
        verbose_print(
            f"Install blocked by the device package verifier ({message[:160]!r}); "
            "retrying with verification disabled", self.verbose)
        with self._verification_bypassed(device):
            ok, message = self._install_once(device, apk_path)
        if not ok:
            return False, f"Device package verifier blocked the install: {message}"
        return True, "Success"

    def _install_once(self, device: str, apk_path: str) -> tuple:
        """
        Purpose:
            Attempt one install and report the outcome.

        Parameters:
            device: Device serial.
            apk_path: Local path to the APK.

        Returns:
            A success flag and a message.

        Implementation notes:
            Installed with replacement, with runtime permissions granted, and allowing a test build. Granting permissions up front matters because the dynamic run cannot answer permission dialogs, and an app blocked on one exercises none of its real behaviour. Success requires both a zero exit and the success marker in the output, since adb reports some failures with a zero exit. Both streams are combined for the message, because adb splits install errors between them inconsistently.
        """
        try:
            result = self.run_adb(["install", "-r", "-g", "-t", apk_path],
                                  device=device, timeout=180)
        except Exception as exc:
            return False, f"adb install failed: {exc}"
        out = (result.stdout + "\n" + result.stderr).strip()
        ok = result.returncode == 0 and "Success" in out
        if ok:
            return True, "Success"
        return False, (out[:400] or "adb install failed")

    @contextlib.contextmanager
    def _verification_bypassed(self, device: str):
        """
        Purpose:
            Temporarily disable the device's package verification, restoring the previous settings afterwards.

        Parameters:
            device: Device serial.

        Returns:
            A context manager. Entering it disables verification; leaving it restores the prior settings.

        Side effects:
            Changes global device settings for the duration of the block.

        Postconditions:
            Every setting is restored to its prior value, including being deleted again when it was previously unset.

        Implementation notes:
            Prior values are read before anything is changed, and the distinction between an unset setting and one set to a value is preserved -- restoring an unset setting by writing a default would leave the device in a different state than it started. Restoration runs in a finally block, so an install that raises still leaves the device as it was found. Each restore is individually guarded so one failure does not abandon the rest.

        Security considerations:
            This disables Play Protect's verification of sideloaded apps. It is scoped as narrowly as possible and always restored. Leaving it off would silently weaken the device against every future install, not just this one.
        """
        prior: Dict[str, Optional[str]] = {}
        for key in _VERIFIER_BYPASS_SETTINGS:
            try:
                result = self.run_adb(["shell", "settings", "get", "global", key],
                                      device=device, timeout=10)
                value = result.stdout.strip()
                prior[key] = None if value in ("", "null") else value
            except Exception as exc:
                verbose_print(f"settings get global {key} failed: {exc}", self.verbose)
                prior[key] = None
        try:
            for key, bypass_value in _VERIFIER_BYPASS_SETTINGS.items():
                self.run_adb(["shell", "settings", "put", "global", key, bypass_value],
                            device=device, timeout=10)
            yield
        finally:
            for key, value in prior.items():
                try:
                    if value is None:
                        self.run_adb(["shell", "settings", "delete", "global", key],
                                    device=device, timeout=10)
                    else:
                        self.run_adb(["shell", "settings", "put", "global", key, value],
                                    device=device, timeout=10)
                except Exception as exc:
                    verbose_print(f"Restoring settings global {key} failed: {exc}", self.verbose)

    def capture_screenshot(self, device: str, timeout: int = 15) -> Optional[bytes]:
        """
        Purpose:
            Capture the device's screen as PNG bytes.

        Parameters:
            device: Device serial, validated before use.
            timeout: Seconds to allow.

        Returns:
            The PNG bytes, or None on failure.

        Raises:
            ValueError: When the device serial is invalid.

        Implementation notes:
            Built directly rather than going through the shared helper, because the image is binary and the helper decodes output as text, which would corrupt it.

        Security considerations:
            The screenshot may contain whatever the app is displaying, including credentials entered during automated interaction.
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
        """
        Purpose:
            Open a URL on the device, used to exercise deep links.

        Parameters:
            device: Device serial.
            url: URL to open.

        Returns:
            True when the intent was delivered.

        Security considerations:
            The URL is passed as its own argument vector element rather than being interpolated into a shell command, so a crafted deep link cannot become a device shell injection. This is the mechanism used to test whether an exported component really is reachable.
        """
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
        """
        Purpose:
            List the third-party packages installed on the device.

        Parameters:
            device: Device serial.

        Returns:
            Package names, sorted; empty on failure.

        Implementation notes:
            System packages are excluded, since the chooser exists to pick an app to analyse and the system list would bury it. Sorted so the list is stable between refreshes.
        """
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
        """
        Purpose:
            Launch an installed app's main activity.

        Parameters:
            device: Device serial.
            package: Package name, validated before use.

        Returns:
            True when the launch command succeeded.

        Implementation notes:
            Launched through the monkey tool with a launcher category rather than by naming an activity, because the main activity's class name is not always known and monkey resolves it from the manifest. A zero exit means the command ran, not that the app is on screen -- an app can start and immediately crash. The caller confirms by other means.

        Security considerations:
            The package name is validated before use. This starts untrusted code on the device, which is the intent of the dynamic pipeline.
        """
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
