#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.mitmproxy_manager

Purpose:
    Stand up a local intercepting proxy, get the device to trust and use it, and confirm that the app's HTTPS traffic really is being captured.

Responsibilities:
    Manage the mitmdump process, install the proxy CA into the device's system store, point the device at the proxy, and verify interception end to end.

Dependencies:
    mitmproxy's mitmdump, openssl, platform tooling on macOS.

Implementation notes:
    Interception is verified rather than assumed. Every part of the chain -- proxy running, CA trusted, device pointed at it, traffic actually flowing -- can fail silently and leave a scan reporting that an app's traffic is safe when it was never inspected. The check drives a real request through the device and looks for it in the proxy's log. The connection is made through an adb reverse tunnel rather than over the network, so the device reaches the proxy on its own loopback address. That works regardless of what network the device is on and avoids exposing the proxy to anything else.

Security considerations:
    This installs a CA certificate into the device's system trust store. From that point the device trusts certificates minted by whoever holds the corresponding key, for every app and every site -- not just the app under test. This is only acceptable on a dedicated test device, and the key lives in the operator's home directory. The proxy itself decrypts all traffic from the device, including credentials and session tokens, and writes request URLs to a file in the system temporary directory.
"""

import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

from .._metadata import NAME as APP_NAME
from ..utils.verbose import verbose_print

MITMPROXY_PORT = 8080
MITMPROXY_TEST_URL = "https://www.google.com/"
_TEST_HOST = urlparse(MITMPROXY_TEST_URL).netloc
_DEVICE_LOOPBACK = "127.0.0.1"

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

def _macos_firewall_allows(python_path: str, verbose: bool) -> Optional[bool]:
    """
    Purpose:
        Determine whether the macOS application firewall already permits this interpreter to accept incoming connections.

    Parameters:
        python_path: Resolved path to the running interpreter.
        verbose: Traces a failure to read the firewall state.

    Returns:
        True or False when the state could be read, None when it could not.

    Implementation notes:
        The three-way return is load-bearing: unknown must be distinguished from denied, because the caller proceeds on unknown and prompts on denied. The firewall lists an application and its verdict on the following line, so the verdict is read by position relative to the match.
    """
    try:
        result = subprocess.run([_SOCKETFILTERFW, "--listapps"],
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if python_path in line:
                verdict = lines[i + 1] if i + 1 < len(lines) else ""
                return "Allow" in verdict
        return False
    except Exception as exc:
        verbose_print(f"Could not read macOS firewall app list: {exc}", verbose)
        return None

def ensure_macos_firewall_exception(verbose: bool = False) -> Tuple[bool, str]:
    """
    Purpose:
        Make sure macOS will let the proxy accept connections, prompting for a one-time exception when it will not.

    Parameters:
        verbose: Traces the decision.

    Returns:
        A success flag and a message.

    Side effects:
        On macOS, may write a temporary script and request elevated privileges to add a firewall exception.

    Implementation notes:
        Non-macOS platforms return success immediately, as do cases where the state is already permitted or cannot be read. Only a definite denial triggers the prompt, so the user is not asked for privileges unnecessarily. Without the exception, macOS silently drops the device's connections to the proxy and the whole interception check fails with no visible cause.

    Security considerations:
        Adding a firewall exception requires elevated privileges and widens what this machine accepts. It is requested for the specific interpreter path rather than broadly, and only when the firewall has actually denied it. The helper script is made owner-only (0o700) rather than world-readable, because osascript runs it as root and root only needs an execute bit to be set, so no other local user has any reason to read or run it.
    """
    if platform.system() != "Darwin":
        return True, "Not macOS; no firewall exception needed."

    python_path = os.path.realpath(sys.executable)
    allowed = _macos_firewall_allows(python_path, verbose)
    if allowed:
        verbose_print(f"macOS firewall already allows {python_path}", verbose)
        return True, "Firewall exception already present."
    if allowed is None:
        return True, "Could not read macOS firewall state; proceeding anyway."

    verbose_print(f"Requesting a one-time macOS firewall exception for {python_path}", verbose)
    script_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".sh", delete=False,
            dir=os.path.realpath(tempfile.gettempdir())) as f:
            f.write(
                "#!/bin/sh\nset -e\n"
                f'"{_SOCKETFILTERFW}" --add "{python_path}"\n'
                f'"{_SOCKETFILTERFW}" --unblockapp "{python_path}"\n'
            )
            script_path = f.name
        os.chmod(script_path, 0o700)
        prompt = (f"{APP_NAME} needs a one-time firewall exception so mitmproxy "
                 "can accept HTTPS-interception connections from the test device.")
        applescript = (
            f'do shell script "{script_path}" with administrator privileges '
            f'with prompt "{prompt}"'
        )
        result = subprocess.run(["osascript", "-e", applescript],
                                capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            verbose_print("macOS firewall exception granted", verbose)
            return True, "Firewall exception added."
        verbose_print(f"Firewall exception request failed/cancelled: {result.stderr}", verbose)
        return False, f"Firewall exception was not granted: {result.stderr.strip()[:200]}"
    except Exception as exc:
        verbose_print(f"Error requesting firewall exception: {exc}", verbose)
        return False, f"Could not request a firewall exception: {exc}"
    finally:
        if script_path:
            try:
                os.unlink(script_path)
            except Exception:
                pass

def _mitmproxy_ca_cert_path() -> Optional[Path]:
    """
    Purpose:
        Locate mitmproxy's generated CA certificate.

    Returns:
        The path when it exists, None otherwise.

    Implementation notes:
        The certificate is generated on mitmproxy's first run, so its absence means mitmproxy has never been started rather than that anything is wrong. The caller says so.
    """
    path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    return path if path.exists() else None

def _compute_android_cert_hash(cert_path: Path) -> Optional[str]:
    """
    Purpose:
        Compute the filename Android expects for a system CA certificate.

    Parameters:
        cert_path: Path to the certificate.

    Returns:
        The hash, or None when it could not be computed.

    Implementation notes:
        Android names system certificates by a hash of the subject, using OpenSSL's legacy algorithm specifically -- the modern one produces a different value and a certificate installed under it is silently ignored. Shelling out to openssl rather than computing it in Python keeps the legacy algorithm exactly right; reimplementing it is a well-known source of certificates that install without taking effect. Returns None rather than raising when openssl is missing, and the caller reports that.
    """
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
             "-in", str(cert_path), "-noout"],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        lines = result.stdout.strip().splitlines()
        return lines[0] if lines else None
    except Exception:
        return None

class MitmproxyManager:
    """
    Purpose:
        Runs an intercepting proxy and configures a device to route its traffic through it.

    Attributes:
        verbose: Whether proxy activity is traced.

    Invariants:
        A proxy this manager started is tracked so it can be stopped; the device proxy setting and the reverse tunnel are cleared by the matching teardown method.

    Thread-safety:
        Not safe to share. The proxy port and the device proxy setting are single global resources.

    Security considerations:
        Holds the process that decrypts the device's traffic, and installs the CA that makes that possible.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the manager.

        Parameters:
            verbose: Enables tracing.

        Postconditions:
            No proxy is running and no flow log is set.
        """
        self.verbose = verbose
        self._proxy_process: Optional[subprocess.Popen] = None
        self._flow_log_path: Optional[str] = None
        verbose_print("MitmproxyManager initialized", self.verbose)

    def is_mitmproxy_installed(self) -> bool:
        """
        Purpose:
            Check whether mitmdump is available.

        Returns:
            True when mitmdump is on PATH.
        """
        found = shutil.which("mitmdump") is not None
        verbose_print(f"mitmdump on PATH: {found}", self.verbose)
        return found

    def _kill_stray_mitmdump(self) -> None:
        """
        Purpose:
            Kill any proxy left running on the port by an earlier run.

        Side effects:
            Sends termination signals to matching processes.

        Implementation notes:
            A previous scan that crashed or was killed leaves mitmdump holding the port, and the next start then fails with a bind error that looks like a configuration problem. Processes are matched on the exact port-bearing command line, so an unrelated mitmdump the user is running on another port is left alone. Each process id is checked as a digit string before conversion. A process that has already exited is skipped silently, but one this user may not signal (typically a mitmdump started by another account) is logged, because it will keep holding the port and the next start will fail. A short pause follows, since the port is not free the instant the signal is sent.
        """
        try:
            result = subprocess.run(
                ["pgrep", "-f", f"mitmdump -p {MITMPROXY_PORT} "],
                capture_output=True, text=True, timeout=5)
        except Exception as exc:
            verbose_print(f"Could not check for an orphaned mitmdump: {exc}", self.verbose)
            return
        pids = [p for p in result.stdout.split() if p.isdigit()]
        for pid_str in pids:
            try:
                os.kill(int(pid_str), signal.SIGTERM)
                verbose_print(f"Killed orphaned mitmdump process {pid_str}", self.verbose)
            except ProcessLookupError:
                continue
            except PermissionError as exc:
                verbose_print(f"Could not kill orphaned mitmdump process {pid_str}: {exc}", self.verbose)
        if pids:
            time.sleep(0.3)

    def start_proxy(self) -> bool:
        """
        Purpose:
            Start the proxy with an addon that logs every request URL.

        Returns:
            True when the proxy started.

        Side effects:
            Writes an addon script and a flow log into the system temporary directory, and spawns mitmdump.

        Implementation notes:
            The addon is generated rather than shipped, so the log path is fixed at start time and the script has no configuration of its own. Only request URLs are logged, not bodies. The log exists to answer whether interception is working, and writing full request bodies would put credentials on disk for a liveness check.

        Security considerations:
            Both generated paths are resolved and confirmed to be inside the temporary directory before anything is written, so a manipulated temporary directory setting cannot redirect the write elsewhere. The log still records every URL the device requests while the proxy is running, which can include tokens carried in query strings.
        """
        verbose_print(f"Starting mitmproxy on port {MITMPROXY_PORT}", self.verbose)
        self._kill_stray_mitmdump()
        tmp = os.path.realpath(tempfile.gettempdir())
        log_path = os.path.join(tmp, "lu77u_mitmproxy_flows.txt")
        script_path = os.path.join(tmp, "lu77u_mitmaddon.py")
        for p in (log_path, script_path):
            if not os.path.realpath(p).startswith(tmp):
                verbose_print(f"Refusing to write outside tempdir: {p}", self.verbose)
                return False
        addon_script = (
            "import mitmproxy.http\n"
            "def request(flow: mitmproxy.http.HTTPFlow):\n"
            f"    with open({log_path!r}, 'a') as f:\n"
            "        f.write(flow.request.pretty_url + '\\n')\n"
        )
        try:
            with open(script_path, "w") as f:
                f.write(addon_script)
            self._flow_log_path = log_path
            if os.path.exists(log_path):
                os.remove(log_path)

            self._proxy_process = subprocess.Popen(
                ["mitmdump", "-p", str(MITMPROXY_PORT), "-s", script_path, "--quiet"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            verbose_print(f"mitmdump PID: {self._proxy_process.pid}", self.verbose)

            deadline = time.time() + 5.0
            while time.time() < deadline:
                time.sleep(0.2)
                try:
                    with socket.create_connection(("127.0.0.1", MITMPROXY_PORT), timeout=1):
                        verbose_print("mitmproxy port is open", self.verbose)
                        return True
                except (ConnectionRefusedError, OSError):
                    pass

            verbose_print("mitmproxy did not open its port in time", self.verbose)
            self.stop_proxy()
            return False
        except FileNotFoundError:
            verbose_print("mitmdump binary not found", self.verbose)
            return False
        except Exception as exc:
            verbose_print(f"Failed to start mitmproxy: {exc}", self.verbose)
            return False

    def stop_proxy(self) -> None:
        """
        Purpose:
            Stop the proxy this manager started.

        Side effects:
            Terminates the proxy process.

        Implementation notes:
            Terminates first and kills if that does not complete, so mitmdump gets a chance to flush its log. The handle is cleared in a finally block, so a failure to stop does not leave the manager believing it still owns a process.
        """
        verbose_print("Stopping mitmproxy", self.verbose)
        if self._proxy_process:
            try:
                self._proxy_process.terminate()
                self._proxy_process.wait(timeout=5)
            except Exception as exc:
                verbose_print(f"Error terminating mitmproxy: {exc}", self.verbose)
                self._proxy_process.kill()
            finally:
                self._proxy_process = None

    def configure_device_proxy(self, adb_manager, device: str) -> bool:
        """
        Purpose:
            Point the device's global proxy setting at the local proxy through a reverse tunnel.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            True when both the tunnel and the setting were established.

        Side effects:
            Creates a reverse tunnel and changes a global device setting.

        Implementation notes:
            The reverse tunnel makes the proxy reachable on the device's own loopback address, so the setting works regardless of the device's network and the proxy is never exposed to other hosts.

        Security considerations:
            This routes all of the device's HTTP traffic through the proxy, not just the app under test. It must be cleared afterwards.
        """
        fwd = adb_manager.run_adb(
            ["reverse", f"tcp:{MITMPROXY_PORT}", f"tcp:{MITMPROXY_PORT}"],
            device=device, timeout=10)
        if fwd.returncode != 0:
            verbose_print(f"adb reverse failed: {fwd.stderr.strip()[:200]}", self.verbose)
            return False
        proxy_value = f"{_DEVICE_LOOPBACK}:{MITMPROXY_PORT}"
        verbose_print(f"Setting device proxy: {proxy_value}", self.verbose)
        result = adb_manager.shell(device, f"settings put global http_proxy {proxy_value}")
        return result.returncode == 0

    def clear_device_proxy(self, adb_manager, device: str) -> None:
        """
        Purpose:
            Remove the device proxy setting and the reverse tunnel.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Side effects:
            Resets the global proxy setting and removes the tunnel.

        Implementation notes:
            The setting is cleared with the platform's idiom for "no proxy" rather than deleted, which is what Android expects. Tunnel removal is guarded, so a device that disconnected mid-scan does not turn cleanup into an error.

        Security considerations:
            Leaving the proxy setting in place would send the device's traffic to a port that is no longer listening, breaking its networking, or worse, to whatever later binds that port.
        """
        verbose_print(f"Clearing device proxy on {device}", self.verbose)
        adb_manager.shell(device, "settings put global http_proxy :0")
        try:
            adb_manager.run_adb(["reverse", "--remove", f"tcp:{MITMPROXY_PORT}"],
                                device=device, timeout=10)
        except Exception as exc:
            verbose_print(f"Failed to remove adb reverse tunnel: {exc}", self.verbose)

    def is_ca_installed(self, adb_manager, device: str, cert_hash: str) -> bool:
        """
        Purpose:
            Check whether the proxy's CA is already in the device's system trust store.

        Parameters:
            adb_manager: Device control.
            device: Device serial.
            cert_hash: The Android certificate filename hash.

        Returns:
            True when the certificate is present.
        """
        result = adb_manager.shell(
            device, f"test -f /system/etc/security/cacerts/{cert_hash}.0 && echo EXISTS",
            timeout=10)
        return "EXISTS" in result.stdout

    def install_ca_cert(self, adb_manager, device: str) -> Tuple[bool, str]:
        """
        Purpose:
            Install the proxy's CA into the device's system trust store so that HTTPS can be intercepted.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            A success flag and a message.

        Side effects:
            Pushes a certificate, remounts the system partition writable, and writes into the system trust store.

        Implementation notes:
            Installed into the system store rather than the user store because apps targeting modern Android do not trust user-added CAs by default, so a user-store installation would silently fail to intercept exactly the apps worth testing. An already-installed certificate short-circuits, so repeated runs do not remount the filesystem. Each failure returns a specific message -- no certificate yet, no openssl, remount refused -- because these fail for quite different reasons and a generic failure leaves the user with nothing to act on.

        Security considerations:
            This is the most invasive operation in the tool. Making the system partition writable and adding a CA to the system store permanently weakens the device's trust model for every app on it until the certificate is removed. It requires root, and it belongs only on a device dedicated to analysis.
        """
        cert_path = _mitmproxy_ca_cert_path()
        if cert_path is None:
            return False, "mitmproxy CA cert not found (needs to run at least once first)."
        cert_hash = _compute_android_cert_hash(cert_path)
        if not cert_hash:
            return False, "Could not compute the Android cert hash (is openssl installed?)."
        if self.is_ca_installed(adb_manager, device, cert_hash):
            verbose_print(f"mitmproxy CA already installed ({cert_hash}.0)", self.verbose)
            return True, "CA already installed"

        remote_tmp = "/data/local/tmp/lu77u_mitm_ca.pem"
        if not adb_manager.push(device, str(cert_path), remote_tmp):
            return False, "Failed to push the CA cert to the device."
        remount = adb_manager.shell(device, "su -c 'mount -o rw,remount /'", timeout=15)
        if remount.returncode != 0:
            return False, f"Could not remount the device filesystem writable: {remount.stderr.strip()[:150]}"
        dest = f"/system/etc/security/cacerts/{cert_hash}.0"
        cp = adb_manager.shell(device, f"su -c 'cp {remote_tmp} {dest}'", timeout=15)
        if cp.returncode != 0:
            return False, f"Failed to install the CA cert: {cp.stderr.strip()[:150]}"
        adb_manager.shell(device, f"su -c 'chmod 644 {dest}'", timeout=10)
        verbose_print(f"Installed mitmproxy CA as system cert: {dest}", self.verbose)
        return True, "CA installed"

    def make_test_request(self, adb_manager, device: str) -> bool:
        """
        Purpose:
            Drive a request from the device through the proxy, to prove interception works.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            True when the browser was launched.

        Side effects:
            Opens a URL in the device's browser.

        Implementation notes:
            A random value is added to the URL so the request is not served from a cache, which would produce no flow through the proxy and look like a failure to intercept. A true return means the browser launched, not that traffic was captured; that is checked separately.
        """
        url = f"{MITMPROXY_TEST_URL}?probe={uuid.uuid4().hex[:8]}"
        verbose_print(f"Opening {url} in the device browser", self.verbose)
        if not adb_manager.open_url(device, url):
            verbose_print("Could not launch the browser for the test request", self.verbose)
            return False
        return True

    def check_flow_captured(self) -> bool:
        """
        Purpose:
            Check whether the test request appears in the proxy's flow log.

        Returns:
            True when the test host was seen.

        Implementation notes:
            This is the actual proof that interception works. Everything before it can succeed while traffic still bypasses the proxy -- because the CA was not trusted, or the firewall dropped the connection, or the app pins certificates. A missing log reads as not captured rather than as an error, since it means the proxy never wrote anything.
        """
        if not self._flow_log_path or not os.path.exists(self._flow_log_path):
            verbose_print("Flow log not found", self.verbose)
            return False
        try:
            with open(self._flow_log_path) as f:
                flows = f.read()
            captured = _TEST_HOST in flows
            verbose_print(f"{_TEST_HOST} captured: {captured}", self.verbose)
            return captured
        except Exception as exc:
            verbose_print(f"Error reading flow log: {exc}", self.verbose)
            return False

    def run_https_check(self, adb_manager, device: str) -> Tuple[bool, str]:
        """
        Purpose:
            Run the full interception check: firewall, CA, proxy, device configuration and a real request.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            A success flag and a message describing the outcome.

        Side effects:
            Everything the individual steps do: starts a proxy, installs a CA, reconfigures the device.

        Implementation notes:
            The firewall and CA steps are advisory -- a failure is traced and the check continues -- because either can already be satisfied in ways this code cannot see, and the end-to-end test is what actually decides. Only a missing mitmproxy fails fast, since without it nothing else can be attempted.

        Security considerations:
            A successful run leaves the device with a trusted interception CA and a proxy setting; the caller is responsible for teardown.
        """
        verbose_print("Running HTTPS intercept check", self.verbose)
        if not self.is_mitmproxy_installed():
            return False, "mitmproxy is not installed."

        fw_ok, fw_msg = ensure_macos_firewall_exception(self.verbose)
        if not fw_ok:
            verbose_print(f"Firewall exception not granted: {fw_msg}", self.verbose)

        ca_ok, ca_msg = self.install_ca_cert(adb_manager, device)
        if not ca_ok:
            verbose_print(f"CA install failed: {ca_msg}", self.verbose)

        if not self.start_proxy():
            return False, "Failed to start mitmproxy on port 8080."
        try:
            if not self.configure_device_proxy(adb_manager, device):
                return False, "Failed to configure the device's proxy/reverse tunnel."
            time.sleep(0.3)
            self.make_test_request(adb_manager, device)
            deadline = time.time() + 6.0
            captured = False
            while time.time() < deadline:
                if self.check_flow_captured():
                    captured = True
                    break
                time.sleep(0.3)
            if captured:
                return True, f"HTTPS traffic decrypted and captured ({_TEST_HOST})."
            if not fw_ok:
                return False, f"No HTTPS traffic captured - {fw_msg}"
            if not ca_ok:
                return False, f"No HTTPS traffic captured - CA install failed: {ca_msg}"
            return False, ("No HTTPS traffic captured - the device may not be routing "
                           "traffic through the configured proxy (a known limitation "
                           "on some emulator network configurations).")
        except Exception as exc:
            verbose_print(f"HTTPS intercept check errored: {exc}", self.verbose)
            return False, f"HTTPS intercept check failed: {exc}"
        finally:
            try:
                self.clear_device_proxy(adb_manager, device)
            except Exception as exc:
                verbose_print(f"Failed to clear device proxy: {exc}", self.verbose)
            self.stop_proxy()
