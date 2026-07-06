"""mitmproxy setup and HTTPS-intercept verification for dynamic analysis."""

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

from ..utils.verbose import verbose_print

MITMPROXY_PORT = 8080
MITMPROXY_TEST_URL = "https://www.google.com/"
_TEST_HOST = urlparse(MITMPROXY_TEST_URL).netloc
_DEVICE_LOOPBACK = "127.0.0.1"

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

def _macos_firewall_allows(python_path: str, verbose: bool) -> Optional[bool]:
    """Return True/False if ``python_path`` has an explicit firewall allow
    rule, or None if the (unprivileged, read-only) check itself failed."""
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
        return False  # binary not listed at all -> no rule yet
    except Exception as exc:
        verbose_print(f"Could not read macOS firewall app list: {exc}", verbose)
        return None

def ensure_macos_firewall_exception(verbose: bool = False) -> Tuple[bool, str]:
    """Best-effort: let this interpreter accept incoming connections through
    the macOS Application Firewall.

    mitmproxy binds to all interfaces, but macOS's per-app firewall silently
    *drops* (no RST, no error) inbound connections from non-loopback sources —
    like an emulator's virtual network — to any binary without an explicit
    allow rule. That's indistinguishable from the network just not working:
    connections from the host itself (127.0.0.1) always bypass the firewall
    and succeed, so a health-check never catches it, and the device sees only
    a plain timeout. A no-op on non-macOS platforms or once the rule exists;
    never raises.
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
        os.chmod(script_path, 0o755)
        prompt = ("lu77U-MobileSec needs a one-time firewall exception so mitmproxy "
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
    """Locate mitmproxy's CA cert, auto-generated on its first run."""
    path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    return path if path.exists() else None

def _compute_android_cert_hash(cert_path: Path) -> Optional[str]:
    """Compute the legacy OpenSSL subject-hash Android's system cert store
    uses as a filename (``<hash>.0``). There's no pure-Python equivalent for
    this specific legacy algorithm, so this shells out to the near-universally
    available ``openssl`` CLI (mitmproxy itself sits on the same OpenSSL/
    cryptography stack under the hood).
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
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._proxy_process: Optional[subprocess.Popen] = None
        self._flow_log_path: Optional[str] = None
        verbose_print("MitmproxyManager initialized", self.verbose)

    def is_mitmproxy_installed(self) -> bool:
        found = shutil.which("mitmdump") is not None
        verbose_print(f"mitmdump on PATH: {found}", self.verbose)
        return found

    def _kill_stray_mitmdump(self) -> None:
        """Best-effort: clean up an orphaned mitmdump from an earlier run that
        crashed or was interrupted before its own ``stop_proxy()`` ran.

        Without this, ``start_proxy()``'s "is the port open" check can see a
        *stale* process still listening and report success without actually
        starting (or later being able to track/tear down) a fresh instance —
        correctness bug, not just wasted time, since a leftover process could
        be running stale addon logic from whenever it was originally started.
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
            except (ProcessLookupError, PermissionError):
                pass
        if pids:
            time.sleep(0.3)  # let the port actually free up before rebinding

    def start_proxy(self) -> bool:
        """Start ``mitmdump`` with a flow-logging addon. Returns True once listening."""
        verbose_print(f"Starting mitmproxy on port {MITMPROXY_PORT}", self.verbose)
        self._kill_stray_mitmdump()
        tmp = os.path.realpath(tempfile.gettempdir())
        log_path = os.path.join(tmp, "lu77u_mitmproxy_flows.txt")
        script_path = os.path.join(tmp, "lu77u_mitmaddon.py")
        # Guard: ensure both paths resolve inside the system temp directory.
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
        """Tunnel the device's own loopback port back to mitmproxy via ``adb
        reverse``, then point the device's global proxy at that loopback
        address. See the module docstring for why this replaced the
        ``10.0.2.2`` emulator-alias approach.
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
        verbose_print(f"Clearing device proxy on {device}", self.verbose)
        adb_manager.shell(device, "settings put global http_proxy :0")
        try:
            adb_manager.run_adb(["reverse", "--remove", f"tcp:{MITMPROXY_PORT}"],
                                device=device, timeout=10)
        except Exception as exc:
            verbose_print(f"Failed to remove adb reverse tunnel: {exc}", self.verbose)

    def is_ca_installed(self, adb_manager, device: str, cert_hash: str) -> bool:
        result = adb_manager.shell(
            device, f"test -f /system/etc/security/cacerts/{cert_hash}.0 && echo EXISTS",
            timeout=10)
        return "EXISTS" in result.stdout

    def install_ca_cert(self, adb_manager, device: str) -> Tuple[bool, str]:
        """Install mitmproxy's CA cert as a trusted *system* cert on the device.

        Requires root (uses ``su`` to remount ``/`` read-write and copy into
        ``/system/etc/security/cacerts/``). Without this, every HTTPS request
        through the proxy fails the TLS handshake since the device won't trust
        mitmproxy's certificate — an "interception" check with no cert trust
        step would only ever prove network reachability, not real interception.
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
        url = f"{MITMPROXY_TEST_URL}?probe={uuid.uuid4().hex[:8]}"
        verbose_print(f"Opening {url} in the device browser", self.verbose)
        if not adb_manager.open_url(device, url):
            verbose_print("Could not launch the browser for the test request", self.verbose)
            return False
        return True

    def check_flow_captured(self) -> bool:
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
        """Ensure firewall access → install CA → start proxy → configure device
        → open HTTPS page → verify."""
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
            time.sleep(0.3)  # brief margin for the settings change to apply
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
                return False, f"No HTTPS traffic captured — {fw_msg}"
            if not ca_ok:
                return False, f"No HTTPS traffic captured — CA install failed: {ca_msg}"
            return False, ("No HTTPS traffic captured — the device may not be routing "
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