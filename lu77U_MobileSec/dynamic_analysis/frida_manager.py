#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.frida_manager

Purpose:
    Get Frida onto a device and keep it usable: pick a server build matching the device and the installed bindings, fetch and verify it, deploy and start it, and run instrumentation scripts against the app under test.

Responsibilities:
    Version selection, download with checksum verification, caching, device-side lifecycle, port forwarding and script execution.

Dependencies:
    frida and frida-tools when installed, urllib, lzma, platformdirs.

Implementation notes:
    The server version must match the client bindings, so it is read from the installed frida package rather than fetched as the latest release. A newer server than the client refuses to connect, and defaulting to the latest would break the pipeline every time Frida publishes a release. Server binaries are cached per version and architecture, so repeated runs against the same device download nothing.

Security considerations:
    This module downloads an executable from the internet and runs it as root on a device. The archive's published checksum is fetched and verified before extraction; a mismatch discards the download. The checksum comes from the same origin as the binary, so this defends against corruption and tampering in transit rather than against a compromised release. Running frida-server as root gives complete control of the device, and the app under test is untrusted. This belongs only on a device dedicated to analysis.
"""

import hashlib
import lzma
import json
import re
import shutil
import subprocess
import time
import urllib.request
import zlib
from pathlib import Path
from typing import Optional, Tuple

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

import platformdirs

from .._metadata import NAME as APP_NAME
from ..utils.verbose import verbose_print

FRIDA_GITHUB_API = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_DEVICE_PORT = 27042
FRIDA_CACHE_DIR = Path(platformdirs.user_cache_dir(APP_NAME)) / "frida"


def _pinned_frida_version() -> str:
    """
    Purpose:
        Determine which frida-server version to deploy.

    Returns:
        The installed bindings' version, or a known-good fallback.

    Implementation notes:
        Read from the installed frida package so client and server always match. The version is pattern-checked before use, because it becomes part of a download URL and a filename. The fallback is a specific known-good release rather than the latest, so an environment without the bindings still gets a server that works with the tools.
    """
    try:
        import frida
        version = getattr(frida, "__version__", "") or ""
        if _VERSION_RE.match(version):
            return version
    except Exception:
        pass
    return "16.7.19"


FRIDA_SERVER_VERSION = _pinned_frida_version()


def _local_frida_port(device: str) -> int:
    """
    Purpose:
        Choose a stable local port for forwarding to a device's Frida server.

    Parameters:
        device: Device serial.

    Returns:
        A port in a fixed range, derived from the serial.

    Implementation notes:
        Derived from the serial rather than allocated, so two devices analysed concurrently get different ports while the same device always gets the same one -- which makes a stale forward reusable rather than a conflict.

    Known limitations:
        Two serials can hash to the same port. With a handful of attached devices this is unlikely, and the failure is a visible forward conflict rather than silent cross-talk.
    """
    return 28000 + (zlib.crc32(device.encode()) % 1000)


class FridaManager:
    """
    Purpose:
        Manages the Frida server lifecycle and runs instrumentation scripts.

    Attributes:
        verbose: Whether Frida activity is traced.

    Invariants:
        Every port forward this class creates is removed in a finally block, so a failed script does not leak forwards.

    Thread-safety:
        Not safe to share across threads targeting the same device; the device-side server is a single shared resource.

    Security considerations:
        Every method here either downloads code, runs it as root on a device, or injects into a running app.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the manager and ensure the binary cache directory exists.

        Parameters:
            verbose: Enables tracing.

        Side effects:
            Creates the cache directory.
        """
        self.verbose = verbose
        FRIDA_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        verbose_print(f"FridaManager initialized (cache: {FRIDA_CACHE_DIR})", self.verbose)

    def is_frida_tools_installed(self) -> bool:
        """
        Purpose:
            Check whether the frida-tools command-line utilities are available.

        Returns:
            True when frida-ps is on PATH.

        Implementation notes:
            Probed by looking for frida-ps specifically, since that is the tool used to verify the server is reachable. The Python bindings and the command-line tools are separate packages and either can be missing.
        """
        found = shutil.which("frida-ps") is not None
        verbose_print(f"frida-ps on PATH: {found}", self.verbose)
        return found

    def get_latest_frida_version(self) -> Optional[str]:
        """
        Purpose:
            Query the latest published Frida release.

        Returns:
            The version, or None when the query failed or returned an unexpected format.

        Side effects:
            Makes an HTTP request to the release API.

        Implementation notes:
            Not used to choose the deployed version -- that is pinned to the installed bindings -- but available for diagnostics and for reporting that a newer release exists. The returned tag is pattern-checked before being accepted, because a version string from a remote service would otherwise flow into a URL and a filename.

        Security considerations:
            Contacts an external service. The response is validated rather than trusted.
        """
        verbose_print(f"Fetching latest Frida version from {FRIDA_GITHUB_API}", self.verbose)
        try:
            req = urllib.request.Request(
                FRIDA_GITHUB_API, headers={"User-Agent": APP_NAME})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            tag = (data.get("tag_name") or "").lstrip("v")
            if not _VERSION_RE.match(tag):
                verbose_print(f"Frida tag_name has unexpected format: {tag!r}", self.verbose)
                return None
            verbose_print(f"Latest Frida version: {tag}", self.verbose)
            return tag
        except Exception as exc:
            verbose_print(f"Failed to fetch Frida version: {exc}", self.verbose)
            return None

    def build_download_url(self, version: str, frida_arch: str) -> str:
        """
        Purpose:
            Construct the release download URL for a server build.

        Parameters:
            version: Frida version, already validated.
            frida_arch: Frida's architecture name.

        Returns:
            The download URL.

        Security considerations:
            Both components are validated upstream -- the version against a pattern, the architecture through a fixed mapping -- so neither can inject a path into the URL.
        """
        filename = f"frida-server-{version}-android-{frida_arch}.xz"
        url = (f"https://github.com/frida/frida/releases/download/"
               f"{version}/{filename}")
        verbose_print(f"Frida download URL: {url}", self.verbose)
        return url

    def download_and_extract(self, version: str, frida_arch: str) -> Optional[str]:
        """
        Purpose:
            Fetch a frida-server build, verify it and extract it into the cache.

        Parameters:
            version: Frida version.
            frida_arch: Frida's architecture name.

        Returns:
            Path to the extracted binary, or None on failure.

        Side effects:
            Downloads two files, writes the binary into the cache and removes the archive.

        Implementation notes:
            A cached binary short-circuits before any network access. The compressed archive is removed after extraction, since only the binary is needed and the archives are large.

        Security considerations:
            The published checksum is fetched and compared before extraction, and a mismatch deletes the archive and fails. The verification is best-effort in one respect: if the checksum cannot be fetched at all, extraction proceeds with a trace rather than failing. That is a deliberate trade for environments where the checksum URL is unavailable, and it means a download that could not be verified can still be deployed.
        """
        binary_name = f"frida-server-{version}-android-{frida_arch}"
        binary_path = FRIDA_CACHE_DIR / binary_name
        archive_path = binary_path.with_suffix(".xz")

        if binary_path.exists():
            verbose_print(f"Frida binary cached: {binary_path}", self.verbose)
            return str(binary_path)

        url = self.build_download_url(version, frida_arch)
        checksum_url = url + ".sha256"
        verbose_print(f"Downloading Frida {version} ({frida_arch})", self.verbose)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except Exception as exc:
            verbose_print(f"Download failed: {exc}", self.verbose)
            return None

        try:
            req = urllib.request.Request(checksum_url, headers={"User-Agent": APP_NAME})
            with urllib.request.urlopen(req, timeout=15) as resp:
                expected_hash = resp.read().decode().split()[0].lower()
            actual_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                verbose_print(
                    f"SHA256 mismatch for Frida archive: expected {expected_hash}, got {actual_hash}",
                    self.verbose)
                archive_path.unlink(missing_ok=True)
                return None
            verbose_print("Frida archive SHA256 verified", self.verbose)
        except Exception as exc:
            verbose_print(f"Could not verify Frida checksum (proceeding): {exc}", self.verbose)

        verbose_print("Extracting XZ archive", self.verbose)
        try:
            with lzma.open(archive_path) as xz_file:
                data = xz_file.read()
            binary_path.write_bytes(data)
            archive_path.unlink(missing_ok=True)
            verbose_print(f"Extracted to: {binary_path}", self.verbose)
            return str(binary_path)
        except Exception as exc:
            verbose_print(f"Extraction failed: {exc}", self.verbose)
            return None

    def _find_cached_binary(self, frida_arch: str,
                            version: Optional[str] = None) -> Optional[Tuple[str, str]]:
        """
        Purpose:
            Locate a cached server binary for an architecture, optionally at a specific version.

        Parameters:
            frida_arch: Frida's architecture name.
            version: Exact version required, or None for the newest cached.

        Returns:
            The path and version, or None when nothing suitable is cached.

        Implementation notes:
            When no version is required, candidates are sorted by parsed version components rather than by string, so version ten sorts above version nine. Only names matching the version pattern are considered, so an unrelated file in the cache directory cannot be selected as a server binary.
        """
        prefix = "frida-server-"
        suffix = f"-android-{frida_arch}"
        if version is not None:
            path = FRIDA_CACHE_DIR / f"{prefix}{version}{suffix}"
            return (str(path), version) if path.is_file() else None
        candidates = []
        for p in FRIDA_CACHE_DIR.glob(f"{prefix}*{suffix}"):
            cached_version = p.name[len(prefix):-len(suffix)]
            if _VERSION_RE.match(cached_version):
                candidates.append((cached_version, p))
        if not candidates:
            return None
        candidates.sort(key=lambda vp: tuple(int(x) for x in vp[0].split(".")), reverse=True)
        found_version, path = candidates[0]
        return str(path), found_version

    def is_server_on_device(self, adb_manager, device: str) -> bool:
        """
        Purpose:
            Check whether the server binary is already present on the device.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            True when the binary exists at the expected path.
        """
        verbose_print(f"Checking frida-server on {device}", self.verbose)
        result = adb_manager.shell(device, f"test -f {FRIDA_REMOTE_PATH} && echo EXISTS")
        return "EXISTS" in result.stdout

    def push_server(self, adb_manager, device: str, local_binary: str) -> bool:
        """
        Purpose:
            Copy the server binary to the device and make it executable.

        Parameters:
            adb_manager: Device control.
            device: Device serial.
            local_binary: Path to the cached binary.

        Returns:
            True when both the copy and the permission change succeeded.

        Side effects:
            Writes an executable to the device.

        Security considerations:
            Places a binary that will run as root onto the device. Its integrity rests on the checksum verified at download time.
        """
        verbose_print(f"Pushing frida-server to {device}", self.verbose)
        if not adb_manager.push(device, local_binary, FRIDA_REMOTE_PATH):
            return False
        result = adb_manager.shell(device, f"chmod +x {FRIDA_REMOTE_PATH}")
        return result.returncode == 0

    def start_server(self, adb_manager, device: str) -> bool:
        """
        Purpose:
            Start the server on the device and wait briefly for it to come up.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            True when the server is running.

        Side effects:
            Starts a root process on the device.

        Implementation notes:
            Launched in the background under root, so the start command returns immediately rather than blocking. Readiness is then polled, because the process exists before it is listening and connecting in that window fails confusingly. The wait is short and is followed by one final check, so a server that comes up just after the deadline is still detected.
        """
        verbose_print(f"Starting frida-server on {device}", self.verbose)
        adb_manager.shell(
            device, f"su -c '{FRIDA_REMOTE_PATH} -D &'", timeout=5)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if self.is_server_running(adb_manager, device):
                return True
            time.sleep(0.2)
        return self.is_server_running(adb_manager, device)

    def stop_server(self, adb_manager, device: str) -> None:
        """
        Purpose:
            Kill any running server processes on the device.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Side effects:
            Kills processes on the device as root.

        Implementation notes:
            Processes are found by listing and filtering rather than by a stored process id, because the server may have been started by an earlier run or by the user. Each process id is parsed as an integer before use and a non-numeric field is skipped. That matters because the value goes into a device shell command; parsing it is what stops a crafted process name from becoming a command injection.
        """
        verbose_print(f"Stopping frida-server on {device}", self.verbose)
        result = adb_manager.shell(device, "ps | grep frida-server | grep -v grep")
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                pid_raw = parts[1]
                try:
                    pid = int(pid_raw)
                except ValueError:
                    verbose_print(f"Skipping non-numeric PID: {pid_raw!r}", self.verbose)
                    continue
                adb_manager.shell(device, f"su -c 'kill -9 {pid}'")
                verbose_print(f"Killed frida-server PID {pid}", self.verbose)

    def is_server_running(self, adb_manager, device: str) -> bool:
        """
        Purpose:
            Check whether the server process is running on the device.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            True when a server process is present.
        """
        result = adb_manager.shell(device, "ps | grep frida-server | grep -v grep")
        running = bool(result.stdout.strip())
        verbose_print(f"frida-server running: {running}", self.verbose)
        return running

    def verify_frida_ps(self, adb_manager, device: str) -> Tuple[bool, str]:
        """
        Purpose:
            Confirm the server is actually reachable by listing the device's processes through it.

        Parameters:
            adb_manager: Device control.
            device: Device serial.

        Returns:
            A success flag and the output or the failure reason.

        Side effects:
            Creates and removes a port forward, and spawns frida-ps.

        Implementation notes:
            A running process is not the same as a working server, so this performs a real operation through it rather than trusting the process listing. The forward is removed in a finally block, so a failed verification does not leave one behind to conflict with the next attempt.
        """
        local_port = _local_frida_port(device)
        try:
            fwd = adb_manager.run_adb(
                ["forward", f"tcp:{local_port}", f"tcp:{FRIDA_DEVICE_PORT}"],
                device=device, timeout=10)
            if fwd.returncode != 0:
                return False, f"adb forward failed: {fwd.stderr.strip()[:200]}"
        except Exception as exc:
            return False, f"adb forward failed: {exc}"

        try:
            cmd = ["frida-ps", "-H", f"127.0.0.1:{local_port}", "-a"]
            verbose_print(f"frida-ps: {' '.join(cmd)}", self.verbose)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                output = result.stdout.strip()
                ok = result.returncode == 0 and "PID" in output
                return ok, output
            except FileNotFoundError:
                return False, "frida-ps not found (frida-tools not installed)"
            except subprocess.TimeoutExpired:
                return False, "frida-ps timed out"
            except Exception as exc:
                return False, str(exc)
        finally:
            try:
                adb_manager.run_adb(["forward", "--remove", f"tcp:{local_port}"],
                                    device=device, timeout=10)
            except Exception:
                pass

    def run_script(self, adb_manager, device: str, package: str,
                   script_source: str, timeout: int = 20) -> Tuple[bool, str]:
        """
        Purpose:
            Run an instrumentation script inside the app under test and collect what it sends back.

        Parameters:
            adb_manager: Device control.
            device: Device serial.
            package: Package to instrument.
            script_source: The script to inject.
            timeout: Seconds to let the script run.

        Returns:
            A success flag and the collected output or the failure reason.

        Side effects:
            Creates a port forward, attaches to or spawns the app, injects and runs the script, then detaches and cleans up.

        Implementation notes:
            Attaching is tried first and spawning is the fallback, so an already-running app is instrumented in place and one that is not is started. A spawned process is resumed explicitly, since Frida spawns suspended. Messages are collected through a callback rather than returned by the script, which is how Frida's script channel works; errors are captured through the same channel and labelled. The run duration is clamped at both ends, so a caller cannot ask for an instant run that captures nothing or an unbounded one that hangs the pipeline. Output is truncated, because a hooking script on a busy app can emit a great deal. Cleanup -- detach, remote device removal, forward removal -- runs in a finally block with each step individually guarded, so a failure during teardown cannot mask the script's result.

        Security considerations:
            This injects code into a running untrusted app on a rooted device. The script source comes from this tool, not from the app, but the output it returns is attacker-influenced and must be treated as untrusted text.
        """
        try:
            import frida
        except ImportError:
            return False, "frida Python bindings are not available."

        if not self.is_server_running(adb_manager, device):
            return False, "frida-server is not running on the device."

        local_port = _local_frida_port(device)
        address = f"127.0.0.1:{local_port}"
        try:
            fwd = adb_manager.run_adb(
                ["forward", f"tcp:{local_port}", f"tcp:{FRIDA_DEVICE_PORT}"],
                device=device, timeout=10)
            if fwd.returncode != 0:
                return False, f"adb forward failed: {fwd.stderr.strip()[:200]}"
        except Exception as exc:
            return False, f"adb forward failed: {exc}"

        messages = []

        def _on_message(message, _data):
            """
            Purpose:
                Collect messages the injected script sends back.

            Parameters:
                message: The Frida message object.
                _data: Binary payload, unused.

            Side effects:
                Appends to the enclosing message list.

            Implementation notes:
                Errors are recorded rather than raised, so a script that fails partway still returns whatever it managed to emit. Everything is stringified, since payloads can be any JSON-compatible value.
            """
            mtype = message.get("type")
            if mtype == "send":
                messages.append(str(message.get("payload")))
            elif mtype == "error":
                messages.append("ERROR: " + str(message.get("description") or message))

        dev = None
        session = None
        try:
            mgr = frida.get_device_manager()
            try:
                dev = mgr.add_remote_device(address)
            except Exception:
                dev = mgr.get_device(f"socket@{address}") if hasattr(mgr, "get_device") else None
                if dev is None:
                    dev = mgr.add_remote_device(address)
            try:
                session = dev.attach(package)
            except Exception:
                pid = dev.spawn([package])
                session = dev.attach(pid)
                dev.resume(pid)
            script = session.create_script(script_source)
            script.on("message", _on_message)
            script.load()
            time.sleep(max(1, min(int(timeout), 60)))
            try:
                script.unload()
            except Exception:
                pass
            output = "\n".join(messages).strip() or "(script ran; no send() output emitted)"
            return True, output[:8000]
        except Exception as exc:
            return False, f"Frida script failed: {exc}"
        finally:
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass
            try:
                frida.get_device_manager().remove_remote_device(address)
            except Exception:
                pass
            try:
                adb_manager.run_adb(["forward", "--remove", f"tcp:{local_port}"],
                                    device=device, timeout=10)
            except Exception:
                pass

    def setup_and_verify(self, adb_manager, device: str,
                         has_root: bool) -> Tuple[bool, str]:
        """
        Purpose:
            Bring Frida fully online for a device: check prerequisites, deploy the right server, start it and confirm it works.

        Parameters:
            adb_manager: Device control.
            device: Device serial.
            has_root: Whether the device grants root.

        Returns:
            A success flag and a message describing the outcome.

        Side effects:
            May download a binary, and deploys and starts a root process on the device.

        Implementation notes:
            Prerequisites are checked in order of cost, so the cheap failures -- no root, no tools -- are reported before anything is downloaded. Any existing server is stopped before the new one is pushed, since a running process holds the binary and a version mismatch is otherwise hard to diagnose. The final verification is a real operation through the server, not a process check, and the success message reports how many processes were visible so the user can see it genuinely worked. An unsupported architecture names the ones that are supported, rather than failing opaquely.

        Security considerations:
            Root is required and is checked first. Everything this does afterwards runs with full device privileges.
        """
        verbose_print(f"Frida setup on {device}, root={has_root}", self.verbose)
        if not has_root:
            return False, "Root access is required for Frida."
        if not self.is_frida_tools_installed():
            return False, "frida-tools not available on PATH."

        abi = adb_manager.get_architecture(device)
        if not abi:
            return False, "Could not detect device CPU architecture."
        frida_arch = adb_manager.abi_to_frida_arch(abi)
        if not frida_arch:
            return False, (f"Unsupported architecture: {abi}. "
                           "Supported: arm64-v8a, armeabi-v7a, x86_64, x86.")
        verbose_print(f"ABI {abi} -> frida arch {frida_arch}", self.verbose)
        version = FRIDA_SERVER_VERSION
        cached = self._find_cached_binary(frida_arch, version=version)
        if cached:
            local_binary, _ = cached
            verbose_print(f"Using cached frida-server {version}", self.verbose)
        else:
            local_binary = self.download_and_extract(version, frida_arch)
            if not local_binary:
                return False, f"Failed to download/extract frida-server {version}-{frida_arch}."
        self.stop_server(adb_manager, device)

        if not self.push_server(adb_manager, device, local_binary):
            return False, "Failed to push frida-server to device."

        if not self.start_server(adb_manager, device):
            return False, "frida-server did not start."

        ok, output = self.verify_frida_ps(adb_manager, device)
        if ok:
            lines = [l for l in output.splitlines()
                     if l.strip() and not l.startswith("PID") and not l.startswith("---")]
            return True, f"Frida {version} running; {len(lines)} processes visible."
        return False, f"frida-server started but frida-ps failed: {output[:200]}"
