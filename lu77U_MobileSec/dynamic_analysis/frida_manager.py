"""Frida server lifecycle management for dynamic analysis."""

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

from ..utils.verbose import verbose_print

FRIDA_GITHUB_API = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_DEVICE_PORT = 27042
FRIDA_CACHE_DIR = Path(platformdirs.user_cache_dir("lu77U-MobileSec")) / "frida"


def _pinned_frida_version() -> str:
    """The frida-server version to run on the device.

    Must match the installed ``frida`` Python binding (the injected agent) — a
    server/agent version mismatch fails to connect. We deliberately do NOT track
    the newest GitHub release: the binding is pinned to the last Frida 16.x in
    pyproject.toml because 16.x ships the built-in ``Java`` global the
    verification hooks rely on (Frida 17 dropped it from raw create_script
    scripts). Deriving from the installed binding keeps the on-device server from
    ever drifting away from that pin.
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
    """Deterministic per-device local port for the ``adb forward`` tunnel.

    Using a device-derived port (rather than always 27042) means two
    concurrent sessions against different devices don't fight over the same
    host-side forward.
    """
    return 28000 + (zlib.crc32(device.encode()) % 1000)


class FridaManager:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        FRIDA_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        verbose_print(f"FridaManager initialized (cache: {FRIDA_CACHE_DIR})", self.verbose)

    def is_frida_tools_installed(self) -> bool:
        """Whether the host ``frida-ps`` CLI is importable/available."""
        found = shutil.which("frida-ps") is not None
        verbose_print(f"frida-ps on PATH: {found}", self.verbose)
        return found

    def get_latest_frida_version(self) -> Optional[str]:
        """Return the latest Frida release tag (e.g. ``17.15.3``) or None."""
        verbose_print(f"Fetching latest Frida version from {FRIDA_GITHUB_API}", self.verbose)
        try:
            req = urllib.request.Request(
                FRIDA_GITHUB_API, headers={"User-Agent": "lu77U-MobileSec"})
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
        filename = f"frida-server-{version}-android-{frida_arch}.xz"
        url = (f"https://github.com/frida/frida/releases/download/"
               f"{version}/{filename}")
        verbose_print(f"Frida download URL: {url}", self.verbose)
        return url

    def download_and_extract(self, version: str, frida_arch: str) -> Optional[str]:
        """Download + extract the server binary (cached). Returns its path or None."""
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

        # Verify SHA256 when the release provides a checksum file.
        try:
            req = urllib.request.Request(checksum_url, headers={"User-Agent": "lu77U-MobileSec"})
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
        """Return ``(local_path, version)`` for a cached frida-server binary
        matching this architecture, or None if none is cached.

        When ``version`` is given, only a binary of exactly that version is
        returned (so a stale, differently-versioned cache — e.g. a leftover 17.x
        server that would mismatch the pinned 16.x agent — is ignored rather than
        used just because it's newest). Without it, the newest cached binary
        wins.
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
        verbose_print(f"Checking frida-server on {device}", self.verbose)
        result = adb_manager.shell(device, f"test -f {FRIDA_REMOTE_PATH} && echo EXISTS")
        return "EXISTS" in result.stdout

    def push_server(self, adb_manager, device: str, local_binary: str) -> bool:
        """Push frida-server to the device and mark it executable."""
        verbose_print(f"Pushing frida-server to {device}", self.verbose)
        if not adb_manager.push(device, local_binary, FRIDA_REMOTE_PATH):
            return False
        result = adb_manager.shell(device, f"chmod +x {FRIDA_REMOTE_PATH}")
        return result.returncode == 0

    def start_server(self, adb_manager, device: str) -> bool:
        """Start frida-server in the background and confirm it is running."""
        verbose_print(f"Starting frida-server on {device}", self.verbose)
        # su -c so it runs as root; '&' backgrounds it inside the device shell.
        adb_manager.shell(
            device, f"su -c '{FRIDA_REMOTE_PATH} -D &'", timeout=5)
        # Poll instead of a blind sleep: frida-server usually binds well under
        # a second, so this returns as soon as it's actually up rather than
        # always paying the same fixed wait.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if self.is_server_running(adb_manager, device):
                return True
            time.sleep(0.2)
        return self.is_server_running(adb_manager, device)

    def stop_server(self, adb_manager, device: str) -> None:
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
        result = adb_manager.shell(device, "ps | grep frida-server | grep -v grep")
        running = bool(result.stdout.strip())
        verbose_print(f"frida-server running: {running}", self.verbose)
        return running

    def verify_frida_ps(self, adb_manager, device: str) -> Tuple[bool, str]:
        """Run host ``frida-ps`` against the device's frida-server.

        The device serial (e.g. ``127.0.0.1:6555`` for a TCP-connected
        emulator) is an *adb* endpoint, not the frida-server's own port — using
        it directly with ``-H`` connects to the wrong socket and frida-ps fails
        with "connection closed". Instead we ``adb forward`` a local port to
        the device's frida-server port (27042) and connect through that,
        which works uniformly for USB and TCP-connected devices.
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
        """Attach a Frida JS snippet to ``package`` and collect its ``send()`` output.

        Used by the dynamic-verification tool surface so the model can hook the
        target app to prove a static finding at runtime. Connects through the same
        ``adb forward`` tunnel :meth:`verify_frida_ps` uses (the device serial is
        an adb endpoint, not the frida-server port), attaches to the running app
        (spawning it if needed), loads the script, and gathers messages for a
        bounded window before detaching. Returns ``(ok, collected_output)``.

        Scope: the caller is responsible for ensuring ``package`` is the target
        app — the verification tool layer enforces that before calling here.
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
                # Already added from a previous run in this process — reuse it.
                dev = mgr.get_device(f"socket@{address}") if hasattr(mgr, "get_device") else None
                if dev is None:
                    dev = mgr.add_remote_device(address)
            try:
                session = dev.attach(package)
            except Exception:
                # App isn't running yet — spawn, attach, resume.
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
        """Full setup: arch → version → download → push → start → verify."""
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