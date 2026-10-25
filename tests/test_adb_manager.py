#!/usr/bin/env python3
"""
Module: test_adb_manager

Purpose:
    Installing an APK against a device package verifier, and the automatic retry that clears it.

Responsibilities:
    Pin which failures are retried, that verification is disabled only for the retry, and that the prior settings are always restored.

Dependencies:
    pytest, subprocess, and the device manager.

Implementation notes:
    A real run hit a verification failure on the install, the same block a person clears by hand on the device, which silently skipped dynamic verification for every finding. The identical APK installed fine seconds later in the next phase. These pin the automatic retry.

Security considerations:
    The retry disables the device's package verification, which is a real weakening of the device. Restoration is asserted on both the success and failure paths, because leaving it off would affect every future install on that device rather than just this one.
"""

import subprocess

import pytest

from lu77U_MobileSec.dynamic_analysis.adb_manager import ADBManager

DEVICE = "127.0.0.1:6555"


class FakeCompleted:
    """
    Purpose:
        Stand in for a completed subprocess result.

    Attributes:
        returncode: The process exit status.
        stdout: Captured standard output.
        stderr: Captured standard error.
    """
    def __init__(self, returncode=0, stdout="", stderr=""):
        """
        Purpose:
            Record the fake process outcome.

        Parameters:
            returncode: The exit status.
            stdout: Standard output text.
            stderr: Standard error text.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeAdb:
    """
    Purpose:
        Script device responses by command shape and record every call made.

    Attributes:
        calls: Every argument vector the code under test ran.
        install_results: Queued install outcomes, each a result or an exception to raise, consumed in order.
        settings: The device's verification settings, mutated as the code changes them.
        shell_outputs: Standard output for device shell commands, keyed by the start of the command.

    Implementation notes:
        The settings are modelled as real mutable state rather than asserted call-by-call, which is what lets the tests prove the values were genuinely restored rather than merely that some restore command was issued.
    """
    def __init__(self):
        """
        Purpose:
            Start with the verification settings in their enabled, default state.
        """
        self.calls = []
        self.install_results = []
        self.settings = {
            "verifier_verify_adb_installs": "1",
            "package_verifier_enable": "1",
            "package_verifier_user_consent": "1",
            "upload_apk_enable": "1",
        }
        self.shell_outputs = {}

    def run(self, cmd, capture_output_unused, text_unused, timeout_unused):
        """
        Purpose:
            Answer one device command, recording it and updating the fake settings.

        Parameters:
            cmd: The argument vector.
            capture_output_unused: Accepted to match the real signature; unused.
            text_unused: Accepted to match the real signature; unused.
            timeout_unused: Accepted to match the real signature; unused.

        Returns:
            The scripted result for this command shape.
        """
        self.calls.append(list(cmd))
        if "install" in cmd:
            if self.install_results:
                result = self.install_results.pop(0)
                if isinstance(result, Exception):
                    raise result
                return result
            return FakeCompleted(0, "Success", "")
        if "settings" in cmd:
            if "get" in cmd:
                key = cmd[-1]
                return FakeCompleted(0, self.settings.get(key, ""), "")
            if "put" in cmd:
                key, value = cmd[-2], cmd[-1]
                self.settings[key] = value
                return FakeCompleted(0, "", "")
            if "delete" in cmd:
                key = cmd[-1]
                self.settings.pop(key, None)
                return FakeCompleted(0, "", "")
        if "shell" in cmd:
            for prefix, output in self.shell_outputs.items():
                if cmd[-1].startswith(prefix):
                    return FakeCompleted(0, output, "")
        return FakeCompleted(0, "", "")


@pytest.fixture
def fake_adb(monkeypatch):
    """
    Purpose:
        Install the fake device in place of the real subprocess call.

    Parameters:
        monkeypatch: Replaces the subprocess entry point.

    Returns:
        The fake, so tests can inspect its calls and settings.
    """
    fake = FakeAdb()
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, capture_output, text, timeout: fake.run(cmd, capture_output, text, timeout))
    return fake


def _install_calls(fake):
    """
    Purpose:
        Select the install commands from everything the fake recorded.

    Parameters:
        fake: The fake device.

    Returns:
        The install argument vectors.
    """
    return [c for c in fake.calls if "install" in c]


def _settings_calls(fake):
    """
    Purpose:
        Select the settings commands from everything the fake recorded.

    Parameters:
        fake: The fake device.

    Returns:
        The settings argument vectors.
    """
    return [c for c in fake.calls if "settings" in c]


class TestOrdinaryInstall:
    """
    Purpose:
        Installs that need no verifier intervention.
    """
    def test_a_plain_success_never_touches_settings(self, fake_adb):
        """
        Purpose:
            Pin that a successful install leaves the device's verification settings alone entirely.

        Parameters:
            fake_adb: The fake device.

        Security considerations:
            This is the important negative: verification must only ever be touched on the specific failure that needs it, never as a matter of course.
        """
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert (ok, message) == (True, "Success")
        assert len(_install_calls(fake_adb)) == 1
        assert _settings_calls(fake_adb) == []

    def test_install_still_grants_runtime_perms_and_allows_test_only(self, fake_adb):
        """
        Purpose:
            Pin that the install grants runtime permissions and permits a test build.

        Parameters:
            fake_adb: The fake device.

        Implementation notes:
            Granting permissions up front matters because the dynamic run cannot answer permission dialogs, and an app blocked on one exercises none of its real behaviour.
        """
        ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        install_cmd = _install_calls(fake_adb)[0]
        assert "-r" in install_cmd and "-g" in install_cmd and "-t" in install_cmd

    def test_a_non_verifier_failure_is_not_retried(self, fake_adb):
        """
        Purpose:
            Pin that a failure unrelated to verification is reported as-is, with no settings change and no retry.

        Parameters:
            fake_adb: The fake device.

        Implementation notes:
            A settings toggle cannot fix a bad signature or a full disk, so retrying would weaken the device for nothing and hide the real reason.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]")]
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert ok is False
        assert "INSUFFICIENT_STORAGE" in message
        assert len(_install_calls(fake_adb)) == 1
        assert _settings_calls(fake_adb) == []


def test_an_apk_for_another_abi_is_not_sent(fake_adb, tmp_path):
    """
    Purpose:
        Pin that an APK whose native code targets none of the device's ABIs is refused with that reason before any install, and that an overlapping ABI installs as usual.

    Parameters:
        fake_adb: The fake device, reporting an arm64-only ABI list.
        tmp_path: Directory for the APK.

    Implementation notes:
        An APK pulled from an x86_64 emulator was sent to an arm64 one and failed with adb's bare INSTALL_FAILED_NO_MATCHING_ABIS.
    """
    import zipfile
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/x86_64/libapp.so", b"x")
    fake_adb.shell_outputs = {"ro.product.cpu.abilist": "arm64-v8a"}
    ok, message = ADBManager().install_apk(DEVICE, str(apk))
    assert ok is False
    assert "x86_64" in message and "arm64-v8a" in message
    assert _install_calls(fake_adb) == []
    fake_adb.shell_outputs = {"ro.product.cpu.abilist": "x86_64,x86"}
    assert ADBManager().install_apk(DEVICE, str(apk)) == (True, "Success")


class TestVerifierBlockedInstall:
    """
    Purpose:
        Installs blocked by the device package verifier.
    """
    def test_a_verifier_failure_is_retried_with_verification_disabled(self, fake_adb):
        """
        Purpose:
            Pin that a verification failure triggers exactly one retry, which succeeds.

        Parameters:
            fake_adb: The fake device.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "Performing Streamed Install",
                          "Failure [INSTALL_FAILED_VERIFICATION_FAILURE]")]
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert (ok, message) == (True, "Success")
        assert len(_install_calls(fake_adb)) == 2

    def test_a_copy_signed_with_another_key_is_replaced(self, fake_adb):
        """
        Purpose:
            Pin that an install refused because the installed copy has another signing key uninstalls that copy and installs once more, and that this needs a valid package name.

        Parameters:
            fake_adb: The fake device.
        """
        refused = FakeCompleted(1, "Performing Streamed Install",
                                "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package a.b signatures do not match]")
        fake_adb.install_results = [refused]
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk", package="a.b")
        assert ok and "different key" in message
        assert ["uninstall", "a.b"] == [c for c in fake_adb.calls if "uninstall" in c][0][-2:]
        fake_adb.install_results = [refused]
        fake_adb.calls.clear()
        ok, _ = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert not ok and not [c for c in fake_adb.calls if "uninstall" in c]

    def test_an_install_that_hangs_is_retried_with_verification_disabled(self, fake_adb):
        """
        Purpose:
            Pin that an install which timed out, as one waiting on the verifier's consent dialog does, is retried once with verification disabled.

        Parameters:
            fake_adb: The fake device.
        """
        fake_adb.install_results = [subprocess.TimeoutExpired(["adb", "install"], 180)]
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert (ok, message) == (True, "Success")
        assert len(_install_calls(fake_adb)) == 2
        assert any(c[-1] in ("0", "-1") for c in fake_adb.calls if "put" in c)

    def test_the_verifier_is_disabled_before_the_retry_install(self, fake_adb):
        """
        Purpose:
            Pin that the bypass values are written before the retry is attempted.

        Parameters:
            fake_adb: The fake device.

        Implementation notes:
            Both disabling and restoring are writes, so this asserts only that a bypass value was written at some point, not that every write in the sequence was one. The restoration is pinned separately by comparing the final state.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_VERIFICATION_FAILURE]")]
        adb = ADBManager()
        adb.install_apk(DEVICE, "/tmp/app.apk")
        put_calls = [c for c in fake_adb.calls if "put" in c]
        assert any(c[-1] in ("0", "-1") for c in put_calls)

    def test_settings_are_restored_after_a_successful_retry(self, fake_adb):
        """
        Purpose:
            Pin that every verification setting is back to its original value after a successful retry.

        Parameters:
            fake_adb: The fake device.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_VERIFICATION_FAILURE]")]
        original = dict(fake_adb.settings)
        ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert fake_adb.settings == original

    def test_settings_are_restored_even_when_the_retry_also_fails(self, fake_adb):
        """
        Purpose:
            Pin that the settings are restored even when the retry fails too, and that the failure names the verifier.

        Parameters:
            fake_adb: The fake device.

        Security considerations:
            This is the case that would otherwise leave a device permanently unprotected: the operation failed, so nothing looks successful, and without restoration in a finally block the bypass would simply stay.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_VERIFICATION_FAILURE]"),
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_VERIFICATION_FAILURE]"),
        ]
        original = dict(fake_adb.settings)
        ok, message = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert ok is False
        assert "package verifier" in message.lower()
        assert fake_adb.settings == original

    def test_a_verification_timeout_is_also_retried(self, fake_adb):
        """
        Purpose:
            Pin that a verification timeout is treated as a verifier block and retried.

        Parameters:
            fake_adb: The fake device.

        Implementation notes:
            The timeout is the same block arriving differently: the device could not reach the verification service, and the install is refused for the same reason.
        """
        fake_adb.install_results = [
            FakeCompleted(1, "", "Failure [INSTALL_FAILED_VERIFICATION_TIMEOUT]")]
        ok, _ = ADBManager().install_apk(DEVICE, "/tmp/app.apk")
        assert ok is True
        assert len(_install_calls(fake_adb)) == 2


PACKAGE = "com.demo.vault"
INSTALLED_PATH = "/data/app/~~dB6k8IVjQrt4KMgs==/com.demo.vault-5gPKSg4Rd91UUp==/base.apk"


class TestReuseInstalledCopy:
    """
    Purpose:
        Installing only when the device does not already hold this exact build.
    """

    @pytest.fixture
    def local_apk(self, tmp_path, monkeypatch):
        """
        Purpose:
            Write a local APK stand-in and fix the version its manifest reports.

        Parameters:
            tmp_path: Directory the file is written into.
            monkeypatch: Replaces the manifest reader.

        Returns:
            The file's path and SHA-256.
        """
        import hashlib
        from lu77U_MobileSec.dynamic_analysis import adb_manager
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"demo apk bytes")
        monkeypatch.setattr(adb_manager, "local_apk_version", lambda unused_path: ("7", "1.4.0"))
        return str(apk), hashlib.sha256(b"demo apk bytes").hexdigest()

    def _device(self, fake_adb, *, paths=(INSTALLED_PATH,), code="7", name="1.4.0", sha=None):
        """
        Purpose:
            Script what the device reports about the installed package.

        Parameters:
            fake_adb: The fake device.
            paths: Installed APK paths; empty when the package is absent.
            code: The installed versionCode.
            name: The installed versionName.
            sha: The installed base.apk's SHA-256, or None when sha256sum gives nothing.
        """
        fake_adb.shell_outputs = {
            f"pm path {PACKAGE}": "".join(f"package:{p}\n" for p in paths),
            f"dumpsys package {PACKAGE}": f"    versionCode={code} minSdk=21 targetSdk=34\n    versionName={name}\n",
            "sha256sum ": f"{sha}  {INSTALLED_PATH}\n" if sha else "",
        }

    def test_the_same_build_is_not_reinstalled(self, fake_adb, local_apk):
        """
        Purpose:
            Pin that an installed copy with the same version and hash is reused.

        Parameters:
            fake_adb: The fake device.
            local_apk: The local APK and its hash.
        """
        path, sha = local_apk
        self._device(fake_adb, sha=sha)
        ok, message = ADBManager().install_apk(DEVICE, path, package=PACKAGE)
        assert ok and message.startswith("Already installed")
        assert _install_calls(fake_adb) == []

    @pytest.mark.parametrize("device", [
        {"paths": ()},
        {"code": "6"},
        {"name": "1.3.9"},
        {"sha": "0" * 64},
        {"sha": None},
        {"paths": (INSTALLED_PATH, "/data/app/x/split_config.arm64_v8a.apk")},
        {"paths": ("/data/app/bad path; reboot/base.apk",)},
    ])
    def test_anything_else_is_installed(self, fake_adb, local_apk, device):
        """
        Purpose:
            Pin that a missing package, another version, a different build, an unprovable hash, a split install or an unusable path all lead to an install.

        Parameters:
            fake_adb: The fake device.
            local_apk: The local APK and its hash.
            device: What the device reports, overriding a matching installed copy.
        """
        path, sha = local_apk
        self._device(fake_adb, **{"sha": sha, **device})
        ok, _ = ADBManager().install_apk(DEVICE, path, package=PACKAGE)
        assert ok and len(_install_calls(fake_adb)) == 1
        assert not any("sha256sum /data/app/bad" in c[-1] for c in fake_adb.calls)

    def test_without_a_package_name_it_installs_directly(self, fake_adb, local_apk):
        """
        Purpose:
            Pin that a caller that does not name the package gets a plain install and no device queries.

        Parameters:
            fake_adb: The fake device.
            local_apk: The local APK and its hash.
        """
        path, _sha = local_apk
        ADBManager().install_apk(DEVICE, path)
        assert len(_install_calls(fake_adb)) == 1
        assert not [c for c in fake_adb.calls if "shell" in c]
