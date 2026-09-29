#!/usr/bin/env python3
"""
Module: test_web_dynamic_failure_paths

Purpose:
    The failure paths in the dashboard and the dynamic-analysis layer that used to vanish silently, and the teardown guards that must keep swallowing what they swallow.

Responsibilities:
    Pin that each failure that now produces a log line does produce it, that the cases deliberately left quiet stay quiet, that cancellation and interpreter stops still propagate, and that the macOS firewall helper script is created owner-only.

Dependencies:
    pytest, the web application, job manager, checkpoint, routes and services, and the Frida and mitmproxy managers, with fakes standing in for the device, the frida bindings, subprocess and the event loop.

Implementation notes:
    Each logging assertion patches the verbose_print name the module under test actually calls, so the check is on what that module reported rather than on whatever the shared sinks happen to be doing.

Security considerations:
    Nothing here touches the real system, network or a device. Process signalling, osascript, chmod, adb and the frida bindings are all replaced before the code under test runs, and every file written lands under the test's own temporary directory.
"""

import asyncio
import sys
import threading
import types

import pytest

from lu77U_MobileSec.ai import provider_factory
from lu77U_MobileSec.ai.registry import CURATED_MODELS
from lu77U_MobileSec.dynamic_analysis import dynamic_analyzer as dyn_mod
from lu77U_MobileSec.dynamic_analysis import frida_manager as fm_mod
from lu77U_MobileSec.dynamic_analysis import mitmproxy_manager as mitm_mod
from lu77U_MobileSec.utils.cancellation import ScanCancelled
from lu77U_MobileSec.web import app as app_mod
from lu77U_MobileSec.web import checkpoint as ckpt_mod
from lu77U_MobileSec.web import jobs as jobs_mod
from lu77U_MobileSec.web.routes import dynamic as dyn_route
from lu77U_MobileSec.web.services import analysis_service as as_mod
from lu77U_MobileSec.web.services import settings_service as ss_mod


def capture_logs(monkeypatch, module):
    """
    Purpose:
        Replace a module's verbose_print with a recorder and hand back what it records.

    Parameters:
        monkeypatch: Swaps the function for the duration of the test.
        module: The module whose verbose_print is replaced.

    Returns:
        The list the recorder appends each message to.
    """
    logged = []
    monkeypatch.setattr(module, "verbose_print",
                        lambda message, _=False: logged.append(message))
    return logged


class TestOrphanedMitmdump:
    """
    Purpose:
        Killing a mitmdump left holding the proxy port by an earlier run.
    """
    def test_permission_error_is_logged_and_a_vanished_process_is_skipped(self, monkeypatch):
        """
        Purpose:
            Pin that a process this user may not signal is reported, while one that has already exited is skipped without a word.

        Parameters:
            monkeypatch: Replaces pgrep, os.kill, the pause and the logger.

        Implementation notes:
            Both errors used to be swallowed together, so a mitmdump owned by another account kept the port and the next start failed with a bind error that looked like a configuration problem.
        """
        logged = capture_logs(monkeypatch, mitm_mod)
        signalled = []

        def _kill(pid, _):
            """
            Purpose:
                Stand in for os.kill: the first process has gone, the second belongs to someone else.

            Parameters:
                pid: The process id being signalled.
                _: The signal being sent, ignored.

            Raises:
                ProcessLookupError: For process 111.
                PermissionError: For process 222.
            """
            signalled.append(pid)
            if pid == 111:
                raise ProcessLookupError(pid)
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(mitm_mod.subprocess, "run",
                            lambda *_, **__: types.SimpleNamespace(stdout="111\n222\n"))
        monkeypatch.setattr(mitm_mod.os, "kill", _kill)
        monkeypatch.setattr(mitm_mod.time, "sleep", lambda _: None)

        mitm_mod.MitmproxyManager(verbose=False)._kill_stray_mitmdump()

        assert signalled == [111, 222]
        assert any(m.startswith("Could not kill orphaned mitmdump process 222:") for m in logged)
        assert not any("111" in m for m in logged)


class TestFirewallHelperScript:
    """
    Purpose:
        The temporary script run as root to add the macOS firewall exception.
    """
    def test_the_script_is_owner_only(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that the helper script is chmodded to 0o700, is handed to osascript, and is removed afterwards.

        Parameters:
            monkeypatch: Replaces the platform check, the firewall probe, the temporary directory, chmod and subprocess.
            tmp_path: Where the helper script is written instead of the system temporary directory.

        Security considerations:
            The script used to be made world-readable and world-executable. osascript runs it as root, which needs only the owner's execute bit, so nobody else on the machine has a reason to read or run it.
        """
        modes = []
        commands = []

        def _run(argv, **_):
            """
            Purpose:
                Stand in for subprocess.run and report the elevation as granted.

            Parameters:
                argv: The command that would have been run.
                _: The subprocess options, ignored.

            Returns:
                A successful completed-process shape.
            """
            commands.append(list(argv))
            return types.SimpleNamespace(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(mitm_mod.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(mitm_mod, "_macos_firewall_allows", lambda _, __: False)
        monkeypatch.setattr(mitm_mod.tempfile, "gettempdir", lambda: str(tmp_path))
        monkeypatch.setattr(mitm_mod.os, "chmod", lambda _, mode: modes.append(mode))
        monkeypatch.setattr(mitm_mod.subprocess, "run", _run)

        outcome = mitm_mod.ensure_macos_firewall_exception(verbose=False)

        assert outcome == (True, "Firewall exception added.")
        assert modes == [0o700]
        assert [argv[0] for argv in commands] == ["osascript"]
        assert list(tmp_path.iterdir()) == []


class FakeJobs:
    """
    Purpose:
        A job manager stand-in for the application lifespan, whose startup reconciliation and quota resumes can be made to fail.

    Attributes:
        verbose: Whether the manager traces.
        loop: The event loop bound at startup.
        reconcile_error: Raised by the startup reconciliation, when set.
        resume_attempts: How many times the quota-resume loop asked for a resume.
        cancelled_all: Whether shutdown cancelled the active scans.
    """
    def __init__(self, reconcile_error=None):
        """
        Purpose:
            Build the stand-in.

        Parameters:
            reconcile_error: The exception startup reconciliation raises, or None to succeed.
        """
        self.verbose = False
        self.loop = None
        self.reconcile_error = reconcile_error
        self.resume_attempts = 0
        self.cancelled_all = False

    def bind_loop(self, loop):
        """
        Purpose:
            Accept the running loop, as the real manager does at startup.

        Parameters:
            loop: The running event loop.
        """
        self.loop = loop

    def reconcile_orphans(self):
        """
        Purpose:
            Stand in for marking scans interrupted by the last shutdown.

        Raises:
            Exception: Whatever reconcile_error holds, when it is set.
        """
        if self.reconcile_error is not None:
            raise self.reconcile_error

    def auto_resume_interrupted(self):
        """
        Purpose:
            Stand in for resuming interrupted scans; does nothing.
        """

    def resume_expired_quota_pauses(self):
        """
        Purpose:
            Count a quota-resume attempt, failing the first one.

        Raises:
            RuntimeError: On the first attempt only.
        """
        self.resume_attempts += 1
        if self.resume_attempts == 1:
            raise RuntimeError("store unavailable")

    def cancel_all_active(self):
        """
        Purpose:
            Record that shutdown cancelled the active scans.
        """
        self.cancelled_all = True

    def emit_log(self, _, __):
        """
        Purpose:
            Accept a log line routed through the application's sink; unused here.

        Parameters:
            _: The scan the line belongs to, ignored.
            __: The log line, ignored.
        """


def run_lifespan(jobs, body=None):
    """
    Purpose:
        Drive the application lifespan from startup to shutdown around an optional body, with a timeout so a stuck shutdown fails instead of hanging.

    Parameters:
        jobs: The job manager stand-in attached to the application state.
        body: An optional coroutine function run while the application is up.
    """
    application = types.SimpleNamespace(state=types.SimpleNamespace(jobs=jobs))

    async def _drive():
        """
        Purpose:
            Enter and leave the lifespan, running the body in between.
        """
        async with app_mod._lifespan(application):
            if body is not None:
                await body()

    asyncio.run(asyncio.wait_for(_drive(), timeout=5))


class TestApplicationLifespan:
    """
    Purpose:
        Startup and shutdown of the dashboard application.
    """
    def test_a_failing_startup_reconcile_is_logged(self, monkeypatch):
        """
        Purpose:
            Pin that a failed reconciliation of interrupted scans is logged and the application still starts and shuts down.

        Parameters:
            monkeypatch: Replaces the verbose logger the application calls.

        Implementation notes:
            The failure used to be swallowed, leaving scans shown as running forever with nothing in any log to say why.
        """
        logged = capture_logs(monkeypatch, app_mod.verbose_mod)
        jobs = FakeJobs(reconcile_error=RuntimeError("scan store unreadable"))

        run_lifespan(jobs)

        assert "Startup reconciliation of interrupted scans failed: scan store unreadable" in logged
        assert jobs.cancelled_all

    def test_the_quota_loop_survives_a_failure_and_still_stops(self, monkeypatch):
        """
        Purpose:
            Pin that one failed quota resume does not end the loop, and that shutdown still cancels it.

        Parameters:
            monkeypatch: Shortens the resume interval and replaces the verbose logger.

        Implementation notes:
            The loop suppresses Exception only. Cancellation is a BaseException and must pass through, or shutdown would wait on the task forever; the timeout in run_lifespan turns that into a failure here.
        """
        capture_logs(monkeypatch, app_mod.verbose_mod)
        monkeypatch.setattr(app_mod, "_QUOTA_RESUME_CHECK_INTERVAL_S", 0)
        jobs = FakeJobs()

        async def _wait_for_two_attempts():
            """
            Purpose:
                Yield to the loop until the quota task has tried to resume twice.
            """
            for _ in range(200):
                if jobs.resume_attempts >= 2:
                    return
                await asyncio.sleep(0)

        run_lifespan(jobs, _wait_for_two_attempts)

        assert jobs.resume_attempts >= 2
        assert jobs.cancelled_all


class TestCheckpointWrites:
    """
    Purpose:
        Persisting and clearing a scan's resume state.
    """
    def test_a_failing_write_is_logged(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a checkpoint that cannot be written is reported rather than lost silently, and that the scan is not interrupted.

        Parameters:
            monkeypatch: Replaces the verbose logger.
            tmp_path: Holds a plain file standing where the checkpoint directory should be.
        """
        logged = capture_logs(monkeypatch, ckpt_mod)
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")

        ckpt_mod._write_json(blocker / "stage.json", {"stage": "decompiled"})

        assert len(logged) == 1
        assert logged[0].startswith("Checkpoint could not be written to stage.json: ")

    def test_a_successful_write_is_silent_and_reads_back(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a normal write logs nothing and round-trips.

        Parameters:
            monkeypatch: Replaces the verbose logger.
            tmp_path: The checkpoint directory's parent.
        """
        logged = capture_logs(monkeypatch, ckpt_mod)
        target = tmp_path / "checkpoint" / "stage.json"

        ckpt_mod._write_json(target, {"stage": "sast_done"})

        assert logged == []
        assert ckpt_mod._read_json(target) == {"stage": "sast_done"}

    def test_clear_removes_the_directory(self, tmp_path):
        """
        Purpose:
            Pin that clearing a checkpoint removes its whole directory.

        Parameters:
            tmp_path: Holds the checkpoint directory.
        """
        directory = tmp_path / "checkpoint"
        (directory / "regions").mkdir(parents=True)
        (directory / "stage.json").write_text("{}", encoding="utf-8")

        ckpt_mod.ScanCheckpoint("scan-1", directory, {}, resume=False).clear()

        assert not directory.exists()


class FlakyLoop:
    """
    Purpose:
        An event loop stand-in whose first cross-thread handoff fails, as a closed loop's does.

    Attributes:
        calls: How many handoffs were attempted.
        delivered: How many handoffs went through.
    """
    def __init__(self):
        """
        Purpose:
            Start with nothing attempted.
        """
        self.calls = 0
        self.delivered = 0

    def call_soon_threadsafe(self, _, *__):
        """
        Purpose:
            Fail the first handoff and count the rest as delivered.

        Parameters:
            _: The callable that would have been scheduled, ignored.
            __: Its arguments, ignored.

        Raises:
            RuntimeError: On the first call only.
        """
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("Event loop is closed")
        self.delivered += 1


class TestEventDelivery:
    """
    Purpose:
        Delivering a scan's events to its dashboard subscribers.
    """
    def test_one_failing_subscriber_neither_stops_the_rest_nor_logs(self, monkeypatch):
        """
        Purpose:
            Pin that a failed handoff to one subscriber is suppressed, the others still receive the event, it stays in the backlog, and nothing is logged.

        Parameters:
            monkeypatch: Replaces the verbose logger.

        Implementation notes:
            This runs on the log-sink path, so logging a delivery failure here would re-enter the same delivery. The assertion that nothing was logged is what holds that line.
        """
        logged = capture_logs(monkeypatch, jobs_mod)
        manager = jobs_mod.JobManager(verbose=False)
        loop = FlakyLoop()
        manager.subscribe("scan-1")
        manager.subscribe("scan-1")
        manager.bind_loop(loop)

        manager.emit_log("scan-1", "hello")

        assert loop.calls == 2
        assert loop.delivered == 1
        assert logged == []
        late = manager.subscribe("scan-1")
        assert late.get_nowait()["message"] == "hello"


class FakeDeviceBridge:
    """
    Purpose:
        A device bridge that reports root.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Build the bridge.

        Parameters:
            verbose: Ignored.
        """

    def check_root(self, _):
        """
        Purpose:
            Report root access.

        Parameters:
            _: The device serial, ignored.

        Returns:
            Always True.
        """
        return True


class FakeFrida:
    """
    Purpose:
        An instrumentation manager whose readiness check passes and whose stop can be made to fail.

    Attributes:
        stop_error: Raised by stop_server, when set.
    """
    stop_error = None

    def __init__(self, verbose=False):
        """
        Purpose:
            Build the manager.

        Parameters:
            verbose: Ignored.
        """

    def setup_and_verify(self, *_):
        """
        Purpose:
            Report a working server.

        Parameters:
            _: The positional arguments the real manager takes (the device bridge, the device serial and whether root is available), ignored.

        Returns:
            A success flag and message.
        """
        return True, "frida-server is running."

    def stop_server(self, *_):
        """
        Purpose:
            Stop the server, or fail to.

        Parameters:
            _: The positional arguments the real manager takes (the device bridge and the device serial), ignored.

        Raises:
            Exception: Whatever stop_error holds, when it is set.
        """
        if self.stop_error is not None:
            raise self.stop_error


class FakeInterception:
    """
    Purpose:
        An interception manager whose HTTPS check passes.
    """
    def __init__(self, verbose=False):
        """
        Purpose:
            Build the manager.

        Parameters:
            verbose: Ignored.
        """

    def run_https_check(self, *_):
        """
        Purpose:
            Report working interception.

        Parameters:
            _: The positional arguments the real manager takes (the device bridge and the device serial), ignored.

        Returns:
            A success flag and message.
        """
        return True, "HTTPS interception verified."


@pytest.fixture
def device_checks(monkeypatch):
    """
    Purpose:
        Swap the device, instrumentation and interception managers in the readiness route for fakes, and record what the route logs.

    Parameters:
        monkeypatch: Replaces the managers and the verbose logger.

    Returns:
        The list the route's log lines are recorded into.
    """
    monkeypatch.setattr(dyn_route, "ADBManager", FakeDeviceBridge)
    monkeypatch.setattr(dyn_route, "FridaManager", FakeFrida)
    monkeypatch.setattr(dyn_route, "MitmproxyManager", FakeInterception)
    return capture_logs(monkeypatch, dyn_route)


class TestReadinessFridaStop:
    """
    Purpose:
        Stopping frida-server after the device readiness check.
    """
    def test_a_failed_stop_is_logged_and_reported(self, device_checks, monkeypatch):
        """
        Purpose:
            Pin that a stop that fails shows up both in the log and in the check's message, without changing the verdict.

        Parameters:
            device_checks: The recorded route log lines.
            monkeypatch: Makes the stop fail.

        Security considerations:
            frida-server runs as root. The failure used to be swallowed, so the operator was never told that a root instrumentation server might still be running on the device.
        """
        monkeypatch.setattr(FakeFrida, "stop_error", RuntimeError("device offline"))

        results = dyn_route._run_device_checks("emulator-5554", False)

        warning = "Could not stop frida-server after the readiness check: device offline"
        assert results["frida"] == {"ok": True, "message": f"frida-server is running. {warning}"}
        assert warning in device_checks

    def test_a_clean_stop_leaves_the_message_alone(self, device_checks):
        """
        Purpose:
            Pin that a successful stop adds nothing to the message or the log.

        Parameters:
            device_checks: The recorded route log lines.
        """
        results = dyn_route._run_device_checks("emulator-5554", False)

        assert results["frida"] == {"ok": True, "message": "frida-server is running."}
        assert not any("Could not stop" in m for m in device_checks)


def unreachable_dashboard(**_):
    """
    Purpose:
        A progress callback whose dashboard client has gone away.

    Parameters:
        _: The progress fields, ignored.

    Raises:
        RuntimeError: Always.
    """
    raise RuntimeError("dashboard went away")


def cancelling_dashboard(**_):
    """
    Purpose:
        A progress callback that signals the user stopped the scan.

    Parameters:
        _: The progress fields, ignored.

    Raises:
        ScanCancelled: Always.
    """
    raise ScanCancelled()


def build_dynamic_analyzer(progress, monkeypatch):
    """
    Purpose:
        Build a DynamicAnalyzer without constructing any real device manager.

    Parameters:
        progress: The progress callback.
        monkeypatch: Replaces the interception manager constructor.

    Returns:
        The analyzer.
    """
    monkeypatch.setattr(dyn_mod, "MitmproxyManager", lambda **_: None)
    return dyn_mod.DynamicAnalyzer(progress=progress, adb=object(), frida=object())


def build_analysis_service(progress, _):
    """
    Purpose:
        Build an AnalysisService.

    Parameters:
        progress: The progress callback.
        _: The monkeypatch fixture, ignored; accepted so both builders share one signature.

    Returns:
        The service.
    """
    return as_mod.AnalysisService(progress=progress)


PROGRESS_OWNERS = [
    pytest.param(dyn_mod, build_dynamic_analyzer, id="dynamic_analyzer"),
    pytest.param(as_mod, build_analysis_service, id="analysis_service"),
]


class TestProgressWrappers:
    """
    Purpose:
        The progress methods that shield a scan from a failing dashboard callback.
    """
    @pytest.mark.parametrize("module, build", PROGRESS_OWNERS)
    def test_a_failing_callback_is_logged_not_raised(self, module, build, monkeypatch):
        """
        Purpose:
            Pin that a callback failure is logged and does not escape into the scan.

        Parameters:
            module: The module whose logger is recorded.
            build: Builds the object whose progress method is exercised.
            monkeypatch: Replaces the verbose logger.
        """
        logged = capture_logs(monkeypatch, module)
        runner = build(unreachable_dashboard, monkeypatch)

        runner.progress("sast", 40, "Scanning")

        assert "Progress update could not be delivered: dashboard went away" in logged

    @pytest.mark.parametrize("module, build", PROGRESS_OWNERS)
    def test_cancellation_still_propagates(self, module, build, monkeypatch):
        """
        Purpose:
            Pin that a cancellation raised through the callback still stops the scan and is not logged as a delivery failure.

        Parameters:
            module: The module whose logger is recorded.
            build: Builds the object whose progress method is exercised.
            monkeypatch: Replaces the verbose logger.
        """
        logged = capture_logs(monkeypatch, module)
        runner = build(cancelling_dashboard, monkeypatch)

        with pytest.raises(ScanCancelled):
            runner.progress("sast", 40, "Scanning")
        assert not any("Progress update" in m for m in logged)


class TestAnalysisThreadInterrupts:
    """
    Purpose:
        How the named analysis thread hands exceptions back to its caller.
    """
    @pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
    def test_an_interpreter_stop_reraises(self, interrupt, monkeypatch):
        """
        Purpose:
            Pin that a KeyboardInterrupt or SystemExit inside the thread is re-raised there and still reaches the caller.

        Parameters:
            interrupt: The BaseException subclass raised inside the thread.
            monkeypatch: Replaces the thread exception hook, so the re-raise is observed and not printed.

        Implementation notes:
            The thread used to catch BaseException and only record it, which treated an interpreter stop exactly like an ordinary analysis error.
        """
        hooked = []
        monkeypatch.setattr(threading, "excepthook", lambda args: hooked.append(args.exc_type))

        def _stop():
            """
            Purpose:
                Raise the interpreter stop.

            Raises:
                BaseException: The parametrized interrupt, always.
            """
            raise interrupt()

        with pytest.raises(interrupt):
            as_mod._run_named("validation", _stop)
        assert hooked == [interrupt]

    def test_an_ordinary_error_is_only_recorded(self, monkeypatch):
        """
        Purpose:
            Pin that an ordinary exception is handed to the caller without also escaping the thread.

        Parameters:
            monkeypatch: Replaces the thread exception hook.
        """
        hooked = []
        monkeypatch.setattr(threading, "excepthook", lambda args: hooked.append(args.exc_type))

        def _fail():
            """
            Purpose:
                Raise an ordinary error.

            Raises:
                ValueError: Always.
            """
            raise ValueError("bad region")

        with pytest.raises(ValueError, match="bad region"):
            as_mod._run_named("chains", _fail)
        assert hooked == []


class TestSettingsModelListing:
    """
    Purpose:
        Listing a provider's models for the settings page.
    """
    def test_a_listing_failure_is_logged_and_falls_back(self, monkeypatch):
        """
        Purpose:
            Pin that a provider that cannot list its models is logged and the curated list is shown instead.

        Parameters:
            monkeypatch: Replaces the provider factory and the verbose logger.
        """
        logged = capture_logs(monkeypatch, ss_mod)

        def _unreachable(_, **__):
            """
            Purpose:
                Stand in for building a provider whose endpoint cannot be reached.

            Parameters:
                _: The provider identifier, ignored.
                __: The keyword arguments the real factory takes, such as verbose, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("endpoint unreachable")

        monkeypatch.setattr(provider_factory, "build_provider", _unreachable)

        assert ss_mod.list_models("claude") == CURATED_MODELS["claude"]
        assert "Could not list models for claude: endpoint unreachable" in logged


class TestFridaVersionPin:
    """
    Purpose:
        Choosing the frida-server version from the installed bindings.
    """
    def test_missing_bindings_fall_back(self, monkeypatch):
        """
        Purpose:
            Pin that absent bindings give the known-good fallback.

        Parameters:
            monkeypatch: Makes importing frida fail.
        """
        monkeypatch.setitem(sys.modules, "frida", None)
        assert fm_mod._pinned_frida_version() == "16.7.19"

    @pytest.mark.parametrize("version, expected", [
        ("17.2.1", "17.2.1"),
        ("17.2.1-dev", "16.7.19"),
        ((17, 2, 1), "16.7.19"),
        (None, "16.7.19"),
    ])
    def test_the_installed_version_is_checked(self, version, expected, monkeypatch):
        """
        Purpose:
            Pin that a well-formed installed version is used and anything else, including a non-string, gives the fallback without raising.

        Parameters:
            version: The version the fake bindings report.
            expected: The version that should be chosen.
            monkeypatch: Installs the fake bindings.

        Implementation notes:
            Only ImportError and OSError are suppressed now, so the version is coerced to str before the pattern check; a non-string must not turn into a TypeError at import time.
        """
        monkeypatch.setitem(sys.modules, "frida", types.SimpleNamespace(__version__=version))
        assert fm_mod._pinned_frida_version() == expected


class FakeFridaScript:
    """
    Purpose:
        An injected script that emits one message on load and fails to unload.

    Attributes:
        handler: The message callback the manager registered.
    """
    def __init__(self):
        """
        Purpose:
            Start with no handler registered.
        """
        self.handler = None

    def on(self, _, handler):
        """
        Purpose:
            Register the message handler.

        Parameters:
            _: The event name, ignored.
            handler: The callback.
        """
        self.handler = handler

    def load(self):
        """
        Purpose:
            Emit one message through the registered handler.
        """
        self.handler({"type": "send", "payload": "hooked"}, None)

    def unload(self):
        """
        Purpose:
            Fail to unload.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError("script already destroyed")


class FakeFridaSession:
    """
    Purpose:
        An attached session that fails to detach.
    """
    def create_script(self, _):
        """
        Purpose:
            Create the script.

        Parameters:
            _: The script source, ignored.

        Returns:
            A fake script.
        """
        return FakeFridaScript()

    def detach(self):
        """
        Purpose:
            Fail to detach.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError("session already detached")


class FakeFridaDevice:
    """
    Purpose:
        A remote device that attaches to the target.
    """
    def attach(self, _):
        """
        Purpose:
            Attach to the target.

        Parameters:
            _: The package or process id, ignored.

        Returns:
            A fake session.
        """
        return FakeFridaSession()


class FakeDeviceManager:
    """
    Purpose:
        frida's device manager, whose remote device cannot be removed afterwards.
    """
    def add_remote_device(self, _):
        """
        Purpose:
            Add the forwarded device.

        Parameters:
            _: The forwarded host and port, ignored.

        Returns:
            A fake device.
        """
        return FakeFridaDevice()

    def remove_remote_device(self, _):
        """
        Purpose:
            Fail to remove the device.

        Parameters:
            _: The forwarded host and port, ignored.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError("device already removed")


class FakeForwardingBridge:
    """
    Purpose:
        A device bridge whose port forward succeeds and whose forward removal fails.

    Attributes:
        calls: The adb argument lists received, in order.
    """
    def __init__(self):
        """
        Purpose:
            Start with no calls recorded.
        """
        self.calls = []

    def run_adb(self, args, **_):
        """
        Purpose:
            Record the command; succeed for the forward, fail for its removal.

        Parameters:
            args: The adb arguments.
            _: The keyword options the real bridge accepts, such as the device serial and the timeout, ignored.

        Returns:
            A successful completed-process shape.

        Raises:
            RuntimeError: When asked to remove the forward.
        """
        self.calls.append(list(args))
        if "--remove" in args:
            raise RuntimeError("adb went away")
        return types.SimpleNamespace(returncode=0, stderr="")


class TestFridaScriptTeardown:
    """
    Purpose:
        The guarded teardown after an instrumentation script has run.
    """
    def test_teardown_failures_do_not_mask_the_result(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that unload, detach, device removal and forward removal can all fail without hiding what the script sent back.

        Parameters:
            monkeypatch: Installs fake frida bindings and removes the run delay.
            tmp_path: Stands in for the frida binary cache.
        """
        device_manager = FakeDeviceManager()
        monkeypatch.setitem(sys.modules, "frida",
                            types.SimpleNamespace(get_device_manager=lambda: device_manager))
        monkeypatch.setattr(fm_mod, "FRIDA_CACHE_DIR", tmp_path / "frida")
        monkeypatch.setattr(fm_mod.time, "sleep", lambda _: None)
        manager = fm_mod.FridaManager(verbose=False)
        monkeypatch.setattr(manager, "is_server_running", lambda _, __: True)
        bridge = FakeForwardingBridge()

        outcome = manager.run_script(bridge, "emulator-5554", "com.example.target",
                                     "send('hooked');", timeout=1)

        assert outcome == (True, "hooked")
        assert bridge.calls[-1][:2] == ["forward", "--remove"]
