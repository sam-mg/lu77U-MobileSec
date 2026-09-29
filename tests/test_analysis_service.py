#!/usr/bin/env python3
"""
Module: test_analysis_service

Purpose:
    Phase two of a scan: verifying findings against a running application and then exploring it on the device.

Responsibilities:
    Pin that runtime findings reach the report, that the device session runs whether or not there were static findings, that the device tooling is constructed once for the whole phase, that every failure degrades instead of ending the scan, and that the graded phases run on named threads carrying the scan's context.

Dependencies:
    pytest, the dynamic analysis package, the analysis service and the cancellation exception.

Implementation notes:
    The device layer is replaced throughout with fakes that record how they were configured, so nothing here needs a device, an emulator or an installed application.
"""

import threading

import pytest

from lu77U_MobileSec import dynamic_analysis
from lu77U_MobileSec.utils.cancellation import ScanCancelled
from lu77U_MobileSec.web.services.analysis_service import AnalysisService

class FakeBasicInfo:
    """
    Purpose:
        The smallest stand-in for the extracted application information the phase reads.

    Attributes:
        package_name: The application's package name.
    """
    package_name = "com.example.target"

class FakeDetectionResult:
    """
    Purpose:
        The smallest stand-in for a detection result.

    Attributes:
        basic_info: The extracted application information.
    """
    basic_info = FakeBasicInfo()

class FakeADBManager:
    """
    Purpose:
        A device bridge that reports a configurable install outcome and counts how many times it was constructed.

    Attributes:
        installed: Whether the install is reported as successful.
        message: The message the install reports.
        construct_count: How many times the bridge was constructed during the phase.
    """
    installed = True
    message = "Success"
    construct_count = 0

    def __init__(self, verbose=False):
        """
        Purpose:
            Build the bridge and count the construction.

        Parameters:
            verbose: The verbosity flag, unused here.

        Side effects:
            Increments the construction count.
        """
        FakeADBManager.construct_count += 1

    def install_apk(self, unused_device, unused_apk_path):
        """
        Purpose:
            Report the configured install outcome without touching a device.

        Parameters:
            unused_device: The device serial, unused here.
            unused_apk_path: The application file, unused here.

        Returns:
            The configured success flag and message.
        """
        return FakeADBManager.installed, FakeADBManager.message

class FakeFridaManager:
    """
    Purpose:
        An instrumentation manager that only counts how many times it was constructed.

    Attributes:
        construct_count: How many times the manager was constructed during the phase.
    """
    construct_count = 0

    def __init__(self, verbose=False):
        """
        Purpose:
            Build the manager and count the construction.

        Parameters:
            verbose: The verbosity flag, unused here.

        Side effects:
            Increments the construction count.
        """
        FakeFridaManager.construct_count += 1

class FakeDynamicAnalyzer:
    """
    Purpose:
        A device session that records how it was configured and returns a canned result.

    Attributes:
        last_kwargs: How the most recent session was configured.
        raises: An error to raise instead of running, or None to run normally.
        result: A result to return instead of the canned one, or None for the canned one.
    """
    last_kwargs = None
    raises = None
    result = None

    def __init__(self, verbose=False, progress=None, is_cancelled=None,
                 adb=None, frida=None):
        """
        Purpose:
            Build the session, keeping the progress callback so the run can report through it.

        Parameters:
            verbose: The verbosity flag, unused here.
            progress: The progress callback, or None for one that does nothing.
            is_cancelled: The cancellation callback, unused here.
            adb: The device bridge, unused here.
            frida: The instrumentation manager, unused here.
        """
        self.progress = progress or (lambda **unused_kwargs: None)

    def run(self, device, package, ui_steps=20, skip_app_info=False, frida_env=None):
        """
        Purpose:
            Record how the session was configured, then either raise the configured error or report progress and return a result.

        Parameters:
            device: The device serial.
            package: The application's package name.
            ui_steps: How many interaction steps the session was given.
            skip_app_info: Whether the session was told to skip the information-gathering step.
            frida_env: The instrumentation result carried over from verification.

        Returns:
            The configured result, or a canned one holding a device, environment checks, actions and one runtime finding.

        Raises:
            Exception: Whatever was configured to be raised, standing in for a device failure or a cancellation.

        Side effects:
            Records the configuration and reports one progress event.
        """
        FakeDynamicAnalyzer.last_kwargs = {
            "device": device, "package": package,
            "ui_steps": ui_steps, "skip_app_info": skip_app_info,
            "frida_env": frida_env,
        }
        if FakeDynamicAnalyzer.raises is not None:
            raise FakeDynamicAnalyzer.raises
        self.progress(phase="ui_interact", percent=60, message="exploring")
        return FakeDynamicAnalyzer.result or {
            "device": {"serial": device},
            "env_checks": {"root": True, "https_intercept": {"ok": True}},
            "actions": [{"iteration": 1, "action": "tap"}],
            "runtime_findings": [{"vulnerability_type": "Interceptable HTTPS Traffic",
                                  "severity": "Medium", "file": "runtime://network"}],
        }

@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    """
    Purpose:
        Reset the fakes and put them in place of the real device layer for every test in this module.

    Parameters:
        monkeypatch: Replaces the device bridge, the instrumentation manager and the session.

    Side effects:
        Clears the recorded state on each fake and replaces the three real classes.

    Implementation notes:
        The fakes record on the class rather than the instance, because the phase constructs them itself and the test never sees the instances, so they have to be reset between tests explicitly.
    """
    FakeDynamicAnalyzer.last_kwargs = None
    FakeDynamicAnalyzer.raises = None
    FakeDynamicAnalyzer.result = None
    FakeADBManager.installed = True
    FakeADBManager.construct_count = 0
    FakeFridaManager.construct_count = 0
    monkeypatch.setattr(dynamic_analysis, "ADBManager", FakeADBManager)
    monkeypatch.setattr(dynamic_analysis, "FridaManager", FakeFridaManager)
    monkeypatch.setattr(dynamic_analysis, "DynamicAnalyzer", FakeDynamicAnalyzer)

@pytest.fixture
def events():
    """
    Purpose:
        Collect the progress events the phase reports.

    Returns:
        The empty list events are appended to.
    """
    return []

@pytest.fixture
def service(events):
    """
    Purpose:
        Build the analysis service, reporting its progress into the collected events.

    Parameters:
        events: The list progress events are appended to.

    Returns:
        The service.
    """
    def progress(phase, percent, message=""):
        """
        Purpose:
            Record one progress event.

        Parameters:
            phase: The phase the event belongs to.
            percent: The overall progress the event reports.
            message: The event's message.

        Side effects:
            Appends the event to the collected list.
        """
        events.append((phase, percent, message))
    return AnalysisService(verbose=False, progress=lambda **kw: progress(**kw))

def run_phase(service, findings, monkeypatch, verification=None):
    """
    Purpose:
        Drive the device phase with the verification step replaced by a stub.

    Parameters:
        service: The analysis service.
        findings: The static findings the phase is given, which it appends runtime findings to.
        monkeypatch: Replaces the verification step.
        verification: The verification outcome to report, or None for a successful default.

    Returns:
        The session summary the phase produced.

    Side effects:
        Replaces the verification step and may append runtime findings to the list passed in.
    """
    def fake_verification(**kwargs):
        """
        Purpose:
            Return the findings unchanged along with the configured verification outcome.

        Parameters:
            kwargs: Everything the phase passed, of which only the findings are read.

        Returns:
            The findings and the verification outcome.
        """
        return kwargs["findings"], (verification or {"install": {"ok": True},
                                                     "verified_count": 1, "total_count": 1})
    monkeypatch.setattr(dynamic_analysis, "run_dynamic_verification", fake_verification)
    return service._run_dynamic_phase(
        device="emulator-5554",
        detection_result=FakeDetectionResult(),
        apk_path="/tmp/app.apk",
        jadx_output_dir="/tmp/jadx",
        vulnerabilities=findings,
        static_transcript="",
        ai_provider=object(),
    )

class TestDeviceSession:
    """
    Purpose:
        The on-device session: what it produces and how it is configured.
    """
    def test_runtime_findings_reach_the_report(self, service, monkeypatch):
        """
        Purpose:
            Pin that a finding observed at runtime is appended to the scan's findings.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.
        """
        findings = [{"title": "static finding"}]
        session = run_phase(service, findings, monkeypatch)
        assert session["environment"]["attempted"] is True
        assert [f.get("vulnerability_type") for f in findings[1:]] == [
            "Interceptable HTTPS Traffic"]

    def test_session_runs_even_without_static_findings(self, service, monkeypatch):
        """
        Purpose:
            Pin that with nothing to verify the session still runs and its runtime finding still lands, with the reason recorded.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            Nothing to verify is not nothing to find: the runtime observations do not depend on a static finding existing first, so skipping the session would lose them entirely on a clean static scan.
        """
        findings = []
        session = run_phase(service, findings, monkeypatch)
        assert session["reason"] == "No static findings to verify."
        assert session["environment"]["attempted"] is True
        assert session["attempted"] is True
        assert len(findings) == 1

    def test_ui_budget_is_reduced_for_a_merged_scan(self, service, monkeypatch):
        """
        Purpose:
            Pin that a session following a verification step gets a smaller interaction budget and skips the information-gathering step.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            Verification has already launched the application and gathered its information, so repeating both would spend the session's budget re-establishing what is already known.
        """
        run_phase(service, [{"title": "x"}], monkeypatch)
        assert FakeDynamicAnalyzer.last_kwargs["ui_steps"] < 20
        assert FakeDynamicAnalyzer.last_kwargs["skip_app_info"] is True

    def test_progress_is_remapped_into_the_session_band(self, service, events, monkeypatch):
        """
        Purpose:
            Pin that the session's own progress is rescaled into the slice of the overall scan it occupies.

        Parameters:
            service: The analysis service.
            events: The collected progress events.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            The session reports its own progress from nothing to complete, so passing that through unchanged would send the overall bar backwards near the end of a scan.
        """
        run_phase(service, [{"title": "x"}], monkeypatch)
        percents = [p for phase, p, _ in events if phase in ("ui_interact", "session_done")]
        assert percents and all(88 <= p <= 91 for p in percents)

    def test_app_is_installed_when_verification_did_not(self, service, monkeypatch):
        """
        Purpose:
            Pin that the phase installs the application itself when verification did not.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step and records installs.
        """
        calls = []
        original = FakeADBManager.install_apk

        def tracking_install(self, device, apk_path):
            """
            Purpose:
                Record the install and defer to the original behaviour.

            Parameters:
                self: The bridge the install is called on, a real parameter here because this stands in for an unbound method rather than being one.
                device: The device serial.
                apk_path: The application file.

            Returns:
                Whatever the original install reported.

            Side effects:
                Records the install.
            """
            calls.append(apk_path)
            return original(self, device, apk_path)

        monkeypatch.setattr(FakeADBManager, "install_apk", tracking_install)
        run_phase(service, [], monkeypatch)
        assert calls == ["/tmp/app.apk"]

    def test_install_is_not_repeated_after_verification(self, service, monkeypatch):
        """
        Purpose:
            Pin that the phase does not install again when verification already did.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step and records installs.

        Implementation notes:
            A second install reinstalls over the running application, which clears the state the verification step just established.
        """
        calls = []
        monkeypatch.setattr(FakeADBManager, "install_apk",
                            lambda self, _, p: (calls.append(p), (True, "Success"))[1])
        run_phase(service, [{"title": "x"}], monkeypatch)
        assert calls == []

    def test_one_adb_and_frida_manager_serve_the_whole_phase(self, service, monkeypatch):
        """
        Purpose:
            Pin that the device bridge and the instrumentation manager are each constructed once for the entire phase.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            A merged scan used to build four bridges, one per sub-step, and provision the instrumentation twice against the same device, which is slow and can leave two agents contending on one process.
        """
        run_phase(service, [{"title": "x"}], monkeypatch)
        assert FakeADBManager.construct_count == 1
        assert FakeFridaManager.construct_count == 1

    def test_a_successful_verification_frida_result_reaches_the_session(self, service, monkeypatch):
        """
        Purpose:
            Pin that a successful instrumentation result from verification is handed on to the session.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            Carrying it over is what lets the session skip provisioning the instrumentation a second time.
        """
        run_phase(service, [{"title": "x"}], monkeypatch, verification={
            "install": {"ok": True}, "frida": {"ok": True, "message": "16.7.19"},
            "verified_count": 1, "total_count": 1})
        assert FakeDynamicAnalyzer.last_kwargs["frida_env"] == {
            "ok": True, "message": "16.7.19"}

    def test_verification_gets_a_triage_provider(self, service, monkeypatch):
        """
        Purpose:
            Pin that the verification step is given the provider chosen for triage.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step with a recorder.

        Implementation notes:
            Triage returns only which findings need proof at runtime and no prose, so it routes to a smaller model when one is configured. Whatever the routing decided has to reach the call rather than being dropped on the way.
        """
        captured = {}

        def fake_verification(**kwargs):
            """
            Purpose:
                Record everything the phase passed and return the findings unchanged.

            Parameters:
                kwargs: Everything the phase passed, all of it recorded.

            Returns:
                The findings and a successful verification outcome.

            Side effects:
                Records the call arguments.
            """
            captured.update(kwargs)
            return kwargs["findings"], {"install": {"ok": True},
                                        "verified_count": 1, "total_count": 1}

        monkeypatch.setattr(dynamic_analysis, "run_dynamic_verification", fake_verification)
        service._run_dynamic_phase(
            device="emulator-5554", detection_result=FakeDetectionResult(),
            apk_path="/tmp/app.apk", jadx_output_dir="/tmp/jadx",
            vulnerabilities=[{"title": "x"}], static_transcript="",
            ai_provider=object())
        assert "triage_provider" in captured

class TestFailuresDegrade:
    """
    Purpose:
        That every failure in this phase is recorded rather than ending the scan, with cancellation as the one exception.
    """
    def test_install_failure_is_recorded_not_raised(self, service, monkeypatch):
        """
        Purpose:
            Pin that a failed install is recorded on the session summary with the reason the device gave.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            The static findings are already complete by this point, so failing the scan over a device problem would discard a finished analysis.
        """
        FakeADBManager.installed = False
        FakeADBManager.message = "INSTALL_FAILED_INVALID_APK"
        session = run_phase(service, [], monkeypatch)
        assert session["environment"]["attempted"] is False
        assert "INSTALL_FAILED_INVALID_APK" in session["environment"]["reason"]

    def test_session_error_does_not_fail_the_scan(self, service, monkeypatch):
        """
        Purpose:
            Pin that an error inside the session is recorded and leaves the existing findings untouched.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.
        """
        FakeDynamicAnalyzer.raises = RuntimeError("adb died")
        findings = [{"title": "static finding"}]
        session = run_phase(service, findings, monkeypatch)
        assert session["environment"]["attempted"] is False
        assert "adb died" in session["environment"]["reason"]
        assert findings == [{"title": "static finding"}]

    def test_cancellation_propagates(self, service, monkeypatch):
        """
        Purpose:
            Pin that a cancellation is raised through rather than recorded as a device failure.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the verification step.

        Implementation notes:
            Cancellation is the user's own action, so swallowing it here would leave a scan they stopped carrying on to the next phase.
        """
        FakeDynamicAnalyzer.raises = ScanCancelled()
        with pytest.raises(ScanCancelled):
            run_phase(service, [{"title": "x"}], monkeypatch)

    def test_missing_package_skips_the_whole_phase(self, service):
        """
        Purpose:
            Pin that with no package name the phase is skipped with a reason and nothing on the device is touched.

        Parameters:
            service: The analysis service.

        Implementation notes:
            Every device command is scoped by the package name, so without one there is nothing the phase could safely do.
        """
        class NoPackage:
            """
            Purpose:
                A detection result carrying no application information.

            Attributes:
                basic_info: Always absent.
            """
            basic_info = None

        session = service._run_dynamic_phase(
            device="emulator-5554", detection_result=NoPackage(),
            apk_path="/tmp/app.apk", jadx_output_dir="/tmp/jadx",
            vulnerabilities=[], static_transcript="", ai_provider=object())
        assert session == {"attempted": False,
                           "reason": "Could not determine the app's package name "
                                     "from static analysis."}


class TestRunNamed:
    """
    Purpose:
        The helper that runs a phase on its own named thread.

    Implementation notes:
        The validation and chain transcripts used to be named after whatever default name the scan's worker thread happened to have, which made them indistinguishable from each other and from anything else in the log.
    """
    def test_the_thread_is_named(self):
        """
        Purpose:
            Pin that the work runs on a thread carrying the name it was given.
        """
        from lu77U_MobileSec.web.services.analysis_service import _run_named

        seen = {}
        _run_named("validation", lambda: seen.setdefault(
            "name", threading.current_thread().name))
        assert seen["name"] == "validation"

    def test_the_return_value_comes_back(self):
        """
        Purpose:
            Pin that the work's return value reaches the caller.
        """
        from lu77U_MobileSec.web.services.analysis_service import _run_named

        assert _run_named("chains", lambda: [1, 2, 3]) == [1, 2, 3]

    def test_an_exception_is_reraised_on_the_caller(self):
        """
        Purpose:
            Pin that an error raised inside the work is raised again on the calling thread.

        Implementation notes:
            An error raised on a separate thread otherwise disappears entirely, leaving the phase to look as though it had simply returned nothing.
        """
        from lu77U_MobileSec.web.services.analysis_service import _run_named

        def _boom():
            """
            Purpose:
                Raise an ordinary error.

            Raises:
                ValueError: Always.
            """
            raise ValueError("nope")

        with pytest.raises(ValueError, match="nope"):
            _run_named("validation", _boom)

    def test_scan_cancelled_is_reraised_too(self):
        """
        Purpose:
            Pin that a cancellation raised inside the work also reaches the calling thread.
        """
        from lu77U_MobileSec.web.services.analysis_service import _run_named

        def _cancel():
            """
            Purpose:
                Raise a cancellation.

            Raises:
                ScanCancelled: Always.
            """
            raise ScanCancelled()

        with pytest.raises(ScanCancelled):
            _run_named("chains", _cancel)

    def test_the_current_scan_id_contextvar_survives(self):
        """
        Purpose:
            Pin that the scan the work belongs to is still known inside the named thread.

        Implementation notes:
            A thread started plainly begins with an empty context, which would silently drop every log line the named work emits from the live view, since that is how each line is attributed to a scan.
        """
        from lu77U_MobileSec.web.events import current_scan_id
        from lu77U_MobileSec.web.services.analysis_service import _run_named

        token = current_scan_id.set("scan-123")
        try:
            seen = _run_named("validation", lambda: current_scan_id.get())
        finally:
            current_scan_id.reset(token)
        assert seen == "scan-123"

    def test_grade_findings_names_validation_and_chains_threads(self, service, monkeypatch):
        """
        Purpose:
            Pin that the grading step runs validation and chain building on threads named after them.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the validation and chain steps with recorders.
        """
        seen_names = []

        def fake_validate(unused_findings, **unused_kwargs):
            """
            Purpose:
                Record the name of the thread validation ran on.

            Parameters:
                unused_findings: The findings, unused here.
                unused_kwargs: Everything else, unused here.

            Side effects:
                Records the thread name.
            """
            seen_names.append(threading.current_thread().name)

        def fake_build_chains(unused_findings, **unused_kwargs):
            """
            Purpose:
                Record the name of the thread chain building ran on.

            Parameters:
                unused_findings: The findings, unused here.
                unused_kwargs: Everything else, unused here.

            Returns:
                An empty chain list.

            Side effects:
                Records the thread name.
            """
            seen_names.append(threading.current_thread().name)
            return []

        monkeypatch.setattr(
            "lu77U_MobileSec.validation.validate_findings", fake_validate)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.build_chains", fake_build_chains)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.annotate_related_findings", lambda _: 0)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.sort_findings", lambda f: f)

        service._grade_findings([{"title": "x"}], ai_provider=object())
        assert "validation" in seen_names
        assert "chains" in seen_names

    def test_grade_findings_logs_its_output_tokens(self, service, monkeypatch, capsys):
        """
        Purpose:
            Pin that grading reports what it cost in generated tokens.

        Parameters:
            service: The analysis service.
            monkeypatch: Replaces the validation and chain steps and the provider configuration.
            capsys: Captures the printed output.

        Implementation notes:
            The figure is a before and after reading of the provider's own cumulative counter rather than a separate accounting path, so the difference across validation and chain building is exactly what grading cost.
        """
        class FakeProvider:
            """
            Purpose:
                A provider carrying only the cumulative token counter the measurement reads.

            Attributes:
                name: The provider name.
                model: The configured model.
                usage: The cumulative counters.
            """
            name = "ollama"
            model = "x"
            def __init__(self):
                """
                Purpose:
                    Build the provider with its counters at zero.
                """
                self.usage = {"completion_tokens": 0}

        def fake_validate(unused_findings, provider=None, **unused_kwargs):
            """
            Purpose:
                Charge a fixed number of generated tokens to the provider.

            Parameters:
                unused_findings: The findings, unused here.
                provider: The provider whose counter is charged, or None for no provider.
                unused_kwargs: Everything else, unused here.

            Side effects:
                Increases the provider's generated token count.
            """
            if provider is not None:
                provider.usage["completion_tokens"] += 30

        def fake_build_chains(unused_findings, provider=None, **unused_kwargs):
            """
            Purpose:
                Charge a fixed number of generated tokens to the provider.

            Parameters:
                unused_findings: The findings, unused here.
                provider: The provider whose counter is charged, or None for no provider.
                unused_kwargs: Everything else, unused here.

            Returns:
                An empty chain list.

            Side effects:
                Increases the provider's generated token count.
            """
            if provider is not None:
                provider.usage["completion_tokens"] += 20
            return []

        monkeypatch.setattr(
            "lu77U_MobileSec.validation.validate_findings", fake_validate)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.build_chains", fake_build_chains)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.annotate_related_findings", lambda _: 0)
        monkeypatch.setattr(
            "lu77U_MobileSec.validation.sort_findings", lambda f: f)
        monkeypatch.setattr(
            "lu77U_MobileSec.web.services.analysis_service.user_settings.get_provider_config",
            lambda _: {"model": "x", "cheap_model": ""})

        verbose_service = type(service)(verbose=True, progress=service._progress)
        verbose_service._grade_findings([{"title": "x"}], ai_provider=FakeProvider())
        out = capsys.readouterr().out
        assert "Grading (validation + chains) output:" in out
        assert "50 completion tokens" in out
