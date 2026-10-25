#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.services.analysis_service

Purpose:
    Run a complete scan end to end: detect the framework, decompile and analyse, grade and chain the findings, optionally verify them on a device, write the reports, and clean up.

Responsibilities:
    Sequence the phases, choose the right analyzer, report progress, and handle the cases where a phase cannot run.

Dependencies:
    The detector, the analyzer registry, the validation package, the dynamic pipeline, the report generators.

Implementation notes:
    Each phase degrades rather than aborting. An unsupported framework still produces a detection report, an analyzer that fails preflight reports why, and an absent device skips verification -- because a partial result is useful and a lost scan is not. Progress is reported continuously, since the phases take minutes and the dashboard is the only window onto them.

Security considerations:
    This is the orchestrator that launches decompilers over untrusted APKs and, when verification runs, installs and drives the app on a real device. The containment for each of those lives in the layer that performs it.
"""

import contextvars
import hashlib
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ...analyzers.registry import get_analyzer_class
from ...config import user_settings
from ...detection.detector import MobileSecurityDetector
from ...utils.cancellation import ScanCancelled
from ...utils.output_manager import OutputManager
from ...utils.verbose import plural, verbose_print
from ...validation.validator import sdk_note
from ..serializers import build_result

def provider_outage(result: Dict[str, Any]) -> str:
    """
    Purpose:
        Name the provider outage a scan stopped on, if it stopped on one.

    Parameters:
        result: The scan result.

    Returns:
        "provider_quota" for an exhausted quota, "provider_unreachable" when the provider's host could not be reached when the scan stopped using it, otherwise "".

    Implementation notes:
        Both mean the AI phases are incomplete for a reason outside the app and the scan can be redone later from its checkpoint, so both pause instead of finishing. Quota is checked first: it is the more specific verdict and carries its own retry window.
    """
    if quota_exhausted(result):
        return "provider_quota"
    details = (result or {}).get("analyzer_details") or {}
    usage = details.get("llm_usage") or {}
    return "provider_unreachable" if usage.get("unreachable") else ""


def quota_exhausted(result: Dict[str, Any]) -> bool:
    """
    Purpose:
        Report whether a scan stopped because the AI provider's quota ran out.

    Parameters:
        result: The scan result.

    Returns:
        True when the provider reported an exhausted quota.

    Implementation notes:
        Distinguished from other failures because the outcome differs: a quota failure pauses the scan for a later automatic resume, while any other failure ends it. The provider's own classification is used rather than re-reading the error text.
    """
    details = (result or {}).get("analyzer_details") or {}
    usage = details.get("llm_usage") or {}
    unavailable = usage.get("unavailable") or ""
    return str(unavailable).startswith("fatal_quota:")

UNSUPPORTED_FRAMEWORKS = {
    "kony", "kony visualizer", "libgdx", "unity", "unreal",
}

_DEVICE_LOCKS: Dict[str, threading.Lock] = {}
_DEVICE_LOCKS_GUARD = threading.Lock()


def hold_device(device: str, is_cancelled: Callable[[], bool], waiting: Callable[[], None]) -> threading.Lock:
    """
    Purpose:
        Take the one-at-a-time lock for a device, waiting for any other scan using it.

    Parameters:
        device: The device serial.
        is_cancelled: Polled while waiting, so a stopped scan does not wait forever.
        waiting: Called once if the device is busy, to tell the user why the scan is waiting.

    Returns:
        The held lock, which the caller releases.

    Raises:
        ScanCancelled: When the scan is stopped while waiting.

    Implementation notes:
        Two scans can run at once, and each installs its app, starts and stops frida-server and drives the screen of the device it picked; with one emulator attached both picked it, and one scan's teardown stopped the other's frida-server mid-check. The static phases still run in parallel; only the device phase is serialised, per device.
    """
    with _DEVICE_LOCKS_GUARD:
        lock = _DEVICE_LOCKS.setdefault(device, threading.Lock())
    if lock.acquire(blocking=False):
        return lock
    waiting()
    while not lock.acquire(timeout=2):
        if is_cancelled():
            raise ScanCancelled()
    return lock


_SESSION_PROGRESS_START = 88
_SESSION_PROGRESS_END = 91

_SESSION_UI_STEPS = 8


def _apk_digest(apk_path: str) -> str:
    """
    Purpose:
        Identify an APK by its content, for scoping reused review verdicts to one app.

    Parameters:
        apk_path: Path to the APK.

    Returns:
        The SHA-256 hex digest, or an empty string when the file cannot be read, which turns verdict reuse off.

    Implementation notes:
        Content rather than package name, because a vulnerable app and its fixed version can share a package name, a version and every file path, and a verdict on one must not be applied to the other.
    """
    digest = hashlib.sha256()
    try:
        with open(apk_path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def _run_named(name: str, fn: Callable[[], Any]) -> Any:
    """
    Purpose:
        Run a callable on its own named thread, propagating its result or its exception.

    Parameters:
        name: Thread name, which appears in per-region logs and metrics.
        fn: The callable.

    Returns:
        Whatever the callable returned.

    Raises:
        Whatever the callable raised, re-raised on the calling thread.

    Side effects:
        Starts a thread and waits for it.

    Implementation notes:
        The thread is named because the provider layer attributes transcripts and metrics by thread name, which is what makes per-region cost attribution possible. The current context is copied into the thread, so the scan identity propagates and log lines emitted inside still reach the right job's stream. Exceptions are captured and re-raised on the caller's thread rather than being lost as an unhandled thread exception, so the phase's own error handling still applies.
    """
    context = contextvars.copy_context()
    outcome: Dict[str, Any] = {}

    def _target() -> None:
        """
        Purpose:
            Thread body that runs the callable and captures its outcome.

        Side effects:
            Records either the return value or the exception for the caller to retrieve.

        Raises:
            BaseException: A non-Exception such as KeyboardInterrupt or SystemExit, after it has been recorded for the caller.

        Implementation notes:
            An ordinary Exception, ScanCancelled included since it subclasses Exception, is recorded and re-raised on the caller's thread so the phase's own error handling applies. A BaseException that is not an Exception is an interpreter-level stop rather than an analysis failure, so it is recorded for the caller and then re-raised here as well instead of being quietly converted into an ordinary error.
        """
        try:
            outcome["result"] = fn()
        except Exception as exc:
            outcome["error"] = exc
        except BaseException as exc:
            outcome["error"] = exc
            raise

    thread = threading.Thread(target=context.run, args=(_target,),
                              name=name, daemon=True)
    thread.start()
    thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


def _cheap_provider_or_same(main_provider, verbose: bool):
    """
    Purpose:
        Return a provider configured with the cheap model, or the original when there is no distinct one.

    Parameters:
        main_provider: The provider in use.
        verbose: Enables tracing.

    Returns:
        A provider to use for the high-volume grading work.

    Implementation notes:
        Grading and triage make many small calls where the strongest model adds little, so a cheaper one is used when the user configured one. When none is configured, or it is the same model, the original is returned rather than rebuilding an identical provider. Failure to read the configuration returns the original, so a settings problem costs the saving rather than the scan.
    """
    if main_provider is None:
        return None
    try:
        cheap_model = str(
            user_settings.get_provider_config(main_provider.name).get("cheap_model") or ""
        ).strip()
    except Exception:
        return main_provider
    if not cheap_model or cheap_model == main_provider.model:
        return main_provider
    from ...ai.provider_factory import build_provider
    return build_provider(main_provider.name, verbose=verbose, cheap=True)


class AnalysisService:
    """
    Purpose:
        Runs one complete scan.

    Attributes:
        verbose: Whether the scan is traced and working files are kept.
        is_cancelled: Polled between phases.
        checkpoint: Records progress so an interrupted scan can resume.

    Invariants:
        Every phase either produces its result or records why it could not, so the scan always yields a renderable document.

    Thread-safety:
        One instance per scan; not shared.
    """
    def __init__(self, verbose: bool = False,
                 progress: Optional[Callable[..., None]] = None,
                 is_cancelled: Optional[Callable[[], bool]] = None,
                 checkpoint=None):
        """
        Purpose:
            Construct the service for one scan.

        Parameters:
            verbose: Enables tracing and preserves working files.
            progress: Reports phase progress.
            is_cancelled: Polled between phases.
            checkpoint: Records progress for resumption.
        """
        self.verbose = verbose
        self._progress = progress or (lambda **unused_kw: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.checkpoint = checkpoint

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        """
        Purpose:
            Report phase progress to the caller.

        Parameters:
            phase: Stage identifier.
            percent: Overall completion.
            message: Human-readable description.

        Side effects:
            Invokes the progress callback, which raises when the scan has been asked to stop.

        Implementation notes:
            Any other callback failure is logged and otherwise ignored, because a dashboard that cannot take an update must not end the scan. contextlib.suppress cannot replace the handler because ScanCancelled subclasses Exception and has to be re-raised first.
        """
        try:
            self._progress(phase=phase, percent=percent, message=message)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Progress update could not be delivered: {exc}", self.verbose)

    def run(self, apk_path: str) -> Dict[str, Any]:
        """
        Purpose:
            Run the full scan and return its result.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            The scan result.

        Raises:
            RuntimeError: When framework detection produced nothing, which leaves nothing to analyse.
            ScanCancelled: When the user stopped the scan.

        Side effects:
            Decompiles the APK, makes provider requests, may drive a device, writes reports, and removes working files.

        Implementation notes:
            Detection runs first because it selects everything after it -- which analyzer, which decompiler, which prompt. An unsupported framework or a failed preflight does not end the scan: the result records the reason and the report still describes the app, because a report saying why an app was not analysed is far better than an empty one that reads as clean. Findings are graded and chained before any device work, so verification spends its budget on findings that survived gating. Working files are removed at the end unless verbose is set, since decompiled output is large and a user who wants to inspect it runs verbose. A failed analysis is logged under an "Analysis failed" prefix, because the analyzers' own reasons do not always match the dashboard feed's filter and a scan once ended there with no reason shown at all.
        """
        self.progress("detecting", 10, "Detecting framework and reading the manifest")
        detector = MobileSecurityDetector(verbose=self.verbose)
        detection_result = detector.detect(apk_path)
        if not detection_result:
            raise RuntimeError("Framework detection failed - no result returned")

        framework_name = "generic"
        if detection_result.framework_results:
            primary = detection_result.framework_results.get_primary_framework_name()
            framework_name = primary if primary != "Unknown" else "generic"

        analyzer_cls = get_analyzer_class(framework_name)
        supported = analyzer_cls is not None

        vulnerabilities: List[Dict[str, Any]] = []
        analysis_success = False
        analyzer_results: Dict[str, Any] = {
            "framework": framework_name,
            "analysis_time": 0,
            "files_analyzed": 0,
            "decompilation_status": "Not started",
        }
        output_manager = None
        dynamic_session: Optional[Dict[str, Any]] = None

        if supported:
            analyzer = analyzer_cls(
                verbose=self.verbose,
                progress=lambda phase, percent, message="": self.progress(phase, percent, message),
                is_cancelled=self.is_cancelled,
            )
            analyzer.checkpoint = self.checkpoint
            ready, preflight_reason = analyzer.preflight(apk_path)
            if not ready:
                verbose_print(
                    f"{analyzer.framework_label} analyzer not ready: {preflight_reason}",
                    self.verbose)
                supported = False
                analyzer_results["unsupported_framework"] = True
                analyzer_results["decompilation_status"] = "Tool Not Configured"
                analyzer_results["error"] = preflight_reason
            else:
                want_dynamic = user_settings.get_dynamic_verification()
                device = self._pick_device() if want_dynamic else None

                self.progress("analyzing", 40,
                              f"Decompiling APK and analyzing {analyzer.framework_label} sources")

                analysis_result = analyzer.analyze(apk_path, defer_cleanup=bool(device))
                jadx_output_dir = None
                static_transcript = ""
                code_graph = None
                if isinstance(analysis_result, dict):
                    analysis_success = analysis_result.get("success", False)
                    vulnerabilities = analysis_result.get("vulnerabilities", []) or []
                    output_manager = analysis_result.get("output_manager")
                    jadx_output_dir = (analysis_result.get("source_root")
                                      or analysis_result.get("jadx_output_dir"))
                    static_transcript = analysis_result.get("static_transcript", "") or ""
                    code_graph = analysis_result.get("code_graph")
                    analyzer_results = {
                        "framework": analysis_result.get("framework", analyzer.framework_label),
                        "analysis_time": analysis_result.get("analysis_time", 0),
                        "files_analyzed": analysis_result.get("files_analyzed", 0),
                        "decompilation_status": "Successful" if analysis_success else "Failed",
                        "error": analysis_result.get("error"),
                        "agent_coverage": analysis_result.get("agent_coverage") or {},
                        "limitation": analysis_result.get("limitation") or "",
                    }
                if not analysis_success:
                    verbose_print(
                        f"Analysis failed: {analyzer_results.get('error') or 'the analyzer gave no reason'}",
                        self.verbose)

                if analysis_success:
                    if device:
                        lock = hold_device(device, self.is_cancelled, lambda: self.progress(
                            "device_check", 62, f"Waiting for {device}: another scan is using it"))
                        try:
                            dynamic_session = self._run_dynamic_phase(
                                device=device,
                                detection_result=detection_result,
                                apk_path=apk_path,
                                jadx_output_dir=jadx_output_dir,
                                vulnerabilities=vulnerabilities,
                                static_transcript=static_transcript,
                                ai_provider=analyzer.ai_provider,
                                code_graph=code_graph,
                            )
                        finally:
                            lock.release()
                        self._cleanup_deferred(analyzer, jadx_output_dir)
                    else:
                        reason = ("Dynamic verification is disabled in Settings."
                                  if not want_dynamic else
                                  "No emulator or device connected, so every finding "
                                  "below is static and unverified. Start an Android "
                                  "emulator or attach a device with USB debugging on, "
                                  "confirm it appears in `adb devices`, then re-run "
                                  "the scan to verify these findings at runtime.")
                        dynamic_session = {"attempted": False, "reason": reason}
        else:
            verbose_print(
                f"Framework '{framework_name}' is not yet supported for deep "
                f"analysis - producing a detection-only report.", self.verbose)
            analyzer_results["unsupported_framework"] = True
            analyzer_results["decompilation_status"] = "Unsupported Framework"

        if output_manager is None:
            output_manager = OutputManager(verbose=self.verbose)
            output_manager.create_output_directory(apk_path)

        chains: List[Dict[str, Any]] = []
        if vulnerabilities:
            basic = getattr(detection_result, "basic_info", None)
            chains = self._grade_findings(
                vulnerabilities, getattr(analyzer, "ai_provider", None) if supported else None,
                app_note=sdk_note(getattr(basic, "min_sdk", None), getattr(basic, "target_sdk", None)),
                scope=_apk_digest(apk_path))

        vulnerability_results = {
            "vulnerabilities": vulnerabilities,
            "analysis_success": analysis_success,
            "chains": [c.get("chain", {}) for c in chains],
        }

        try:
            provider = getattr(analyzer, "ai_provider", None)
            if provider is not None and hasattr(provider, "usage_summary"):
                analyzer_results["llm_usage"] = provider.usage_summary()
        except Exception as exc:
            verbose_print(f"Could not record LLM usage: {exc}", self.verbose)

        self.progress("reporting", 92, "Generating JSON report")
        json_path = None
        try:
            from ...report_generator.json_exporter import JSONExporter

            json_path = JSONExporter(verbose=self.verbose).export_analysis_results(
                detection_result=detection_result,
                output_path=apk_path,
                vulnerability_results=vulnerability_results,
                analyzer_results=analyzer_results,
                output_manager=output_manager,
            )
        except Exception as exc:
            verbose_print(f"JSON export failed: {exc}", self.verbose)

        self.progress("finalizing", 98, "Finalizing results")
        result = build_result(
            json_path=json_path,
            detection_result=detection_result,
            analyzer_results=analyzer_results,
            supported=supported,
            framework_name=framework_name,
            dynamic_session=dynamic_session,
        )

        if provider_outage(result):
            verbose_print(
                "AI provider quota exhausted or provider unreachable; skipping working-file "
                "cleanup so this scan stays resumable", self.verbose)
        else:
            self._cleanup_working_files(output_manager)
        return result

    def _pick_device(self) -> Optional[str]:
        """
        Purpose:
            Choose a device for the dynamic phase.

        Returns:
            A device serial, or None when none is attached.

        Implementation notes:
            An emulator is preferred over a physical device. The dynamic phase installs a CA and runs an untrusted app as root, and doing that to a disposable emulator is the safer default when the user has not chosen explicitly. Discovery failures return None rather than raising, so a machine without the platform tools simply skips verification.
        """
        try:
            from ...dynamic_analysis import ADBManager
            devices = ADBManager(verbose=self.verbose).list_devices()
        except Exception as exc:
            verbose_print(f"Device discovery failed: {exc}", self.verbose)
            return None
        if not devices:
            return None
        emulator = next((d for d in devices if d.get("is_emulator")), None)
        chosen = emulator or devices[0]
        return chosen.get("serial")

    def _grade_findings(self, vulnerabilities: List[Dict[str, Any]],
                        ai_provider, app_note: str = "", scope: str = "") -> List[Dict[str, Any]]:
        """
        Purpose:
            Deduplicate, gate, review and chain the findings.

        Parameters:
            vulnerabilities: Raw findings from the analysis.
            ai_provider: Provider for the review passes.
            app_note: The app's declared SDK levels, told to the review passes.
            scope: The APK's digest, so a cached verdict is reused only for this same app.

        Returns:
            The graded findings, ordered for the report.

        Side effects:
            Makes provider requests and mutates the findings.

        Implementation notes:
            The cheaper model is used where one is configured, since grading is many small judgements rather than one deep analysis. Token usage is sampled before and after, so the report can attribute what grading cost separately from the analysis itself.
        """
        from ...validation import (
            annotate_related_findings, build_chains, sort_findings,
            validate_findings)

        judge_provider = _cheap_provider_or_same(ai_provider, self.verbose)
        tokens_before = getattr(judge_provider, "usage", {}).get("completion_tokens", 0)

        try:
            self.progress("validating", 88, "Validating findings")
            _run_named("validation", lambda: validate_findings(
                vulnerabilities, provider=judge_provider, app_note=app_note, scope=scope,
                verbose=self.verbose, is_cancelled=self.is_cancelled,
                progress=lambda phase, unused_percent, message="":
                    self.progress(phase, 88, message)))
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Validation failed ({exc}); reporting findings ungraded",
                          self.verbose)

        try:
            related = annotate_related_findings(vulnerabilities)
            if related:
                verbose_print(
                    f"Cross-referenced {plural(related, 'related finding pair')}",
                    self.verbose)
        except Exception as exc:
            verbose_print(f"Relating findings failed ({exc}); continuing", self.verbose)

        chains: List[Dict[str, Any]] = []
        try:
            self.progress("chaining", 90, "Looking for exploit chains")
            chains = _run_named("chains", lambda: build_chains(
                vulnerabilities, provider=judge_provider,
                verbose=self.verbose, is_cancelled=self.is_cancelled)) or []
            if chains:
                _run_named("chains", lambda: validate_findings(
                    chains, provider=None, verbose=self.verbose))
                self.progress("chaining", 91,
                              f"{plural(len(chains), 'exploit chain')} confirmed")
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Chain building failed ({exc}); continuing", self.verbose)
            chains = []

        vulnerabilities.extend(chains)
        vulnerabilities[:] = sort_findings(vulnerabilities)
        tokens_after = getattr(judge_provider, "usage", {}).get("completion_tokens", 0)
        if tokens_after > tokens_before:
            verbose_print(
                f"Grading (validation + chains) output: "
                f"{tokens_after - tokens_before} completion tokens", self.verbose)
        return chains

    def _run_dynamic_phase(
        self, *, device: str, detection_result, apk_path: str,
        jadx_output_dir, vulnerabilities: List[Dict[str, Any]],
        static_transcript: str, ai_provider, code_graph=None,
    ) -> Dict[str, Any]:
        """
        Purpose:
            Run the on-device phase: verify the static findings, then exercise the app.

        Parameters:
            device: Device serial.
            detection_result: Detection output.
            apk_path: Path to the APK.
            jadx_output_dir: Decompiled source root.
            vulnerabilities: Findings to verify.
            static_transcript: The static phase's reasoning.
            ai_provider: Provider for the verification agent.
            code_graph: Code graph for structural hints.

        Returns:
            The session results.

        Side effects:
            Installs and drives the app, and modifies device state.

        Implementation notes:
            A missing package name stops the phase immediately with a stated reason, since nothing on the device can be targeted without it. Each precondition that fails records why rather than silently skipping, so the report distinguishes "not verified because there was no device" from "not verified because nothing needed verifying".
        """
        basic_info = getattr(detection_result, "basic_info", None)
        package = getattr(basic_info, "package_name", None) if basic_info else None
        if not package:
            reason = "Could not determine the app's package name from static analysis."
            return {"attempted": False, "reason": reason}

        from ...dynamic_analysis import ADBManager, FridaManager
        adb = ADBManager(verbose=self.verbose)
        frida = FridaManager(verbose=self.verbose)

        session: Dict[str, Any] = {}
        installed = False
        if vulnerabilities and jadx_output_dir:
            session = self._verify_findings(
                device=device, package=package, apk_path=apk_path,
                jadx_output_dir=jadx_output_dir, vulnerabilities=vulnerabilities,
                static_transcript=static_transcript, ai_provider=ai_provider,
                code_graph=code_graph, adb=adb, frida=frida)
            installed = bool(session.get("install", {}).get("ok"))
        elif not jadx_output_dir:
            session = {"attempted": False,
                       "reason": "Decompiled sources were not available for verification."}
        else:
            session = {"attempted": False, "reason": "No static findings to verify."}

        session["environment"] = self._run_device_session(
            device=device, package=package, apk_path=apk_path,
            vulnerabilities=vulnerabilities, installed=installed,
            adb=adb, frida=frida, frida_env=session.get("frida"))
        if session["environment"].get("attempted"):
            session["attempted"] = True
        return session

    def _verify_findings(
        self, *, device: str, package: str, apk_path: str, jadx_output_dir,
        vulnerabilities: List[Dict[str, Any]], static_transcript: str,
        ai_provider, code_graph=None, adb=None, frida=None,
    ) -> Dict[str, Any]:
        """
        Purpose:
            Run the verification agent against the device to settle the static findings.

        Parameters:
            device: Device serial.
            package: Package under test.
            apk_path: Path to the APK.
            jadx_output_dir: Decompiled source root.
            vulnerabilities: Findings to verify, mutated with their verdicts.
            static_transcript: The static phase's reasoning.
            ai_provider: Provider for the agent.
            code_graph: Code graph for structural hints.
            adb: Device manager.
            frida: Instrumentation manager.

        Returns:
            The verification session results.

        Side effects:
            Installs the app, runs instrumentation, and mutates the findings.

        Implementation notes:
            The static transcript is passed through so the agent knows what has already been established and does not repeat that reasoning on the device, where every step is far more expensive.
        """
        try:
            from ...dynamic_analysis import run_dynamic_verification
            self.progress("device_check", 63,
                          f"Preparing dynamic verification on {device}…")
            memory = user_settings.get_agent_memory()
            _, session = run_dynamic_verification(
                provider=ai_provider,
                device=device,
                package=package,
                apk_path=apk_path,
                jadx_output_dir=jadx_output_dir,
                findings=vulnerabilities,
                static_transcript=static_transcript if memory else "",
                code_graph=code_graph,
                progress=lambda phase, percent, message="": self.progress(phase, percent, message),
                is_cancelled=self.is_cancelled,
                verbose=self.verbose,
                adb=adb,
                frida=frida,
                triage_provider=_cheap_provider_or_same(ai_provider, self.verbose),
            )
            self.progress(
                "dynamic_done", 88,
                f"Dynamic verification complete - {session.get('verified_count', 0)}/"
                f"{plural(session.get('total_count', 0), 'finding')} verified")
            session["attempted"] = True
            return session
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Dynamic verification failed: {exc}", self.verbose)
            self._strip_verify_ids(vulnerabilities)
            return {"attempted": False, "reason": f"Dynamic verification failed: {exc}"}

    def _run_device_session(
        self, *, device: str, package: str, apk_path: str,
        vulnerabilities: List[Dict[str, Any]], installed: bool,
        adb=None, frida=None, frida_env=None,
    ) -> Dict[str, Any]:
        """
        Purpose:
            Run the exploratory device session after verification.

        Parameters:
            device: Device serial.
            package: Package under test.
            apk_path: Path to the APK.
            vulnerabilities: Findings so far.
            installed: Whether the app is already installed.
            adb: Device manager.
            frida: Instrumentation manager.
            frida_env: The verification phase's instrumentation result, reused when it succeeded.

        Returns:
            The session results.

        Side effects:
            Drives the app, intercepts traffic, and may produce runtime findings.

        Implementation notes:
            The instrumentation result is reused rather than re-established, since redeploying the server would cost a minute and change nothing. A narrow interaction budget is used here because verification has already had its turn; this pass is for observing behaviour rather than settling specific claims.
        """
        from ...dynamic_analysis import ADBManager, DynamicAnalyzer

        adb = adb or ADBManager(verbose=self.verbose)
        try:
            if not installed:
                ok, message = adb.install_apk(device, apk_path, package=package)
                if not ok:
                    verbose_print(f"Device session: install failed: {message}", self.verbose)
                    return {"attempted": False,
                            "reason": f"Could not install the app on the device: {message}"}

            span = _SESSION_PROGRESS_END - _SESSION_PROGRESS_START

            def _progress(phase: str, percent: int, message: str = "") -> None:
                """
                Purpose:
                    Map the device session's own progress onto the scan's overall progress range.

                Parameters:
                    phase: Stage identifier.
                    percent: Completion within the session.
                    message: Human-readable description.

                Implementation notes:
                    The session reports zero to a hundred for itself, which is scaled into the narrow band the scan reserves for it. Without the scaling, the overall progress bar would jump back to near zero when the session started.
                """
                scaled = _SESSION_PROGRESS_START + round(percent * span / 100)
                self.progress(phase, scaled, message)

            analyzer = DynamicAnalyzer(verbose=self.verbose, progress=_progress,
                                       is_cancelled=self.is_cancelled, adb=adb, frida=frida)
            result = analyzer.run(device, package, ui_steps=_SESSION_UI_STEPS,
                                  skip_app_info=True, frida_env=frida_env)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"On-device session failed: {exc}", self.verbose)
            return {"attempted": False, "reason": f"On-device session failed: {exc}"}

        runtime_findings = result.get("runtime_findings") or []
        vulnerabilities.extend(runtime_findings)
        actions = result.get("actions") or []
        self.progress(
            "session_done", _SESSION_PROGRESS_END,
            f"On-device session complete - {plural(len(actions), 'UI action')}, "
            f"{plural(len(runtime_findings), 'runtime finding')}")
        return {
            "attempted": True,
            "device": result.get("device"),
            "env_checks": result.get("env_checks", {}),
            "actions": actions,
            "runtime_findings": runtime_findings,
        }

    @staticmethod
    def _strip_verify_ids(vulnerabilities: List[Dict[str, Any]]) -> None:
        """
        Purpose:
            Remove the temporary identifiers verification attached to the findings.

        Parameters:
            vulnerabilities: The findings, mutated in place.

        Implementation notes:
            These exist only so the agent can refer to findings by a short name during verification. Left in place they would reach the report and the stored result as a meaningless field.
        """
        for v in vulnerabilities:
            v.pop("_verify_id", None)

    def _cleanup_deferred(self, analyzer, jadx_output_dir) -> None:
        """
        Purpose:
            Remove the decompiled output once the scan no longer needs it.

        Parameters:
            analyzer: The analyzer, consulted for its working directory.
            jadx_output_dir: Decompiled source root.

        Side effects:
            Recursively deletes directories, unless verbose is set.

        Implementation notes:
            Decompiled output for a large app is hundreds of megabytes, and keeping it for every scan would fill a disk quickly. Verbose preserves it, which is the documented way to inspect what the analysis actually read. Deferred until the end because the dynamic phase reads the same sources during verification.
        """
        if self.verbose:
            return
        import shutil
        for directory in (jadx_output_dir, getattr(analyzer, "apk_dir", None)):
            try:
                if directory and Path(directory).exists():
                    shutil.rmtree(directory)
                    verbose_print(f"Cleaned up directory: {directory}", self.verbose)
            except Exception as exc:
                verbose_print(f"Warning: could not clean up {directory}: {exc}", self.verbose)

    def _cleanup_working_files(self, output_manager) -> None:
        """
        Purpose:
            Remove the intermediate directories a scan produced, keeping the reports.

        Parameters:
            output_manager: Supplies the output directory and the naming scheme.

        Side effects:
            Recursively deletes matching directories, unless verbose is set.

        Implementation notes:
            Matched by the output manager's own naming patterns, scoped to this scan's APK name, so only directories this scan created are removed and a neighbouring scan's output in the same folder is untouched. The reports and the JSON export are deliberately not matched -- those are the scan's product.
        """
        if self.verbose or output_manager is None:
            return
        import shutil
        folder = output_manager.get_output_dir()
        apk_name = output_manager.get_apk_name() or ""
        if not folder or not Path(folder).exists():
            return
        folder = Path(folder)
        for pattern in (f"{apk_name}_jadx_output_*", f"{apk_name}_dynamic_*",
                       f"{apk_name}_flutter_libs_*", f"{apk_name}_flutter_output_*",
                       f"{apk_name}_rn_bundle_*", f"{apk_name}_rn_output_*"):
            for path in folder.glob(pattern):
                try:
                    if path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                except Exception as exc:
                    verbose_print(f"Cleanup: could not remove {path}: {exc}", self.verbose)
        for pattern in ("*.apk", f"{apk_name}_Ollama_Request_Response_*.md"):
            for path in folder.glob(pattern):
                try:
                    path.unlink(missing_ok=True)
                except Exception as exc:
                    verbose_print(f"Cleanup: could not remove {path}: {exc}", self.verbose)
        verbose_print(f"Cleaned up working files in {folder}", self.verbose)
