"""UI-agnostic wrapper around the existing analysis engine."""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ...config import user_settings
from ...detection.detector import MobileSecurityDetector
from ...utils.cancellation import ScanCancelled
from ...utils.output_manager import OutputManager
from ...utils.verbose import verbose_print
from ..serializers import build_result

UNSUPPORTED_FRAMEWORKS = {
    "cordova", "kony", "kony visualizer", "libgdx", "unity", "unreal",
    "xamarin", "flutter", "react native", "expo",
}

class AnalysisService:
    """Run one APK through detection → static analysis → dynamic verification
    → reporting and return a DTO."""

    def __init__(self, verbose: bool = False,
                 progress: Optional[Callable[..., None]] = None,
                 is_cancelled: Optional[Callable[[], bool]] = None):
        self.verbose = verbose
        self._progress = progress or (lambda **kw: None)
        self.is_cancelled = is_cancelled or (lambda: False)

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        try:
            self._progress(phase=phase, percent=percent, message=message)
        except ScanCancelled:
            raise
        except Exception:
            pass

    def run(self, apk_path: str) -> Dict[str, Any]:
        self.progress("detecting", 10, "Detecting framework and reading the manifest")
        detector = MobileSecurityDetector(verbose=self.verbose)
        detection_result = detector.detect(apk_path)
        if not detection_result:
            raise RuntimeError("Framework detection failed — no result returned")

        framework_name = "generic"
        if detection_result.framework_results:
            primary = detection_result.framework_results.get_primary_framework_name()
            framework_name = primary if primary != "Unknown" else "generic"

        supported = framework_name.lower() not in UNSUPPORTED_FRAMEWORKS

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
            want_dynamic = user_settings.get_dynamic_verification()
            device = self._pick_device() if want_dynamic else None

            self.progress("analyzing", 40,
                          "Decompiling APK and analyzing Java/Kotlin sources")
            from ...analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer

            analyzer = JavaKotlinAnalyzer(
                verbose=self.verbose,
                progress=lambda phase, percent, message="": self.progress(phase, percent, message),
            )
            analysis_result = analyzer.analyze_java_kotlin_apk(
                apk_path, defer_cleanup=bool(device))
            jadx_output_dir = None
            static_transcript = ""
            code_graph = None
            if isinstance(analysis_result, dict):
                analysis_success = analysis_result.get("success", False)
                vulnerabilities = analysis_result.get("vulnerabilities", []) or []
                output_manager = analysis_result.get("output_manager")
                jadx_output_dir = analysis_result.get("jadx_output_dir")
                static_transcript = analysis_result.get("static_transcript", "") or ""
                code_graph = analysis_result.get("code_graph")
                analyzer_results = {
                    "framework": analysis_result.get("framework", "Java/Kotlin"),
                    "analysis_time": analysis_result.get("analysis_time", 0),
                    "files_analyzed": analysis_result.get("files_analyzed", 0),
                    "decompilation_status": "Successful" if analysis_success else "Failed",
                    "error": analysis_result.get("error"),
                }

            if analysis_success:
                if device and jadx_output_dir:
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
                    self._cleanup_deferred(analyzer, jadx_output_dir)
                else:
                    reason = ("Dynamic verification is disabled in Settings."
                              if not want_dynamic else
                              "No emulator/device connected.")
                    # Dynamic verification didn't run at all — leave findings
                    # without a dynamic_verification key (no per-finding badge);
                    # the reason is surfaced once via dynamic_session.
                    dynamic_session = {"attempted": False, "reason": reason}
        else:
            verbose_print(
                f"Framework '{framework_name}' is not yet supported for deep "
                f"analysis — producing a detection-only report.", self.verbose)
            analyzer_results["unsupported_framework"] = True
            analyzer_results["decompilation_status"] = "Unsupported Framework"

        # Ensure we have an OutputManager so reports land in one scan folder.
        if output_manager is None:
            output_manager = OutputManager(verbose=self.verbose)
            output_manager.create_output_directory(apk_path)

        vulnerability_results = {
            "vulnerabilities": vulnerabilities,
            "analysis_success": analysis_success,
        }

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
        except Exception as exc:  # pragma: no cover - reporting is best-effort
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

        self._cleanup_working_files(output_manager)
        return result

    def _pick_device(self) -> Optional[str]:
        """Best-effort device discovery; prefers an emulator over a physical
        device when both are attached. Never raises — a missing ``adb``
        binary or a discovery error just means Phase 2 doesn't run."""
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

    def _run_dynamic_phase(
        self, *, device: str, detection_result, apk_path: str,
        jadx_output_dir, vulnerabilities: List[Dict[str, Any]],
        static_transcript: str, ai_provider, code_graph=None,
    ) -> Dict[str, Any]:
        """Run Phase 2 against ``device``; annotates the verified findings in
        place and returns the session summary. Best-effort: any failure here just
        leaves findings without a dynamic_verification badge rather than failing
        the whole scan — Phase 1's results are still valid on their own."""
        basic_info = getattr(detection_result, "basic_info", None)
        package = getattr(basic_info, "package_name", None) if basic_info else None
        if not package:
            reason = "Could not determine the app's package name from static analysis."
            return {"attempted": False, "reason": reason}

        if not vulnerabilities:
            return {"attempted": False, "reason": "No static findings to verify."}

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
            )
            self.progress(
                "dynamic_done", 88,
                f"Dynamic verification complete — {session.get('verified_count', 0)}/"
                f"{session.get('total_count', 0)} finding(s) verified")
            session["attempted"] = True
            return session
        except ScanCancelled:
            raise
        except Exception as exc:  # pragma: no cover - device work is best-effort
            verbose_print(f"Dynamic verification failed: {exc}", self.verbose)
            reason = f"Dynamic verification failed: {exc}"
            self._strip_verify_ids(vulnerabilities)
            return {"attempted": False, "reason": reason}

    @staticmethod
    def _strip_verify_ids(vulnerabilities: List[Dict[str, Any]]) -> None:
        for v in vulnerabilities:
            v.pop("_verify_id", None)

    def _cleanup_deferred(self, analyzer, jadx_output_dir) -> None:
        """Delete the decompiled tree kept around for Phase 2, mirroring the
        cleanup ``JavaKotlinAnalyzer`` itself would have done immediately if
        ``defer_cleanup`` hadn't been requested."""
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
        """After a normal (non-verbose) run, remove the bulky working files from
        the scan folder, keeping only the JSON (meta.json + result.json are
        written by the web store; the engine's analysis JSON stays too). ``-V``
        keeps everything for debugging. Idempotent — safe even if some parts were
        already cleaned (e.g. the decompiled tree via ``_cleanup_deferred``)."""
        if self.verbose or output_manager is None:
            return
        import shutil
        folder = output_manager.get_output_dir()
        apk_name = output_manager.get_apk_name() or ""
        if not folder or not Path(folder).exists():
            return
        folder = Path(folder)
        for pattern in (f"{apk_name}_jadx_output_*", f"{apk_name}_dynamic_*"):
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