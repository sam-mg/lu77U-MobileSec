#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.flutter_analyzer

Purpose:
    Analyse a Flutter app by recovering Dart structure from the AOT snapshot, since none of the application's logic is in the Dalvik bytecode.

Responsibilities:
    Check that Blutter is configured, extract the native payload, run Blutter, build a graph over the recovered output, and run the analysis phases.

Dependencies:
    Blutter through its runner, the APK payload extractor.

Implementation notes:
    Flutter compiles Dart to a machine-code snapshot in libapp.so, so the usual decompilation path finds only generated plugin bindings. What Blutter recovers is class and method structure with strings rather than readable source, which is less than Java decompilation gives -- the analysis is correspondingly shallower and the report says so.
"""

import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .agent.profiles import FLUTTER
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.apk_payload import available_native_abis, extract_native_libs
from ..decompiler.blutter_runner import run_blutter
from ..utils.cancellation import ScanCancelled
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..utils.verbose import plural, verbose_print

class FlutterAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses Flutter apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.

    Invariants:
        Produces a result in the standard shape whether or not the recovery succeeded.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "Flutter"
    profile = FLUTTER

    def __init__(self, verbose: bool = False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the Flutter analyzer.

        Parameters:
            verbose: Enables tracing and preserves working files.
            progress: Reports phase progress.
            is_cancelled: Polled between phases.
        """
        super().__init__(verbose=verbose, progress=progress, is_cancelled=is_cancelled)
        self.apk_base = None
        self.source_root = None
        self.output_manager = OutputManager(verbose=verbose)

    def preflight(self) -> Tuple[bool, str]:
        """
        Purpose:
            Check that Blutter is configured.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            Checked before the APK is touched, since without Blutter there is nothing this analyzer can do and the reason names the setting to configure.
        """
        from ..tools_checker.blutter_checker import check_blutter_configured
        if not check_blutter_configured(verbose=self.verbose):
            return False, ("Blutter is not configured. Set blutter_path in Settings "
                           "to blutter.py from a Blutter checkout.")
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Recover the app's Dart structure and analyse it.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the recovered output for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts native libraries, runs Blutter, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            Only one architecture is extracted, because Blutter supports arm64 and the other slices are the same code compiled differently. Two preconditions are checked with distinct messages: the APK may ship no arm64 slice at all, or it may ship one that contains no Dart payload. Those are different problems for the user -- the first is an unsupported build, the second means the app is probably not Flutter -- and one combined message would leave them guessing.
        """
        verbose_print("Starting Flutter APK analysis...", self.verbose)
        self.output_manager.create_output_directory(apk_path)
        self.apk_base = Path(apk_path).stem

        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base,
        )

        lib_dir = self.output_manager.get_flutter_lib_dir()
        try:
            analysis_start = time.time()

            self.progress("extracting", 35, "Extracting native libraries from the APK…")
            extracted = extract_native_libs(apk_path, lib_dir, verbose=self.verbose)
            if extracted is None:
                present = available_native_abis(apk_path)
                return self._failure(
                    "Blutter only supports arm64-v8a, and this APK doesn't ship an "
                    f"arm64-v8a native library (found: {present or 'none'}).")
            if not (extracted / "libapp.so").is_file():
                return self._failure(
                    "No libapp.so found in this APK's arm64-v8a native libraries - "
                    "this doesn't look like a Flutter app's native payload.")

            self.progress("decompiling", 45,
                          "Running Blutter (may compile the Dart SDK on first use "
                          "against a new Dart version - this can take a while)…")
            out_dir = self.output_manager.get_flutter_output_dir()
            decompiled = run_blutter(extracted, out_dir, verbose=self.verbose)
            if decompiled is None:
                return self._failure(
                    "Blutter could not disassemble this app's Dart AOT binary - check "
                    "that blutter_path points at a working install and that this "
                    "Dart/Flutter version is one Blutter supports.")
            self.source_root = out_dir
            self.progress("decompiling", 58, "Blutter disassembly complete")

            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the disassembly…")
            from .flutter.graph import build_flutter_graph
            code_graph = build_flutter_graph(self.source_root, verbose=self.verbose)
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'node')}")

            checkpoint = getattr(self, "checkpoint", None)
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "over Blutter's output. Flutter has no full-dump fallback - try a "
                    "different model or provider.")

            files_analyzed = sum(1 for _ in Path(self.source_root).rglob("*") if _.is_file())
            verbose_print(f"Agentic analysis produced {plural(len(vulnerabilities), 'finding')}", self.verbose)
            self.progress("agentic_done", 82, f"Agentic process completed - {plural(len(vulnerabilities), 'finding')}")

            self.progress("agentic_done", 84, "Running deterministic scanners…")
            vulnerabilities = self.merge_findings(
                vulnerabilities, self.run_sast(self.source_root, apk_path=apk_path))

            analysis_time = time.time() - analysis_start
            if vulnerabilities:
                self.enrich_vulnerabilities(vulnerabilities, self.source_root)
                display_vulnerabilities(vulnerabilities, self.verbose)
            else:
                verbose_print("No vulnerabilities found!", self.verbose)
            verbose_print(f"Total time taken: {analysis_time:.2f} seconds", self.verbose)

            if not self.verbose and not defer_cleanup:
                self._cleanup([lib_dir, self.source_root])

            return {
                'success': True,
                'vulnerabilities': vulnerabilities or [],
                'analysis_time': analysis_time,
                'files_analyzed': files_analyzed,
                'framework': self.framework_label,
                'output_manager': self.output_manager,
                'jadx_output_dir': self.source_root,
                'source_root': self.source_root,
                'static_transcript': static_transcript,
                'agent_coverage': getattr(self, 'agent_coverage', {}),
                'code_graph': code_graph,
            }
        except ScanCancelled:
            raise
        except Exception as e:
            verbose_print(f"Flutter analysis failed: {e}", self.verbose)
            if not self.verbose:
                self._cleanup([lib_dir, self.source_root])
            return {
                'success': False,
                'vulnerabilities': [],
                'analysis_time': 0,
                'files_analyzed': 0,
                'framework': self.framework_label,
                'error': str(e),
            }

    def _failure(self, message: str) -> Dict[str, Any]:
        """
        Purpose:
            Build the result for an analysis that could not run.

        Parameters:
            message: Why it could not run.

        Returns:
            A result in the normal shape, marked unsuccessful and carrying the reason.

        Implementation notes:
            Returned rather than raised, and in the same shape as a successful result, so the caller reports the app with an explanation instead of losing the scan. The reason reaches the report, so it is written for the person reading it rather than as a diagnostic.
        """
        verbose_print(message, self.verbose)
        return {
            'success': False,
            'vulnerabilities': [],
            'analysis_time': 0,
            'files_analyzed': 0,
            'framework': self.framework_label,
            'error': message,
        }

    def _cleanup(self, directories: List) -> None:
        """
        Purpose:
            Remove the working directories this analysis created.

        Parameters:
            directories: Directories to remove; empty entries are skipped.

        Side effects:
            Recursively deletes directories.

        Implementation notes:
            Each removal is guarded, so one failure does not leave the rest behind. Extracted payloads and decompiler output are large, and keeping them for every scan would fill a disk.
        """
        for directory in directories:
            if not directory:
                continue
            try:
                path = Path(directory)
                if path.exists():
                    shutil.rmtree(path)
                    verbose_print(f"Cleaned up directory: {path}", self.verbose)
            except Exception as exc:
                verbose_print(f"Warning: could not clean up {directory}: {exc}", self.verbose)
