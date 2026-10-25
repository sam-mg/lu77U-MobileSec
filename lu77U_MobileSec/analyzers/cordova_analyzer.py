#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.cordova_analyzer

Purpose:
    Analyse a Cordova app by examining its bundled web assets, which hold the application logic, rather than the Dalvik shell around them.

Responsibilities:
    Extract the web assets, build a graph over them, and run the analysis phases.

Dependencies:
    The APK payload extractor.

Implementation notes:
    Cordova needs no external decompiler: the JavaScript and HTML ship in readable form inside the APK, so this analyzer has no preflight requirement and always runs. The interesting surface is the plugin bridge and the origins the WebView is configured to allow, which is why the configuration file is extracted alongside the assets.
"""

import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .agent.profiles import CORDOVA
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.apk_payload import extract_cordova_www
from ..utils.cancellation import ScanCancelled
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..utils.verbose import plural, verbose_print


class CordovaAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses Cordova and PhoneGap apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "Cordova"
    profile = CORDOVA

    def __init__(self, verbose: bool = False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the Cordova analyzer.

        Parameters:
            verbose: Enables tracing and preserves working files.
            progress: Reports phase progress.
            is_cancelled: Polled between phases.
        """
        super().__init__(verbose=verbose, progress=progress, is_cancelled=is_cancelled)
        self.apk_base = None
        self.source_root = None
        self.output_manager = OutputManager(verbose=verbose)

    def preflight(self, apk_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Purpose:
            Report readiness; this analyzer has no external requirements.

        Parameters:
            apk_path: The APK about to be scanned; unused here, since this analyzer's requirements do not depend on how the app was built.

        Returns:
            Always ready.

        Implementation notes:
            Cordova assets are plain text inside the APK, so nothing has to be installed for this path to work.
        """
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Extract the app's web assets and analyse them.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the extracted assets for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts web assets, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            The directory structure of the assets is preserved, since Cordova code resolves relative paths between its own files and a flattened tree would break both the analysis and the reader's ability to follow it.

        Security considerations:
            Extraction goes through the containment-checked path, so a crafted archive entry cannot write outside the output directory.
        """
        verbose_print("Starting Cordova APK analysis...", self.verbose)
        self.output_manager.create_output_directory(apk_path)
        self.apk_base = Path(apk_path).stem

        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base,
        )

        www_dir = self.output_manager.get_cordova_www_dir()
        try:
            analysis_start = time.time()

            self.progress("extracting", 35, "Extracting the app's web assets (assets/www) from the APK…")
            extracted = extract_cordova_www(apk_path, www_dir, verbose=self.verbose)
            if extracted is None:
                return self._failure(
                    "No Cordova web assets (assets/www/) were found in this APK - "
                    "it may not be a Cordova/PhoneGap app after all.")
            self.source_root = www_dir
            self.progress("decompiling", 58, "Web assets extracted")

            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the app's web layer…")
            from .cordova.graph import build_cordova_graph
            code_graph = build_cordova_graph(self.source_root, verbose=self.verbose)
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'page or script', 'pages and scripts')}")

            checkpoint = getattr(self, "checkpoint", None)
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "over this app's web assets. Cordova has no full-dump fallback - try "
                    "a different model or provider.")

            files_analyzed = sum(
                1 for _ in Path(self.source_root).rglob("*")
                if _.is_file() and _.suffix.lower() in (".js", ".html", ".htm"))
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
                self._cleanup([self.source_root])

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
            verbose_print(f"Cordova analysis failed: {e}", self.verbose)
            if not self.verbose:
                self._cleanup([self.source_root])
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
