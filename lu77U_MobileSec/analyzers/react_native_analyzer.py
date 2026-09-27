#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.react_native_analyzer

Purpose:
    Analyse a React Native app by recovering its JavaScript bundle, which is where the application logic lives.

Responsibilities:
    Locate and extract the bundle, choose the right decompiler for its format, run it, and analyse the result.

Dependencies:
    The Hermes decompiler and the plain-JavaScript decompiler, either of which suffices.

Implementation notes:
    React Native ships its bundle in two forms -- plain JavaScript or Hermes bytecode -- and they need different tools. Which one applies is not knowable until the bundle is extracted and its magic bytes read, which is why preflight accepts either tool being configured rather than requiring a specific one.
"""

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .agent.profiles import REACT_NATIVE
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.apk_payload import extract_member, find_js_bundle, is_hermes
from ..decompiler.hermes_runner import decompile_hbc
from ..decompiler.rn_bundle_decompiler import decompile_js_bundle
from ..utils.cancellation import ScanCancelled
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..utils.verbose import plural, verbose_print

class ReactNativeAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses React Native and Expo apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "React Native"
    profile = REACT_NATIVE

    def __init__(self, verbose: bool = False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the React Native analyzer.

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
            Check that at least one bundle decompiler is configured.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            Either tool is enough to proceed, because the bundle format is only discovered after extraction. The message says so explicitly rather than naming one tool, so a user who configures the wrong one understands why the scan still failed later.
        """
        from ..tools_checker.hermes_checker import check_hermes_configured
        from ..tools_checker.rn_decompiler_checker import check_rn_decompiler_configured
        hermes_ok = check_hermes_configured(verbose=self.verbose)
        rn_ok = check_rn_decompiler_configured(verbose=self.verbose)
        if not hermes_ok and not rn_ok:
            return False, (
                "Neither hermes-decomp nor react-native-decompiler is configured. "
                "Set hermes_decomp_path (for Hermes-compiled bundles) or "
                "rn_decompiler_path (for plain-JS bundles) in Settings - which one "
                "you need depends on how this app's bundle was built, and is only "
                "known once the bundle is extracted.")
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Recover the app's JavaScript and analyse it.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the recovered sources for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts the bundle, runs a decompiler, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            The bundle is located by convention and then by extension, since apps do rename it and failing on the name would mean not analysing the app at all. The format is decided by the bundle's magic bytes rather than its name, because both forms ship under the same filename. That decides which decompiler runs, and a missing one for the format actually present is reported as such.
        """
        verbose_print("Starting React Native APK analysis...", self.verbose)
        self.output_manager.create_output_directory(apk_path)
        self.apk_base = Path(apk_path).stem

        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base,
        )

        bundle_dir = self.output_manager.get_rn_bundle_dir()
        try:
            analysis_start = time.time()

            self.progress("extracting", 35, "Extracting the JavaScript bundle from the APK…")
            bundle_member = find_js_bundle(apk_path, verbose=self.verbose)
            if not bundle_member:
                return self._failure("No JavaScript bundle found in this APK's assets.")

            bundle_path = extract_member(apk_path, bundle_member, bundle_dir, verbose=self.verbose)
            if not bundle_path:
                return self._failure("Could not extract the JavaScript bundle from the APK.")

            hermes = is_hermes(bundle_path)
            verbose_print(
                f"Bundle format: {'Hermes bytecode' if hermes else 'plain JavaScript'}",
                self.verbose)

            self.progress("decompiling", 45,
                          f"Decompiling the {'Hermes' if hermes else 'JavaScript'} bundle…")
            out_dir = self.output_manager.get_rn_output_dir()
            if hermes:
                decompiled = decompile_hbc(bundle_path, out_dir, verbose=self.verbose)
                if decompiled is None:
                    return self._failure(
                        "hermes-decomp could not decompile this Hermes bundle - an "
                        "unsupported bytecode version, or hermes_decomp_path doesn't "
                        "point at a working install.")
            else:
                decompiled = decompile_js_bundle(bundle_path, out_dir, verbose=self.verbose)
                if decompiled is None:
                    return self._failure(
                        "react-native-decompiler could not decompile this bundle - it "
                        "may be a Webpack v5 bundle (unsupported), or rn_decompiler_path "
                        "doesn't point at a working install.")
            self.source_root = out_dir
            self.progress("decompiling", 58, "Decompilation complete")
            self._write_bundle_metadata(out_dir, bundle_member, hermes)

            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the decompiled bundle…")
            from .react_native.graph import build_rn_graph
            code_graph = build_rn_graph(self.source_root, verbose=self.verbose)
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'module')}")

            checkpoint = getattr(self, "checkpoint", None)
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "for this bundle. React Native has no full-dump fallback - try a "
                    "different model or provider.")

            files_analyzed = sum(1 for _ in Path(self.source_root).rglob("*.js"))
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
                self._cleanup([bundle_dir, self.source_root])

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
            verbose_print(f"React Native analysis failed: {e}", self.verbose)
            if not self.verbose:
                self._cleanup([bundle_dir, self.source_root])
            return {
                'success': False,
                'vulnerabilities': [],
                'analysis_time': 0,
                'files_analyzed': 0,
                'framework': self.framework_label,
                'error': str(e),
            }

    def _write_bundle_metadata(self, out_dir, bundle_member: str, hermes: bool) -> None:
        """
        Purpose:
            Record which archive entry the bundle came from and what format it was in.

        Parameters:
            out_dir: Where the recovered sources were written.
            bundle_member: The archive entry the bundle came from.
            hermes: Whether it was Hermes bytecode.

        Side effects:
            Writes a metadata file beside the recovered sources.

        Implementation notes:
            Written because the recovered output alone does not say where it came from, and a reader looking at reconstructed JavaScript needs to know whether it was decompiled from bytecode -- which is far less faithful -- or merely unbundled. A write failure is traced rather than raised, since the metadata is a convenience and the sources are the product.
        """
        meta = {"bundle_member": bundle_member, "format": "hermes" if hermes else "javascript"}
        try:
            (Path(out_dir) / "package-metadata.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8")
        except OSError as exc:
            verbose_print(f"Could not write bundle metadata: {exc}", self.verbose)

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
