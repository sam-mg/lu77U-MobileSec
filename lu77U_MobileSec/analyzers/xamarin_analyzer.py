#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.xamarin_analyzer

Purpose:
    Analyse a Xamarin or MAUI app by recovering its managed .NET assemblies and decompiling them to C#, falling back to assembly strings when no decompiler is available.

Responsibilities:
    Extract the assemblies, decompile the app's own, build a graph, and analyse.

Dependencies:
    The Xamarin extractor and the .NET decompiler runner.

Implementation notes:
    This is the one analyzer with a genuinely useful degraded mode. Without a .NET decompiler the extracted assemblies still yield their string constants, which surface hardcoded URLs and credentials -- most of what a static pass finds in a Xamarin app anyway. So the decompiler is not a preflight requirement.
"""

import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .agent.profiles import XAMARIN
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.ilspy_runner import app_assemblies, decompile_assemblies, resolve_ilspy
from ..decompiler.xamarin_extractor import (
    extract_xamarin_assemblies, summarize_assemblies, write_string_sidecars)
from ..utils.cancellation import ScanCancelled
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..utils.verbose import plural, verbose_print


class XamarinAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses Xamarin and .NET MAUI apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "Xamarin"
    profile = XAMARIN

    def __init__(self, verbose: bool = False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the Xamarin analyzer.

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
            Report readiness; this analyzer runs with or without a .NET decompiler.

        Returns:
            Always ready.

        Implementation notes:
            Deliberately unconditional. The decompiler improves the analysis considerably but its absence degrades to string extraction rather than preventing the scan, and the report records which mode ran.
        """
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Recover the app's managed assemblies and analyse them.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the recovered output for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts assemblies, may run a decompiler, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            Only the app's own assemblies are decompiled; the bundled framework is excluded, since it is identical in every Xamarin app and would take longer than the app itself. When decompilation is unavailable, string sidecars are written beside the assemblies and the analysis proceeds on those.

        Security considerations:
            Assemblies are attacker-controlled executable content. They are extracted and passed to a decompiler as files, never loaded into this process.
        """
        verbose_print("Starting Xamarin APK analysis...", self.verbose)
        self.output_manager.create_output_directory(apk_path)
        self.apk_base = Path(apk_path).stem

        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base,
        )

        assemblies_dir = self.output_manager.get_xamarin_assemblies_dir()
        try:
            analysis_start = time.time()

            self.progress("extracting", 35,
                          "Recovering .NET assemblies from the APK…")
            extracted = extract_xamarin_assemblies(
                apk_path, assemblies_dir, verbose=self.verbose)
            if extracted is None:
                return self._failure(
                    "No .NET assemblies were recovered from this APK. It may not be "
                    "a Xamarin/.NET MAUI app, or it uses an AssemblyStore layout this "
                    "extractor does not yet parse.")
            self.source_root = assemblies_dir

            inventory = summarize_assemblies(self.source_root)
            self._write_inventory(inventory)
            self.progress(
                "extracting", 44,
                f"{plural(len(inventory['assemblies']), 'assembly', 'assemblies')} recovered "
                f"({len(inventory['app_assemblies'])} from the app itself)")

            write_string_sidecars(self.source_root, verbose=self.verbose)

            if resolve_ilspy():
                targets = app_assemblies(self.source_root)
                self.progress("decompiling", 50,
                              f"Decompiling {plural(len(targets), 'app assembly', 'app assemblies')} to C#…")
                decompile_assemblies(self.source_root, self.source_root,
                                     verbose=self.verbose,
                                     is_cancelled=self.is_cancelled)
            else:
                self.progress(
                    "decompiling", 50,
                    "ilspycmd is not configured - analyzing assembly strings instead")

            self.progress("decompiling", 58, "Assemblies ready")
            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the app's "
                          ".NET assemblies…")

            code_graph = self._build_graph()
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'type')}")

            checkpoint = getattr(self, "checkpoint", None)
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "over this app's .NET assemblies. Xamarin has no full-dump "
                    "fallback - try a different model or provider.")

            files_analyzed = sum(
                1 for p in Path(self.source_root).rglob("*")
                if p.is_file() and p.suffix.lower() in (".cs", ".dll"))
            verbose_print(
                f"Agentic analysis produced {plural(len(vulnerabilities), 'finding')}", self.verbose)
            self.progress("agentic_done", 82,
                          f"Agentic process completed - {plural(len(vulnerabilities), 'finding')}")

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
            verbose_print(f"Xamarin analysis failed: {e}", self.verbose)
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

    def _write_inventory(self, inventory: Dict[str, Any]) -> None:
        """
        Purpose:
            Record which assemblies were recovered and what was done with each.

        Parameters:
            inventory: The assembly summary.

        Side effects:
            Writes an inventory file beside the recovered output.

        Implementation notes:
            Written because a Xamarin result is hard to interpret without it: a reader needs to know which assemblies were decompiled, which yielded only strings, and which were skipped as framework code.
        """
        app = inventory.get("app_assemblies") or []
        every = inventory.get("assemblies") or []
        lines = [
            f"App assemblies ({len(app)}) - start here:",
            *(f"  {name}" for name in app),
            "",
            f"Framework/runtime assemblies ({len(every) - len(app)}) - not the app:",
            *(f"  {name}" for name in every if name not in app),
            "",
            "Each <assembly>.dll has a <assembly>.dll.txt of its literal strings.",
            "Where .cs files are present the assembly was decompiled; where they "
            "are not, the .txt sidecar is what there is to read.",
        ]
        try:
            (Path(self.source_root) / "assemblies.txt").write_text(
                "\n".join(lines), encoding="utf-8")
        except OSError as exc:
            verbose_print(f"Could not write the assembly inventory: {exc}", self.verbose)

    def _build_graph(self):
        """
        Purpose:
            Build the structural graph over the recovered output.

        Returns:
            The graph, or None when there was too little to build one.

        Implementation notes:
            Guarded, because graph construction is an enhancement -- it lets the agent phase fan out across regions rather than scanning one tree, and its absence degrades the analysis rather than failing it.
        """
        if not any(Path(self.source_root).rglob("*.cs")):
            verbose_print(
                "No C# was recovered, so no code map is built; the agent works "
                "from the assembly inventory and string sidecars", self.verbose)
            return None
        try:
            from .xamarin.graph import build_xamarin_graph
            return build_xamarin_graph(self.source_root, verbose=self.verbose)
        except Exception as exc:
            verbose_print(f"Could not build the Xamarin code map ({exc}); "
                          "continuing with the file tree", self.verbose)
            return None

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
