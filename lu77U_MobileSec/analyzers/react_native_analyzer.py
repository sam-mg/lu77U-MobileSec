#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.react_native_analyzer

Purpose:
    Analyse a React Native app: recover its JavaScript bundle as one file per Metro module, split into the app and the framework, decompile its Java/Kotlin platform layer, and analyse both.

Responsibilities:
    Locate and extract the bundle, recover its modules the right way for its format, decompile the platform layer, write the overview that maps native modules to the JavaScript that calls them, build the graph, and run the analysis phases.

Dependencies:
    hermes-decomp for Hermes bytecode, the built-in Metro splitter for plain bundles (react-native-decompiler as a fallback), JADX for the platform layer.

Implementation notes:
    React Native ships its bundle in two forms -- plain JavaScript or Hermes bytecode. A plain Metro bundle is already the app's code and is split and laid out here with no external tool; Hermes bytecode needs hermes-decomp, whose per-module extraction is preferred over a whole-bundle decompile because modules are what the app/framework split is computed over. The platform layer matters as much as the bundle: native modules -- Java methods any JavaScript in the app can call -- live there, and React Native apps' file-reading, crypto and device-integrity code usually does too.
"""

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .agent.profiles import REACT_NATIVE
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.apk_payload import extract_member, find_js_bundle, is_hermes
from ..decompiler.hermes_runner import decompile_hbc, extract_hbc_modules
from ..decompiler.rn_bundle_decompiler import decompile_js_bundle
from ..decompiler.rn_metro import read_extracted_modules, split_plain_bundle, write_module_tree
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
        module_evidence_dirs: The directories holding one recovered module per file.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "React Native"
    profile = REACT_NATIVE
    module_evidence_dirs = ("app_modules", "framework_modules")

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

    def preflight(self, apk_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Purpose:
            Check that the tool this app's bundle needs is configured.

        Parameters:
            apk_path: The APK about to be scanned, whose bundle format decides what is needed.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            A plain-JavaScript bundle needs nothing: it is split and laid out by this tool itself. A Hermes bundle needs hermes-decomp. When the APK is not known yet, either decompiler being configured is accepted, as before, because the format is only discovered once the bundle is read.
        """
        from ..tools_checker.hermes_checker import check_hermes_configured
        from ..tools_checker.rn_decompiler_checker import check_rn_decompiler_configured
        hermes_ok = check_hermes_configured(verbose=self.verbose)
        if apk_path:
            fmt = self._bundle_format(apk_path)
            if fmt == "javascript":
                return True, ""
            if fmt == "hermes":
                if hermes_ok:
                    return True, ""
                return False, ("This app's bundle is Hermes bytecode and hermes-decomp is not "
                               "configured. Set hermes_decomp_path in Settings.")
        rn_ok = check_rn_decompiler_configured(verbose=self.verbose)
        if not hermes_ok and not rn_ok:
            return False, (
                "Neither hermes-decomp nor react-native-decompiler is configured. "
                "Set hermes_decomp_path (for Hermes-compiled bundles) or "
                "rn_decompiler_path (for plain-JS bundles) in Settings - which one "
                "you need depends on how this app's bundle was built, and is only "
                "known once the bundle is extracted.")
        return True, ""

    def _bundle_format(self, apk_path: str) -> str:
        """
        Purpose:
            Read whether an APK's bundle is Hermes bytecode or plain JavaScript without extracting it.

        Parameters:
            apk_path: The APK.

        Returns:
            "hermes", "javascript", or "" when there is no readable bundle.
        """
        import zipfile
        from .react_native.overview import HERMES_MAGIC
        member = find_js_bundle(apk_path, verbose=False)
        if not member:
            return ""
        try:
            with zipfile.ZipFile(apk_path) as zf, zf.open(member) as handle:
                head = handle.read(8)
        except (zipfile.BadZipFile, KeyError, OSError):
            return ""
        return "hermes" if head == HERMES_MAGIC else "javascript"

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Recover the app's JavaScript and platform layer and analyse them.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the recovered sources for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts the bundle, runs hermes-decomp and JADX as needed, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            The bundle is located by convention and then by extension, since apps do rename it, and its format is decided by its magic bytes rather than its name. A failure to decompile the platform layer is traced and the JavaScript analysis continues, since the bundle is the larger part of the app.
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
                          f"Recovering the {'Hermes' if hermes else 'JavaScript'} bundle's modules…")
            out_dir = self.output_manager.get_rn_output_dir()
            recovered = self._recover_modules(bundle_path, Path(out_dir), hermes)
            if recovered is None:
                return self._failure(
                    "hermes-decomp could not decompile this Hermes bundle - an "
                    "unsupported bytecode version, or hermes_decomp_path doesn't "
                    "point at a working install." if hermes else
                    "This bundle is not a Metro bundle the built-in splitter recognises, and "
                    "react-native-decompiler (rn_decompiler_path) is not configured or failed.")
            self.source_root = out_dir

            self.progress("decompiling", 54, "Decompiling the Android platform layer with JADX…")
            self.decompile_platform_layer(apk_path, out_dir)
            from .react_native.overview import write_rn_overview
            write_rn_overview(out_dir, apk_path, bundle_path, recovered)
            self.progress("decompiling", 58, "Decompilation complete")

            self._write_bundle_metadata(out_dir, bundle_member, hermes)

            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the recovered app…")
            from .react_native.graph import build_rn_graph
            code_graph = build_rn_graph(self.source_root, verbose=self.verbose)
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'module')}")

            checkpoint = getattr(self, "checkpoint", None)
            label = ("React Native (Hermes bytecode, decompiled)" if hermes
                     else "React Native (plain JavaScript bundle)")
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, framework_label=label, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "for this bundle. React Native has no full-dump fallback - try a "
                    "different model or provider.")

            files_analyzed = (len(code_graph.nodes) if code_graph is not None else
                              sum(1 for _ in Path(self.source_root).rglob("*.js")))
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

    def _recover_modules(self, bundle_path: Path, out_dir: Path, hermes: bool) -> Optional[str]:
        """
        Purpose:
            Recover the bundle as a Metro module tree under the analysis root, falling back to an external decompiler's output.

        Parameters:
            bundle_path: The extracted bundle.
            out_dir: The analysis root.
            hermes: Whether the bundle is Hermes bytecode.

        Returns:
            A short description of what was recovered, or None when nothing could be.

        Side effects:
            Runs hermes-decomp or reads the plain bundle, and writes app_modules/ and framework_modules/.

        Implementation notes:
            hermes-decomp's extraction is written to a scratch directory inside the root and removed once the module tree is written, so each module appears once in the tree the agent searches. When an older hermes-decomp lacks the extract command, its whole-bundle decompile is used and the graph falls back to splitting that file. A plain bundle that the Metro splitter does not recognise -- a Webpack or Haul bundle -- goes to react-native-decompiler when one is configured.
        """
        if hermes:
            scratch = out_dir / ".hermes_extract"
            if extract_hbc_modules(bundle_path, scratch, verbose=self.verbose) is not None:
                tree = write_module_tree(read_extracted_modules(scratch), out_dir, verbose=self.verbose)
                shutil.rmtree(scratch, ignore_errors=True)
                if tree is not None:
                    return (f"{plural(len(tree.app_ids), 'app-region module')}, "
                            f"{plural(len(tree.framework_ids), 'framework module')}")
            shutil.rmtree(scratch, ignore_errors=True)
            return "whole-bundle decompile" if decompile_hbc(bundle_path, out_dir, verbose=self.verbose) else None
        try:
            text = Path(bundle_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        tree = write_module_tree(split_plain_bundle(text), out_dir, verbose=self.verbose)
        if tree is not None:
            return (f"{plural(len(tree.app_ids), 'app-region module')}, "
                    f"{plural(len(tree.framework_ids), 'framework module')}")
        return "react-native-decompiler output" if decompile_js_bundle(bundle_path, out_dir, verbose=self.verbose) else None

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
