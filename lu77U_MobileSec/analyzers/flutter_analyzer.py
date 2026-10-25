#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.flutter_analyzer

Purpose:
    Analyse a Flutter app: recover its Dart code -- by Blutter from the AOT snapshot of a release build, or as original source from the kernel snapshot of a debug build, or as the snapshot's strings when Blutter cannot disassemble it -- together with its Java/Kotlin platform layer, and run the analysis phases over both.

Responsibilities:
    Tell the build modes apart, recover the Dart side the right way for each, decompile the platform layer, write the overview that links the two through their platform channels, build the graph, and run the agent and the rule engine.

Dependencies:
    Blutter through its runner, the kernel source extractor, the snapshot string extractor, JADX through the Java/Kotlin decompiler, the APK payload extractor, the Flutter graph.

Implementation notes:
    Flutter compiles Dart to a machine-code snapshot in libapp.so for release builds, so the Dalvik bytecode holds only the platform layer. What Blutter recovers is class and method structure with strings rather than readable source, which is less than Java decompilation gives. A debug build is the opposite case: it ships kernel_blob.bin, which carries the original Dart source, and no libapp.so at all -- it used to be rejected outright for that. The platform layer is decompiled in both modes because Flutter cannot check for root, debuggers, emulators or tampering itself: those checks, and much plugin behaviour, live in Java/Kotlin behind a MethodChannel, so analysing only the Dart side misses half the app.
"""

import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .agent.profiles import FLUTTER
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..decompiler.apk_payload import available_native_abis, extract_native_libs
from ..decompiler.blutter_runner import run_blutter
from ..decompiler.dart_kernel import extract_kernel_sources, is_debug_build
from ..decompiler.dart_snapshot import write_snapshot_strings
from ..utils.cancellation import ScanCancelled
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..utils.verbose import plural, verbose_print

def _pool_line(path: Path, line: int) -> str:
    """
    Purpose:
        Read one line of a Blutter pool or object dump.

    Parameters:
        path: The file.
        line: The 1-based line.

    Returns:
        The line, or "" when the file cannot be read or is shorter.

    Implementation notes:
        A missing or unreadable dump only costs the extra quoted values that line would have contributed, so the failure is answered with an empty line rather than raised.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else ""


_QUOTED_VALUE_RE = re.compile(r"['\"`]([^'\"`\n]{4,200})['\"`]")

class FlutterAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses Flutter apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.
        module_evidence_dirs: The directories holding one recovered module per file.
        limitation: Why the Dart side could only be read in part, for the report; empty when it was read in full.

    Invariants:
        Produces a result in the standard shape whether or not the recovery succeeded.

    Thread-safety:
        One instance per scan.
    """
    framework_label = "Flutter"
    profile = FLUTTER
    module_evidence_dirs = ("asm", "dart_source", "dart_packages")

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
        self.limitation = ""
        self.output_manager = OutputManager(verbose=verbose)

    def preflight(self, apk_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Purpose:
            Check that the tool this app's build mode needs is configured.

        Parameters:
            apk_path: The APK about to be scanned; when it is a debug build, Blutter is not needed.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            Checked before the APK is touched, since a release build cannot be analysed without Blutter and the reason names the setting to configure. A debug build carries its Dart source and needs nothing beyond what every scan has, so refusing it for a missing Blutter would turn away the easiest Flutter app there is.
        """
        if apk_path and is_debug_build(apk_path):
            return True, ""
        from ..tools_checker.blutter_checker import check_blutter_configured
        if not check_blutter_configured(verbose=self.verbose):
            return False, ("Blutter is not configured. Set blutter_path in Settings "
                           "to blutter.py from a Blutter checkout. (Debug builds, which "
                           "ship kernel_blob.bin, are analysed without it.)")
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Recover the app's Dart code and platform layer and analyse them.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the recovered output for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Extracts the payload, runs Blutter or recovers the kernel source or the snapshot strings, runs JADX, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            The build mode is read from the archive itself, so a debug build never waits on Blutter. For a release build only one architecture is extracted, because Blutter supports arm64 and the other slices are the same code compiled differently. When Blutter is configured but cannot disassemble this build -- the APK has no arm64 slice, as one pulled from an x86_64 emulator does, or Blutter fails on its Dart version -- the scan continues on the snapshot's strings, the platform layer, the manifest and the native libraries, and the result carries a limitation saying what was not read; that used to end the scan with no findings and a score of zero, which read as a terrible app rather than an unread one. The strings are recovered after the platform layer so the manifest's package can mark the app's own identifiers. A missing Blutter still fails here, as preflight does, because that is a setting the user can fix. A failure to decompile the platform layer is traced and the Dart-side analysis continues, since the Dart side is the larger part of the app and losing it over JADX would be the worse outcome.
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
            out_dir = self.output_manager.get_flutter_output_dir()

            if is_debug_build(apk_path):
                mode = "debug"
                self.progress("decompiling", 45,
                              "Debug build - recovering the Dart source from kernel_blob.bin…")
                extraction = extract_kernel_sources(apk_path, out_dir, verbose=self.verbose)
                if extraction is None:
                    return self._failure(
                        "This is a debug Flutter build (it ships kernel_blob.bin), but no "
                        "app source could be recovered from the kernel snapshot.")
                packages = dict(extraction.packages)
                self.progress("decompiling", 52,
                              f"Recovered {plural(len(extraction.app_files), 'app source file')} "
                              f"and {plural(len(packages), 'package')}")
            else:
                mode, failure = self._recover_release(apk_path, lib_dir, out_dir)
                if failure is not None:
                    return failure
                packages = {}
            self.source_root = out_dir

            self.progress("decompiling", 55, "Decompiling the Android platform layer with JADX…")
            self.decompile_platform_layer(apk_path, out_dir)

            if mode == "strings":
                from .agent.native_loading import manifest_package
                self.progress("decompiling", 57, "Reading the strings in libapp.so…")
                recovered_strings = write_snapshot_strings(
                    apk_path, out_dir, package=manifest_package(out_dir), verbose=self.verbose)
                if recovered_strings is None:
                    return self._failure(
                        f"{self.limitation} No strings could be read from libapp.so either, "
                        "so there is nothing on the Dart side to analyse.")
                self.limitation += (
                    f" Analysed instead: the {plural(recovered_strings.total, 'string')} in "
                    f"libapp.so ({recovered_strings.abi}), the Java/Kotlin platform layer, the "
                    "manifest and the native libraries; the Dart program logic was not read.")

            from .flutter.graph import build_flutter_graph, write_flutter_overview
            if write_flutter_overview(out_dir, mode, packages, verbose=self.verbose) is None:
                verbose_print("No Flutter overview was written; the agent starts from the object pool", self.verbose)
            self.progress("decompiling", 58, "Flutter recovery complete")

            self.progress("agentic_start", 62,
                          "Agentic process beginning - AI is navigating the recovered app…")
            code_graph = build_flutter_graph(self.source_root, verbose=self.verbose)
            if code_graph is not None:
                self.progress("agentic_start", 64,
                              f"Code map built - {plural(len(code_graph.nodes), 'node')}")

            checkpoint = getattr(self, "checkpoint", None)
            label = {
                "debug": "Flutter (debug build - original Dart source)",
                "release": "Flutter (release build - Blutter disassembly)",
                "strings": "Flutter (release build - no Dart disassembly: libapp.so strings, "
                           "the platform layer and native libraries only)",
            }[mode]
            vulnerabilities, completed_ok, static_transcript = self.run_agent(
                self.source_root, code_graph, framework_label=label, checkpoint=checkpoint)
            if not completed_ok:
                return self._failure(
                    "The active AI provider could not drive the agentic analysis loop "
                    "over the recovered app. Flutter has no full-dump fallback - try a "
                    "different model or provider.")

            files_analyzed = (len(code_graph.nodes) if code_graph is not None else
                              sum(1 for _ in Path(self.source_root).rglob("*") if _.is_file()))
            verbose_print(f"Agentic analysis produced {plural(len(vulnerabilities), 'finding')}", self.verbose)
            self.progress("agentic_done", 82, f"Agentic process completed - {plural(len(vulnerabilities), 'finding')}")

            self.progress("agentic_done", 84, "Running deterministic scanners…")
            vulnerabilities = self.merge_findings(
                vulnerabilities, self.run_sast(self.source_root, apk_path=apk_path))

            analysis_time = time.time() - analysis_start
            if vulnerabilities:
                self._recite_pool_findings(vulnerabilities, self.source_root)
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
                'limitation': self.limitation,
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

    def _recite_pool_findings(self, vulnerabilities: List[Dict[str, Any]], source_root) -> None:
        """
        Purpose:
            Point a finding that cites Blutter's object pool or object dump at the app code that loads the value.

        Parameters:
            vulnerabilities: The findings, updated in place.
            source_root: The Flutter analysis root.

        Side effects:
            Rewrites file and line on findings that cite pp.txt or objs.txt and whose value the app's code loads, keeping the original under pool_reference.

        Implementation notes:
            The pool and the object dump list every constant the snapshot holds, so a secret is easy to find there and impossible to judge: the line says nothing about which screen uses it or how. A benchmark scan reported a debug key at objs.txt line 20285 when the code that shows it was the hidden developer screen. Every quoted value in the finding, and on the cited pool line, is looked up in the app's own disassembly; a value the model cut short with an ellipsis is first completed from the dump. The first one found becomes the citation. A value the app's code never loads leaves the finding as it was.
        """
        from .flutter.recovered import LiteralLocator
        locator = None
        for vuln in vulnerabilities:
            cited = str(vuln.get("file") or "")
            if Path(cited).name not in ("pp.txt", "objs.txt"):
                continue
            locator = locator or LiteralLocator(source_root)
            text = " ".join(str(vuln.get(k) or "") for k in ("title", "description", "code_snippet"))
            try:
                line = int(vuln.get("line_number") or str(vuln.get("line") or "0").split("-")[0])
            except ValueError:
                line = 0
            if line > 0:
                text += " " + _pool_line(Path(source_root) / Path(cited).name, line)
            for literal in _QUOTED_VALUE_RE.findall(text):
                hit = locator.locate(literal)
                shortened = literal.rstrip(".…")
                if hit is None and shortened != literal:
                    full = locator.complete(shortened)
                    hit = locator.locate(full) if full else None
                if hit is None:
                    continue
                vuln["pool_reference"] = f"{cited}:{vuln.get('line') or ''}".rstrip(":")
                vuln["file"], vuln["line"] = hit[0], str(hit[1])
                vuln["line_number"] = vuln["line_end"] = hit[1]
                verbose_print(f"Re-cited a finding from {cited} to {hit[0]}:{hit[1]}", self.verbose)
                break

    def _recover_release(self, apk_path: str, lib_dir: Path,
                         out_dir: Path) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Purpose:
            Recover a release build's Dart code with Blutter, or decide to fall back to its strings.

        Parameters:
            apk_path: Path to the APK.
            lib_dir: Where the native libraries are extracted.
            out_dir: Where Blutter writes its output.

        Returns:
            The mode to continue in -- "release" after a Blutter recovery, "strings" when Blutter cannot disassemble this build -- and the failure result to return instead, or None.

        Side effects:
            Extracts the arm64 native libraries, runs Blutter, and sets the limitation when falling back.

        Implementation notes:
            The two fallbacks are the cases no setting can fix: an APK with no arm64 slice and a Dart version Blutter cannot build. Each is logged as a warning, so the reason reaches the scan log and the dashboard instead of the scan ending without one. An arm64 slice with no libapp.so is still a failure, because that is not a Flutter payload at all.
        """
        from ..tools_checker.blutter_checker import check_blutter_configured
        if not check_blutter_configured(verbose=self.verbose):
            return "release", self._failure(
                "This is a release Flutter build and Blutter is not configured. Set "
                "blutter_path in Settings to blutter.py from a Blutter checkout.")
        self.progress("extracting", 35, "Extracting native libraries from the APK…")
        extracted = extract_native_libs(apk_path, lib_dir, verbose=self.verbose)
        if extracted is None:
            present = available_native_abis(apk_path)
            self._fall_back(
                "Blutter disassembles arm64-v8a only, and this APK ships no arm64-v8a "
                f"native library (found: {', '.join(present) or 'none'}), so the Dart code "
                "could not be disassembled. An APK pulled from an x86_64 emulator carries "
                "only that slice; scan an arm64-v8a or universal build for full coverage.")
            return "strings", None
        if not (extracted / "libapp.so").is_file():
            return "release", self._failure(
                "No libapp.so found in this APK's arm64-v8a native libraries - "
                "this doesn't look like a Flutter app's native payload.")

        self.progress("decompiling", 45,
                      "Running Blutter (may compile the Dart SDK on first use "
                      "against a new Dart version - this can take a while)…")
        if run_blutter(extracted, out_dir, verbose=self.verbose) is None:
            self._fall_back(
                "Blutter could not disassemble this app's Dart AOT binary, so the Dart code "
                "was not disassembled. Check that blutter_path points at a working install "
                "and that this Dart/Flutter version is one Blutter supports.")
            return "strings", None
        self.progress("decompiling", 52, "Blutter disassembly complete")
        return "release", None

    def _fall_back(self, reason: str) -> None:
        """
        Purpose:
            Record why the Dart side will be read from its strings only, and say so in the log.

        Parameters:
            reason: Why Blutter could not be used, written for the person reading the report.

        Side effects:
            Sets the limitation and logs it as a warning.

        Implementation notes:
            Logged with a leading "Warning:" so the dashboard's feed filter keeps it; the message on its own matched none of its patterns, which is how a scan once ended with no visible reason at all.
        """
        self.limitation = reason
        verbose_print(f"Warning: {reason}", self.verbose)
        self.progress("decompiling", 45, "Blutter cannot disassemble this build - "
                                         "continuing on libapp.so strings and the platform layer")

    def _failure(self, message: str) -> Dict[str, Any]:
        """
        Purpose:
            Build the result for an analysis that could not run.

        Parameters:
            message: Why it could not run.

        Returns:
            A result in the normal shape, marked unsuccessful and carrying the reason.

        Implementation notes:
            Returned rather than raised, and in the same shape as a successful result, so the caller reports the app with an explanation instead of losing the scan. The reason reaches the report, so it is written for the person reading it rather than as a diagnostic. It is logged under a "failed" prefix because the dashboard's feed filter drops lines matching none of its patterns, and a bare reason was dropped exactly that way.
        """
        verbose_print(f"Flutter analysis failed: {message}", self.verbose)
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
