#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.utils.output_manager

Purpose:
    Own every output path a scan produces, so that the naming scheme -- APK stem, artifact tag, run timestamp -- is defined once and no component invents its own filename.

Responsibilities:
    Establish the output directory and run timestamp, then derive report, log, and intermediate-artifact paths from them.

Dependencies:
    pathlib, datetime, threading, .._metadata for the product name.

Implementation notes:
    Outputs are written beside the APK rather than into a central results directory. That keeps a scan self-contained and trivially shareable, and it means two scans of different APKs never collide even when both run in the same second. Every derived name embeds the run timestamp, so re-scanning the same APK adds a new set of artifacts instead of overwriting the previous one. Comparing two runs is a routine part of using this tool, and overwriting would make that impossible.

Security considerations:
    The output directory is derived from the operator-supplied APK path, not from anything inside the APK, so a malicious package name cannot redirect where files are written. Package names that do reach a filename are filtered to an explicit allowlist first.
"""

import re
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional
from .._metadata import NAME as APP_NAME
from .verbose import verbose_print

def _slug(text: str) -> str:
    """
    Purpose:
        Reduce arbitrary text to a short token safe to embed in a filename.

    Parameters:
        text: Any value; coerced with str.

    Returns:
        A bounded token of at most 40 characters containing only letters, digits, dot, underscore and hyphen. Never empty -- falls back to "worker".

    Complexity:
        O(n) in input length.

    Implementation notes:
        The substitution is an allowlist: everything outside the safe set becomes a hyphen, so no separator or control character can survive. Leading and trailing hyphens are stripped so the token does not read as a flag or produce a doubled separator when joined. The non-empty fallback matters because this is used to build a path; an empty token would silently collapse two distinct filenames into one.
    """
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(text)).strip("-")[:40] or "worker"

class OutputManager:
    """
    Purpose:
        Holds the identity of one scan -- which APK, which directory, which timestamp -- and derives every output path from it.

    Attributes:
        verbose: Whether path computations are traced.
        output_dir: Directory receiving all artifacts; the APK's own directory.
        timestamp: Run identifier, formatted YYYYMMDD_HHMMSS.
        apk_name: APK filename stem, used as the prefix of every artifact.

    Invariants:
        output_dir, timestamp and apk_name are all None until create_output_directory has been called, and all non-None afterwards. Every path accessor enforces this rather than trusting it, because calling an accessor early is a plausible mistake and the result would otherwise be a path built from the string "None".

    Thread-safety:
        Safe to share across analysis threads for reading. All accessors are pure functions of state that stops changing once create_output_directory returns, and that call is expected to happen on one thread before any worker starts. Concurrent calls to create_output_directory are not supported.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Create an uninitialised manager; paths become available only after create_output_directory.

        Parameters:
            verbose: Enables tracing of every path computation.

        Postconditions:
            output_dir, timestamp and apk_name are all None, so every path accessor raises until the directory is established.
        """
        self.verbose = verbose
        self.output_dir = None
        self.timestamp = None
        self.apk_name = None
        verbose_print("OutputManager initialized", self.verbose)
        
    def create_output_directory(self, apk_path: str) -> Path:
        """
        Purpose:
            Establish the output location and the run timestamp that every subsequent path is derived from.

        Parameters:
            apk_path: Path to the APK under analysis. Only its parent directory and its stem are used; the file itself is not opened.

        Returns:
            The output directory as a Path.

        Raises:
            OSError: Propagated when the directory cannot be created -- a read-only location or a permissions problem. This is fatal for the scan, since there is nowhere to write results.

        Postconditions:
            output_dir, timestamp and apk_name are populated, and the directory exists. Path accessors become usable.

        Side effects:
            Creates the directory tree if it is missing, and reads the wall clock.

        Implementation notes:
            The timestamp is captured once here rather than per artifact, so that every file from one scan shares an identifier and can be grouped by eye. Deriving it per call would scatter a single run across several timestamps. exist_ok is set because the APK's own directory almost always exists already; this call is about guaranteeing the directory rather than claiming it.

        Security considerations:
            The location comes from the operator-supplied APK path, never from APK contents.
        """
        verbose_print(f"Creating output directory structure for: {apk_path}", self.verbose)

        apk_path_obj = Path(apk_path)
        self.apk_name = apk_path_obj.stem
        self.output_dir = apk_path_obj.parent

        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        verbose_print(f"Generated timestamp: {self.timestamp}", self.verbose)
        verbose_print(f"APK name: {self.apk_name}", self.verbose)
        verbose_print(f"Using scan output directory: {self.output_dir}", self.verbose)

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            verbose_print(f"Failed to create output directory {self.output_dir}: {e}", self.verbose)
            raise

        verbose_print(f"create_output_directory returning: {self.output_dir}", self.verbose)
        return self.output_dir
    
    def get_html_path(self) -> str:
        """
        Purpose:
            Compute the path of the HTML report.

        Returns:
            The report path as a string.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet, meaning create_output_directory was never called. Raised rather than returning None so that a mis-ordered call fails at the point of the mistake instead of writing to a path built from None.

        Side effects:
            Writes one line to the verbose stream. No file or directory is created.

        Complexity:
            O(1).
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_{self.timestamp}.html")
        verbose_print(f"HTML path computed: {path}", self.verbose)
        return path
    
    def get_css_path(self) -> str:
        """
        Purpose:
            Compute the path of the stylesheet accompanying the HTML report.

        Returns:
            The stylesheet path as a string.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet, meaning create_output_directory was never called. Raised rather than returning None so that a mis-ordered call fails at the point of the mistake instead of writing to a path built from None.

        Side effects:
            Writes one line to the verbose stream. No file or directory is created.

        Complexity:
            O(1).
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_{self.timestamp}.css")
        verbose_print(f"CSS path computed: {path}", self.verbose)
        return path
    
    def get_json_path(self) -> str:
        """
        Purpose:
            Compute the path of the machine-readable JSON results file.

        Returns:
            The JSON path as a string.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet, meaning create_output_directory was never called. Raised rather than returning None so that a mis-ordered call fails at the point of the mistake instead of writing to a path built from None.

        Side effects:
            Writes one line to the verbose stream. No file or directory is created.

        Complexity:
            O(1).
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / f"{self.apk_name}_analysis-{self.timestamp}.json")
        verbose_print(f"JSON path computed: {path}", self.verbose)
        return path
    
    def get_pdf_filename(self, package_name: str) -> str:
        """
        Purpose:
            Build the PDF report filename, which is named after the application package rather than the APK file so that it stays meaningful when detached from the scan directory.

        Parameters:
            package_name: Package identifier recovered from the manifest. This is attacker-controlled and is filtered here.

        Returns:
            A filename, not a path.

        Raises:
            ValueError: When the run timestamp has not been established yet.

        Complexity:
            O(n) in the length of the package name.

        Security considerations:
            The package name is declared inside the APK and can contain anything, including path separators and traversal sequences. Filtering keeps only alphanumerics, dot, underscore and hyphen -- an allowlist, so an unexpected character cannot slip through. Dots survive because package identifiers are dotted, and they are harmless once separators are gone.
        """
        if not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        
        verbose_print(f"Generating PDF filename for package: {package_name}", self.verbose)
        clean_package = "".join(c for c in package_name if c.isalnum() or c in "._-")
        verbose_print(f"Clean package name: {clean_package}", self.verbose)
        
        date_part = self.timestamp.split('_')[0]
        time_part = self.timestamp.split('_')[1]
        filename = f"{APP_NAME}-{clean_package}-{date_part}-{time_part}.pdf"
        verbose_print(f"PDF filename generated: {filename}", self.verbose)
        return filename
    
    def get_pdf_path(self, package_name: str) -> str:
        """
        Purpose:
            Compute the full path of the PDF report.

        Parameters:
            package_name: Package identifier; filtered by get_pdf_filename.

        Returns:
            The PDF path as a string.

        Raises:
            ValueError: When the output directory has not been established yet.

        Security considerations:
            Containment relies on get_pdf_filename returning a bare filename; see its security note.
        """
        if not self.output_dir:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = str(self.output_dir / self.get_pdf_filename(package_name))
        verbose_print(f"PDF path computed: {path}", self.verbose)
        return path
    
    def get_jadx_output_dir(self) -> Path:
        """
        Purpose:
            Compute the path of the directory JADX decompiles into.

        Returns:
            The directory as a Path. It is not created here -- JADX creates it.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet, meaning create_output_directory was never called. Raised rather than returning None so that a mis-ordered call fails at the point of the mistake instead of writing to a path built from None.

        Side effects:
            Writes one line to the verbose stream. No file or directory is created.

        Complexity:
            O(1).
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_jadx_output_{self.timestamp}"
        verbose_print(f"JADX output dir computed: {path}", self.verbose)
        return path

    def _named_dir(self, tag: str) -> Path:
        """
        Purpose:
            Build an artifact directory path following the shared naming scheme, so that each framework-specific accessor is a single line.

        Parameters:
            tag: Short artifact identifier embedded in the directory name.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet.

        Implementation notes:
            Exists so the apk-stem/tag/timestamp convention is written once. The framework accessors that call it differ only in their tag, and keeping the format string in one place is what stops them drifting apart.
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_{tag}_{self.timestamp}"
        verbose_print(f"{tag} dir computed: {path}", self.verbose)
        return path

    def get_flutter_lib_dir(self) -> Path:
        """
        Purpose:
            Directory holding libapp.so and the other Flutter native libraries extracted from the APK, which Blutter consumes.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("flutter_libs")

    def get_flutter_output_dir(self) -> Path:
        """
        Purpose:
            Directory receiving Blutter's reconstructed Dart output.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("flutter_output")

    def get_rn_bundle_dir(self) -> Path:
        """
        Purpose:
            Directory holding the React Native JavaScript bundle extracted from the APK assets, before any Hermes decompilation.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("rn_bundle")

    def get_rn_output_dir(self) -> Path:
        """
        Purpose:
            Directory receiving the processed React Native sources that the analyzer reads.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("rn_output")

    def get_xamarin_assemblies_dir(self) -> Path:
        """
        Purpose:
            Directory holding the .NET assemblies recovered from a Xamarin or MAUI APK, which ilspycmd decompiles.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("xamarin_assemblies")

    def get_cordova_www_dir(self) -> Path:
        """
        Purpose:
            Directory holding the Cordova web assets extracted from the APK, which carry the application logic in a hybrid app.

        Returns:
            The directory as a Path. Not created.

        Raises:
            ValueError: When create_output_directory has not been called.
        """
        return self._named_dir("cordova_www")
    
    def get_llm_log_path(self, provider_label: str, request_timestamp: str) -> Path:
        """
        Purpose:
            Path of the transcript recording one AI request and its response, kept so that a finding can be traced back to the exchange that produced it.

        Parameters:
            provider_label: Provider name embedded in the filename.
            request_timestamp: Identifier for this specific request, distinct from the run timestamp, since one scan makes many requests.

        Returns:
            The transcript path as a Path, with a .md extension.

        Raises:
            ValueError: When the output directory has not been established yet.

        Implementation notes:
            The calling thread's name is appended when it is not the main thread. Analysis fans out across workers that can issue requests within the same second, and without the worker tag two of them would compute the same path and one transcript would overwrite the other. The thread name is slugged before use because it is not constrained to filename-safe characters.

        Security considerations:
            These transcripts contain the full prompt, which includes decompiled application source. They are written beside the APK in plaintext and should be treated as sensitive as the APK itself.
        """
        if not self.output_dir:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        worker = threading.current_thread().name
        tag = f"_{_slug(worker)}" if worker != "MainThread" else ""
        path = (self.output_dir /
                f"{self.apk_name}_{provider_label}_Request_Response_{request_timestamp}{tag}.md")
        verbose_print(f"{provider_label} log path computed for request timestamp "
                     f"{request_timestamp}: {path}", self.verbose)
        return path

    def get_ollama_log_path(self, request_timestamp: str) -> Path:
        """
        Purpose:
            Transcript path for an Ollama request.

        Parameters:
            request_timestamp: Identifier for this specific request.

        Returns:
            The transcript path as a Path.

        Raises:
            ValueError: When the output directory has not been established yet.

        Deprecation:
            Retained for callers written before providers were pluggable. New code should call get_llm_log_path with an explicit provider label.
        """
        return self.get_llm_log_path("Ollama", request_timestamp)

    def get_llm_metrics_path(self) -> Path:
        """
        Purpose:
            Path of the JSONL file recording one line per AI call -- token counts, timings and outcome -- for cost and performance review.

        Returns:
            The metrics path as a Path.

        Raises:
            ValueError: When the output directory has not been established yet.

        Implementation notes:
            This path deliberately omits the run timestamp, so repeated scans of the same APK append to one file and usage can be compared across runs. That makes it the one artifact here shared between runs, and the reason the format is JSONL: appending is safe where rewriting a JSON document would not be.
        """
        if not self.output_dir:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        return self.output_dir / f"{self.apk_name}_llm_calls.jsonl"

    def get_dynamic_dir(self) -> Path:
        """
        Purpose:
            Directory collecting every artifact produced on-device: Frida output, captured traffic and the UI action log.

        Returns:
            The directory as a Path.

        Raises:
            ValueError: When the output directory and timestamp have not been established yet.

        Side effects:
            Creates the directory, unlike the other directory accessors.

        Implementation notes:
            This one creates eagerly because the dynamic writers append to their files as events arrive, rather than writing once at the end; there is no single later point at which creating it would be natural.

        Security considerations:
            The contents include intercepted network traffic, which may carry the application's credentials and session tokens in plaintext.
        """
        if not self.output_dir or not self.timestamp:
            raise ValueError("Output directory not initialized. Call create_output_directory first.")
        path = self.output_dir / f"{self.apk_name}_dynamic_{self.timestamp}"
        path.mkdir(parents=True, exist_ok=True)
        verbose_print(f"Dynamic dir computed: {path}", self.verbose)
        return path

    def get_frida_log_path(self) -> Path:
        """
        Purpose:
            Path of the JSON log of Frida instrumentation events.

        Returns:
            The log path as a Path.

        Raises:
            ValueError: When create_output_directory has not been called.

        Side effects:
            Creates the dynamic directory as a consequence of resolving it.

        Security considerations:
            Hook output can include arguments passed to cryptographic and authentication APIs, so this file may contain live secrets.
        """
        path = self.get_dynamic_dir() / f"{self.apk_name}_Frida_Log_{self.timestamp}.json"
        verbose_print(f"Frida log path computed: {path}", self.verbose)
        return path

    def get_traffic_log_path(self) -> Path:
        """
        Purpose:
            Path of the JSON log of traffic intercepted by the local proxy.

        Returns:
            The log path as a Path.

        Raises:
            ValueError: When create_output_directory has not been called.

        Side effects:
            Creates the dynamic directory as a consequence of resolving it.

        Security considerations:
            Captured requests routinely contain authorization headers, session cookies and request bodies in cleartext, because interception is the point. Treat this file as credential material.
        """
        path = self.get_dynamic_dir() / f"{self.apk_name}_Traffic_{self.timestamp}.json"
        verbose_print(f"Traffic log path computed: {path}", self.verbose)
        return path

    def get_action_log_path(self) -> Path:
        """
        Purpose:
            Path of the JSON log of UI actions the automator performed, which is what makes a dynamic run reproducible.

        Returns:
            The log path as a Path.

        Raises:
            ValueError: When create_output_directory has not been called.

        Side effects:
            Creates the dynamic directory as a consequence of resolving it.
        """
        path = self.get_dynamic_dir() / f"{self.apk_name}_Actions_{self.timestamp}.json"
        verbose_print(f"Action log path computed: {path}", self.verbose)
        return path
    
    def get_output_dir(self) -> Optional[Path]:
        """
        Purpose:
            Expose the scan's output directory.

        Returns:
            The directory as a Path, or None when create_output_directory has not been called.

        Implementation notes:
            Returns None rather than raising, unlike the path accessors. This is a state query -- callers use it to ask whether a scan has started -- so the absent case is an answer, not a mistake.
        """
        verbose_print(f"get_output_dir returning: {self.output_dir}", self.verbose)
        return self.output_dir
    
    def get_timestamp(self) -> Optional[str]:
        """
        Purpose:
            Expose the run timestamp shared by every artifact of this scan.

        Returns:
            The timestamp string, or None when create_output_directory has not been called.
        """
        verbose_print(f"get_timestamp returning: {self.timestamp}", self.verbose)
        return self.timestamp
    
    def get_apk_name(self) -> Optional[str]:
        """
        Purpose:
            Expose the APK filename stem used as the prefix of every artifact name.

        Returns:
            The stem, or None when create_output_directory has not been called.
        """
        verbose_print(f"get_apk_name returning: {self.apk_name}", self.verbose)
        return self.apk_name
