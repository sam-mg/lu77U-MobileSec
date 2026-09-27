#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.java_kotlin_decompiler

Purpose:
    Run JADX over an APK to recover Java source, which is the decompilation path for a conventional Android app and therefore the one most scans take.

Responsibilities:
    Resolve the JADX path, probe the output filesystem's case sensitivity, invoke JADX with the flags this tool needs, and report how many classes it failed on.

Dependencies:
    subprocess, re, ..config.user_settings.

Implementation notes:
    JADX is expected to partly fail. Real APKs are obfuscated and sometimes deliberately malformed, and JADX writes error comments into the source it cannot decompile rather than stopping. This module therefore judges success by whether output exists, not by the exit code, and counts the errors so the report can say how complete the decompilation was.

Security considerations:
    JADX is invoked as an argument vector with no shell. The APK path comes from the operator and the output directory is constructed by this tool, so no APK-derived value reaches the command line.
"""

import re
import subprocess
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config import user_settings

def _resolve_jadx_path() -> str:
    """
    Purpose:
        Resolve the path to the JADX executable.

    Returns:
        The configured path, falling back to the legacy settings module.

    Side effects:
        Loads user settings on first call.

    Implementation notes:
        The legacy fallback keeps an installation working that was configured before settings moved into the JSON file and never re-saved. The legacy import is deferred so it is only paid when the current setting is empty.
    """
    path = user_settings.get_jadx_path()
    if path:
        return path
    from ..config.settings import JADX_PATH as LEGACY_JADX_PATH
    return LEGACY_JADX_PATH

class JavaKotlinDecompiler:
    """
    Purpose:
        Decompiles an APK to Java source using JADX.

    Attributes:
        verbose: Whether decompilation is traced.

    Invariants:
        Returns an output directory only when JADX actually produced files there; otherwise None.

    Thread-safety:
        Holds no per-decompilation state, but two concurrent calls must be given different output directories.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the decompiler and trace the resolved JADX path.

        Parameters:
            verbose: Enables tracing.

        Implementation notes:
            The path is resolved and traced at construction as a diagnostic, but resolved again per invocation so a setting changed mid-session takes effect.
        """
        self.verbose = verbose
        verbose_print("JavaKotlinDecompiler initialized", self.verbose)
        verbose_print(f"JADX path configured as: {_resolve_jadx_path()}", self.verbose)
    
    @staticmethod
    def _filesystem_is_case_sensitive(directory: Path) -> bool:
        """
        Purpose:
            Determine whether the output filesystem distinguishes filenames by case.

        Parameters:
            directory: Directory to probe, created if missing.

        Returns:
            True when the filesystem is case-sensitive; False on any error.

        Side effects:
            Creates the directory and writes and removes a probe file.

        Implementation notes:
            This is tested empirically rather than inferred from the platform, because it is a property of the filesystem rather than the operating system: macOS defaults to case-insensitive but can be case-sensitive, and a network or container mount can be either on any platform. It matters because obfuscated Android code routinely contains classes differing only in case. On a case-insensitive filesystem those overwrite each other, silently losing source; telling JADX to rename them instead preserves every class at the cost of altered names. The probe writes one name and checks for a differently-cased one, which is the only reliable test. It is cleaned up in a finally block so a failure does not leave the probe behind. Any error reads as case-insensitive, which is the conservative answer: it makes JADX rename, which is always safe, where wrongly assuming case sensitivity would lose classes.
        """
        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".jadx_case_probe_aA"
            probe.write_text("", encoding="utf-8")
            try:
                return not (directory / ".jadx_case_probe_AA").exists()
            finally:
                probe.unlink(missing_ok=True)
        except OSError:
            return False

    def jadx_decompile(self, apk_path: str, output_dir: Path = None):
        """
        Purpose:
            Decompile an APK to Java source.

        Parameters:
            apk_path: Path to the APK.
            output_dir: Directory to write source into; derived from the APK name when omitted.

        Returns:
            The output directory, or None when JADX produced nothing.

        Side effects:
            Creates the output directory and spawns JADX, which can run for several minutes on a large app.

        Implementation notes:
            The flags are chosen for machine reading rather than human browsing. Imports are omitted because fully-qualified names in the body are unambiguous for an analyzer. Bad code is shown rather than dropped, since a method JADX could only partly decompile still carries evidence. Renaming is restricted to what is necessary for names to be valid and printable. Case sensitivity is probed first and the corresponding flag added, so JADX knows whether it may keep colliding names. Success is judged by output existing and being non-empty, not by the exit code. JADX exits non-zero on an APK it partly decompiled, and treating that as failure would discard a usable result for most obfuscated apps. No timeout is set. Decompiling a large app legitimately takes many minutes and a wrong limit would truncate real work; cancellation is handled at a higher level instead.

        Known limitations:
            The FileNotFoundError handler references a name that is not defined in this module, so if JADX is genuinely missing that handler raises NameError, which the following handler catches and reports as a generic decompilation error. The failure is still reported and still returns None, but the message does not name the missing executable.
        """
        if output_dir is None:
            apk_path_obj = Path(apk_path)
            apk_dir = apk_path_obj.parent
            apk_name = apk_path_obj.stem
            output_dir = apk_dir / f"{apk_name}_jadx_output"
            verbose_print(f"Output directory auto-generated from APK name", self.verbose)
        
        verbose_print(f"JADX output directory: {output_dir}", self.verbose)
        
        try:
            case_sensitive = self._filesystem_is_case_sensitive(Path(output_dir))
            jadx_cmd = [
                _resolve_jadx_path(),
                '--output-dir', str(output_dir),
                '--no-imports',
                '--show-bad-code',
                '--rename-flags', 'case,valid,printable',
            ]
            if case_sensitive:
                jadx_cmd.append('--fs-case-sensitive')
            jadx_cmd.append(apk_path)
            verbose_print(
                f"Filesystem at {output_dir} is "
                f"{'case-sensitive - JADX will keep original names' if case_sensitive else 'case-insensitive - JADX will rename colliding classes'}",
                self.verbose)
            
            verbose_print(f"Command: {' '.join(jadx_cmd)}", self.verbose)
            
            result = subprocess.run(jadx_cmd, capture_output=True, text=True)
            
            verbose_print(f"Subprocess execution completed", self.verbose)
            verbose_print(f"Return code: {result.returncode}", self.verbose)
            verbose_print(f"STDOUT length: {len(result.stdout)}", self.verbose)
            verbose_print(f"STDERR length: {len(result.stderr)}", self.verbose)
            
            output_exists = output_dir.exists()
            verbose_print(f"Output directory exists: {output_exists}", self.verbose)
            
            if output_exists:
                output_files = list(output_dir.iterdir())
                verbose_print(f"Output directory contains {len(output_files)} items", self.verbose)
            
            if output_exists and any(output_dir.iterdir()):
                error_count = self.parse_jadx_errors(result.stdout, result.stderr)
                if result.returncode == 0:
                    verbose_print(f"JADX decompilation completed successfully with {error_count} errors", self.verbose)
                else:
                    verbose_print(f"JADX decompilation completed with return code {result.returncode} and {error_count} errors", self.verbose)
                verbose_print(f"Decompiled output directory: {output_dir}", self.verbose)
                return output_dir
            else:
                verbose_print(f"JADX decompilation failed with return code: {result.returncode}", self.verbose)
                if result.stderr:
                    verbose_print(f"Error details: {result.stderr[:500]}", self.verbose)
                if result.stdout:
                    verbose_print(f"Output details: {result.stdout[:500]}", self.verbose)
                return None
                
        except FileNotFoundError as e:
            verbose_print(f"JADX executable not found at: {JADX_PATH}", self.verbose)
            verbose_print("JADX not found. Please install JADX and ensure it's in your PATH.", self.verbose)
            verbose_print(f"FileNotFoundError: {e}", self.verbose)
            return None
        except Exception as e:
            verbose_print(f"JADX decompilation error: {e}", self.verbose)
            import traceback
            if self.verbose:
                verbose_print("Full traceback:", self.verbose)
                traceback.print_exc()
            return None

    def parse_jadx_errors(self, stdout: str, stderr: str) -> int:
        """
        Purpose:
            Count how many classes JADX failed to decompile.

        Parameters:
            stdout: JADX standard output.
            stderr: JADX standard error.

        Returns:
            The error count, zero when none could be determined.

        Implementation notes:
            JADX prints a summary line with a total, which is read first. When that is absent the error lines in stderr are counted instead, which is cruder but gives the right order of magnitude. The count matters because it quantifies how complete the decompilation was. An app where JADX failed on most classes will produce a thin analysis, and that is worth telling the reader rather than letting the result look definitive.
        """
        verbose_print("Parsing JADX error output", self.verbose)
        error_count = 0
        
        if stdout:
            error_match = re.search(r'ERROR - (\d+)', stdout)
            if error_match:
                error_count = int(error_match.group(1))
                verbose_print(f"Found {error_count} errors in STDOUT", self.verbose)
        
        if error_count == 0 and stderr:
            error_count = stderr.count('ERROR')
            if error_count > 0:
                verbose_print(f"Found {error_count} 'ERROR' strings in STDERR", self.verbose)
        
        verbose_print(f"Total error count: {error_count}", self.verbose)
        return error_count

    def decompile(self, apk_path: str, output_dir: Path = None):
        """
        Purpose:
            Public entry point for decompiling an APK.

        Parameters:
            apk_path: Path to the APK.
            output_dir: Directory to write source into; derived from the APK name when omitted.

        Returns:
            The output directory, or None on failure.

        Implementation notes:
            A thin wrapper, kept so callers depend on a tool-agnostic name rather than on JADX specifically.
        """
        verbose_print("decompile() method called", self.verbose)
        result = self.jadx_decompile(apk_path, output_dir)
        verbose_print(f"decompile() returning: {result}", self.verbose)
        return result
