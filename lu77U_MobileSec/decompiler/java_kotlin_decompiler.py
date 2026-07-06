"""JADX Wrapper Module for lu77U-MobileSec"""

import re
import subprocess
from pathlib import Path
from ..utils.verbose import verbose_print
from ..config import user_settings

def _resolve_jadx_path() -> str:
    """Prefer the user settings file; fall back to the legacy constant."""
    path = user_settings.get_jadx_path()
    if path:
        return path
    from ..config.settings import JADX_PATH as LEGACY_JADX_PATH
    return LEGACY_JADX_PATH

class JavaKotlinDecompiler:
    """Wrapper class for JADX decompiler operations for Java/Kotlin apps"""

    def __init__(self, verbose: bool = False):
        """Initialize Java/Kotlin decompiler"""
        self.verbose = verbose
        verbose_print("JavaKotlinDecompiler initialized", self.verbose)
        verbose_print(f"JADX path configured as: {_resolve_jadx_path()}", self.verbose)
    
    def jadx_decompile(self, apk_path: str, output_dir: Path = None):
        """Decompile APK using JADX decompiler tool"""
        if output_dir is None:
            apk_path_obj = Path(apk_path)
            apk_dir = apk_path_obj.parent
            apk_name = apk_path_obj.stem
            output_dir = apk_dir / f"{apk_name}_jadx_output"
            verbose_print(f"Output directory auto-generated from APK name", self.verbose)
        
        verbose_print(f"JADX output directory: {output_dir}", self.verbose)
        
        try:
            jadx_cmd = [
                _resolve_jadx_path(),
                '--output-dir', str(output_dir),
                '--no-imports',
                '--show-bad-code',
                apk_path
            ]
            
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
        """Parse JADX output to extract error count and status"""
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
        """Main decompilation method for Java/Kotlin APKs"""
        verbose_print("decompile() method called", self.verbose)
        result = self.jadx_decompile(apk_path, output_dir)
        verbose_print(f"decompile() returning: {result}", self.verbose)
        return result