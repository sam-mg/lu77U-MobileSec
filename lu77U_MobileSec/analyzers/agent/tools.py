"""Navigation tools the agent uses instead of a pre-flattened file dump."""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...utils.xml_utils import is_framework_layout_file

MAX_READ_CHARS = 12000
MAX_TREE_ENTRIES = 400
MAX_SEARCH_MATCHES = 60
MAX_LIST_ENTRIES = 200

_FRAMEWORK_FRAGMENTS = (
    "/androidx/", "/android/", "/kotlin/", "/kotlinx/", "/com/google/",
    "/org/jetbrains/", "/org/intellij/",
)

_RES_QUALIFIER_RE = re.compile(r"^(values|drawable|layout|color|mipmap|anim|menu)-")

def _is_resource_variant_dir(rel: str) -> bool:
    parts = rel.replace(os.sep, "/").split("/")
    for i, seg in enumerate(parts):
        if seg == "res" and i + 1 < len(parts):
            return bool(_RES_QUALIFIER_RE.match(parts[i + 1]))
    return False

class AgentTools:
    """File navigation + search, scoped to one JADX output directory."""

    def __init__(self, jadx_output_dir):
        self.root = Path(jadx_output_dir).resolve()
        self._read_progress: Dict[str, int] = {}

    def _resolve(self, rel_path: str) -> Path:
        """Resolve a model-supplied path inside the sandbox, or raise."""
        rel_path = (rel_path or "").strip().lstrip("/")
        candidate = (self.root / rel_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"path escapes sandbox: {rel_path!r}")
        return candidate

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    @staticmethod
    def _is_framework(rel: str) -> bool:
        """Whether ``rel`` is framework/library noise rather than app-authored
        content: an androidx/kotlin/etc. package, an AppCompat/Design/Material
        support-library resource (``abc_*``, ``design_*``, ...), or a locale/
        density/API-qualified resource-directory variant."""
        probe = "/" + rel.replace(os.sep, "/")
        if any(frag in probe for frag in _FRAMEWORK_FRAGMENTS):
            return True
        if is_framework_layout_file(Path(rel).name):
            return True
        return _is_resource_variant_dir(rel)

    def list_files(self, path: str = "") -> str:
        """List immediate children (dirs and files with sizes) of ``path``."""
        try:
            base = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not base.exists():
            return f"ERROR: not found: {path}"
        if base.is_file():
            return f"{self._rel(base)} ({base.stat().st_size} bytes) [file]"

        entries = []
        for child in sorted(base.iterdir()):
            rel = self._rel(child)
            if child.is_dir():
                entries.append(f"{rel}/  [dir]")
            else:
                entries.append(f"{rel}  ({child.stat().st_size} bytes)")
        if len(entries) > MAX_LIST_ENTRIES:
            extra = len(entries) - MAX_LIST_ENTRIES
            entries = entries[:MAX_LIST_ENTRIES] + [f"... (+{extra} more)"]
        return "\n".join(entries) if entries else "(empty directory)"

    def read_file(self, path: str, start_line: Optional[int] = None) -> str:
        """Return a bounded window of the file's text content with a 1-based
        line-number gutter (``  13| <code>``), so the model can cite exact
        ``line`` values for its findings.

        A file larger than one call's ``MAX_READ_CHARS`` budget is paged: a
        repeated ``read_file`` on the *same* path with no explicit
        ``start_line`` automatically continues from the line after the last
        one shown — it never returns the same (or a silently truncated) head
        again. Pass ``start_line`` to jump to a specific line instead (e.g.
        because ``search_code`` pointed at it).
        """
        try:
            target = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists() or not target.is_file():
            return f"ERROR: not a file: {path}"
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return f"ERROR: could not read {path}: {e}"

        lines = content.splitlines() or [""]
        total_lines = len(lines)
        key = str(target)
        first_line = max(1, start_line) if start_line is not None else self._read_progress.get(key, 1)

        if first_line > total_lines:
            return (
                f"(already read to the end of this file — {total_lines} line(s) total, "
                f"nothing more to show. Pass start_line to jump elsewhere if needed.)"
            )

        # Walk forward from first_line, keeping whole lines under MAX_READ_CHARS;
        # always take at least one line so a single pathological long line can't
        # stall progress.
        selected: List[str] = []
        used_chars = 0
        last_line = first_line - 1
        for lineno in range(first_line, total_lines + 1):
            line_text = lines[lineno - 1]
            entry_len = len(line_text) + 1
            if selected and used_chars + entry_len > MAX_READ_CHARS:
                break
            selected.append(line_text)
            used_chars += entry_len
            last_line = lineno

        self._read_progress[key] = last_line + 1

        width = len(str(total_lines))
        numbered = "\n".join(
            f"{lineno:>{width}}| {line}"
            for lineno, line in zip(range(first_line, last_line + 1), selected)
        )
        if last_line < total_lines:
            numbered += (
                f"\n... (showing lines {first_line}-{last_line} of {total_lines}; call "
                f"read_file again on this path to continue from line {last_line + 1}, "
                f"or pass start_line to jump elsewhere)"
            )
        return numbered

    def inspect_native(self, path: str) -> str:
        """List a native ``.so`` library's dynamic symbol table via ``objdump -T``.

        Text-based dynamic-symbol output — not a full disassembly — is the
        practical way to review JNI code without a GUI disassembler (Ghidra/IDA):
        it surfaces exported ``Java_<package>_<Class>_<method>`` entry points
        (the JNI methods reachable from Java) alongside imported libc symbols,
        so unsafe calls (``strcpy``, ``system``, ``exec``, ``sprintf``, ...) are
        visible in one bounded, greppable block.
        """
        try:
            target = self._resolve(path)
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists() or not target.is_file():
            return f"ERROR: not a file: {path}"
        if target.suffix != ".so":
            return f"ERROR: not a native library (.so): {path}"
        if shutil.which("objdump") is None:
            return "ERROR: objdump is not installed on this host"
        try:
            result = subprocess.run(
                ["objdump", "-T", str(target)],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            return f"ERROR: objdump failed: {e}"
        output = (result.stdout or "").strip() or (result.stderr or "").strip()
        if not output:
            return "(no symbols found)"
        # objdump prints the absolute host path it was given on its first line
        # ("<path>: file format ..."); swap in the sandbox-relative path so the
        # model never sees local filesystem layout.
        output = output.replace(str(target), path, 1)
        truncated = len(output) > MAX_READ_CHARS
        if truncated:
            output = output[:MAX_READ_CHARS] + f"\n... [truncated at {MAX_READ_CHARS} chars]"
        return output

    def search_code(self, pattern: str, path: str = "") -> str:
        """Grep-style search across decompiled sources (returns file:line: match)."""
        if not pattern:
            return "ERROR: empty pattern"
        try:
            base = self._resolve(path) if path else self.root
        except ValueError as e:
            return f"ERROR: {e}"
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        matches: List[str] = []
        for file_path in self._iter_source_files(base):
            rel = self._rel(file_path)
            # A broad, unscoped search (no explicit path) skips framework/
            # resource-boilerplate noise so 80+ locale strings.xml duplicates or
            # AppCompat internals don't dilute the match budget; an explicit
            # path still searches everything under it (the agent asked for it).
            if not path and self._is_framework(rel):
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        if regex.search(line):
                            snippet = line.strip()[:200]
                            matches.append(f"{rel}:{lineno}: {snippet}")
                            if len(matches) >= MAX_SEARCH_MATCHES:
                                matches.append(f"... (stopped at {MAX_SEARCH_MATCHES} matches)")
                                return "\n".join(matches)
            except Exception:
                continue
        return "\n".join(matches) if matches else "(no matches)"

    def file_tree(self) -> str:
        """Paths + sizes only (no contents), app code first, framework code last."""
        app_entries, fw_entries = [], []
        for file_path in self._iter_source_files(self.root, include_resources=True):
            rel = self._rel(file_path)
            try:
                size = file_path.stat().st_size
            except OSError:
                size = 0
            line = f"{rel} ({size}b)"
            (fw_entries if self._is_framework(rel) else app_entries).append(line)

        entries = app_entries
        if len(entries) < MAX_TREE_ENTRIES:
            entries = entries + fw_entries[: MAX_TREE_ENTRIES - len(entries)]
        truncated = (len(app_entries) + len(fw_entries)) - len(entries)
        out = entries[:MAX_TREE_ENTRIES]
        if truncated > 0:
            out.append(f"... (+{truncated} more files not shown; use list_files/search_code)")

        natives = self._native_library_summary()
        if natives:
            out = out + ["", "## Native libraries (inspect_native to list symbols)"] + natives
        return "\n".join(out) if out else "(no source files found)"

    def _native_library_summary(self) -> List[str]:
        """One representative path per unique ``.so`` name (deduped across
        per-ABI ``lib/<abi>/`` copies, which are the same library compiled for
        different architectures — listing all of them would just be noise)."""
        seen = {}
        for so_path in sorted(self.root.rglob("*.so")):
            name = so_path.name
            if name not in seen:
                seen[name] = so_path
        lines = []
        for name, so_path in sorted(seen.items()):
            try:
                size = so_path.stat().st_size
            except OSError:
                size = 0
            lines.append(f"{self._rel(so_path)} ({size}b)")
        return lines

    def app_source_files(self) -> List[str]:
        """Relative paths of the app's own ``.java``/``.kt`` sources (framework
        packages and generated ``R``/``BuildConfig`` excluded). Used by the
        agent loop's coverage tracking and anti-loop steering to name the files
        still worth examining."""
        out: List[str] = []
        for fp in self._iter_source_files(self.root):
            rel = self._rel(fp)
            if self._is_framework(rel):
                continue
            stem = Path(rel).stem
            if stem == "R" or stem.startswith("R$") or stem == "BuildConfig":
                continue
            out.append(rel)
        return sorted(out)

    def app_resource_files(self) -> List[str]:
        """Security-relevant app resource files (with sizes) that the code graph
        doesn't cover because they aren't classes — network security config,
        raw assets, and the user-facing strings. Small and high-signal, meant to
        replace the full 400-line file-tree appendix when a graph is present."""
        wanted_dirs = ("res/xml/", "res/raw/")
        wanted_files = ("res/values/strings.xml",)
        out: List[str] = []
        res_root = self.root / "resources" / "res"
        if res_root.exists():
            for sub in ("xml", "raw"):
                d = res_root / sub
                if d.is_dir():
                    for f in sorted(d.iterdir()):
                        if f.is_file():
                            try:
                                out.append(f"{self._rel(f)} ({f.stat().st_size}b)")
                            except OSError:
                                out.append(self._rel(f))
            strings = res_root / "values" / "strings.xml"
            if strings.is_file():
                try:
                    out.append(f"{self._rel(strings)} ({strings.stat().st_size}b)")
                except OSError:
                    out.append(self._rel(strings))
        return out

    def manifest_summary(self) -> str:
        """Return the AndroidManifest.xml content (bounded), if present."""
        for candidate in (
            self.root / "resources" / "AndroidManifest.xml",
            self.root / "AndroidManifest.xml",
        ):
            if candidate.exists():
                return self.read_file(self._rel(candidate))
        return "(AndroidManifest.xml not found)"

    def _iter_source_files(self, base: Path, include_resources: bool = False):
        exts = {".java", ".kt", ".xml", ".smali"} if include_resources else {".java", ".kt"}
        if base.is_file():
            if base.suffix in exts:
                yield base
            return
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                if Path(name).suffix in exts:
                    yield Path(dirpath) / name