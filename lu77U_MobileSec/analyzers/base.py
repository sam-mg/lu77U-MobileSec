#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.base

Purpose:
    The contract every framework analyzer implements, plus the machinery they share: running the rule engine and the AI agent, merging their findings, and attaching real source evidence to what the model reported.

Responsibilities:
    Declare the abstract interface, orchestrate the two analysis engines, resolve a model-cited path to a real file, and build the code context shown in reports.

Dependencies:
    The agent package, the SAST runner, the validation helpers, the syntax highlighter.

Implementation notes:
    The most important shared behaviour here is evidence enrichment. A model reports a file and a line; this layer finds the real file, locates the cited code in it, and attaches the surrounding lines. That is what turns an assertion into something a reader can check -- and what lets the gates refute a claim the code does not support.

Security considerations:
    File paths in findings come from model output and are untrusted. Resolution is confined to the decompiled source root, and an ambiguous path is refused rather than guessed at, because attaching the wrong file's code to a finding would be worse than attaching none.
"""

import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .agent.profiles import JAVA_KOTLIN, SourceProfile
from .evidence_hop import hop_terms
from ..report_generator.syntax_highlight import highlight_lines
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import plural, verbose_print
from ..validation.claim_terms import aliases_present, api_terms, evidence_supports, names_present, salient_terms
from ..validation.dedupe import RULE_SOURCES, finding_identity, finding_richness

CONTEXT_PADDING_LINES = 4

from .layout import PLATFORM_DIR

NATIVE_CONTEXT_MAX_LINES = 80

_BINARY_SNIFF_BYTES = 8192


def _looks_like_text(path: Path) -> bool:
    """
    Purpose:
        Decide whether a file is text, by sniffing its opening bytes.

    Parameters:
        path: The file.

    Returns:
        True when the opening bytes contain no null byte.

    Implementation notes:
        Only the head is read, since decompiled trees contain large binaries and reading them whole to classify them would dominate the pass. A null byte is the practical discriminator here: decompiled source never contains one, and the binaries alongside it almost always do.
    """
    try:
        with path.open("rb") as handle:
            chunk = handle.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return False
    return b"\x00" not in chunk

MITIGATION_WINDOW_LINES = 20

_WEBVIEW_MITIGATIONS = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in (
        ("setAllowFileAccess(false)", r"setAllowFileAccess\s*\(\s*false\s*\)"),
        ("setAllowFileAccessFromFileURLs(false)",
         r"setAllowFileAccessFromFileURLs\s*\(\s*false\s*\)"),
        ("setAllowUniversalAccessFromFileURLs(false)",
         r"setAllowUniversalAccessFromFileURLs\s*\(\s*false\s*\)"),
        ("setAllowContentAccess(false)", r"setAllowContentAccess\s*\(\s*false\s*\)"),
        ("setJavaScriptCanOpenWindowsAutomatically(false)",
         r"setJavaScriptCanOpenWindowsAutomatically\s*\(\s*false\s*\)"),
        ("setWebViewClient(...)", r"setWebViewClient\s*\("),
    )
)

_SQL_FINDING_RE = re.compile(
    r"\bsql\b|sqli|injection|rawquery|raw query|execsql|prepared statement"
    r"|string concatenation.*quer|quer.*concatenat", re.IGNORECASE)

_ENUM_DECL_RE_TMPL = r"\benum\s+{name}\b"

MAX_BASENAME_CANDIDATES = 200

CLAIM_SCAN_BYTES = 512_000


class BaseAnalyzer(ABC):
    """
    Purpose:
        Base class for the per-framework analyzers.

    Attributes:
        verbose: Whether analysis is traced.
        is_cancelled: Polled between phases.
        profile: The framework profile selecting prompts and heuristics.
        agent_coverage: What the AI phase managed to examine, recorded for the report.
        module_evidence_dirs: Top-level directories of the analysis root whose files are each one recovered module, so a finding citing one also records what the whole module contains.

    Invariants:
        Every finding that leaves an analyzer has been through evidence enrichment, so its cited location has been resolved or explicitly marked unresolved.

    Thread-safety:
        One instance per scan. The agent phase fans out internally across threads.
    """
    framework_label: str = "unknown"

    profile: SourceProfile = JAVA_KOTLIN

    module_evidence_dirs: Tuple[str, ...] = ()

    def __init__(self, verbose: bool = False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the analyzer.

        Parameters:
            verbose: Enables tracing.
            progress: Reports phase progress.
            is_cancelled: Polled between phases.
        """
        self.verbose = verbose
        self._progress = progress or (lambda *unused_a, **unused_kw: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.ai_provider = None

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        """
        Purpose:
            Report progress to the caller.

        Parameters:
            phase: Stage identifier.
            percent: Overall completion.
            message: Human-readable description.

        Raises:
            ScanCancelled: When the callback signals that the user stopped the scan.

        Implementation notes:
            A cancellation raised by the callback is re-raised because it is how a stop request reaches the analysis. Any other failure is logged and dropped, since an undeliverable progress update must not end a scan. contextlib.suppress cannot express this, because ScanCancelled subclasses Exception and has to be let through first.
        """
        try:
            self._progress(phase, percent, message)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Progress update could not be delivered: {exc}", self.verbose)

    @abstractmethod
    def preflight(self, apk_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Purpose:
            Report whether this analyzer has what it needs to run.

        Parameters:
            apk_path: The APK about to be scanned, when known, for an analyzer whose requirements depend on how the app was built.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            Checked before decompilation so a missing tool is reported immediately rather than after minutes of work. The reason is shown to the user, so it names what to configure.
        """

    @abstractmethod
    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> Dict[str, Any]:
        """
        Purpose:
            Analyse an APK and return the findings. Implemented by each framework analyzer.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the decompiled output for a later phase to read.

        Returns:
            The analysis results.

        Implementation notes:
            Cleanup is deferrable because dynamic verification reads the same decompiled sources after static analysis finishes.
        """


    def run_sast(self, source_root, apk_path=None) -> List[Dict[str, Any]]:
        """
        Purpose:
            Run the deterministic rule engine over the decompiled source.

        Parameters:
            source_root: Root of the decompiled source.
            apk_path: Path to the APK, for extractors that read the archive.

        Returns:
            The rule findings.

        Implementation notes:
            Run independently of the AI phase, so a scan without a working provider still produces rule-backed findings, and the two engines' agreement remains a meaningful confidence signal.
        """
        from .sast.runner import run_sast_findings
        try:
            findings = run_sast_findings(
                source_root, self.profile.key, verbose=self.verbose,
                is_cancelled=self.is_cancelled, apk_path=apk_path)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"Deterministic scanners failed ({exc}); continuing", self.verbose)
            return []
        if findings:
            verbose_print(
                f"Deterministic scanners produced {plural(len(findings), 'finding')}", self.verbose)
        return findings


    def run_agent(self, source_root, code_graph, framework_label: Optional[str] = None,
                 leads: Optional[List[Any]] = None, checkpoint=None):
        """
        Purpose:
            Run the AI analysis over the decompiled source, fanned out across code regions where a graph is available.

        Parameters:
            source_root: Root of the decompiled source.
            code_graph: Structural graph of the code, when one was built.
            framework_label: Framework name for the prompt.
            leads: Pre-identified starting points for the agent.
            checkpoint: Records per-region progress for resumption.

        Returns:
            The findings, whether coverage was complete, and the reasoning transcript.

        Implementation notes:
            Two paths: with a graph the work is split into surface regions and run in parallel, which is both faster and more thorough because each agent gets a bounded, coherent slice of the app. Without one it falls back to a single agent over the whole tree. Coverage is recorded either way, because a report has to be able to say which parts of the app the AI actually examined.
        """
        label = framework_label or self.framework_label
        self.agent_coverage: Dict[str, Any] = {}
        scope = dict(getattr(code_graph, "ownership", None) or {})
        if code_graph is not None and getattr(code_graph, "nodes", None):
            from .agent.fanout import run_surface_agents
            fanout_kwargs = {"checkpoint": checkpoint} if checkpoint is not None else {}
            findings, ok, transcript = run_surface_agents(
                self.ai_provider,
                source_root,
                self.profile,
                code_graph,
                label,
                is_cancelled=self.is_cancelled,
                progress=self.progress,
                verbose=self.verbose,
                coverage=self.agent_coverage,
                leads=leads,
                **fanout_kwargs,
            )
            if scope:
                self.agent_coverage["scope"] = scope
            return self._with_file_review(findings, source_root, code_graph, label, leads), ok, transcript
        from .agent.agent_loop import run_agent_analysis
        from ..config import user_settings

        budget = user_settings.get_agent_budget()
        minutes = budget.get("max_minutes") or 0
        telemetry: Dict[str, Any] = {}
        static_signals: Dict[str, Any] = {"framework": label}
        if leads:
            static_signals["leads"] = list(leads)
            static_signals["leads_total"] = len(leads)
        ckpt_kwargs = (
            {"resume_state": checkpoint.region_state("single"),
             "on_checkpoint": (lambda state: checkpoint.save_region("single", state))}
            if checkpoint is not None else {})
        findings, ok, transcript = run_agent_analysis(
            self.ai_provider,
            source_root,
            static_signals,
            code_graph=code_graph,
            profile=self.profile,
            is_cancelled=self.is_cancelled,
            verbose=self.verbose,
            max_steps=budget.get("max_steps_per_region") or None,
            deadline=(time.monotonic() + minutes * 60) if minutes else None,
            telemetry=telemetry,
            **ckpt_kwargs,
        )
        from .agent.fanout import _coverage_block

        self.agent_coverage = _coverage_block(
            [{"key": "single", "nodes": 0, "steps": telemetry.get("steps", 0),
              "files_read": telemetry.get("files_read", 0),
              "stop_reason": telemetry.get("stop_reason", "unknown"),
              "findings": len(findings or [])}],
            self.ai_provider)
        if scope:
            self.agent_coverage["scope"] = scope
        return self._with_file_review(findings, source_root, code_graph, label, leads), ok, transcript

    def _with_file_review(self, findings, source_root, code_graph, label: str,
                          leads: Optional[List[Any]]) -> List[Dict[str, Any]]:
        """
        Purpose:
            Add the file-by-file review's findings to the agent's.

        Parameters:
            findings: The agent's findings.
            source_root: Root of the decompiled source.
            code_graph: The code graph, or None.
            label: Framework name for the review context.
            leads: The rule engine's leads.

        Returns:
            The agent's findings followed by the review's.

        Side effects:
            Makes review requests and records the pass under agent_coverage["file_review"].

        Implementation notes:
            Runs after the agent rather than instead of it: the agent follows data between files, the review guarantees each flagged file was read once with full attention, and benchmark scans needed both. Findings are appended without merging, because the validation stage's deduplication already folds the same issue reported twice and keeps the better-evidenced copy. A provider that has gone unavailable is not asked again. Any failure other than cancellation leaves the agent's findings as they were, since the review only adds.
        """
        from .agent.file_review import run_file_review
        from ..config import user_settings

        if getattr(self.ai_provider, "unavailable", None):
            return findings
        telemetry: Dict[str, Any] = {}
        try:
            self.progress("agentic", 81, "Reviewing the flagged files one at a time")
            reviewed = run_file_review(
                self.ai_provider, source_root, self.profile, code_graph, label, leads=leads,
                max_parts=user_settings.get_agent_budget().get("max_review_parts", 0),
                is_cancelled=self.is_cancelled, verbose=self.verbose, telemetry=telemetry)
        except ScanCancelled:
            raise
        except Exception as exc:
            verbose_print(f"File review failed ({exc}); keeping the agent's findings", self.verbose)
            reviewed = []
        self.agent_coverage["file_review"] = telemetry
        return [*(findings or []), *reviewed]

    @staticmethod
    def merge_findings(agent_findings: List[Dict[str, Any]],
                       sast_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Purpose:
            Combine the agent's findings with the rule engine's, keeping the richer version of anything both reported.

        Parameters:
            agent_findings: Findings from the AI phase.
            sast_findings: Findings from the rule engine.

        Returns:
            The merged findings.

        Implementation notes:
            Two keys are used together: title plus file, and the coarse location identity. The first catches the same issue described identically, the second the same issue at the same place described differently by one engine. Agent findings are processed first, so an index established by one is reused rather than duplicated. The location identity is not used across engines: a rule-engine finding and an AI finding at one place go on to the validation stage, whose deduplication merges them with their content absorbed, the merge recorded and different facts kept apart. Here the richer one simply replaced the other, and a Ghera scan lost the scanner's "enforcePermission() reads the app's own identity" to the agent's vaguer "exported service guarded by a weak permission" on the same line, with no trace. This is a first pass, not the full deduplication.
        """
        def key(f: Dict[str, Any]) -> Tuple[str, str]:
            """
            Purpose:
                Build the title-and-file key used for the first-pass merge.

            Parameters:
                f: The finding.

            Returns:
                The normalised key.

            Implementation notes:
                Normalised for case and whitespace, since the two engines format titles differently and an exact match would never fire.
            """
            title = (f.get("title") or f.get("vulnerability_type") or "").strip().lower()
            return title, str(f.get("file", "")).strip()

        merged: List[Dict[str, Any]] = []
        seen: Dict[Tuple[str, str], int] = {}
        seen_identity: Dict[Tuple[Any, ...], int] = {}
        for finding in [*(agent_findings or []), *(sast_findings or [])]:
            k = key(finding)
            located = finding_identity(finding)
            identity = None if located is None else (*located, str(finding.get("source") or "") in RULE_SOURCES)
            idx = seen.get(k)
            if idx is None and identity is not None:
                idx = seen_identity.get(identity)
            if idx is None:
                seen[k] = len(merged)
                if identity is not None:
                    seen_identity[identity] = len(merged)
                merged.append(finding)
                continue
            seen[k] = idx
            if identity is not None:
                seen_identity[identity] = idx
            if finding_richness(finding) > finding_richness(merged[idx]):
                merged[idx] = finding
        return merged


    def source_prefixes(self) -> List[str]:
        """
        Purpose:
            Path prefixes to try when resolving a model-cited file.

        Returns:
            The prefixes; empty by default.

        Implementation notes:
            Overridden by analyzers whose decompiled layout puts sources under a known subdirectory, so the model can cite a path relative to the package root and still resolve.
        """
        return []

    def resolve_source_path(self, source_root, file_rel: str,
                            claim_terms: Optional[Sequence[str]] = None
                            ) -> Optional[Path]:
        """
        Purpose:
            Resolve a file path as a model wrote it to a real file in the decompiled tree.

        Parameters:
            source_root: Root of the decompiled source.
            file_rel: The cited path.
            claim_terms: Security concepts the finding claims, used to disambiguate.

        Returns:
            The resolved path, or None when it could not be resolved unambiguously.

        Implementation notes:
            Resolution goes from exact to increasingly tolerant: the path as given, then under each known prefix, then by basename across the tree. Ambiguity is refused rather than guessed. When several files share a basename the path suffix is tried first, then the claim terms -- if exactly one candidate contains the APIs the finding names, that is the file. When nothing distinguishes them, None is returned and the finding is marked unresolved, which the gates then treat as a downgrade rather than a refutation. A very large number of same-named files short-circuits the whole attempt, because searching them is expensive and the result would be ambiguous anyway.

        Security considerations:
            The cited path is model output. It is used to search within the source root rather than joined and opened, and the leading separator is stripped, so a cited absolute path cannot escape the tree.
        """
        if not file_rel or not source_root:
            return None
        source_root = Path(source_root)
        file_rel = file_rel.strip().lstrip("/")
        candidates = [source_root / file_rel]
        for prefix in self.source_prefixes():
            candidates.append(source_root / prefix / file_rel)
        for candidate in candidates:
            if candidate.is_file():
                return candidate

        normalized = file_rel.replace("\\", "/")
        basename = Path(normalized).name
        if not basename:
            return None

        try:
            twins = self._basename_candidates(source_root, basename)
        except Exception:
            return None
        if not twins:
            return None
        if len(twins) == 1:
            return twins[0]
        if len(twins) > MAX_BASENAME_CANDIDATES:
            verbose_print(
                f"Refusing to resolve {file_rel!r}: over {MAX_BASENAME_CANDIDATES} "
                "files share that basename", self.verbose)
            return None

        if "/" in normalized:
            suffix = "/" + normalized
            suffix_matches = [t for t in twins
                              if str(t).replace("\\", "/").endswith(suffix)]
            if len(suffix_matches) == 1:
                return suffix_matches[0]

        if claim_terms:
            supporting = [t for t in twins
                         if self._file_supports_terms(t, claim_terms)]
            if len(supporting) == 1:
                return supporting[0]

        verbose_print(
            f"Refusing to resolve {file_rel!r}: {len(twins)} files share that "
            "basename and nothing distinguishes them", self.verbose)
        return None

    @staticmethod
    def _basename_candidates(source_root: Path, basename: str) -> List[Path]:
        """
        Purpose:
            Find every file in the tree with a given basename.

        Parameters:
            source_root: Root of the decompiled source.
            basename: The filename to find.

        Returns:
            The matches, sorted.

        Implementation notes:
            Sorted so that resolution is deterministic between runs, which matters because a resolved path ends up in the report.
        """
        return sorted(source_root.rglob(basename), key=str)

    @staticmethod
    def _file_supports_terms(path: Path, term_ids: Sequence[str]) -> bool:
        """
        Purpose:
            Check whether a file contains the APIs a finding claims, to disambiguate between same-named files.

        Parameters:
            path: The candidate file.
            term_ids: The claimed concepts.

        Returns:
            True when the file contains matching vocabulary.

        Implementation notes:
            Only the head of the file is read, which bounds the cost across many candidates and is where the imports and class declarations that signal the relevant APIs appear. Decoded leniently, since a decompiled file can contain undecodable bytes and failing on one would drop a valid candidate.
        """
        try:
            with path.open("rb") as handle:
                blob = handle.read(CLAIM_SCAN_BYTES).decode("utf-8", errors="ignore")
        except OSError:
            return False
        return evidence_supports(term_ids, blob)

    @staticmethod
    def _anchor_line(snippet_lines: List[str]) -> Optional[str]:
        """
        Purpose:
            Choose the line from a snippet most likely to be findable in the source.

        Parameters:
            snippet_lines: Non-empty lines of the snippet.

        Returns:
            The anchor line, or None.

        Implementation notes:
            Structural lines -- lone braces and closers -- are skipped, because they appear everywhere and would match the wrong place immediately. A minimum length filters out other near-universal fragments. Falls back to the first line when nothing better exists, since an imperfect anchor is better than giving up on locating the snippet.
        """
        for line in snippet_lines:
            stripped = line.strip()
            if len(stripped) >= 6 and stripped not in ("{", "}", "};", "});"):
                return stripped
        return snippet_lines[0].strip() if snippet_lines else None

    def _locate_snippet_span(self, source_lines: List[str], code_snippet: str) -> Optional[tuple]:
        """
        Purpose:
            Find where a reported snippet actually appears in the source file.

        Parameters:
            source_lines: The file's lines.
            code_snippet: The snippet the finding reported.

        Returns:
            The start and end line numbers, or None when the snippet was not found.

        Implementation notes:
            Located by anchor rather than by matching the whole snippet, because a model reformats and abridges what it quotes and an exact multi-line match almost never succeeds. The span is extended by the snippet's own length, so the highlighted region covers what was reported rather than a single line. This is what lets a finding cite a real line range even when the model's own line number was wrong.
        """
        snippet_lines = [l for l in code_snippet.splitlines() if l.strip()]
        anchor = self._anchor_line(snippet_lines)
        if not anchor:
            return None
        for idx, line in enumerate(source_lines):
            if anchor in line:
                start = idx + 1
                end = min(len(source_lines), start + max(1, len(snippet_lines)) - 1)
                return (start, end)
        return None

    def _build_code_context(self, source_lines: List[str], start: int, end: int, filename: str,
                            window: Optional[Tuple[int, int]] = None) -> Dict:
        """
        Purpose:
            Build the code excerpt shown in the report: the cited lines plus surrounding context, highlighted.

        Parameters:
            source_lines: The file's lines.
            start: First cited line.
            end: Last cited line.
            filename: Used to select a syntax lexer.
            window: Explicit first and last context lines, replacing the default padding; widened if needed so it always contains the cited lines.

        Returns:
            The context block with real line numbers, the highlight range, the raw lines and their highlighted forms.

        Implementation notes:
            Bounds are clamped to the file, so a model citing a line past the end yields the end of the file rather than an error. Padding is added on both sides because a line in isolation rarely shows whether an issue is real -- the guard above it or the sink below is usually the deciding context. Both raw and highlighted lines are carried, so the renderer can use the highlighted form and anything else can read the raw text.
        """
        n = len(source_lines)
        start = max(1, min(start, n))
        end = max(start, min(end, n))
        if window:
            ctx_start = max(1, min(window[0], start))
            ctx_end = min(n, max(window[1], end))
        else:
            ctx_start = max(1, start - CONTEXT_PADDING_LINES)
            ctx_end = min(n, end + CONTEXT_PADDING_LINES)
        window = source_lines[ctx_start - 1:ctx_end]
        return {
            "start_line": ctx_start,
            "end_line": ctx_end,
            "highlight_start": start,
            "highlight_end": end,
            "lines": window,
            "lines_html": highlight_lines(window, filename),
            "snippet": "\n".join(source_lines[start - 1:end]),
        }

    def enrich_vulnerabilities(self, vulnerabilities: List[Dict], source_root) -> None:
        """
        Purpose:
            Attach real source evidence to every finding: the resolved file, the located line range, and the surrounding code.

        Parameters:
            vulnerabilities: The findings, mutated in place.
            source_root: Root of the decompiled source.

        Side effects:
            Reads source files and mutates the findings.

        Implementation notes:
            This is the step that makes the rest of the pipeline possible. Gating refutes a claim by checking the cited code, deduplication compares locations, and the report shows the excerpt -- all of which depend on the finding pointing at a real place in a real file. Findings whose path cannot be resolved are marked rather than dropped, so the gates can downgrade them for being uncheckable instead of the analyzer silently discarding a possibly-real issue. A finding citing a native library takes its excerpt from the decompiled view the agent read, when Ghidra produced one, labelled as Ghidra pseudo-C so nobody mistakes it for the developer's source. The claim vocabulary one step from the citation - the bodies of app methods the cited lines call, or the code reading a cited res/values entry - is recorded as hop_terms (see evidence_hop), because a model rightly cites a helper's call or a key's declaration while the API its claim names sits in the helper.
        """
        _enum_cache: Dict[str, bool] = {}
        for vuln in vulnerabilities:
            try:
                file_rel = vuln.get("file", "")
                if not file_rel:
                    continue
                terms = salient_terms(
                    f"{vuln.get('title', '')} {vuln.get('vulnerability_type', '')}")
                source_path = self.resolve_source_path(
                    source_root, file_rel, claim_terms=terms)
                if not source_path:
                    vuln["source_unresolved"] = True
                    continue
                if not _looks_like_text(source_path):
                    if not self._attach_native_context(vuln, source_root, source_path, _enum_cache):
                        verbose_print(
                            f"Skipping code context for "
                            f"'{vuln.get('vulnerability_type', vuln.get('title', 'finding'))}': "
                            f"{source_path.name} is binary, not source", self.verbose)
                    continue
                source_lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if not source_lines:
                    continue

                start = int(vuln.get("line_number") or 0)
                end = int(vuln.get("line_end") or 0) or start

                if start <= 0:
                    span = self._locate_snippet_span(source_lines, vuln.get("code_snippet", ""))
                    if span is None:
                        continue
                    start, end = span

                if end < start:
                    start, end = end, start

                context = self._build_code_context(source_lines, start, end, source_path.name)
                if self._is_recovered_module(source_path, source_root):
                    context["module_terms"] = self._module_terms(source_lines, vuln)
                hop = hop_terms(Path(source_root), source_path, source_lines, start, end, vuln)
                if hop:
                    context["hop_terms"] = hop
                vuln["code_snippet"] = context.pop("snippet")
                vuln["code_context"] = context
                self._attach_evidence_fields(
                    vuln, source_lines, start, end, source_root, _enum_cache)
                verbose_print(
                    f"Attached code context for "
                    f"'{vuln.get('vulnerability_type', vuln.get('title', 'finding'))}': "
                    f"{source_path.name} lines {context['start_line']}-{context['end_line']} "
                    f"(highlight {context['highlight_start']}-{context['highlight_end']})", self.verbose)
            except Exception as e:
                verbose_print(f"Could not enrich vulnerability with source context: {e}", self.verbose)

    def _is_recovered_module(self, source_path: Path, source_root) -> bool:
        """
        Purpose:
            Decide whether a cited file is one recovered cross-platform module.

        Parameters:
            source_path: The resolved file.
            source_root: Root of the analysis tree.

        Returns:
            True when the file sits under one of this analyzer's module directories.
        """
        if not self.module_evidence_dirs:
            return False
        try:
            rel = source_path.resolve().relative_to(Path(source_root).resolve())
        except (OSError, ValueError):
            return False
        return bool(rel.parts) and rel.parts[0] in self.module_evidence_dirs

    @staticmethod
    def _module_terms(source_lines: List[str], vuln: Dict) -> List[str]:
        """
        Purpose:
            Record the claim vocabulary a whole recovered module contains.

        Parameters:
            source_lines: The module's lines.
            vuln: The finding, whose title supplies the API names worth looking for.

        Returns:
            The claim-table aliases, and the APIs the title names, that occur anywhere in the module.

        Implementation notes:
            A Dart library recovered by Blutter, or a Metro module, is one source file: a WebView channel is registered in initState while the finding rightly cites its handler, and CryptoJS.AES is called a few lines below the key it is given. The few lines around a citation miss those, and real findings were refuted for it. Only the vocabulary is recorded, never the code, so the claim gates can see what the module contains at almost no cost.
        """
        text = "\n".join(source_lines)
        terms = aliases_present(text)
        names = api_terms(f"{vuln.get('title', '')} {vuln.get('vulnerability_type', '')}")
        return terms + names_present(text, names)

    def _attach_native_context(self, vuln: Dict, source_root, library: Path,
                               enum_cache: Dict[str, bool]) -> bool:
        """
        Purpose:
            Attach the decompiled code a native finding cites, taken from the view the agent read.

        Parameters:
            vuln: The finding, mutated in place.
            source_root: Root of the decompiled tree.
            library: The resolved library the finding cites.
            enum_cache: Shared cache of enum lookups, passed through to the evidence fields.

        Returns:
            True when an excerpt was attached; False when the library has no decompiled view or the citation cannot be tied to any function in it.

        Side effects:
            Mutates the finding, repairing its line numbers when the citation had to be mapped.

        Implementation notes:
            Kept apart from the text-file path because a native citation is resolved differently: by the view's line numbers, or, when the model cited an address or a number past the end, by the function it names. The text path's fallback of searching for the cited snippet is never used here, since a model-written snippet is not how native citations are made. The excerpt is the whole function rather than a few lines either side, because the function's name and its buffer declarations sit in the signature and the locals, often well above the defect, and both a reader and the claim gates need them to see what the finding is about. Its header comment is reworded to say it is Ghidra pseudo-C and the context records the same, so the report never presents reconstructed code as the developer's source.

        Known limitations:
            A function longer than NATIVE_CONTEXT_MAX_LINES falls back to the usual padding, so its excerpt may not show the signature.
        """
        view = self._native_view_lines(source_root, library)
        if not view:
            return False
        from .agent.tools import locate_native_citation
        span = locate_native_citation(
            view, int(vuln.get("line_number") or 0), int(vuln.get("line_end") or 0),
            vuln.get("line"),
            f"{vuln.get('title', '')} {vuln.get('vulnerability_type', '')} "
            f"{vuln.get('description', '')}")
        if span is None:
            return False
        start, end = span
        vuln["line_number"], vuln["line_end"] = start, end
        from .agent.tools import native_function_span
        window = native_function_span(view, start)
        if window and window[1] - window[0] < NATIVE_CONTEXT_MAX_LINES:
            header = view[window[0] - 1]
            if header.startswith("// ---- "):
                view[window[0] - 1] = "// Ghidra decompilation (pseudo-C) of " + header[len("// ---- "):]
        else:
            window = None
        context = self._build_code_context(view, start, end, f"{library.name}.c", window=window)
        context["origin"] = "Ghidra decompilation (pseudo-C), not the developer's source"
        vuln["code_snippet"] = context.pop("snippet")
        vuln["code_context"] = context
        self._attach_evidence_fields(vuln, view, start, end, source_root, enum_cache)
        verbose_print(
            f"Attached decompiled context for "
            f"'{vuln.get('vulnerability_type', vuln.get('title', 'finding'))}': "
            f"{library.name} lines {context['start_line']}-{context['end_line']} "
            f"(highlight {context['highlight_start']}-{context['highlight_end']})", self.verbose)
        return True

    def decompile_platform_layer(self, apk_path: str, out_dir) -> Optional[Path]:
        """
        Purpose:
            Decompile the app's Java/Kotlin platform layer next to a cross-platform app's recovered code.

        Parameters:
            apk_path: Path to the APK.
            out_dir: The analysis root; the output goes under its platform/ directory.

        Returns:
            The platform directory, or None when JADX is not configured or produced nothing.

        Side effects:
            Runs JADX, which can take a minute or more on a large app.

        Implementation notes:
            Used by the frameworks whose logic is not in the DEX -- Flutter and React Native -- because their root, emulator and integrity checks, native modules and plugin internals still are. Written inside the analysis root so the agent's tools can read and search it beside the recovered code, and so each framework's overview can link the two. The framework packages JADX writes alongside the app (androidx, io.flutter, kotlin) are left on disk and filtered by the profile's noise fragments rather than deleted, so a lead into them can still be followed.
        """
        from ..tools_checker.jadx_checker import check_jadx_configured
        from ..decompiler.java_kotlin_decompiler import JavaKotlinDecompiler
        if not check_jadx_configured(verbose=self.verbose):
            verbose_print("JADX not configured - skipping the platform layer", self.verbose)
            return None
        target = Path(out_dir) / PLATFORM_DIR
        try:
            result = JavaKotlinDecompiler(verbose=self.verbose).jadx_decompile(apk_path, output_dir=target)
        except Exception as exc:
            verbose_print(f"Platform-layer decompilation failed: {exc}", self.verbose)
            return None
        return Path(result) if result else None

    def _native_view_lines(self, source_root, library: Path) -> List[str]:
        """
        Purpose:
            Recover the decompiled view of a native library that a finding cites, numbered as the agent saw it.

        Parameters:
            source_root: Root of the decompiled tree.
            library: The resolved library the finding cites.

        Returns:
            The view's lines, or an empty list when the file is not a native library or Ghidra produced no code for it.

        Implementation notes:
            The agent cites native findings by the line numbers of the inspect_native view, so the evidence has to come from that same view rather than from the binary. Without it a native finding carries no excerpt and the gates cap it as unverifiable, even though the agent read the decompiled code and cited the exact line. The tool surface is imported here rather than at module load because it pulls in the Ghidra runner, which only native findings need.
        """
        if library.suffix != ".so":
            return []
        try:
            from .agent.tools import AgentTools
            rel = library.resolve().relative_to(Path(source_root).resolve()).as_posix()
            return AgentTools(source_root).native_view(rel) or []
        except Exception as exc:
            verbose_print(f"Decompiled view unavailable for {library.name}: {exc}", self.verbose)
            return []

    def _attach_evidence_fields(self, vuln: Dict, source_lines: List[str],
                                start: int, end: int,
                                source_root, enum_cache: Dict[str, bool]) -> None:
        """
        Purpose:
            Attach the located span, the code context and any nearby mitigations to one finding.

        Parameters:
            vuln: The finding, mutated in place.
            source_lines: The resolved file's lines.
            start: First line of the located span.
            end: Last line of the located span.
            source_root: Root of the decompiled tree, for relative paths.
            enum_cache: Shared cache of enum lookups, reused across findings.

        Side effects:
            Mutates the finding.

        Implementation notes:
            Nearby mitigating calls are detected within a window around the cited line and recorded on the finding, which is what the WebView gate later uses to lower a ceiling. Detecting them here, where the source is already loaded, avoids a second pass over the file. The enum cache is passed in rather than held per call, because the same type is asked about repeatedly across a result set and each lookup searches the decompiled tree. SQL provenance and vendor tagging are both optional enrichment, so a failure in either is logged and leaves that field off the finding rather than losing the rest of its evidence.
        """
        n = len(source_lines)
        w_start = max(1, start - MITIGATION_WINDOW_LINES)
        w_end = min(n, end + MITIGATION_WINDOW_LINES)
        window = "\n".join(source_lines[w_start - 1:w_end])
        vuln["evidence_window"] = window

        blob = f"{vuln.get('title', '')} {vuln.get('vulnerability_type', '')} {vuln.get('vuln_class', '')}".lower()

        if any(k in blob for k in ("webview", "javascript", "js bridge", "js interface",
                                   "addjavascriptinterface", "file access", "web view")):
            found = [label for label, rx in _WEBVIEW_MITIGATIONS if rx.search(window)]
            vuln["webview_mitigations"] = found

        if _SQL_FINDING_RE.search(blob):
            from .sast.extractors.injection import resolve_sql_provenance
            text = "\n".join(source_lines)

            def _enum_lookup(type_name: str) -> bool:
                """
                Purpose:
                    Report whether a named type is an enum, with the answer cached across findings.

                Parameters:
                    type_name: The type to check.

                Returns:
                    True when the type appears to be an enum declaration.

                Implementation notes:
                    Cached because the same type is asked about repeatedly across a result set, and each lookup searches the decompiled tree. Used to suppress a class of false positive: a constant referenced from an enum is not a hardcoded secret, and without this check enum members are reported as such.
                """
                if type_name in enum_cache:
                    return enum_cache[type_name]
                hit = False
                try:
                    rx = re.compile(_ENUM_DECL_RE_TMPL.format(name=re.escape(type_name)))
                    for cand in list(Path(source_root).rglob(f"{type_name}.java"))[:8]:
                        if rx.search(cand.read_text(encoding="utf-8", errors="ignore")[:CLAIM_SCAN_BYTES]):
                            hit = True
                            break
                except Exception:
                    hit = False
                enum_cache[type_name] = hit
                return hit

            try:
                vuln["operand_provenance"] = resolve_sql_provenance(text, start, _enum_lookup)
            except Exception as exc:
                verbose_print(f"SQL operand provenance could not be resolved for {vuln.get('file', '')}: {exc}", self.verbose)

        try:
            from .agent.code_graph import vendor_sdk_for_path
            sdk = vendor_sdk_for_path(str(vuln.get("file", "")))
            if sdk:
                vuln["vendor_sdk"] = sdk
        except Exception as exc:
            verbose_print(f"Vendor SDK tagging failed for {vuln.get('file', '')}: {exc}", self.verbose)
