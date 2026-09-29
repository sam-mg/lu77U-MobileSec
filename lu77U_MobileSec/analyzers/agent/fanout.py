#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.fanout

Purpose:
    Run the analysis agent across the app's regions in parallel: partition the graph, allocate budget, run one agent per region, and merge what they found.

Responsibilities:
    Assign regions and leads, allocate steps and time, run the workers, record coverage, and stitch the results and transcripts together.

Dependencies:
    The partitioner, the agent loop, the budget, the provider layer.

Implementation notes:
    Fanning out is what makes the AI phase both faster and more thorough. Each agent gets a bounded region with its own entry points and its own guidance, rather than one agent trying to hold an entire app in context and losing the thread. Coverage is recorded per region, so a report can say which parts of the app the AI actually examined and which it did not reach. A phase that quietly analysed half an app and reported few findings would read as a clean result.

Thread-safety:
    Workers run concurrently against a shared provider, which bounds its own concurrency internally. Per-region state is per worker; the shared result and coverage structures are written under the provider's own coordination and collected after the workers finish.
"""

import contextlib
import contextvars
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .budget import Deadline
from .code_graph import NativeLib
from .leads import Lead, MAX_LEADS_PER_REGION
from .partition import Region, partition_graph
from .surfaces import guidance_for_families
from ...validation import finding_identity, finding_richness
from ...config import user_settings
from ...utils.cancellation import ScanCancelled
from ...utils.verbose import plural, verbose_print

PROGRESS_START = 64
PROGRESS_END = 82


class _SurfaceResult:
    """
    Purpose:
        What one region's agent produced.

    Attributes:
        Its region, the findings, whether it completed, its transcript and its exploration statistics.

    Thread-safety:
        Written by one worker and read after the workers finish.
    """
    __slots__ = ("surface", "findings", "completed_ok", "transcript", "error",
                 "nodes", "stop_reason", "steps", "files_read")

    def __init__(self, surface: Region):
        """
        Purpose:
            Construct the result holder for one region.

        Parameters:
            surface: The region this agent covers.
        """
        self.surface = surface
        self.findings: List[Dict[str, Any]] = []
        self.completed_ok = False
        self.transcript = ""
        self.error: Optional[BaseException] = None
        self.nodes = 0
        self.stop_reason = "unknown"
        self.steps = 0
        self.files_read = 0


def _finding_key(v: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Purpose:
        Build the key identifying a finding across regions.

    Parameters:
        v: The finding.

    Returns:
        The key.

    Implementation notes:
        Regions overlap at their boundaries, so two agents can report the same issue. Keying on what identifies it -- rather than on which agent found it -- is what lets the merge collapse those.
    """
    title = (v.get("title") or v.get("vulnerability_type") or "").strip().lower()
    return (title, str(v.get("file", "")).strip(), str(v.get("line", "")).strip())


def merge_surface_findings(results: List[_SurfaceResult]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Combine the findings from every region, dropping cross-region duplicates.

    Parameters:
        results: The per-region results.

    Returns:
        The merged findings.

    Implementation notes:
        Deduplicated on the finding key rather than merged in detail, since the thorough merge with severity and corroboration handling happens later in validation. This pass only prevents the same issue appearing once per region that touched it.
    """
    out: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str, str], int] = {}
    seen_identity: Dict[Tuple[str, str, str], int] = {}
    for result in results:
        for finding in result.findings:
            key = _finding_key(finding)
            if not key[0]:
                continue
            finding.setdefault("surface", result.surface.key)
            finding.setdefault("source", "agent")

            identity = finding_identity(finding)
            idx = seen.get(key)
            if idx is None and identity is not None:
                idx = seen_identity.get(identity)
            if idx is None:
                seen[key] = len(out)
                if identity is not None:
                    seen_identity[identity] = len(out)
                out.append(finding)
                continue
            seen[key] = idx
            if identity is not None:
                seen_identity[identity] = idx
            if finding_richness(finding) > finding_richness(out[idx]):
                out[idx] = finding
    return out


MIN_REGION_STEPS = 8


def allocate_steps(assignments: List[Tuple[Region, Any]],
                   max_steps: Optional[int]) -> Dict[str, Optional[int]]:
    """
    Purpose:
        Divide the step budget across the regions.

    Parameters:
        assignments: The regions and their subgraphs.
        max_steps: Total steps available; None means unbounded.

    Returns:
        The step allowance per region, None per region when unbounded.

    Implementation notes:
        Allocated by region weight rather than equally, because regions differ substantially in how much there is to examine and an equal split starves the large ones while leaving the small ones with budget they cannot use. Every region gets a floor, so even a small one has enough steps to reach a conclusion rather than stopping mid-investigation.
    """
    keys = [region.key for region, _ in assignments]
    if max_steps is None or not keys:
        return {key: max_steps for key in keys}

    sizes = {region.key: len(sub.nodes) for region, sub in assignments}
    total_nodes = sum(sizes.values())
    if total_nodes <= 0:
        return {key: max_steps for key in keys}

    total_budget = max_steps * len(keys)
    raw = {key: sizes[key] / total_nodes * total_budget for key in keys}
    allocated = {key: int(raw[key]) for key in keys}
    remainder = total_budget - sum(allocated.values())
    by_fraction = sorted(keys, key=lambda k: (-(raw[k] - allocated[k]), k))
    for key in by_fraction[:remainder]:
        allocated[key] += 1

    return {key: max(MIN_REGION_STEPS, allocated[key]) for key in keys}


def _assign_native_libs(assignments: List[Tuple[Region, Any]],
                        libs: List[NativeLib]) -> None:
    """
    Purpose:
        Attach the native libraries to the regions most likely to care about them.

    Parameters:
        assignments: The regions and their subgraphs, mutated to record the attachment.
        libs: The native libraries found in the app.

    Side effects:
        Records the attached libraries on the regions.

    Implementation notes:
        Native libraries belong to no region in the call graph, since the graph covers Dalvik code. Attaching them to the regions whose code loads them is what lets an agent investigating a Java-side finding also inspect the native half, rather than the libraries being invisible to every agent.
    """
    if not libs or not assignments:
        return

    groups: Dict[str, List[NativeLib]] = {}
    for lib in libs:
        groups.setdefault(lib.path.rsplit("/", 1)[-1], []).append(lib)

    ordered = sorted(assignments,
                     key=lambda pair: (-len(pair[1].nodes), pair[0].key))

    for position, basename in enumerate(sorted(groups)):
        group = groups[basename]
        representative = next((l for l in group if "arm64" in l.path), group[0])
        _, sub = ordered[position % len(ordered)]
        sub.native_libs = list(getattr(sub, "native_libs", None) or [])
        sub.native_libs.append(representative)


def _norm_lead_path(path: str) -> str:
    """
    Purpose:
        Normalise a lead's path for matching against region members.

    Parameters:
        path: The lead's file path.

    Returns:
        The normalised path.

    Implementation notes:
        The rule engine and the graph express paths differently, and a lead that fails to match a region is simply lost -- so the two are normalised to one form before comparison.
    """
    return str(path or "").strip().lstrip("/").replace("\\", "/")


def _leads_by_region(
    assignments: List[Tuple[Region, Any]], leads: Sequence[Lead],
) -> Tuple[Dict[str, List[Lead]], List[Lead]]:
    """
    Purpose:
        Distribute the deterministic scanners' leads to the regions containing them.

    Parameters:
        assignments: The regions and their subgraphs.
        leads: The leads to distribute.

    Returns:
        The leads grouped by region, and the leads that matched no region.

    Implementation notes:
        Each agent receives only the leads in its own region, so its prompt points at code it can actually reach. Giving every agent every lead would waste context and send agents chasing findings outside their scope. Unmatched leads are returned rather than dropped, so a finding in a file no region covers is still visible to the caller and counts against coverage.
    """
    file_owner: Dict[str, str] = {}
    basename_owners: Dict[str, set] = {}
    for region, sub in assignments:
        for node in sub.nodes.values():
            path = _norm_lead_path(getattr(node, "file", ""))
            if not path:
                continue
            file_owner.setdefault(path, region.key)
            basename_owners.setdefault(path.rsplit("/", 1)[-1], set()).add(region.key)

    by_region: Dict[str, List[Lead]] = {region.key: [] for region, _ in assignments}
    unowned: List[Lead] = []
    for lead in leads:
        path = _norm_lead_path(lead.file)
        owner = file_owner.get(path)
        if owner is None:
            owners = basename_owners.get(path.rsplit("/", 1)[-1], set())
            owner = next(iter(owners)) if len(owners) == 1 else None
        if owner is None:
            unowned.append(lead)
            continue
        by_region[owner].append(lead)

    for lead in unowned:
        target = min(by_region, key=lambda k: (len(by_region[k]), k))
        by_region[target].append(lead)

    for key, region_leads in by_region.items():
        if len(region_leads) > MAX_LEADS_PER_REGION:
            by_region[key] = region_leads[:MAX_LEADS_PER_REGION]
    return by_region, unowned


def _weights_from_leads(code_graph, leads: Optional[Sequence[Lead]]) -> Dict[str, int]:
    """
    Purpose:
        Weight graph nodes by how much attention they deserve, using the leads.

    Parameters:
        code_graph: The code graph.
        leads: The rule engine's leads.

    Returns:
        The per-node weights.

    Implementation notes:
        Nodes the rule engine already flagged are weighted up, which feeds into partitioning: regions are balanced by weight, so a region dense with leads is kept smaller and its agent has proportionally more budget per finding to investigate.
    """
    weights: Dict[str, int] = {}
    for lead in leads or []:
        node = code_graph.node_for_file(getattr(lead, "file", ""))
        if node is not None:
            weights[node.descriptor] = weights.get(node.descriptor, 0) + 1
    return weights


def run_surface_agents(
    provider,
    source_root,
    profile,
    code_graph,
    framework_label: str,
    is_cancelled: Optional[Callable[[], bool]] = None,
    progress: Optional[Callable[..., None]] = None,
    verbose: bool = False,
    coverage: Optional[Dict[str, Any]] = None,
    leads: Optional[Sequence[Lead]] = None,
    checkpoint=None,
) -> Tuple[List[Dict[str, Any]], bool, str]:
    """
    Purpose:
        Run the agent across every region of the app and return the merged findings.

    Parameters:
        provider: The AI provider.
        source_root: Root of the decompiled source.
        profile: The framework profile.
        code_graph: The code graph.
        framework_label: Framework name for the prompts.
        is_cancelled: Polled by the workers.
        progress: Reports progress.
        verbose: Traces the fan-out.
        coverage: Populated with what each region managed to examine.
        leads: The rule engine's findings, as starting points.
        checkpoint: Per-region resume state.

    Returns:
        The merged findings, whether coverage was complete, and the stitched transcript.

    Side effects:
        Makes many provider requests across several threads, and records per-region checkpoints.

    Implementation notes:
        A shared deadline bounds the whole phase, and it is registered as a throttle observer on the provider, so time the workers spend blocked on rate limiting is credited back rather than counted against the analysis. Without that, a throttling provider would silently reduce coverage rather than just taking longer. Regions with resumable checkpoint state are skipped or resumed rather than repeated, which is what makes an interrupted scan cheap to continue. The opening progress announcement is best-effort and any failure delivering it, ScanCancelled included, is suppressed, because each worker polls is_cancelled before starting its region and that is where a stop request takes effect. Empty subgraphs are dropped before workers are started, so no agent is launched with nothing to examine. Coverage is recorded whether or not every region finished, because the report needs to state what was examined regardless of how the phase ended.
    """
    from .agent_loop import run_agent_analysis

    is_cancelled = is_cancelled or (lambda: False)
    progress = progress or (lambda *unused_a, **unused_kw: None)

    budget = user_settings.get_agent_budget()
    max_steps = budget.get("max_steps_per_region") or None
    minutes = budget.get("max_minutes") or 0
    deadline = Deadline(minutes * 60 if minutes else None)
    add_observer = getattr(provider, "add_throttle_observer", None)
    if callable(add_observer):
        add_observer(deadline.credit)

    regions = partition_graph(
        code_graph, verbose=verbose, weights=_weights_from_leads(code_graph, leads))
    assignments: List[Tuple[Region, Any]] = []
    for region in regions:
        sub = code_graph.subgraph_of(region.members)
        if not sub.nodes:
            continue
        assignments.append((region, sub))

    if not assignments:
        verbose_print("Fan-out: nothing to partition; falling back to one agent", verbose)
        solo: Dict[str, Any] = {}
        solo_signals: Dict[str, Any] = {"framework": framework_label}
        if leads:
            solo_signals["leads"] = list(leads)
            solo_signals["leads_total"] = len(leads)
        solo_ckpt = (
            {"resume_state": checkpoint.region_state("single"),
             "on_checkpoint": (lambda s: checkpoint.save_region("single", s))}
            if checkpoint is not None else {})
        findings, ok, transcript = run_agent_analysis(
            provider, source_root, solo_signals,
            code_graph=code_graph, profile=profile,
            is_cancelled=is_cancelled, verbose=verbose,
            max_steps=max_steps, deadline=deadline, telemetry=solo, **solo_ckpt)
        if coverage is not None:
            coverage.update(_coverage_block(
                [{"key": "single", "nodes": len(getattr(code_graph, "nodes", []) or []),
                  "steps": solo.get("steps", 0),
                  "files_read": solo.get("files_read", 0),
                  "stop_reason": solo.get("stop_reason", "unknown"),
                  "findings": len(findings or [])}],
                provider))
        deadline.close()
        return findings, ok, transcript

    _assign_native_libs(assignments, code_graph.native_libs)

    step_budgets = allocate_steps(assignments, max_steps)

    leads_by_region, unowned_leads = _leads_by_region(assignments, leads or [])
    leads_total = len(leads or [])

    total = len(assignments)
    verbose_print(
        f"Fan-out: {plural(total, 'region agent')} - "
        + ", ".join(f"{r.key}({len(g.nodes)}, {step_budgets[r.key] or 'unlimited'} steps)"
                    for r, g in assignments), verbose)
    verbose_print(
        f"AI phase budget: up to {total} x {max_steps or 'unlimited'} model calls"
        + (f", capped at {minutes} min" if minutes else ", no time cap"), verbose)
    with contextlib.suppress(Exception):
        progress("agentic", PROGRESS_START,
                 f"Examining {plural(total, 'code region')} - up to "
                 f"{total * max_steps if max_steps else 'unlimited'} model calls"
                 + (f", {minutes} min cap" if minutes else ""))

    tokens_before = getattr(provider, "usage", {}).get("completion_tokens", 0)

    results = [_SurfaceResult(surface) for surface, _ in assignments]
    lock = threading.Lock()
    done = [0]

    def worker(index: int, surface: Region, subgraph) -> None:
        """
        Purpose:
            Run one region's agent and record its result.

        Parameters:
            index: The region's position, used for naming and budget.
            surface: The region.
            subgraph: The region's slice of the code graph.

        Side effects:
            Makes provider requests, writes a region checkpoint, and records the result.

        Raises:
            BaseException: A KeyboardInterrupt, SystemExit or other non-Exception raised by the region, after it has been recorded on the region's result.

        Implementation notes:
            Failures are captured into the region's result rather than propagated, so one region failing costs its findings rather than the whole phase -- and the coverage record shows which region it was. Only ordinary exceptions are absorbed that way; a BaseException such as KeyboardInterrupt or SystemExit is recorded and then re-raised, because it is a request to stop the process rather than a region failure and must not be downgraded to an error line. ScanCancelled is an ordinary exception and is recorded like any other failure, then re-raised by the caller after the join. The completion progress update in the finally block is best-effort and suppresses every Exception, ScanCancelled included, because cancellation reaches the caller through result.error and is_cancelled rather than through this callback. The thread is named after the region, which is how the provider attributes transcripts and cost per region.
        """
        result = results[index]
        result.nodes = len(subgraph.nodes)
        try:
            if is_cancelled():
                raise ScanCancelled()
            saved = checkpoint.region_state(surface.key) if checkpoint is not None else None
            if saved and saved.get("done") and saved.get("completed_ok") and not saved.get("resumable"):
                result.findings = [v for v in (saved.get("accumulated") or []) if isinstance(v, dict)]
                result.completed_ok = True
                result.stop_reason = saved.get("stop_reason", "reported")
                result.steps = int(saved.get("steps_taken", 0) or 0)
                result.files_read = len(saved.get("read_files") or []) + len(saved.get("inspected_native") or [])
                result.transcript = "\n\n".join(str(t) for t in (saved.get("transcript") or []))
                verbose_print(
                    f"Region {surface.key}: reused from checkpoint "
                    f"({plural(len(result.findings), 'finding')}), no model calls", verbose)
                return
            objective, skills = guidance_for_families(surface.families)
            telemetry: Dict[str, Any] = {}
            region_ckpt = (
                {"resume_state": saved,
                 "on_checkpoint": (lambda s, k=surface.key: checkpoint.save_region(k, s))}
                if checkpoint is not None else {})
            findings, ok, transcript = run_agent_analysis(
                provider, source_root,
                {"framework": framework_label,
                 "objective": objective,
                 "surface_label": surface.key,
                 "skills": list(skills),
                 "leads": leads_by_region.get(surface.key, []),
                 "leads_total": leads_total},
                code_graph=subgraph, profile=profile,
                is_cancelled=is_cancelled, verbose=verbose,
                max_steps=step_budgets[surface.key], deadline=deadline,
                telemetry=telemetry, **region_ckpt)
            result.stop_reason = telemetry.get("stop_reason", "unknown")
            result.steps = telemetry.get("steps", 0)
            result.files_read = telemetry.get("files_read", 0)
            result.findings = findings or []
            result.completed_ok = bool(ok)
            result.transcript = transcript or ""
        except Exception as exc:
            result.error = exc
        except BaseException as exc:
            result.error = exc
            raise
        finally:
            with lock:
                done[0] += 1
                pct = PROGRESS_START + int(
                    (PROGRESS_END - PROGRESS_START) * done[0] / max(total, 1))
                with contextlib.suppress(Exception):
                    progress("agentic", pct,
                             f"Region {done[0]}/{total} complete - {surface.key}")

    threads = []
    for index, (surface, subgraph) in enumerate(assignments):
        context = contextvars.copy_context()
        thread = threading.Thread(
            target=context.run, args=(worker, index, surface, subgraph),
            name=surface.key, daemon=True)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for result in results:
        if isinstance(result.error, ScanCancelled):
            raise result.error
    for result in results:
        if result.error is not None:
            verbose_print(
                f"Surface {result.surface.key} failed ({result.error}); "
                "keeping the other surfaces' findings", verbose)

    deadline.close()

    findings = merge_surface_findings(results)
    completed_ok = any(r.completed_ok for r in results)
    transcript = _stitch_transcript(results)

    if coverage is not None:
        leads_info = None
        if leads:
            leads_info = {
                "total": leads_total,
                "routed": sum(len(v) for v in leads_by_region.values()),
                "unowned": len(unowned_leads),
                "per_region": {k: len(v) for k, v in leads_by_region.items()},
            }
        coverage.update(_coverage_block(
            [{"key": r.surface.key, "nodes": r.nodes, "steps": r.steps,
              "files_read": r.files_read,
              "stop_reason": (
                  "failed" if r.error is not None else r.stop_reason),
              "findings": len(r.findings)}
             for r in results],
            provider, leads_info=leads_info))

    total_raw = sum(len(r.findings) for r in results)
    verbose_print(
        f"Fan-out complete: {plural(total_raw, 'raw finding')} across {plural(total, 'surface')}, "
        f"{len(findings)} after dedup", verbose)
    tokens_after = getattr(provider, "usage", {}).get("completion_tokens", 0)
    if tokens_after > tokens_before:
        verbose_print(
            f"Phase 1 (agent) output: {tokens_after - tokens_before} completion tokens "
            f"across {plural(total, 'region')}", verbose)
    return findings, completed_ok, transcript


_COMPLETE_REASONS = ("reported",)


def _coverage_block(regions: List[Dict[str, Any]], provider,
                    leads_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Purpose:
        Summarise what the fan-out examined, for the report.

    Parameters:
        regions: The per-region coverage records.
        provider: The provider, consulted for its availability.
        leads_info: How the leads were distributed, including any that matched no region.

    Returns:
        The coverage summary.

    Implementation notes:
        Records not just whether the phase completed but why it did not, because that reason reaches the report's incomplete-analysis notice and is what tells a reader whether to trust a short result. Unmatched leads are included, since a scanner finding that no agent examined is a coverage gap even when every region completed.
    """
    incomplete = [r for r in regions if r["stop_reason"] not in _COMPLETE_REASONS]
    unavailable = getattr(provider, "unavailable", None)

    reason = None
    if unavailable:
        reason = f"AI provider became unavailable ({unavailable})"
    elif any(r["stop_reason"] == "budget_time" for r in incomplete):
        reason = "the scan's time budget was reached"
    elif any(r["stop_reason"] == "budget_steps" for r in incomplete):
        reason = "the per-region step budget was reached"
    elif incomplete:
        reason = "one or more regions did not finish"

    out = {
        "regions": regions,
        "complete": not incomplete,
        "regions_incomplete": len(incomplete),
        "regions_total": len(regions),
        "degraded_reason": reason,
    }
    if leads_info is not None:
        out["leads"] = leads_info
    return out


def _stitch_transcript(results: List[_SurfaceResult]) -> str:
    """
    Purpose:
        Combine the per-region transcripts into one.

    Parameters:
        results: The per-region results.

    Returns:
        The combined transcript.

    Implementation notes:
        Kept in region order with each section labelled, so the dynamic verification phase that reads this can tell which reasoning belongs to which part of the app rather than meeting one undifferentiated stream.
    """
    parts: List[str] = []
    for result in results:
        head = (f"===== REGION: {result.surface.key} - "
                f"{plural(result.nodes, 'class', 'classes')}, "
                f"{plural(len(result.findings), 'finding')} =====")
        if result.error is not None:
            parts.append(f"{head}\n(failed: {type(result.error).__name__}: {result.error})")
        elif result.transcript:
            parts.append(f"{head}\n{result.transcript}")
        else:
            parts.append(f"{head}\n(no transcript)")
    return "\n\n".join(parts)
