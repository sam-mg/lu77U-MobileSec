#!/usr/bin/env python3
"""
Module: test_fanout

Purpose:
    Splitting the code graph into regions, and running one agent over each of them at the same time.

Responsibilities:
    Pin that the regions are disjoint and complete, that they are shaped and balanced sensibly, that each agent gets guidance and a budget matched to its share, that the parallelism works rather than quietly running in sequence, and that the graph holds only the developer's own code.

Dependencies:
    pytest, the fan-out, the partitioner, the code graph, the attack surfaces, the framework profiles and the cancellation exception.

Implementation notes:
    Two things are under test and they matter for different reasons. The partitioning decides what each agent sees, and its load-bearing property is that the regions do not overlap: the previous split by category put one class into several agents, so the same file was read up to five times and a deep-link chain was cut in half between two agents who each saw one end. The threading decides whether the fan-out works at all, and each test there corresponds to a specific way a plain thread breaks a scan silently, such as a lost log line, a lost progress write or a cancellation that never reaches the caller. Those would all pass trivially if the fan-out ran in sequence, so they assert the mechanism rather than the result.
"""

import collections
import contextvars
import threading

import pytest

from lu77U_MobileSec.analyzers.agent import fanout
from lu77U_MobileSec.analyzers.agent.code_graph import CodeGraph, CodeNode, NativeLib
from lu77U_MobileSec.analyzers.agent.partition import (
    MAX_REGION_NODES, MAX_REGIONS, Region, partition_graph)
from lu77U_MobileSec.analyzers.agent.profiles import JAVA_KOTLIN
from lu77U_MobileSec.analyzers.agent.surfaces import guidance_for_families
from lu77U_MobileSec.utils.cancellation import ScanCancelled

_FAMILIES = (("webview", "loadUrl"), ("prefs", "SharedPreferences"),
             ("sql", "rawQuery"), ("crypto", "Cipher"))


def _node(cls, role="class", signals=None, calls=(), **kw):
    """
    Purpose:
        Build one graph node.

    Parameters:
        cls: The class name, which also gives the node its file.
        role: The node's role, such as an exported component.
        signals: What the node was flagged for, keyed by family.
        calls: The classes this one calls.
        kw: Any further node fields, such as the descriptor or the intent actions.

    Returns:
        The node.
    """
    return CodeNode(cls=cls, file=f"sources/com/x/{cls}.java", role=role,
                    signals=signals or {}, calls=list(calls), **kw)


def _graph(entries=3, per_entry=12, native=True):
    """
    Purpose:
        Build a graph of entry points, each reaching its own cluster of helpers.

    Parameters:
        entries: How many entry points to build.
        per_entry: How many helpers each entry point reaches.
        native: Whether to attach a native library.

    Returns:
        The graph.

    Implementation notes:
        Shaped like a real application rather than one node per category, because partitioning runs on call edges and a graph without them gives it nothing to work with.
    """
    nodes = {}
    for e in range(entries):
        helpers = [f"H{e}_{i}" for i in range(per_entry)]
        nodes[f"Entry{e}"] = _node(f"Entry{e}", role="exported-activity",
                                   signals={"ipc": ["getStringExtra"]},
                                   calls=helpers, intent_actions=["VIEW"])
        for i, helper in enumerate(helpers):
            family, call = _FAMILIES[i % len(_FAMILIES)]
            nodes[helper] = _node(helper, signals={family: [call]},
                                  calls=[f"Entry{e}"])
    nodes["Plain"] = _node("Plain")
    libs = [NativeLib(path="lib/arm64-v8a/libx.so")] if native else []
    return CodeGraph(package="com.x", nodes=nodes, native_libs=libs)


def _flagged(graph):
    """
    Purpose:
        Collect the nodes the graph marked as worth reviewing.

    Parameters:
        graph: The graph to read.

    Returns:
        Their keys.
    """
    return {k for k, n in graph.nodes.items() if n.flagged}


class TestPartitionIsDisjoint:
    """
    Purpose:
        That no class is handed to more than one agent, and that none is dropped.
    """
    def test_no_node_lands_in_two_regions(self):
        """
        Purpose:
            Pin that no node appears in two regions.
        """
        graph = _graph()
        counts = collections.Counter(
            k for r in partition_graph(graph) for k in r.members)
        repeated = {k: c for k, c in counts.items() if c > 1}
        assert not repeated, repeated

    def test_every_flagged_node_is_covered(self):
        """
        Purpose:
            Pin that every node worth reviewing appears in some region.

        Implementation notes:
            Being disjoint is easy if things are dropped, so coverage is the other half of the property and has to be asserted alongside it.
        """
        graph = _graph()
        covered = set().union(*[r.members for r in partition_graph(graph)])
        assert covered == _flagged(graph)

    def test_unflagged_nodes_are_not_assigned(self):
        """
        Purpose:
            Pin that a node with nothing to review is not assigned to any region.
        """
        graph = _graph()
        covered = set().union(*[r.members for r in partition_graph(graph)])
        assert "Plain" not in covered

    def test_total_assignments_equal_the_node_count(self):
        """
        Purpose:
            Pin that the assignments add up to exactly the nodes worth reviewing, which is disjointness and coverage in one arithmetic check.
        """
        graph = _graph()
        assert sum(r.size for r in partition_graph(graph)) == len(_flagged(graph))


class TestPartitionShape:
    """
    Purpose:
        The shape of the regions: what stays together, how large they may be, and how many there may be.
    """
    def test_a_call_cluster_stays_together(self):
        """
        Purpose:
            Pin that an entry point and the helpers it calls land in one region.

        Implementation notes:
            A chain split across agents is a chain nobody can see, because each agent holds one end of it and neither can reach the other.
        """
        graph = _graph(entries=3, per_entry=12)
        home = {k: r.key for r in partition_graph(graph) for k in r.members}
        for e in range(3):
            group = {home[f"H{e}_{i}"] for i in range(12)} | {home[f"Entry{e}"]}
            assert len(group) == 1

    def test_regions_grow_from_entry_points(self):
        """
        Purpose:
            Pin that at least one region is grown outwards from an exported component.
        """
        graph = _graph()
        seeded = [r for r in partition_graph(graph) if r.seeds]
        assert seeded, "no region grew from an entry point"
        for region in seeded:
            assert graph.nodes[region.seeds[0]].role.startswith("exported")

    def test_no_region_exceeds_the_map_budget(self):
        """
        Purpose:
            Pin that no region holds more nodes than its map can carry.

        Implementation notes:
            Over the cap the region's own map truncates, which is exactly the failure partitioning exists to prevent.
        """
        graph = _graph(entries=2, per_entry=300)
        for region in partition_graph(graph):
            assert region.size <= MAX_REGION_NODES

    def test_the_agent_count_is_bounded(self):
        """
        Purpose:
            Pin that the number of regions has a ceiling.

        Implementation notes:
            Each region is a full conversation with the model, so this number is the cost ceiling of the phase.
        """
        assert len(partition_graph(_graph(entries=40, per_entry=20))) <= MAX_REGIONS

    def test_tiny_regions_are_merged_away(self):
        """
        Purpose:
            Pin that very small regions are combined rather than each getting an agent of their own.

        Implementation notes:
            A conversation for three classes costs the same setup as one for thirty and returns almost nothing for it.
        """
        assert len(partition_graph(_graph(entries=6, per_entry=2))) < 6

    def test_a_graph_with_no_entry_points_still_partitions(self):
        """
        Purpose:
            Pin that a graph declaring nothing exported still partitions, and covers every node.

        Implementation notes:
            A library, or the thin shell a cross-platform framework leaves behind, declares no exported component at all.
        """
        nodes = {f"C{i}": _node(f"C{i}", signals={"crypto": ["Cipher"]},
                                calls=[f"C{(i + 1) % 30}"]) for i in range(30)}
        regions = partition_graph(CodeGraph(package="com.x", nodes=nodes))
        assert regions
        assert set().union(*[r.members for r in regions]) == set(nodes)

    def test_an_empty_graph_yields_no_regions(self):
        """
        Purpose:
            Pin that an empty graph yields no regions rather than one empty one.
        """
        assert partition_graph(CodeGraph(package="com.x", nodes={})) == []

    def test_isolated_nodes_are_still_reviewed(self):
        """
        Purpose:
            Pin that nodes no entry point reaches are still assigned somewhere.

        Implementation notes:
            Unreachable in the call graph is not the same as unreachable in the application, and those helpers hold findings of their own.
        """
        graph = _graph(entries=1, per_entry=10)
        for i in range(12):
            graph.nodes[f"Lonely{i}"] = _node(f"Lonely{i}",
                                              signals={"crypto": ["Cipher"]})
        covered = set().union(*[r.members for r in partition_graph(graph)])
        assert all(f"Lonely{i}" in covered for i in range(12))

    def test_the_partition_is_reproducible(self):
        """
        Purpose:
            Pin that the same graph partitions the same way every time.

        Implementation notes:
            A scan nobody can reproduce is a scan nobody can debug. Ties used to fall back to set iteration order, which varies between runs of the interpreter.
        """
        graph = _graph()
        runs = [tuple((r.key, tuple(sorted(r.members)))
                      for r in partition_graph(graph)) for _ in range(5)]
        assert len(set(runs)) == 1


def _lopsided_graph():
    """
    Purpose:
        Build a graph whose two entry points reach a shared pool of nodes at very different distances.

    Returns:
        The graph.

    Implementation notes:
        One entry reaches the shared pool in two hops through twenty direct neighbours, and the other only in four through a short chain. A plain breadth-first growth lets the first claim the entire shared pool in one pass before the second's frontier arrives. A real 131-node graph with 3,301 edges produced a five-to-one split from exactly this dynamic rather than from any genuine separation between the two clusters.
    """
    nodes = {
        "A": _node("A", role="exported-activity", intent_actions=["VIEW"],
                   calls=[f"A{i}" for i in range(1, 21)]),
        "B": _node("B", role="exported-activity", intent_actions=["VIEW"],
                   calls=["Bx1"]),
        "Bx1": _node("Bx1", signals={"crypto": ["Cipher"]}, calls=["Bx2"]),
        "Bx2": _node("Bx2", signals={"crypto": ["Cipher"]}, calls=["Bx3"]),
        "Bx3": _node("Bx3", signals={"crypto": ["Cipher"]},
                     calls=[f"S{j}" for j in range(1, 31)]),
    }
    for i in range(1, 21):
        nodes[f"A{i}"] = _node(f"A{i}", signals={"crypto": ["Cipher"]},
                               calls=[f"S{j}" for j in range(1, 31)])
    for j in range(1, 31):
        nodes[f"S{j}"] = _node(f"S{j}", signals={"sql": ["rawQuery"]})
    return CodeGraph(package="com.x", nodes=nodes, native_libs=[])


class TestPartitionBalance:
    """
    Purpose:
        Evening out regions that a plain growth would leave lopsided.

    Implementation notes:
        A real application produced a five-to-one split, where the largest region could not plausibly cover its assignment in the turns it was given while the smallest had turns to spare.
    """
    def test_a_lopsided_graph_is_rebalanced(self):
        """
        Purpose:
            Pin that the largest and smallest regions end up within the permitted ratio of each other.
        """
        from lu77U_MobileSec.analyzers.agent.partition import BALANCE_RATIO

        graph = _lopsided_graph()
        regions = partition_graph(graph)
        sizes = sorted((r.size for r in regions), reverse=True)
        assert sizes[0] / max(1, sizes[-1]) <= BALANCE_RATIO

    def test_a_rebalanced_partition_stays_disjoint_and_complete(self):
        """
        Purpose:
            Pin that rebalancing keeps the regions disjoint and still covering everything.

        Implementation notes:
            Moving nodes between regions is exactly where the two properties the partitioner exists for could be broken.
        """
        graph = _lopsided_graph()
        regions = partition_graph(graph)
        counts = collections.Counter(k for r in regions for k in r.members)
        assert not {k: c for k, c in counts.items() if c > 1}
        assert set().union(*[r.members for r in regions]) == _flagged(graph)

    def test_a_balanced_graph_never_reaches_the_balancing_pass(self, monkeypatch):
        """
        Purpose:
            Pin that an already balanced graph does not enter the rebalancing pass at all.

        Parameters:
            monkeypatch: Makes the rebalancing pass fail if it is reached.

        Implementation notes:
            Every other graph in this module is balanced by construction, so without this they would all be asserting the rebalanced path rather than the original one.
        """
        import lu77U_MobileSec.analyzers.agent.partition as partition_mod

        def _boom(*a, **kw):
            """
            Purpose:
                Fail, so that reaching the rebalancing pass is reported as a test failure.

            Parameters:
                a: Positional arguments, ignored.
                kw: Keyword arguments, ignored.

            Raises:
                AssertionError: Always.
            """
            raise AssertionError("_grow_balanced should not run on a balanced graph")

        monkeypatch.setattr(partition_mod, "_grow_balanced", _boom)
        partition_graph(_graph())

    def test_a_rebalanced_partition_is_still_reproducible(self):
        """
        Purpose:
            Pin that a rebalanced partition comes out the same every time.
        """
        graph = _lopsided_graph()
        runs = [tuple((r.key, tuple(sorted(r.members)))
                      for r in partition_graph(graph)) for _ in range(5)]
        assert len(set(runs)) == 1

    def test_weighted_seeds_prefer_higher_hit_density(self):
        """
        Purpose:
            Pin that a node the deterministic pass already flagged is chosen as a seed ahead of an otherwise identical one.

        Implementation notes:
            The two entry points differ in nothing else, so the ordering can only come from the weighting.
        """
        from lu77U_MobileSec.analyzers.agent.partition import _pick_seeds

        graph = _graph(entries=2, per_entry=5)
        universe = _flagged(graph)
        seeds = _pick_seeds(graph, universe, weights={"Entry0": 5})
        assert seeds[0] == "Entry0"

    def test_regions_are_named_after_their_entry_point(self):
        """
        Purpose:
            Pin that a region's name carries its entry point.

        Implementation notes:
            A name carrying the component tells a reader which part of the application an agent was given; a bare number does not.
        """
        assert any("Entry" in r.key for r in partition_graph(_graph()))


class TestRegionGuidance:
    """
    Purpose:
        The objective and skills each region's agent is given, derived from what the region actually contains.
    """
    def test_guidance_follows_what_the_region_contains(self):
        """
        Purpose:
            Pin that the objective names what the region holds and that skills are selected for it.
        """
        objective, skills = guidance_for_families(["webview", "prefs"])
        assert "WebView" in objective and skills

    def test_a_mixed_region_gets_several_objectives(self):
        """
        Purpose:
            Pin that a region spanning several concerns receives an objective for each.

        Implementation notes:
            A graph region is grown from call edges rather than by topic, so one narrow mission would tell the agent to ignore most of what it was handed.
        """
        objective, _ = guidance_for_families(["webview", "prefs", "ipc"])
        assert objective.count("\n\n") >= 1

    def test_an_empty_family_list_still_produces_guidance(self):
        """
        Purpose:
            Pin that a region with no recognised concerns still gets an objective and skills rather than nothing.
        """
        objective, skills = guidance_for_families([])
        assert objective and skills


class _Recorder:
    """
    Purpose:
        Stand in for the agent loop, recording each region's assignment and the budgets it was given.

    Attributes:
        calls: One record per region, naming its key, objective, skills, nodes, libraries and thread.
        budgets: The step and time budgets each call received.
        findings_by_region: Findings to return, keyed by a region name prefix.
        raiser: Errors to raise, keyed by a region name prefix.
        delay: How long each call occupies its slot, used to make overlap observable.
        lock: Guards the records and the active count.
        concurrent_peak: The highest number of calls in flight at once.
    """
    def __init__(self, findings_by_region=None, raiser=None, delay=0.0):
        """
        Purpose:
            Build the recorder with its scripted outcomes.

        Parameters:
            findings_by_region: Findings to return, keyed by a region name prefix.
            raiser: Errors to raise, keyed by a region name prefix.
            delay: How long each call occupies its slot.
        """
        self.calls = []
        self.budgets = []
        self.findings_by_region = findings_by_region or {}
        self.raiser = raiser or {}
        self.delay = delay
        self.lock = threading.Lock()
        self.concurrent_peak = 0
        self._active = 0

    def __call__(self, provider, source_root, signals, code_graph=None,
                 profile=None, is_cancelled=None, verbose=False,
                 max_steps=None, deadline=None, telemetry=None):
        """
        Purpose:
            Record one region's assignment, then return its scripted findings or raise its scripted error.

        Parameters:
            provider: The AI provider, unused here.
            source_root: The decompiled source root, unused here.
            signals: The region's assignment, read for its label, objective and skills.
            code_graph: The region's subgraph, read for its nodes and libraries.
            profile: The framework profile, unused here.
            is_cancelled: The cancellation callback, unused here.
            verbose: The verbosity flag, unused here.
            max_steps: The step budget this region was given.
            deadline: The time budget this region was given.
            telemetry: The mapping the loop reports its outcome through.

        Returns:
            The region's findings, a success flag and a transcript naming the region.

        Raises:
            Exception: Whatever was scripted for this region.

        Side effects:
            Records the assignment and the budgets, and updates the concurrency peak.
        """
        self.budgets.append({"max_steps": max_steps, "deadline": deadline})
        if telemetry is not None:
            telemetry.update({"stop_reason": "reported", "steps": 1,
                              "findings": 0})
        with self.lock:
            self._active += 1
            self.concurrent_peak = max(self.concurrent_peak, self._active)
        try:
            if self.delay:
                import time
                time.sleep(self.delay)
            key = signals.get("surface_label", "")
            with self.lock:
                self.calls.append({
                    "key": key,
                    "objective": signals.get("objective", ""),
                    "skills": signals.get("skills", []),
                    "nodes": sorted(code_graph.nodes) if code_graph else [],
                    "libs": len(code_graph.native_libs) if code_graph else 0,
                    "thread": threading.current_thread().name,
                })
            for match, exc in self.raiser.items():
                if key.startswith(match):
                    raise exc
            for match, findings in self.findings_by_region.items():
                if key.startswith(match):
                    return list(findings), True, f"T-{key}"
            return [], True, f"T-{key}"
        finally:
            with self.lock:
                self._active -= 1


def _run(monkeypatch, recorder, graph=None, **kw):
    """
    Purpose:
        Replace the agent loop with the recorder and run the fan-out over a graph.

    Parameters:
        monkeypatch: Replaces the agent loop.
        recorder: The stand-in to install.
        graph: The graph to fan out over, or None for the default one.
        kw: Further arguments for the fan-out, such as a progress callback.

    Returns:
        Whatever the fan-out returned.
    """
    monkeypatch.setattr(
        "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", recorder)
    return fanout.run_surface_agents(
        provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
        code_graph=graph if graph is not None else _graph(),
        framework_label="Java/Kotlin", **kw)


class TestFanout:
    """
    Purpose:
        The fan-out itself: one agent per region, running at the same time, with their results merged.
    """
    def test_one_agent_per_region(self, monkeypatch):
        """
        Purpose:
            Pin that exactly one agent runs per region.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        graph = _graph()
        rec = _Recorder()
        _run(monkeypatch, rec, graph=graph)
        assert len(rec.calls) == len(partition_graph(graph))

    def test_agents_never_receive_the_same_file(self, monkeypatch):
        """
        Purpose:
            Pin that no file is handed to two agents.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            Reading the same file in several regions is paid for once per region and returns the same finding each time.
        """
        rec = _Recorder()
        _run(monkeypatch, rec)
        counts = collections.Counter(n for c in rec.calls for n in c["nodes"])
        assert not [k for k, v in counts.items() if v > 1]

    def test_each_agent_gets_guidance_for_its_own_region(self, monkeypatch):
        """
        Purpose:
            Pin that every agent receives an objective and skills.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        rec = _Recorder()
        _run(monkeypatch, rec)
        assert all(c["objective"] and c["skills"] for c in rec.calls)

    def test_native_libraries_are_given_to_exactly_one_agent(self, monkeypatch):
        """
        Purpose:
            Pin that the native libraries are handed out once in total.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            No region owns them, since they are not in the call graph at all, but a library nobody inspects is a coverage gap the report would never mention.
        """
        rec = _Recorder()
        _run(monkeypatch, rec)
        assert sum(c["libs"] for c in rec.calls) == 1

    def test_agents_actually_run_in_parallel(self, monkeypatch):
        """
        Purpose:
            Pin that more than one agent is in flight at once.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            Running them in sequence would satisfy every other test in this class, so the overlap has to be observed directly.
        """
        rec = _Recorder(delay=0.05)
        _run(monkeypatch, rec)
        assert rec.concurrent_peak > 1

    def test_findings_are_merged_and_deduped(self, monkeypatch):
        """
        Purpose:
            Pin that the same finding from two regions appears once and a finding unique to one region is kept.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        shared = {"title": "Same issue", "file": "A.java", "line": "10"}
        rec = _Recorder(findings_by_region={
            "region-1": [shared, {"title": "Only here", "file": "b", "line": "1"}],
            "region-2": [dict(shared)],
        })
        findings, ok, _ = _run(monkeypatch, rec)
        assert ok
        titles = [f["title"] for f in findings]
        assert titles.count("Same issue") == 1
        assert "Only here" in titles

    def test_merged_findings_record_the_region_that_found_them(self, monkeypatch):
        """
        Purpose:
            Pin that a merged finding names the region it came from.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        rec = _Recorder(findings_by_region={
            "region-1": [{"title": "Found", "file": "p", "line": "3"}]})
        findings, _, _ = _run(monkeypatch, rec)
        assert findings[0]["surface"].startswith("region-")

    def test_untitled_findings_are_dropped(self, monkeypatch):
        """
        Purpose:
            Pin that a finding with no title is discarded.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            The title is what the merge deduplicates on and what the report lists, so one without it cannot be handled at all.
        """
        rec = _Recorder(findings_by_region={"region-1": [{"file": "p", "line": "3"}]})
        findings, _, _ = _run(monkeypatch, rec)
        assert findings == []

    def test_one_failing_region_does_not_lose_the_others(self, monkeypatch):
        """
        Purpose:
            Pin that a region raising keeps the other regions' findings and records the failure in the transcript.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        rec = _Recorder(
            findings_by_region={"region-2": [{"title": "Kept", "file": "p", "line": "1"}]},
            raiser={"region-1": RuntimeError("provider exploded")})
        findings, ok, transcript = _run(monkeypatch, rec)
        assert "Kept" in [f["title"] for f in findings]
        assert ok and "provider exploded" in transcript

    def test_phase_1_output_tokens_are_logged(self, monkeypatch, capsys):
        """
        Purpose:
            Pin that the fan-out reports what it cost in generated tokens.

        Parameters:
            monkeypatch: Replaces the agent loop with a recorder that spends tokens.
            capsys: Captures the printed output.

        Implementation notes:
            Taken as a before and after reading of the shared provider's own cumulative counter rather than through a separate accounting path, so the figure is exactly what the phase spent with no per-call plumbing to obtain it.
        """
        class FakeProvider:
            """
            Purpose:
                A provider carrying only the cumulative token counter the measurement reads.

            Attributes:
                usage: The cumulative counters.
            """
            def __init__(self):
                """
                Purpose:
                    Build the provider with its counters at zero.
                """
                self.usage = {"completion_tokens": 0}

        class _TokenSpendingRecorder(_Recorder):
            """
            Purpose:
                A recorder that charges a fixed number of generated tokens to the provider on every call.
            """
            def __call__(self, provider, *a, **kw):
                """
                Purpose:
                    Charge the tokens and then record the call as usual.

                Parameters:
                    provider: The provider whose counter is charged.
                    a: The remaining positional arguments, passed through.
                    kw: The keyword arguments, passed through.

                Returns:
                    Whatever the underlying recorder returned.

                Side effects:
                    Increases the provider's generated token count.
                """
                provider.usage["completion_tokens"] += 50
                return super().__call__(provider, *a, **kw)

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis",
            _TokenSpendingRecorder())
        provider = FakeProvider()
        fanout.run_surface_agents(
            provider=provider, source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin", verbose=True)
        out = capsys.readouterr().out
        assert "Phase 1 (agent) output:" in out
        assert "completion tokens" in out

    def test_cancellation_in_a_child_reaches_the_parent(self, monkeypatch):
        """
        Purpose:
            Pin that a cancellation raised inside a region reaches the caller.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            A plain thread swallows it, and the visible result is a scan the user stopped running happily to completion.
        """
        rec = _Recorder(raiser={"region-1": ScanCancelled()})
        with pytest.raises(ScanCancelled):
            _run(monkeypatch, rec)

    def test_cancellation_wins_over_a_partial_result(self, monkeypatch):
        """
        Purpose:
            Pin that a cancellation is raised even when another region produced findings.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            Returning the partial result instead would present a stopped scan as a finished one.
        """
        rec = _Recorder(
            findings_by_region={"region-2": [{"title": "x", "file": "f", "line": "1"}]},
            raiser={"region-1": ScanCancelled()})
        with pytest.raises(ScanCancelled):
            _run(monkeypatch, rec)

    def test_completed_ok_false_only_when_no_region_drove_a_loop(self, monkeypatch):
        """
        Purpose:
            Pin that the phase reports failure only when no region managed to run its loop at all.

        Parameters:
            monkeypatch: Makes every region report that it could not run.

        Implementation notes:
            That flag is what routes the scan to the whole-application fallback, so setting it whenever any region struggled would spend the largest prompt of the scan unnecessarily.
        """
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis",
            lambda *a, **kw: ([], False, ""))
        _, ok, _ = fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin")
        assert ok is False

    def test_an_empty_graph_falls_back_to_a_single_agent(self, monkeypatch):
        """
        Purpose:
            Pin that with no graph to partition, one agent runs with no region assignment.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        rec = _Recorder()
        _run(monkeypatch, rec, graph=CodeGraph(package="com.x", nodes={}))
        assert len(rec.calls) == 1
        assert rec.calls[0]["objective"] == ""

    def test_the_transcript_labels_each_region(self, monkeypatch):
        """
        Purpose:
            Pin that the combined transcript labels each region's section.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            The transcript is what a reader goes to when a finding looks wrong, and without labels it is one undivided conversation between several agents at once.
        """
        graph = _graph()
        rec = _Recorder()
        _, _, transcript = _run(monkeypatch, rec, graph=graph)
        for region in partition_graph(graph):
            assert f"REGION: {region.key}" in transcript


class _Sub:
    """
    Purpose:
        Stand in for a region's subgraph, carrying only what the budget and library allocation read.

    Attributes:
        nodes: The nodes, whose count is what the allocation uses.
        native_libs: The libraries assigned to this region.
    """
    def __init__(self, size):
        """
        Purpose:
            Build a subgraph of the given size with no libraries.

        Parameters:
            size: How many nodes the subgraph holds.
        """
        self.nodes = {f"n{i}": None for i in range(size)}
        self.native_libs = []


class TestStepAllocation:
    """
    Purpose:
        Dividing the turn budget between regions according to how much each was given to do.

    Implementation notes:
        A 110-node region and a 21-node region, a five-to-one difference in work, previously received the same flat cap, and were measured afterwards at very different rates of classes examined per turn.
    """
    def test_step_budgets_are_proportional_to_region_size(self):
        """
        Purpose:
            Pin that a larger region gets more turns than a smaller one.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import allocate_steps

        big = (Region(key="big"), _Sub(110))
        small = (Region(key="small"), _Sub(21))
        budgets = allocate_steps([big, small], max_steps=40)
        assert budgets["big"] > budgets["small"]

    def test_every_region_gets_at_least_the_floor(self):
        """
        Purpose:
            Pin that even a tiny region beside a huge one gets the minimum number of turns.

        Implementation notes:
            Below that floor a region cannot complete even a single read-and-report cycle, so its share would be spent producing nothing at all.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import (
            MIN_REGION_STEPS, allocate_steps)

        huge = (Region(key="huge"), _Sub(1000))
        tiny = (Region(key="tiny"), _Sub(1))
        budgets = allocate_steps([huge, tiny], max_steps=10)
        assert budgets["tiny"] >= MIN_REGION_STEPS

    def test_the_total_step_budget_is_preserved_in_the_ordinary_case(self):
        """
        Purpose:
            Pin that with no region small enough to need the floor, the turns add up to exactly what was announced.

        Implementation notes:
            The total is told to the user before the phase starts, so a division that quietly produced a different number would make that message wrong.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import allocate_steps

        a = (Region(key="a"), _Sub(60))
        b = (Region(key="b"), _Sub(40))
        budgets = allocate_steps([a, b], max_steps=40)
        assert sum(budgets.values()) == 80

    def test_unbounded_steps_stay_unbounded(self):
        """
        Purpose:
            Pin that an unbounded budget is passed through rather than turned into a number.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import allocate_steps

        a = (Region(key="a"), _Sub(10))
        assert allocate_steps([a], max_steps=None) == {"a": None}

    def test_a_single_region_gets_the_full_budget(self):
        """
        Purpose:
            Pin that a lone region receives the whole per-region budget.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import allocate_steps

        a = (Region(key="a"), _Sub(50))
        assert allocate_steps([a], max_steps=40) == {"a": 40}

    def test_allocation_is_deterministic(self):
        """
        Purpose:
            Pin that the same regions receive the same budgets every time.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import allocate_steps

        regions = [(Region(key=f"r{i}"), _Sub(size))
                  for i, size in enumerate([110, 21, 45, 8])]
        runs = [allocate_steps(regions, max_steps=40) for _ in range(5)]
        assert len(set(tuple(sorted(r.items())) for r in runs)) == 1

    def test_the_fanout_gives_a_larger_region_more_steps_end_to_end(self, monkeypatch):
        """
        Purpose:
            Pin that the fan-out actually applies the division, not merely that the function computes it.

        Parameters:
            monkeypatch: Fixes the configured budget and replaces the agent loop with the recorder.

        Implementation notes:
            The budgets are read off what a real recorder was called with, so a division computed and then ignored would fail here.
        """
        monkeypatch.setattr(
            fanout.user_settings, "get_agent_budget",
            lambda: {"max_steps_per_region": 40, "max_minutes": 0})
        nodes = {}
        nodes["Big"] = _node("Big", role="exported-activity", intent_actions=["VIEW"],
                             calls=[f"BigHelper{i}" for i in range(40)])
        for i in range(40):
            nodes[f"BigHelper{i}"] = _node(f"BigHelper{i}",
                                           signals={"sql": ["rawQuery"]},
                                           calls=["Big"])
        nodes["Small"] = _node("Small", role="exported-activity", intent_actions=["VIEW"],
                               calls=[f"SmallHelper{i}" for i in range(8)])
        for i in range(8):
            nodes[f"SmallHelper{i}"] = _node(f"SmallHelper{i}",
                                             signals={"crypto": ["Cipher"]},
                                             calls=["Small"])
        graph = CodeGraph(package="com.x", nodes=nodes, native_libs=[])

        rec = _Recorder()
        _run(monkeypatch, rec, graph=graph)
        by_key = {c["key"]: b["max_steps"]
                 for c, b in zip(rec.calls, rec.budgets)}
        big_key = next(k for k in by_key if "Big" in k)
        small_key = next(k for k in by_key if "Small" in k)
        assert by_key[big_key] > by_key[small_key]


class TestNativeLibDistribution:
    """
    Purpose:
        Spreading the native libraries across the regions.

    Implementation notes:
        On a real application twelve libraries were found and two inspected, both of the same processor architecture, because every one of them went to a single region, which once budgets are proportional is the smallest one.
    """
    def test_libs_are_spread_across_regions_not_dumped_on_one(self):
        """
        Purpose:
            Pin that every library is assigned and that no single region receives all of them.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import NativeLib
        from lu77U_MobileSec.analyzers.agent.fanout import _assign_native_libs

        regions = [(Region(key=f"r{i}"), _Sub(10)) for i in range(3)]
        libs = [NativeLib(path=f"lib/arm64-v8a/lib{i}.so") for i in range(6)]
        _assign_native_libs(regions, libs)
        counts = [len(sub.native_libs) for _, sub in regions]
        assert sum(counts) == 6
        assert max(counts) < 6

    def test_sibling_abis_are_deduplicated_to_one_representative(self):
        """
        Purpose:
            Pin that the same library built for several architectures is reduced to one, preferring the current one.

        Implementation notes:
            They are the same code compiled differently, so inspecting each is the same work repeated and spends the budget three times over.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import NativeLib
        from lu77U_MobileSec.analyzers.agent.fanout import _assign_native_libs

        regions = [(Region(key="r0"), _Sub(10))]
        libs = [NativeLib(path="lib/armeabi-v7a/libx.so"),
               NativeLib(path="lib/arm64-v8a/libx.so"),
               NativeLib(path="lib/x86/libx.so")]
        _assign_native_libs(regions, libs)
        assert len(regions[0][1].native_libs) == 1
        assert "arm64" in regions[0][1].native_libs[0].path

    def test_no_libs_is_a_no_op(self):
        """
        Purpose:
            Pin that an application with no native code leaves the regions untouched.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _assign_native_libs

        regions = [(Region(key="r0"), _Sub(10))]
        _assign_native_libs(regions, [])
        assert regions[0][1].native_libs == []

    def test_distribution_is_deterministic(self):
        """
        Purpose:
            Pin that the libraries are spread the same way every time.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import NativeLib
        from lu77U_MobileSec.analyzers.agent.fanout import _assign_native_libs

        libs = [NativeLib(path=f"lib/arm64-v8a/lib{i}.so") for i in range(5)]
        results = []
        for _ in range(5):
            regions = [(Region(key=f"r{i}"), _Sub(10)) for i in range(3)]
            _assign_native_libs(regions, libs)
            results.append(tuple(len(sub.native_libs) for _, sub in regions))
        assert len(set(results)) == 1

    def test_libraries_end_to_end_are_not_all_on_the_smallest_region(self, monkeypatch):
        """
        Purpose:
            Pin that the fan-out actually applies the spread, with every library assigned and none of the regions holding them all.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import NativeLib

        graph = _graph(entries=3, per_entry=12)
        graph.native_libs = [NativeLib(path=f"lib/arm64-v8a/lib{i}.so")
                             for i in range(4)]
        rec = _Recorder()
        _run(monkeypatch, rec, graph=graph)
        lib_counts = [c["libs"] for c in rec.calls]
        assert sum(lib_counts) == 4
        assert max(lib_counts) < 4


class TestThreadingHazards:
    """
    Purpose:
        The specific ways running the regions on plain threads breaks a scan without saying so.
    """
    def test_child_threads_inherit_the_parent_context(self, monkeypatch):
        """
        Purpose:
            Pin that a worker runs with the caller's context in place.

        Parameters:
            monkeypatch: Replaces the agent loop with a spy that reads the context.

        Implementation notes:
            Log output is attributed to a scan through a context value, and a thread started plainly begins with an empty context, so every sub-agent's log line would be dropped from the live log with no error anywhere.
        """
        marker = contextvars.ContextVar("test_scan_id", default=None)
        marker.set("scan-123")
        seen = []

        def spy(provider, source_root, signals, **kw):
            """
            Purpose:
                Record the context value visible inside the worker.

            Parameters:
                provider: The AI provider, unused here.
                source_root: The decompiled source root, unused here.
                signals: The region's assignment, unused here.
                kw: Everything else, unused here.

            Returns:
                An empty finding list, a success flag and an empty transcript.

            Side effects:
                Records the context value.
            """
            seen.append(marker.get())
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", spy)
        fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_graph(), framework_label="Java/Kotlin")
        assert seen and all(v == "scan-123" for v in seen)

    def test_worker_threads_are_named_after_their_region(self, monkeypatch):
        """
        Purpose:
            Pin that each worker thread carries its own region's name.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            The provider's transcript filename is only resolved to the second, so parallel workers would overwrite each other's file, and the thread name is what tells them apart.
        """
        rec = _Recorder()
        _run(monkeypatch, rec)
        assert all(c["thread"].startswith("region-") for c in rec.calls)
        assert len({c["thread"] for c in rec.calls}) == len(rec.calls)

    def test_progress_is_emitted_once_per_region_and_stays_in_band(self, monkeypatch):
        """
        Purpose:
            Pin that progress is reported once per region, stays within the phase's slice, opens with the budget announcement and ends at the phase's end.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            The opening message tells the user how many model calls the phase may spend before it starts spending them, which is the one point at which they can still decide otherwise.
        """
        events = []
        lock = threading.Lock()

        def progress(phase, percent, message=""):
            """
            Purpose:
                Record one progress event under a lock, since several workers report at once.

            Parameters:
                phase: The phase the event belongs to.
                percent: The overall progress the event reports.
                message: The event's message.

            Side effects:
                Appends the event to the collected list.
            """
            with lock:
                events.append((phase, percent, message))

        graph = _graph()
        rec = _Recorder(delay=0.01)
        _run(monkeypatch, rec, graph=graph, progress=progress)
        completions = [e for e in events if e[2].startswith("Region ")]
        assert len(completions) == len(partition_graph(graph))
        assert all(fanout.PROGRESS_START <= p <= fanout.PROGRESS_END
                   for _, p, _ in events)
        assert events[0][1] == fanout.PROGRESS_START
        assert "model calls" in events[0][2]
        assert events[-1][1] == fanout.PROGRESS_END

    def test_progress_failure_does_not_break_a_region(self, monkeypatch):
        """
        Purpose:
            Pin that a progress callback raising does not cost a region its findings.

        Parameters:
            monkeypatch: Replaces the agent loop with the recorder.

        Implementation notes:
            Progress is written to a file on disk that can be removed or become unwritable mid-scan, which is a reason to lose a status update and not a region's work.
        """
        def boom(*a, **kw):
            """
            Purpose:
                Fail, standing in for a progress write that could not be made.

            Parameters:
                a: Positional arguments, ignored.
                kw: Keyword arguments, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("meta.json is gone")

        rec = _Recorder(findings_by_region={
            "region-1": [{"title": "Kept", "file": "p", "line": "1"}]})
        findings, _, _ = _run(monkeypatch, rec, progress=boom)
        assert "Kept" in [f["title"] for f in findings]


class TestOllamaLogPathIsCollisionFree:
    """
    Purpose:
        That parallel workers do not overwrite each other's saved transcript.
    """
    def test_parallel_workers_get_distinct_log_paths(self, tmp_path):
        """
        Purpose:
            Pin that two workers running at once are given different transcript paths.

        Parameters:
            tmp_path: The output directory.
        """
        from lu77U_MobileSec.utils.output_manager import OutputManager

        manager = OutputManager()
        manager.output_dir = tmp_path
        manager.apk_name = "base"
        paths = {}

        def grab(key):
            """
            Purpose:
                Record the transcript path this thread was given.

            Parameters:
                key: The name to record the path under.

            Side effects:
                Records the path.
            """
            paths[key] = manager.get_ollama_log_path("20260101_120000")

        threads = [threading.Thread(target=grab, args=(k,), name=f"region-{k}")
                   for k in ("region-1-A", "region-2-B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(paths.values())) == 2

    def test_main_thread_path_is_unchanged(self, tmp_path):
        """
        Purpose:
            Pin that a call from the main thread still produces the original filename.

        Parameters:
            tmp_path: The output directory.

        Implementation notes:
            The command-line path is single-threaded and its transcript filename is what users already have in their saved scans.
        """
        from lu77U_MobileSec.utils.output_manager import OutputManager

        manager = OutputManager()
        manager.output_dir = tmp_path
        manager.apk_name = "base"
        assert manager.get_ollama_log_path("20260101_120000").name == (
            "base_Ollama_Request_Response_20260101_120000.md")


class TestBaseAnalyzerRoutes:
    """
    Purpose:
        Which of the two paths an analyzer takes, depending on whether a graph was built.
    """
    def test_graph_present_routes_to_fanout(self, monkeypatch):
        """
        Purpose:
            Pin that a graph routes to the fan-out.

        Parameters:
            monkeypatch: Records whether the fan-out was called.
        """
        from lu77U_MobileSec.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer

        called = {}
        def _fanout(*a, **kw):
            """
            Purpose:
                Record that the fan-out was reached.

            Parameters:
                a: Positional arguments, ignored.
                kw: Keyword arguments, ignored.

            Returns:
                An empty finding list, a success flag and an empty transcript.

            Side effects:
                Records the call.
            """
            called["fanout"] = True
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.fanout.run_surface_agents", _fanout)
        JavaKotlinAnalyzer().run_agent("/nope", _graph())
        assert called.get("fanout")

    def test_no_graph_routes_to_the_single_loop(self, monkeypatch):
        """
        Purpose:
            Pin that no graph routes to a single agent loop instead.

        Parameters:
            monkeypatch: Records whether the single loop was called.
        """
        from lu77U_MobileSec.analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer

        called = {}
        def _single(*a, **kw):
            """
            Purpose:
                Record that the single loop was reached, and the step budget it was given.

            Parameters:
                a: Positional arguments, ignored.
                kw: Keyword arguments, read for the step budget.

            Returns:
                An empty finding list, a success flag and an empty transcript.

            Side effects:
                Records the call and the budget.
            """
            called["single"] = True
            called["max_steps"] = kw.get("max_steps")
            return [], True, ""

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.agent_loop.run_agent_analysis", _single)
        JavaKotlinAnalyzer().run_agent("/nope", None)
        assert called.get("single")


class TestGraphHoldsOnlyDeveloperCode:
    """
    Purpose:
        That third-party code is excluded from the graph entirely.

    Implementation notes:
        Findings in a bundled library are unactionable, since the developer cannot change that code, and the only useful question about one is which version ships, which the inventory scanner answers without spending a single model call. On a real application 340 of 360 reviewable classes were third-party, so leaving them in spent most of the analysis budget on code nobody could act on.
    """
    @pytest.mark.parametrize("desc", [
        "Lokhttp3/OkHttpClient;",
        "Lretrofit2/Retrofit;",
        "Lcom/appsflyer/internal/AFi1iSDK;",
        "Lco/hyperverge/hypersnapsdk/views/ShadowTextView;",
        "Lcom/facebook/login/LoginManager;",
        "Lio/sentry/Hub;",
        "Lcom/clevertap/android/sdk/CleverTapAPI;",
        "Lorg/npci/upi/security/Foo;",
    ])
    def test_library_classes_are_vendor(self, desc):
        """
        Purpose:
            Pin that each shape of third-party class is recognised as such.

        Parameters:
            desc: A class descriptor from a bundled library.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import is_vendor_class

        assert is_vendor_class(desc)

    @pytest.mark.parametrize("desc", [
        "Lcom/kreditbee/android/MainActivity;",
        "Loa/C0900k;",
        "LA/E;",
        "Lcom/example/app/Login;",
    ])
    def test_app_classes_are_not_vendor(self, desc):
        """
        Purpose:
            Pin that the application's own classes, including obfuscated ones, are not mistaken for third-party code.

        Parameters:
            desc: A class descriptor from the application.

        Implementation notes:
            Obfuscated class names are short and meaningless, which is exactly what a prefix rule can misread, and excluding them would remove the application's own code from its own scan.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import is_vendor_class

        assert not is_vendor_class(desc)

    def test_the_sdk_inventory_table_feeds_the_exclusion(self):
        """
        Purpose:
            Pin that every package the inventory names is also excluded from the graph.

        Implementation notes:
            The two lists must not drift apart: a package worth naming in the report is a package worth keeping out of the review.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import is_vendor_class
        from lu77U_MobileSec.analyzers.sast.extractors.sdk_inventory import SDK_SIGNATURES

        for _name, (_cat, packages, _classes) in SDK_SIGNATURES.items():
            for package in packages:
                assert is_vendor_class(f"L{package}/Anything;"), package


class TestGraphPruning:
    """
    Purpose:
        Removing nodes nothing can reach, and the exceptions to that rule.
    """
    def _graph_with(self, nodes):
        """
        Purpose:
            Build a graph around the given nodes.

        Parameters:
            nodes: The nodes to hold.

        Returns:
            The graph.
        """
        return CodeGraph(package="com.x", nodes=nodes)

    def test_an_isolated_class_is_dropped(self):
        """
        Purpose:
            Pin that a class nothing calls and which calls nothing is removed.

        Implementation notes:
            Nothing can reach it, so nothing in it is reachable either, and reviewing it spends turns on code that cannot run.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _prune_isolated

        nodes = {"Dead": _node("Dead", signals={"crypto": ["Cipher"]}),
                 "A": _node("A", calls=["B"]), "B": _node("B", calls=["A"])}
        _prune_isolated(nodes)
        assert set(nodes) == {"A", "B"}

    def test_an_entry_point_survives_having_no_callers(self):
        """
        Purpose:
            Pin that an exported component is kept even with no callers.

        Implementation notes:
            The platform invokes it rather than the application's own code, so pruning on connections alone would delete the application's front door.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _prune_isolated

        nodes = {"Main": _node("Main", role="exported-activity",
                               intent_actions=["MAIN"])}
        _prune_isolated(nodes)
        assert "Main" in nodes

    def test_a_non_exported_manifest_component_survives_too(self):
        """
        Purpose:
            Pin that a declared component that is not exported is kept as well.

        Implementation notes:
            A component started by name rather than by call is a class reference the call graph never sees, so every such component ends up with no connections whether or not the application actually opens it. A real scan pruned 29 of 36 application classes this way and lost most of the application's own screens.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _prune_isolated

        nodes = {"LogActivity": _node("LogActivity", role="activity")}
        _prune_isolated(nodes)
        assert "LogActivity" in nodes

    def test_a_plain_non_manifest_class_is_still_pruned(self):
        """
        Purpose:
            Pin that an ordinary unreachable class is still removed.

        Implementation notes:
            Every node carries the same default role whether or not it is declared, so the rule has to tell the two apart rather than simply checking that a role is present, or the fix above would stop pruning altogether.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _prune_isolated

        nodes = {"Helper": _node("Helper")}
        _prune_isolated(nodes)
        assert "Helper" not in nodes

    def test_a_file_a_sast_lead_flagged_survives_too(self):
        """
        Purpose:
            Pin that a class the deterministic pass already flagged is matched by file and protected from pruning.

        Implementation notes:
            The reasoning that justifies pruning, that nothing can reach it so nothing is exploitable, does not hold for a class with a confirmed hit in it.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import (
            _match_node_for_file, _prune_isolated)

        nodes = {"LHelper;": _node("Helper", descriptor="LHelper;")}
        lead_file = "sources/com/x/Helper.java"
        node = _match_node_for_file(nodes, lead_file)
        assert node is not None and node.descriptor == "LHelper;"

        _prune_isolated(nodes, protected={node.descriptor})
        assert "LHelper;" in nodes

    def test_a_file_no_lead_names_is_pruned_normally(self):
        """
        Purpose:
            Pin that a file no lead names matches no node and is left to the ordinary rules.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _match_node_for_file

        nodes = {"LHelper;": _node("Helper", descriptor="LHelper;")}
        assert _match_node_for_file(nodes, "sources/com/x/Unrelated.java") is None

    def test_a_native_bridge_survives(self):
        """
        Purpose:
            Pin that a class loading native code is protected from pruning.

        Implementation notes:
            The boundary between managed and native code is among the most worth reviewing, and such a class is often reached only from the native side.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _prune_isolated

        nodes = {"Jni": _node("Jni", signals={"native": ["loadLibrary"]})}
        _prune_isolated(nodes, protected={"Jni"})
        assert "Jni" in nodes

    def test_removing_a_library_does_not_sever_the_path_through_it(self):
        """
        Purpose:
            Pin that two application classes connected only through a removed library are joined directly to each other.

        Implementation notes:
            Otherwise the partitioner puts the two ends in different regions and neither agent sees the flow between them.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _bridge_vendor_edges

        nodes = {"LLogin;": _node("Login", descriptor="LLogin;"),
                 "LTlsConfig;": _node("TlsConfig", descriptor="LTlsConfig;")}
        _bridge_vendor_edges(nodes, {"Lokhttp3/Builder;": {"LLogin;", "LTlsConfig;"}})
        assert "LTlsConfig;" in nodes["LLogin;"].calls
        assert "LLogin;" in nodes["LTlsConfig;"].calls

    def test_a_shared_utility_does_not_fuse_everything(self):
        """
        Purpose:
            Pin that a library class touched by very many callers does not join them all together.

        Implementation notes:
            A logging class used by two hundred callers is not evidence that those callers belong in one region; joining them would produce a single region holding the whole application.
        """
        from lu77U_MobileSec.analyzers.agent.code_graph import _bridge_vendor_edges

        nodes = {f"C{i}": _node(f"C{i}") for i in range(60)}
        _bridge_vendor_edges(nodes, {"Lvendor/Log;": {f"LC{i};" for i in range(60)}})
        assert all(not n.calls for n in nodes.values())


class TestWeightsFromLeads:
    """
    Purpose:
        Turning the deterministic pass's findings into a weighting over graph nodes.

    Implementation notes:
        The partitioner has always accepted a weighting used to rank the nodes regions grow from, but the one caller always passed nothing, so a deterministic finding never influenced which class a region grew from, only which region a lead was routed to once the regions already existed.
    """
    def _lead(self, file, title="X"):
        """
        Purpose:
            Build one lead naming a file.

        Parameters:
            file: The file the lead points at.
            title: The lead's title.

        Returns:
            The lead.
        """
        from lu77U_MobileSec.analyzers.agent.leads import Lead
        return Lead(file=file, line=1, title=title, severity="Medium",
                   detector="manifest")

    def test_a_node_with_two_leads_outweighs_one_with_one(self):
        """
        Purpose:
            Pin that each lead adds to its file's node, so a node with two outweighs one with one.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _weights_from_leads

        graph = CodeGraph(package="com.x", nodes={
            "LA;": _node("A", descriptor="LA;"),
            "LB;": _node("B", descriptor="LB;")})
        leads = [self._lead("sources/com/x/A.java", "one"),
                self._lead("sources/com/x/A.java", "two"),
                self._lead("sources/com/x/B.java", "three")]
        weights = _weights_from_leads(graph, leads)
        assert weights == {"LA;": 2, "LB;": 1}

    def test_no_leads_is_an_empty_weight_map(self):
        """
        Purpose:
            Pin that no leads at all produces no weighting rather than failing.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _weights_from_leads

        graph = CodeGraph(package="com.x", nodes={"LA;": _node("A", descriptor="LA;")})
        assert _weights_from_leads(graph, None) == {}
        assert _weights_from_leads(graph, []) == {}

    def test_a_lead_naming_no_known_file_is_ignored(self):
        """
        Purpose:
            Pin that a lead pointing at a file with no node behind it contributes nothing.

        Implementation notes:
            Manifest-level findings name a file that is not a class, so they have nothing to weight and must not be forced onto an arbitrary node.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _weights_from_leads

        graph = CodeGraph(package="com.x", nodes={"LA;": _node("A", descriptor="LA;")})
        weights = _weights_from_leads(graph, [self._lead("AndroidManifest.xml")])
        assert weights == {}


class TestGraphScopeIsPerApk:
    """
    Purpose:
        That nothing about deciding which code belongs to the application is tuned to any one application.

    Implementation notes:
        Every input comes from the application under analysis: its package identifier, its manifest, the access information in its bytecode and its call edges.
    """
    def test_app_prefixes_come_only_from_the_apk(self):
        """
        Purpose:
            Pin that the prefixes counted as the application's own are derived from its package identifier, and that a different application yields entirely different ones.
        """
        from lu77U_MobileSec.analyzers.agent.ownership import _app_prefixes

        assert _app_prefixes("com.example.app", [], (), ()) == (
            "Lcom/example/", "Lcom/example/app/")
        assert _app_prefixes("io.acme.wallet", [], (), ()) == (
            "Lio/acme/", "Lio/acme/wallet/")

    def test_a_vendor_manifest_component_never_seeds_the_app(self):
        """
        Purpose:
            Pin that a third-party component declared in the manifest does not make its package count as the application's own, while the application's own component does.

        Implementation notes:
            A merged manifest declares the components of every library the application includes, and seeding from those made 13,733 of 15,207 classes count as the application's own on a real scan.
        """
        from lu77U_MobileSec.analyzers.agent.ownership import _app_prefixes

        out = _app_prefixes(
            "com.example.app",
            ["com.google.firebase.auth.internal.RecaptchaActivity",
             "co.hyperverge.hypersnapsdk.activities.HVFaceActivity",
             "com.example.app.ui.MainActivity"],
            ("Lco/hyperverge/",), ("Lcom/google/",))
        assert not any(p.startswith(("Lcom/google/", "Lco/hyperverge/")) for p in out)
        assert "Lcom/example/app/ui/" in out

    def test_a_google_published_app_is_not_classified_as_framework(self):
        """
        Purpose:
            Pin that a prefix normally treated as framework code is not treated that way for an application published under it.

        Implementation notes:
            The prefix identifies the framework for almost every application and identifies the application itself for a handful, so the decision has to consider the package under analysis.
        """
        from lu77U_MobileSec.analyzers.agent.ownership import (
            FRAMEWORK_PREFIXES, _effective_framework_prefixes)

        assert "Lcom/google/" in FRAMEWORK_PREFIXES
        assert "Lcom/google/" not in _effective_framework_prefixes("com.google.android.apps.maps")
        assert "Lcom/google/" in _effective_framework_prefixes("com.example.app")

    def test_generated_classes_are_matched_by_shape_not_by_name(self):
        """
        Purpose:
            Pin that generated classes are recognised by their shape across any package, and that ordinary classes, including obfuscated ones, are not.

        Implementation notes:
            Matching on package names would work for one application's build setup and quietly fail for another's.
        """
        from lu77U_MobileSec.analyzers.agent.ownership import is_generated_class

        for desc in ("Lany/pkg/R;", "Lany/pkg/R$layout;", "Lany/pkg/BuildConfig;",
                     "Lany/pkg/DataBinderMapperImpl;", "Lx/y/UserDao_Impl;",
                     "Lx/y/Hilt_MainActivity;", "Lx/y/DaggerAppComponent;"):
            assert is_generated_class(desc), desc
        for desc in ("Lcom/example/LoginActivity;", "LC1/a;", "Lx/y/Repository;"):
            assert not is_generated_class(desc), desc
