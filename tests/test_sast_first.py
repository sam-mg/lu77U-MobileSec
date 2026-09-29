#!/usr/bin/env python3
"""
Module: test_sast_first

Purpose:
    Running the deterministic scanners before the agent and turning their output into the agent's worklist.

Responsibilities:
    Pin how findings become leads and how they are ordered, capped and deduplicated, how a lead is rendered into the agent's opening context, how leads are routed to the region that owns the file, the phase ordering, and the overlapping of the two independent passes over the application file.

Dependencies:
    pytest, the lead module, the fan-out, the agent loop, the agent tool surface and the Java/Kotlin analyzer.

Implementation notes:
    This exists because of a real scan where the deterministic pass found 66 issues across 26 files in 15 seconds, and the agent, given no worklist, then spent 48 minutes and opened one of those 26 files.
"""

from lu77U_MobileSec.analyzers.agent.leads import (
    Lead, leads_from_findings, render_leads)


def _finding(title="Hardcoded AES key", file="A.java", line=8,
            severity="High", confidence="MEDIUM", detector="secrets",
            vuln_class=""):
    """
    Purpose:
        Build one deterministic finding.

    Parameters:
        title: The finding title.
        file: The file the finding is attributed to.
        line: The line the finding is attributed to.
        severity: The finding's severity.
        confidence: How sure the detector is.
        detector: Which detector produced it.
        vuln_class: The class code, when the detector assigns one.

    Returns:
        The finding.
    """
    return {"title": title, "file": file, "line_number": line,
           "severity": severity, "confidence": confidence,
           "detector": detector, "vuln_class": vuln_class}


class TestLeadsFromFindings:
    """
    Purpose:
        Turning deterministic findings into the agent's worklist.
    """
    def test_leads_are_ordered_by_severity_then_path(self):
        """
        Purpose:
            Pin that leads come back worst first.

        Implementation notes:
            The list is capped, so the order decides what the agent sees at all rather than merely what it sees first.
        """
        findings = [
            _finding(title="Medium one", file="Z.java", severity="Medium"),
            _finding(title="High one", file="A.java", severity="High"),
            _finding(title="Critical one", file="M.java", severity="Critical"),
        ]
        leads = leads_from_findings(findings)
        assert [l.title for l in leads] == ["Critical one", "High one", "Medium one"]

    def test_ties_break_on_high_confidence_first(self):
        """
        Purpose:
            Pin that among equally severe leads the more confident one comes first.
        """
        findings = [
            _finding(title="Medium confidence", severity="High", confidence="MEDIUM"),
            _finding(title="High confidence", severity="High", confidence="HIGH"),
        ]
        leads = leads_from_findings(findings)
        assert leads[0].title == "High confidence"

    def test_leads_are_deduplicated_on_file_line_title(self):
        """
        Purpose:
            Pin that the same finding reported twice becomes one lead.

        Implementation notes:
            Two detectors regularly flag the same line, and a duplicate spends a slot in a capped list on work the agent would do once anyway.
        """
        findings = [_finding(), dict(_finding())]
        assert len(leads_from_findings(findings)) == 1

    def test_a_finding_with_no_file_is_skipped(self):
        """
        Purpose:
            Pin that a finding with no file behind it becomes no lead.

        Implementation notes:
            A lead exists to send the agent to a place in the code, so one with nowhere to go is a wasted slot; findings about the application as a whole reach the report through the deterministic pass regardless.
        """
        findings = [{"title": "App requests 5 dangerous permissions",
                    "severity": "Informational"}]
        assert leads_from_findings(findings) == []

    def test_the_cap_is_respected(self):
        """
        Purpose:
            Pin that no more leads are produced than the cap allows.
        """
        findings = [_finding(title=f"Finding {i}", file=f"F{i}.java")
                   for i in range(200)]
        assert len(leads_from_findings(findings, max_leads=10)) == 10

    def test_order_is_deterministic(self):
        """
        Purpose:
            Pin that the same findings produce the same order every time.

        Implementation notes:
            An unstable order under a cap means two runs over the same application hand the agent different work, which makes a scan impossible to reproduce.
        """
        findings = [_finding(title=f"F{i}", file=f"{i}.java",
                             severity=["Low", "High", "Medium"][i % 3])
                   for i in range(30)]
        runs = [tuple(l.title for l in leads_from_findings(findings)) for _ in range(5)]
        assert len(set(runs)) == 1

    def test_the_check_names_something_concrete_per_detector(self):
        """
        Purpose:
            Pin that a lead tells the agent what to actually verify, worded for the detector that raised it.

        Implementation notes:
            A lead that only names a file and a severity leaves the agent to rediscover what the detector already knew, which is most of the time the lead was supposed to save.
        """
        webview = leads_from_findings([_finding(detector="webview")])[0]
        assert "WebView" in webview.check
        injection = leads_from_findings([_finding(detector="injection")])[0]
        assert "concatenated" in injection.check.lower()


class TestRenderLeads:
    """
    Purpose:
        Rendering the worklist into the block the agent reads.
    """
    def test_no_leads_renders_nothing(self):
        """
        Purpose:
            Pin that an empty worklist renders no block at all.
        """
        assert render_leads([], total=0) == ""

    def test_the_block_names_file_line_and_check(self):
        """
        Purpose:
            Pin that a rendered lead carries its location, its title and what to verify.
        """
        lead = Lead(file="sources/A/D.java", line=8, title="Hardcoded AES key",
                   severity="High", detector="secrets",
                   check="Confirm the value is a real credential.")
        block = render_leads([lead], total=1)
        assert "sources/A/D.java:8" in block
        assert "Hardcoded AES key" in block
        assert "Confirm the value is a real credential." in block

    def test_the_header_shows_region_count_of_total(self):
        """
        Purpose:
            Pin that the block says how many of the scan's total leads this region was given.

        Implementation notes:
            Each region sees only its own share, and without the total the agent cannot tell a short worklist from a whole application with little wrong with it.
        """
        leads = [Lead(file=f"{i}.java", line=1, title=f"t{i}", severity="High",
                      detector="") for i in range(3)]
        block = render_leads(leads, total=31)
        assert "3 of 31" in block


def _region_and_sub(key, files):
    """
    Purpose:
        Build a region and a stand-in subgraph owning the named files.

    Parameters:
        key: The region's key.
        files: The files the region owns.

    Returns:
        The region and its subgraph, shaped as the routing reads them off a real code graph.
    """
    from lu77U_MobileSec.analyzers.agent.partition import Region

    class _Node:
        """
        Purpose:
            A graph node carrying only the file it belongs to.

        Attributes:
            file: The node's file.
        """
        def __init__(self, file):
            """
            Purpose:
                Build the node.

            Parameters:
                file: The node's file.
            """
            self.file = file

    class _Sub:
        """
        Purpose:
            A subgraph holding one node per file.

        Attributes:
            nodes: The nodes, keyed as a real subgraph keys them.
        """
        def __init__(self, files):
            """
            Purpose:
                Build the subgraph from the files it owns.

            Parameters:
                files: The files to build nodes for.
            """
            self.nodes = {f"n{i}": _Node(f) for i, f in enumerate(files)}

    return Region(key=key), _Sub(files)


class TestLeadRouting:
    """
    Purpose:
        Sending each lead to the region that will actually look at its file.
    """
    def test_a_lead_is_routed_to_the_region_that_owns_its_file(self):
        """
        Purpose:
            Pin that a lead goes to the region owning its file and to no other.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _leads_by_region

        a = _region_and_sub("region-a", ["sources/A/D.java"])
        b = _region_and_sub("region-b", ["sources/B/E.java"])
        lead = Lead(file="sources/A/D.java", line=8, title="x",
                   severity="High", detector="secrets")
        by_region, unowned = _leads_by_region([a, b], [lead])
        assert by_region["region-a"] == [lead]
        assert by_region["region-b"] == []
        assert unowned == []

    def test_an_ambiguous_basename_across_regions_is_not_routed_by_guessing(self):
        """
        Purpose:
            Pin that a lead naming only a filename owned by two regions is not assigned by guessing, and is still not dropped.

        Implementation notes:
            This is the same ambiguity that path resolution was hardened against: obfuscated class names collide, so a bare filename can belong to either region and picking one would send the agent to the wrong code.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _leads_by_region

        a = _region_and_sub("region-a", ["sources/A/D.java"])
        b = _region_and_sub("region-b", ["sources/B/D.java"])
        lead = Lead(file="D.java", line=1, title="x", severity="High", detector="")
        by_region, unowned = _leads_by_region([a, b], [lead])
        assert lead in unowned
        assert sum(len(v) for v in by_region.values()) == 1

    def test_every_lead_reaches_exactly_one_region(self):
        """
        Purpose:
            Pin that with unambiguous ownership every lead lands in its own region and none is left over.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _leads_by_region

        a = _region_and_sub("region-a", [f"a/{i}.java" for i in range(5)])
        b = _region_and_sub("region-b", [f"b/{i}.java" for i in range(5)])
        leads = ([Lead(file=f"a/{i}.java", line=1, title=f"a{i}",
                       severity="High", detector="") for i in range(5)]
                 + [Lead(file=f"b/{i}.java", line=1, title=f"b{i}",
                        severity="High", detector="") for i in range(5)])
        by_region, unowned = _leads_by_region([a, b], leads)
        assert not unowned
        assert sorted(l.title for l in by_region["region-a"]) == [f"a{i}" for i in range(5)]
        assert sorted(l.title for l in by_region["region-b"]) == [f"b{i}" for i in range(5)]

    def test_an_unowned_lead_with_a_real_path_is_not_dropped(self):
        """
        Purpose:
            Pin that a lead no region owns still lands somewhere, on the region carrying the fewest so far.

        Implementation notes:
            Manifest-level findings and paths under pruned vendor code have no owning region, and dropping them would silently lose exactly the findings the deterministic pass is best at.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import _leads_by_region

        a = _region_and_sub("region-a", ["a/1.java"])
        b = _region_and_sub("region-b", ["b/1.java"])
        stray = Lead(file="res/xml/network_config.xml", line=1, title="x",
                    severity="Informational", detector="network-config")
        by_region, unowned = _leads_by_region([a, b], [stray])
        assert stray in unowned
        assert sum(len(v) for v in by_region.values()) == 1

    def test_the_per_region_cap_is_applied(self):
        """
        Purpose:
            Pin that no region is given more leads than the per-region cap allows.

        Implementation notes:
            The worklist is part of every turn's context for that region, so an uncapped one would crowd out the code the agent is meant to be reading.
        """
        from lu77U_MobileSec.analyzers.agent.fanout import (
            MAX_LEADS_PER_REGION, _leads_by_region)

        a = _region_and_sub("region-a", [f"a/{i}.java" for i in range(MAX_LEADS_PER_REGION + 10)])
        leads = [Lead(file=f"a/{i}.java", line=1, title=f"a{i}", severity="High",
                     detector="") for i in range(MAX_LEADS_PER_REGION + 10)]
        by_region, _ = _leads_by_region([a], leads)
        assert len(by_region["region-a"]) == MAX_LEADS_PER_REGION


class TestInitialContextRendering:
    """
    Purpose:
        What the worklist changes in the context every agent sees on every turn.

    Implementation notes:
        This is the risky edit in the whole feature, which is why the no-worklist case is pinned as byte-identical: the four frameworks that build no worklist must be completely unaffected.
    """
    def _tools(self, tmp_path):
        """
        Purpose:
            Build a tool surface over an otherwise empty decompiled tree.

        Parameters:
            tmp_path: Directory the tree is created in.

        Returns:
            The tool surface.
        """
        from lu77U_MobileSec.analyzers.agent.tools import AgentTools

        (tmp_path / "sources").mkdir()
        (tmp_path / "resources").mkdir()
        return AgentTools(tmp_path)

    def test_no_leads_renders_no_block_and_no_objective_change(self, tmp_path):
        """
        Purpose:
            Pin that with no worklist the context is identical to what it was, carries no worklist section, and keeps the original objective.

        Parameters:
            tmp_path: Directory the tree is created in.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _build_initial_context

        tools = self._tools(tmp_path)
        signals = {"framework": "Java/Kotlin", "objective": "Watch for SQL injection.",
                  "surface_label": "region-1"}
        with_no_leads_key = _build_initial_context(tools, signals)
        without_leads_key = _build_initial_context(
            tools, {"framework": "Java/Kotlin", "objective": "Watch for SQL injection.",
                    "surface_label": "region-1"})
        assert with_no_leads_key == without_leads_key
        assert "Confirmed leads" not in with_no_leads_key
        assert "Within your surface, be exhaustive" in with_no_leads_key

    def test_leads_render_a_worklist_block_and_reaim_the_objective(self, tmp_path):
        """
        Purpose:
            Pin that a worklist adds its section, names its leads, counts them in the objective, and replaces the exhaustive-exploration instruction with one that puts the leads first.

        Parameters:
            tmp_path: Directory the tree is created in.

        Implementation notes:
            Both halves matter: adding the worklist while still telling the agent to explore exhaustively is how the real scan ended up ignoring it.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _build_initial_context

        tools = self._tools(tmp_path)
        lead = Lead(file="sources/A/D.java", line=8, title="Hardcoded AES key",
                   severity="High", detector="secrets",
                   check="Confirm the value is a real credential.")
        signals = {"framework": "Java/Kotlin", "objective": "Watch for SQL injection.",
                  "surface_label": "region-1", "leads": [lead], "leads_total": 1}
        context = _build_initial_context(tools, signals)
        assert "Confirmed leads" in context
        assert "Hardcoded AES key" in context
        assert "Confirm or refute the 1 concrete lead below" in context
        assert "Leads first, exploration second" in context
        assert "Within your surface, be exhaustive" not in context

    def test_lead_files_join_the_coverage_targets(self, tmp_path):
        """
        Purpose:
            Pin that a lead's file counts towards what the region is expected to have covered.

        Parameters:
            tmp_path: Directory the tree is created in.

        Implementation notes:
            Coverage is what reports a region as incomplete, so a lead the agent never opened has to register as a gap rather than as nothing at all.
        """
        from lu77U_MobileSec.analyzers.agent.agent_loop import _coverage_targets

        tools = self._tools(tmp_path)
        lead = Lead(file="sources/A/D.java", line=8, title="x", severity="High",
                   detector="")
        source_targets, _ = _coverage_targets(None, tools, leads=[lead])
        assert "sources/A/D.java" in source_targets


class TestSastRunsBeforeTheAgent:
    """
    Purpose:
        That the deterministic pass runs first and its output reaches the agent.

    Implementation notes:
        It used to run near the end of the scan, after the entire agent phase, so its findings could never steer anything.
    """
    def _analyzer(self, tmp_path, monkeypatch):
        """
        Purpose:
            Build an analyzer whose decompilation and provider are stubbed out.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Replaces the decompilation and the provider lookup.

        Returns:
            The analyzer and its output directory.
        """
        import lu77U_MobileSec.analyzers.java_kotlin_analyzer as jk_mod

        analyzer = jk_mod.JavaKotlinAnalyzer()
        jadx_dir = tmp_path / "jadx_out"
        jadx_dir.mkdir()

        def _fake_decompile(apk_path_unused):
            """
            Purpose:
                Point the analyzer at the prepared output directory without decompiling anything.

            Parameters:
                apk_path_unused: The application file, unused here.

            Returns:
                True, reporting success.

            Side effects:
                Sets the analyzer's output directory.
            """
            analyzer.jadx_output_dir = jadx_dir
            return True

        monkeypatch.setattr(analyzer, "decompile_apk", _fake_decompile)
        monkeypatch.setattr(jk_mod, "get_active_provider", lambda **_: object())
        return analyzer, jadx_dir

    def test_order_is_sast_then_agent(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that the deterministic pass runs before the agent and that the scan reports success.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Replaces both phases with recorders and removes the graph build.
        """
        analyzer, jadx_dir = self._analyzer(tmp_path, monkeypatch)
        order = []

        def _fake_sast(source_root_unused, **_):
            """
            Purpose:
                Record that the deterministic pass ran and return nothing.

            Parameters:
                source_root_unused: The decompiled source root, unused here.
                _: The keyword arguments the real run_sast accepts (apk_path), ignored.

            Returns:
                An empty finding list.

            Side effects:
                Records the phase.
            """
            order.append("sast")
            return []

        def _fake_run_agent(source_root_unused, code_graph_unused, **_):
            """
            Purpose:
                Record that the agent ran and return nothing.

            Parameters:
                source_root_unused: The decompiled source root, unused here.
                code_graph_unused: The code graph, unused here.
                _: The framework label and worklist the real run_agent accepts, ignored.

            Returns:
                An empty finding list, a success flag and an empty transcript.

            Side effects:
                Records the phase.
            """
            order.append("agent")
            return [], True, ""

        monkeypatch.setattr(analyzer, "run_sast", _fake_sast)
        monkeypatch.setattr(analyzer, "run_agent", _fake_run_agent)
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            lambda *_, **__: None)

        apk_path = str(tmp_path / "fake.apk")
        result = analyzer.analyze_java_kotlin_apk(apk_path, defer_cleanup=True)

        assert order == ["sast", "agent"]
        assert result["success"] is True

    def test_sast_findings_are_handed_to_the_agent_as_leads(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a deterministic finding reaches the agent as a lead.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Supplies one deterministic finding, records what the agent received, and removes the graph build.
        """
        analyzer, jadx_dir = self._analyzer(tmp_path, monkeypatch)
        received = {}

        monkeypatch.setattr(
            analyzer, "run_sast",
            lambda source_root_unused, **_: [
                {"title": "Hardcoded AES key", "file": "A.java", "line_number": 8,
                 "severity": "High", "detector": "secrets", "confidence": "HIGH"}])

        def _fake_run_agent(source_root_unused, code_graph_unused, leads=None, **_):
            """
            Purpose:
                Record the worklist the agent was given and return nothing.

            Parameters:
                source_root_unused: The decompiled source root, unused here.
                code_graph_unused: The code graph, unused here.
                leads: The worklist built from the static pass.
                _: The framework label the real run_agent accepts, ignored.

            Returns:
                An empty finding list, a success flag and an empty transcript.

            Side effects:
                Records the worklist.
            """
            received["leads"] = leads
            return [], True, ""

        monkeypatch.setattr(analyzer, "run_agent", _fake_run_agent)
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            lambda *_, **__: None)

        analyzer.analyze_java_kotlin_apk(str(tmp_path / "fake.apk"), defer_cleanup=True)

        assert received["leads"]
        assert received["leads"][0].title == "Hardcoded AES key"

    def test_the_agent_still_wins_a_title_collision(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that when both passes report the same issue it appears once, with the agent's version kept.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Makes both passes report the same issue at different severities.

        Implementation notes:
            The agent read the surrounding code and the detector matched a pattern, so where they disagree about severity the agent's judgement is the better one.
        """
        analyzer, jadx_dir = self._analyzer(tmp_path, monkeypatch)
        shared = {"title": "Same issue", "file": "A.java", "line": "1",
                 "severity": "Medium", "detector": "secrets"}

        monkeypatch.setattr(
            analyzer, "run_sast",
            lambda source_root_unused, **_: [dict(shared, severity="Low")])

        def _fake_run_agent(source_root_unused, code_graph_unused, **_):
            """
            Purpose:
                Report the shared issue at a higher severity, attributed to the agent.

            Parameters:
                source_root_unused: The decompiled source root, unused here.
                code_graph_unused: The code graph, unused here.
                _: The framework label and worklist the real run_agent accepts, ignored.

            Returns:
                The one finding, a success flag and an empty transcript.
            """
            return ([dict(shared, severity="Critical", source="agent")], True, "")

        monkeypatch.setattr(analyzer, "run_agent", _fake_run_agent)
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            lambda *_, **__: None)

        result = analyzer.analyze_java_kotlin_apk(
            str(tmp_path / "fake.apk"), defer_cleanup=True)

        titles = [v["title"] for v in result["vulnerabilities"]]
        assert titles.count("Same issue") == 1
        survivor = next(v for v in result["vulnerabilities"] if v["title"] == "Same issue")
        assert survivor["severity"] == "Critical"

    def test_the_full_dump_fallback_still_merges_sast(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that when the agent could not complete, the deterministic findings still reach the report.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Makes the agent report failure and stubs the fallback analysis.

        Implementation notes:
            A failed agent phase routes through the whole-application fallback, and losing the deterministic findings there would turn a partial scan into an apparently clean one.
        """
        analyzer, jadx_dir = self._analyzer(tmp_path, monkeypatch)
        (jadx_dir / "sources").mkdir()
        (jadx_dir / "sources" / "A.java").write_text("class A {}\n")

        monkeypatch.setattr(
            analyzer, "run_sast",
            lambda source_root_unused, **_: [
                {"title": "SAST finding", "file": "A.java", "line": "1",
                 "severity": "Medium", "detector": "secrets"}])
        monkeypatch.setattr(
            analyzer, "run_agent",
            lambda source_root_unused, code_graph_unused, **_: ([], False, ""))
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            lambda *_, **__: None)
        monkeypatch.setattr(
            analyzer, "extract_files_for_analysis",
            lambda: {"java_files": {"A.java": "class A {}"}})
        monkeypatch.setattr(
            analyzer, "analyze_files_for_vulnerabilities", lambda files_unused: [])

        result = analyzer.analyze_java_kotlin_apk(
            str(tmp_path / "fake.apk"), defer_cleanup=True)

        titles = [v["title"] for v in result["vulnerabilities"]]
        assert "SAST finding" in titles


class TestAndroguardJadxOverlap:
    """
    Purpose:
        Running the two independent passes over the application file at the same time rather than one after the other.

    Implementation notes:
        The bytecode analysis and the decompilation both only read the raw application file, but ran strictly in sequence: roughly 23 seconds of single-threaded analysis immediately after a 30-second decompile. What is pinned here is the wiring rather than the timing, because real thread interleaving cannot be asserted reliably in a unit test, so the test checks that the graph build actually receives what the early pass produced.
    """
    def test_the_prefetched_result_reaches_build_code_graph(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that the result of the early pass is handed to the graph build rather than being recomputed.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Replaces the decompilation, the provider lookup, both phases, the early pass and the graph build.
        """
        import lu77U_MobileSec.analyzers.java_kotlin_analyzer as jk_mod

        analyzer = jk_mod.JavaKotlinAnalyzer()
        jadx_dir = tmp_path / "jadx_out"
        jadx_dir.mkdir()

        def _fake_decompile(apk_path_unused):
            """
            Purpose:
                Point the analyzer at the prepared output directory without decompiling anything.

            Parameters:
                apk_path_unused: The application file, unused here.

            Returns:
                True, reporting success.

            Side effects:
                Sets the analyzer's output directory.
            """
            analyzer.jadx_output_dir = jadx_dir
            return True

        monkeypatch.setattr(analyzer, "decompile_apk", _fake_decompile)
        monkeypatch.setattr(jk_mod, "get_active_provider", lambda **_: object())
        monkeypatch.setattr(analyzer, "run_sast", lambda source_root_unused, **_: [])
        monkeypatch.setattr(
            analyzer, "run_agent",
            lambda source_root_unused, code_graph_unused, **_: ([], True, ""))

        sentinel = object()
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.analyze_apk_for_code_graph",
            lambda apk_path_unused, verbose_unused=False: sentinel)

        received = {}

        def _fake_build_code_graph(apk_path_unused, preloaded=None, **_):
            """
            Purpose:
                Record what the graph build was handed and return no graph.

            Parameters:
                apk_path_unused: The application file, unused here.
                preloaded: The result of the early pass, recorded.
                _: The decompiled output directory, verbosity flag and worklist the real build_code_graph accepts, ignored.

            Returns:
                Nothing, standing in for a graph that could not be built.

            Side effects:
                Records what was handed in.
            """
            received["preloaded"] = preloaded
            return None

        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            _fake_build_code_graph)

        analyzer.analyze_java_kotlin_apk(str(tmp_path / "fake.apk"), defer_cleanup=True)

        assert received["preloaded"] is sentinel

    def test_a_failed_prefetch_still_lets_the_scan_proceed(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an early pass which produced nothing still leaves the scan able to finish.

        Parameters:
            tmp_path: Directory the output directory is created in.
            monkeypatch: Replaces the decompilation, the provider lookup, both phases, the early pass and the graph build.

        Implementation notes:
            The early pass is an optimisation, so its failure has to cost time rather than the scan.
        """
        import lu77U_MobileSec.analyzers.java_kotlin_analyzer as jk_mod

        analyzer = jk_mod.JavaKotlinAnalyzer()
        jadx_dir = tmp_path / "jadx_out"
        jadx_dir.mkdir()

        def _fake_decompile(apk_path_unused):
            """
            Purpose:
                Point the analyzer at the prepared output directory without decompiling anything.

            Parameters:
                apk_path_unused: The application file, unused here.

            Returns:
                True, reporting success.

            Side effects:
                Sets the analyzer's output directory.
            """
            analyzer.jadx_output_dir = jadx_dir
            return True

        monkeypatch.setattr(analyzer, "decompile_apk", _fake_decompile)
        monkeypatch.setattr(jk_mod, "get_active_provider", lambda **_: object())
        monkeypatch.setattr(analyzer, "run_sast", lambda source_root_unused, **_: [])
        monkeypatch.setattr(
            analyzer, "run_agent",
            lambda source_root_unused, code_graph_unused, **_: ([], True, ""))
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.analyze_apk_for_code_graph",
            lambda apk_path_unused, verbose_unused=False: None)
        monkeypatch.setattr(
            "lu77U_MobileSec.analyzers.agent.code_graph.build_code_graph",
            lambda *_, **__: None)

        result = analyzer.analyze_java_kotlin_apk(
            str(tmp_path / "fake.apk"), defer_cleanup=True)
        assert result["success"] is True
