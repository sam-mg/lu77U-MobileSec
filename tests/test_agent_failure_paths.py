#!/usr/bin/env python3
"""
Module: test_agent_failure_paths

Purpose:
    The failure paths in the agent analysis core that used to vanish silently: checkpoint and resume errors in the agent loop, unreadable class metadata in the code graph and ownership classifier, BaseException in a fan-out worker, and optional enrichment steps in the analyzer base and the SAST extractors.

Responsibilities:
    Pin that each failure is logged or tolerated exactly as documented, that the narrowed handlers still absorb the one error they were narrowed to, that a BaseException escapes a fan-out worker, and that the shared vendor and sink tables stay in the leaf module that breaks the old import cycle.

Dependencies:
    pytest, the agent loop, code graph, graph tables, ownership classifier, call graph and fan-out, the analyzer base, the SQL injection and SDK inventory extractors, and the cancellation exception.

Implementation notes:
    The log assertions replace each module's verbose_print with a recorder rather than capturing stdout, because verbose_print also forwards milestones to dashboard sinks and only the message text matters here. Providers and androguard objects are small fakes, so nothing touches the network, a real model or a real APK.
"""

import ast
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from lu77U_MobileSec.analyzers import base as base_mod
from lu77U_MobileSec.analyzers.agent import agent_loop, call_graph, code_graph, fanout, graph_tables, ownership
from lu77U_MobileSec.analyzers.agent.profiles import JAVA_KOTLIN
from lu77U_MobileSec.analyzers.sast.extractors import injection, sdk_inventory
from lu77U_MobileSec.utils.cancellation import ScanCancelled

_VEC = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_REPORT = ('{"action":"report","vulnerabilities":[{"title":"H","file":"a.java","line":"1",'
           f'"description":"demo","cvss_vector":"{_VEC}"}}]}}')

_SQL_SOURCE = (
    "class A {\n"
    "  void q() {\n"
    "    String col = ColumnType.getName();\n"
    "    db.rawQuery(\"SELECT * FROM t WHERE \" + col, null);\n"
    "  }\n"
    "}\n")


class _LogRecorder:
    """
    Purpose:
        Stand in for verbose_print and keep every message it is handed.

    Attributes:
        messages: Every message received, in order.
    """
    def __init__(self):
        """
        Purpose:
            Start with no recorded messages.
        """
        self.messages = []

    def __call__(self, message, verbose_unused=False):
        """
        Purpose:
            Record one message, ignoring the verbose flag.

        Parameters:
            message: The text that would have been traced.
            verbose_unused: The caller's verbose flag, accepted to match the real signature, ignored.

        Side effects:
            Appends the message.
        """
        self.messages.append(str(message))

    def saw(self, prefix):
        """
        Purpose:
            Report whether any recorded message starts with a prefix.

        Parameters:
            prefix: The expected start of the message.

        Returns:
            True when a recorded message starts with the prefix.
        """
        return any(m.startswith(prefix) for m in self.messages)


class _ReportingProvider:
    """
    Purpose:
        A provider whose every turn is a report carrying one finding, so the agent loop finishes on its first call.

    Attributes:
        calls: How many turns were requested.
    """
    def __init__(self):
        """
        Purpose:
            Start with no calls made.
        """
        self.calls = 0

    def analyze(self, *args_unused, **kwargs_unused):
        """
        Purpose:
            Answer every turn with the report.

        Parameters:
            args_unused: The prompt and any other positional arguments the loop calls with, ignored.
            kwargs_unused: The system message, schema, token limit and session key the loop calls with, ignored.

        Returns:
            The report as a provider response.

        Side effects:
            Increments the call count.
        """
        self.calls += 1
        return {"response": _REPORT}


def _failing_checkpoint(snapshot):
    """
    Purpose:
        Stand in for a checkpoint store whose disk is full.

    Parameters:
        snapshot: The region state that would have been saved.

    Raises:
        OSError: Always, naming the snapshot's region so the message is traceable.
    """
    raise OSError(f"disk full while saving {snapshot.get('region_key')}")


@pytest.fixture
def src(tmp_path):
    """
    Purpose:
        Build a minimal decompiled tree with one file in it.

    Parameters:
        tmp_path: Directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "a.java").write_text("class A {}\n")
    return tmp_path


class TestAgentLoopCheckpointFailures:
    """
    Purpose:
        That a checkpoint that cannot be saved, or a resume state that cannot be applied, is logged and never costs the region its work.
    """
    def test_a_failing_checkpoint_is_logged_and_the_loop_still_finishes(self, src, monkeypatch):
        """
        Purpose:
            Pin that a raising checkpoint callback produces a log line while the region still completes with its finding.

        Parameters:
            src: The decompiled tree.
            monkeypatch: Replaces the loop's verbose_print with a recorder.

        Implementation notes:
            A failed save costs the ability to resume, never the region's work, so the findings and the completion flag must be the same as with a working store.
        """
        log = _LogRecorder()
        monkeypatch.setattr(agent_loop, "verbose_print", log)
        vulns, completed_ok, _ = agent_loop.run_agent_analysis(
            _ReportingProvider(), str(src), on_checkpoint=_failing_checkpoint)
        assert completed_ok is True
        assert [v.get("title") for v in vulns] == ["H"]
        assert log.saw("Region checkpoint could not be saved: disk full")

    def test_a_working_checkpoint_logs_nothing_about_saving(self, src, monkeypatch):
        """
        Purpose:
            Pin that the save-failure line appears only when the save actually fails.

        Parameters:
            src: The decompiled tree.
            monkeypatch: Replaces the loop's verbose_print with a recorder.
        """
        log = _LogRecorder()
        monkeypatch.setattr(agent_loop, "verbose_print", log)
        saved = []
        agent_loop.run_agent_analysis(
            _ReportingProvider(), str(src), on_checkpoint=saved.append)
        assert saved
        assert not log.saw("Region checkpoint could not be saved")

    def test_a_malformed_resume_state_is_logged(self, src, monkeypatch):
        """
        Purpose:
            Pin that a resume state whose coverage fields cannot be applied leaves a log line and the region still runs.

        Parameters:
            src: The decompiled tree.
            monkeypatch: Replaces the loop's verbose_print with a recorder.

        Implementation notes:
            The step count parses, so the first restore block succeeds; the exploratory action count does not, which fails the second block after part of it has been applied. That half-applied state used to leave no trace at all.
        """
        log = _LogRecorder()
        monkeypatch.setattr(agent_loop, "verbose_print", log)
        _, completed_ok, _ = agent_loop.run_agent_analysis(
            _ReportingProvider(), str(src),
            resume_state={"steps_taken": 0, "read_files": ["a.java"],
                          "exploratory_actions": "many"})
        assert completed_ok is True
        assert log.saw("Resume state could not be fully restored: ")


class _NoFlagsVmClass:
    """
    Purpose:
        Stand in for androguard's ExternalClass, which has no access flags to read.
    """


class _FlaggedVmClass:
    """
    Purpose:
        Stand in for a real class definition with fixed access flags.

    Attributes:
        flags: The access flags to report.
    """
    def __init__(self, flags):
        """
        Purpose:
            Record the flags to report.

        Parameters:
            flags: The access flags.
        """
        self.flags = flags

    def get_access_flags(self):
        """
        Purpose:
            Return the recorded access flags.

        Returns:
            The flags.
        """
        return self.flags


class _FakeClassAnalysis:
    """
    Purpose:
        Stand in for one androguard ClassAnalysis with no methods and no outgoing references.

    Attributes:
        name: The class descriptor.
        extends: The superclass, absent here.
        vm_class: What get_vm_class returns.
    """
    def __init__(self, name, vm_class):
        """
        Purpose:
            Build the class.

        Parameters:
            name: The class descriptor.
            vm_class: What get_vm_class should return.
        """
        self.name = name
        self.extends = None
        self.vm_class = vm_class

    def is_external(self):
        """
        Purpose:
            Report that the class is defined in the APK.

        Returns:
            False.
        """
        return False

    def get_vm_class(self):
        """
        Purpose:
            Return the class definition stand-in.

        Returns:
            The vm class.
        """
        return self.vm_class

    def get_methods(self):
        """
        Purpose:
            Return no methods.

        Returns:
            An empty list.
        """
        return []

    def get_xref_to(self):
        """
        Purpose:
            Return no outgoing references.

        Returns:
            An empty list.
        """
        return []


class _BareClass:
    """
    Purpose:
        Stand in for a class object that has a name but no is_external method at all.

    Attributes:
        name: The class descriptor.
    """
    def __init__(self, name):
        """
        Purpose:
            Build the class.

        Parameters:
            name: The class descriptor.
        """
        self.name = name


class _FakeDx:
    """
    Purpose:
        Stand in for androguard's analysis object over a fixed class list.

    Attributes:
        classes: The classes to return.
    """
    def __init__(self, classes):
        """
        Purpose:
            Record the classes.

        Parameters:
            classes: The classes to return.
        """
        self.classes = list(classes)

    def get_classes(self):
        """
        Purpose:
            Return the recorded classes.

        Returns:
            The classes.
        """
        return list(self.classes)


class _FakeApk:
    """
    Purpose:
        Stand in for androguard's APK object: a package name, an unreadable manifest and no component getters.
    """
    def get_package(self):
        """
        Purpose:
            Return a fixed package name.

        Returns:
            The package name.
        """
        return "com.example.app"

    def get_android_manifest_xml(self):
        """
        Purpose:
            Refuse the manifest, so no roles are derived.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError("no manifest in this fake")


_MAIN = "Lcom/example/app/Main;"
_SYNTH = "Lcom/example/app/Main$Lambda;"


def _lead_for(descriptor):
    """
    Purpose:
        Build a lead pointing at a class's source file, which protects its node from pruning.

    Parameters:
        descriptor: The class descriptor.

    Returns:
        An object with the file attribute the graph builder reads.
    """
    return SimpleNamespace(file="sources/" + descriptor[1:-1].split("$", 1)[0] + ".java")


class TestCodeGraphClassMetadata:
    """
    Purpose:
        That the code graph keeps a class whose access flags cannot be read, still skips synthetic classes, and logs manifest getters it cannot call.
    """
    def test_a_class_without_access_flags_is_kept(self):
        """
        Purpose:
            Pin that a class whose definition has no access flags stays in the graph.

        Implementation notes:
            androguard returns an ExternalClass with no get_access_flags for a class it cannot see the definition of. The handler was narrowed to exactly that AttributeError, and dropping the class instead would remove application code from the analysis.
        """
        dx = _FakeDx([_FakeClassAnalysis(_MAIN, _NoFlagsVmClass())])
        graph = code_graph.build_code_graph(
            "app.apk", preloaded=(_FakeApk(), dx), leads=[_lead_for(_MAIN)])
        assert graph is not None
        assert _MAIN in graph.nodes
        assert graph.ownership["synthetic_classes_skipped"] == 0

    def test_a_synthetic_class_is_still_skipped(self):
        """
        Purpose:
            Pin that narrowing the handler left the synthetic-class check itself working.
        """
        dx = _FakeDx([_FakeClassAnalysis(_MAIN, _FlaggedVmClass(0x1)),
                      _FakeClassAnalysis(_SYNTH, _FlaggedVmClass(0x1000))])
        graph = code_graph.build_code_graph(
            "app.apk", preloaded=(_FakeApk(), dx), leads=[_lead_for(_MAIN)])
        assert graph is not None
        assert graph.ownership["synthetic_classes_skipped"] == 1

    def test_missing_manifest_getters_are_logged(self, monkeypatch):
        """
        Purpose:
            Pin that a component getter the APK object cannot answer is logged by name rather than skipped silently.

        Parameters:
            monkeypatch: Replaces the graph's verbose_print with a recorder.
        """
        log = _LogRecorder()
        monkeypatch.setattr(code_graph, "verbose_print", log)
        dx = _FakeDx([_FakeClassAnalysis(_MAIN, _NoFlagsVmClass())])
        code_graph.build_code_graph(
            "app.apk", preloaded=(_FakeApk(), dx), leads=[_lead_for(_MAIN)])
        for getter in ("get_activities", "get_services", "get_receivers", "get_providers"):
            assert log.saw(f"Manifest {getter} could not be read: ")


class TestGraphTablesAndOwnership:
    """
    Purpose:
        That the vendor and sink tables live in one leaf module every consumer shares, and that ownership still merges both vendor sources.
    """
    def test_vendor_prefixes_include_entries_from_both_tables(self):
        """
        Purpose:
            Pin that ownership's vendor set holds every graph-table prefix and every SDK inventory package.

        Implementation notes:
            The inventory-only prefixes are checked separately, so the test fails if the SDK import is dropped even though the graph table alone would still give a non-empty set.
        """
        prefixes = set(ownership._vendor_prefixes())
        inventory = {"L" + pkg.strip("/") + "/"
                     for entry in sdk_inventory.SDK_SIGNATURES.values() for pkg in entry[1]}
        inventory_only = inventory - set(graph_tables.VENDOR_PREFIXES)
        assert set(graph_tables.VENDOR_PREFIXES) <= prefixes
        assert inventory_only
        assert inventory_only <= prefixes

    def test_consumers_share_the_graph_tables_objects(self):
        """
        Purpose:
            Pin that code_graph and call_graph read the graph_tables objects themselves, not copies.

        Implementation notes:
            Identity rather than equality, because an equal copy is exactly the drift a single leaf module exists to prevent.
        """
        assert code_graph._VENDOR_PREFIXES is graph_tables.VENDOR_PREFIXES
        assert code_graph._SINK_FAMILIES is graph_tables.SINK_FAMILIES
        assert call_graph._SINK_FAMILIES is graph_tables.SINK_FAMILIES

    @pytest.mark.parametrize("module", [ownership, call_graph, graph_tables])
    def test_modules_code_graph_imports_do_not_import_it_back(self, module):
        """
        Purpose:
            Pin that the modules code_graph depends on never import code_graph, which is what keeps the import graph acyclic.

        Parameters:
            module: A module on code_graph's import path.
        """
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = {node.module for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom) and node.module}
        assert "code_graph" not in imported

    def test_a_class_without_is_external_is_treated_as_internal(self):
        """
        Purpose:
            Pin that ownership keeps a class object lacking is_external as application code.

        Implementation notes:
            The handler was narrowed to AttributeError; keeping such a class is the safe direction, since dropping it would silently shrink the analysed set.
        """
        dx = _FakeDx([_BareClass(_MAIN)])
        verdict = ownership.classify_packages(dx, "com.example.app")
        assert verdict["stats"]["app_classes"] == 1
        assert ownership.is_app_descriptor(_MAIN, verdict["owner"])


class _Abort(BaseException):
    """
    Purpose:
        A BaseException that is neither KeyboardInterrupt nor SystemExit, so the test can raise one inside a worker thread without side effects on the runner.
    """


def _fanout_graph():
    """
    Purpose:
        Build a small graph of two entry points, each reaching its own helpers, so the fan-out starts more than one worker.

    Returns:
        The graph.
    """
    nodes = {}
    for e in range(2):
        helpers = [f"H{e}_{i}" for i in range(3)]
        nodes[f"Entry{e}"] = code_graph.CodeNode(
            cls=f"Entry{e}", file=f"sources/com/x/Entry{e}.java", role="exported-activity",
            signals={"ipc": ["getStringExtra"]}, calls=list(helpers), intent_actions=["VIEW"])
        for helper in helpers:
            nodes[helper] = code_graph.CodeNode(
                cls=helper, file=f"sources/com/x/{helper}.java",
                signals={"sql": ["rawQuery"]}, calls=[f"Entry{e}"])
    return code_graph.CodeGraph(package="com.x", nodes=nodes)


def _run_fanout(monkeypatch, agent, progress=None):
    """
    Purpose:
        Run the fan-out with the agent loop replaced, capturing any exception that escapes a worker thread.

    Parameters:
        monkeypatch: Replaces the agent loop.
        agent: The stand-in for run_agent_analysis.
        progress: The progress callback to pass, or None.

    Returns:
        The fan-out's return value and the exception types that escaped worker threads.

    Implementation notes:
        threading.excepthook is swapped and restored inside this call rather than through monkeypatch, so the runner's own thread-exception hook is back in place before the test ends and never sees the deliberately escaped exception.
    """
    monkeypatch.setattr(agent_loop, "run_agent_analysis", agent)
    escaped = []
    previous = threading.excepthook
    threading.excepthook = lambda args: escaped.append(args.exc_type)
    try:
        out = fanout.run_surface_agents(
            provider=object(), source_root="/nope", profile=JAVA_KOTLIN,
            code_graph=_fanout_graph(), framework_label="Java/Kotlin", progress=progress)
    finally:
        threading.excepthook = previous
    return out, escaped


class TestFanoutWorkerFailures:
    """
    Purpose:
        That a worker records ordinary failures and re-raises a BaseException, and that its progress updates stay best-effort.
    """
    def test_a_base_exception_in_a_worker_propagates(self, monkeypatch):
        """
        Purpose:
            Pin that a BaseException raised by a region escapes the worker instead of being recorded as an ordinary error.

        Parameters:
            monkeypatch: Replaces the agent loop.

        Implementation notes:
            A KeyboardInterrupt or SystemExit is a request to stop the process, and downgrading it to a region error line hid that request.
        """
        def agent(*args_unused, **kwargs_unused):
            """
            Purpose:
                Stand in for a region that is interrupted.

            Parameters:
                args_unused: The loop's positional arguments, ignored.
                kwargs_unused: The loop's keyword arguments, ignored.

            Raises:
                _Abort: Always.
            """
            raise _Abort()

        _, escaped = _run_fanout(monkeypatch, agent)
        assert escaped
        assert set(escaped) == {_Abort}

    def test_an_ordinary_exception_is_recorded_not_propagated(self, monkeypatch):
        """
        Purpose:
            Pin that an ordinary region failure stays inside the worker and the phase still returns.

        Parameters:
            monkeypatch: Replaces the agent loop.
        """
        def agent(*args_unused, **kwargs_unused):
            """
            Purpose:
                Stand in for a region that fails.

            Parameters:
                args_unused: The loop's positional arguments, ignored.
                kwargs_unused: The loop's keyword arguments, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("region failed")

        (findings, ok, _), escaped = _run_fanout(monkeypatch, agent)
        assert escaped == []
        assert findings == []
        assert ok is False

    def test_a_failing_progress_callback_does_not_break_the_phase(self, monkeypatch):
        """
        Purpose:
            Pin that progress updates which always raise, cancellation included, neither escape a worker nor stop the phase returning its findings.

        Parameters:
            monkeypatch: Replaces the agent loop.
        """
        def agent(*args_unused, **kwargs_unused):
            """
            Purpose:
                Stand in for a region that reports one finding.

            Parameters:
                args_unused: The loop's positional arguments, ignored.
                kwargs_unused: The loop's keyword arguments, ignored.

            Returns:
                One finding, a completion flag and a transcript.
            """
            return [{"title": "x", "file": "f.java", "line": "1"}], True, "T"

        def progress(*args_unused, **kwargs_unused):
            """
            Purpose:
                Stand in for a progress sink that always refuses the update.

            Parameters:
                args_unused: The progress arguments, ignored.
                kwargs_unused: The progress keyword arguments, ignored.

            Raises:
                ScanCancelled: Always.
            """
            raise ScanCancelled()

        (findings, ok, _), escaped = _run_fanout(monkeypatch, agent, progress=progress)
        assert escaped == []
        assert ok is True
        assert findings


class TestAnalyzerBaseFailures:
    """
    Purpose:
        That the analyzer base logs an undeliverable progress update and failed optional enrichment instead of swallowing them, while cancellation still propagates.
    """
    def test_a_failing_progress_callback_is_logged(self, monkeypatch):
        """
        Purpose:
            Pin that a progress callback raising an ordinary error is logged and not raised.

        Parameters:
            monkeypatch: Replaces the base module's verbose_print with a recorder.
        """
        log = _LogRecorder()
        monkeypatch.setattr(base_mod, "verbose_print", log)

        def broken(*args_unused):
            """
            Purpose:
                Stand in for a progress sink whose client went away.

            Parameters:
                args_unused: The progress arguments, ignored.

            Raises:
                ConnectionError: Always.
            """
            raise ConnectionError("client gone")

        analyzer = SimpleNamespace(_progress=broken, verbose=False)
        base_mod.BaseAnalyzer.progress(analyzer, "agentic", 10, "working")
        assert log.saw("Progress update could not be delivered: client gone")

    def test_cancellation_from_progress_still_propagates(self):
        """
        Purpose:
            Pin that a ScanCancelled raised by the progress callback reaches the caller.

        Implementation notes:
            ScanCancelled subclasses Exception, so the logging handler must come after the re-raise or a stop request would be logged and ignored.
        """
        def cancelled(*args_unused):
            """
            Purpose:
                Stand in for a progress sink that reports a user stop.

            Parameters:
                args_unused: The progress arguments, ignored.

            Raises:
                ScanCancelled: Always.
            """
            raise ScanCancelled()

        analyzer = SimpleNamespace(_progress=cancelled, verbose=False)
        with pytest.raises(ScanCancelled):
            base_mod.BaseAnalyzer.progress(analyzer, "agentic", 10, "working")

    def test_sql_provenance_failure_is_logged(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a failing SQL provenance resolver is logged with the finding's file and leaves the other evidence in place.

        Parameters:
            tmp_path: Stands in for the decompiled root.
            monkeypatch: Replaces the resolver and the base module's verbose_print.
        """
        log = _LogRecorder()
        monkeypatch.setattr(base_mod, "verbose_print", log)

        def broken_resolver(*args_unused):
            """
            Purpose:
                Stand in for a provenance resolver that fails.

            Parameters:
                args_unused: The resolver arguments, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("parser broke")

        monkeypatch.setattr(injection, "resolve_sql_provenance", broken_resolver)
        vuln = {"title": "SQL injection in query", "file": "sources/com/x/A.java"}
        lines = _SQL_SOURCE.splitlines()
        base_mod.BaseAnalyzer._attach_evidence_fields(
            SimpleNamespace(verbose=False), vuln, lines, 4, 4,
            tmp_path, {})
        assert "operand_provenance" not in vuln
        assert "evidence_window" in vuln
        assert log.saw("SQL operand provenance could not be resolved for sources/com/x/A.java: parser broke")

    def test_vendor_tagging_failure_is_logged(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a failing vendor lookup is logged with the finding's file and leaves the finding untagged.

        Parameters:
            tmp_path: Stands in for the decompiled root.
            monkeypatch: Replaces the vendor lookup and the base module's verbose_print.
        """
        log = _LogRecorder()
        monkeypatch.setattr(base_mod, "verbose_print", log)

        def broken_lookup(path_unused):
            """
            Purpose:
                Stand in for a vendor lookup that fails.

            Parameters:
                path_unused: The finding's file, ignored.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("table broke")

        monkeypatch.setattr(code_graph, "vendor_sdk_for_path", broken_lookup)
        vuln = {"title": "Hardcoded key", "file": "sources/com/x/A.java"}
        base_mod.BaseAnalyzer._attach_evidence_fields(
            SimpleNamespace(verbose=False), vuln, ["class A {}"], 1, 1,
            tmp_path, {})
        assert "vendor_sdk" not in vuln
        assert log.saw("Vendor SDK tagging failed for sources/com/x/A.java: table broke")


class TestSastExtractorFailures:
    """
    Purpose:
        That a failing enum lookup counts as no evidence, and an unreadable SDK file leaves the version unknown without dropping the SDK.
    """
    def test_a_failing_enum_lookup_counts_as_no_evidence(self):
        """
        Purpose:
            Pin that an enum lookup which raises leaves the operand's verdict unchanged instead of raising.
        """
        def broken(type_name_unused):
            """
            Purpose:
                Stand in for an enum lookup that fails.

            Parameters:
                type_name_unused: The type asked about, ignored.

            Raises:
                OSError: Always.
            """
            raise OSError("tree unreadable")

        assert injection.resolve_sql_provenance(_SQL_SOURCE, 4, broken) == "unknown"

    def test_a_failing_lookup_does_not_stop_later_operands(self):
        """
        Purpose:
            Pin that one operand's failed lookup still lets a later operand prove the value constant.
        """
        text = ("class A {\n"
                "  void q() {\n"
                "    String a = Broken.getA();\n"
                "    String b = ColumnType.getB();\n"
                "    db.rawQuery(\"SELECT \" + a + \" FROM \" + b, null);\n"
                "  }\n"
                "}\n")

        def lookup(type_name):
            """
            Purpose:
                Fail for one type and confirm the other as an enum.

            Parameters:
                type_name: The type asked about.

            Returns:
                True for ColumnType.

            Raises:
                OSError: For Broken.
            """
            if type_name == "Broken":
                raise OSError("tree unreadable")
            return type_name == "ColumnType"

        assert injection.resolve_sql_provenance(text, 5, lookup) == "constant"

    def _sdk_tree(self, tmp_path):
        """
        Purpose:
            Build a decompiled tree holding one Firebase Analytics source file.

        Parameters:
            tmp_path: Directory the tree is written into.

        Returns:
            The tree root and the file inside it.
        """
        pkg = tmp_path / "sources" / "com" / "google" / "firebase" / "analytics"
        pkg.mkdir(parents=True)
        target = pkg / "FirebaseAnalytics.java"
        target.write_text('class FirebaseAnalytics { String VERSION = "21.5.0"; }\n')
        return tmp_path, target

    def _inventory(self, findings):
        """
        Purpose:
            Pull the SDK inventory entries out of the extractor's findings.

        Parameters:
            findings: The extractor's findings.

        Returns:
            The inventory entries keyed by SDK name.
        """
        for finding in findings:
            entries = (finding.extra or {}).get("sdk_inventory")
            if entries:
                return {e["name"]: e for e in entries}
        return {}

    def test_an_unreadable_sdk_file_leaves_the_version_unknown(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an OSError reading the SDK file keeps the SDK in the inventory with no version.

        Parameters:
            tmp_path: Directory the tree is written into.
            monkeypatch: Makes the SDK file unreadable.
        """
        root, target = self._sdk_tree(tmp_path)
        real_read_text = Path.read_text

        def read_text(path, *args, **kwargs):
            """
            Purpose:
                Refuse the SDK file and read everything else normally.

            Parameters:
                path: The file being read.
                args: Positional arguments for the real reader.
                kwargs: Keyword arguments for the real reader.

            Returns:
                The file's text, for any file but the SDK one.

            Raises:
                OSError: For the SDK file.
            """
            if path == target:
                raise OSError("permission denied")
            return real_read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", read_text)
        inventory = self._inventory(sdk_inventory.analyze_sdks(root))
        assert "Firebase Analytics" in inventory
        assert inventory["Firebase Analytics"]["version"] is None

    def test_a_readable_sdk_file_still_supplies_the_version(self, tmp_path):
        """
        Purpose:
            Pin the control case, so the unreadable-file test is known to be exercising the version read.

        Parameters:
            tmp_path: Directory the tree is written into.
        """
        root, _ = self._sdk_tree(tmp_path)
        inventory = self._inventory(sdk_inventory.analyze_sdks(root))
        assert inventory["Firebase Analytics"]["version"] == "21.5.0"
