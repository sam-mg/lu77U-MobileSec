#!/usr/bin/env python3
"""
Module: test_detector_and_report_fixes

Purpose:
    Detector and report defects found by static analysis, each of which failed silently and left a plausible-looking wrong answer behind.

Responsibilities:
    Pin that the comprehensive report refuses to fall back to a generator it cannot drive, that the generator reuse message is logged only on reuse, that the framework class list is not repeated once per DEX file, that Kony and Unity projects are recognised from a directory, and that the taxonomy's public names stay exported.

Dependencies:
    pytest, ast, the comprehensive report builder, the base framework detector, the Kony and Unity detectors with their indicator tables, and the vulnerability taxonomy.

Implementation notes:
    None of these raised anything a user would see. The PDF fallback crashed with an error naming a method signature rather than the missing dependency, the duplicated class list only inflated a count, and the directory detectors swallowed an AttributeError and reported no framework at all. That is why each one is pinned here rather than simply fixed.
"""

import ast
import sys
import types
from pathlib import Path

import pytest

from lu77U_MobileSec.config.constants import KONY_PROJECT_FILES, UNITY_PROJECT_FILES
from lu77U_MobileSec.framework_detector.base_detector import BaseFrameworkDetector
from lu77U_MobileSec.framework_detector.kony_detector import KonyDetector
from lu77U_MobileSec.framework_detector.unity_detector import UnityDetector
from lu77U_MobileSec.report_generator import comprehensive_report_builder as crb
from lu77U_MobileSec.validation import taxonomy
from lu77U_MobileSec.validation.taxonomy import ALL_CODES, VULN_CLASSES

_COMPREHENSIVE = "lu77U_MobileSec.report_generator.comprehensive_pdf_generator"
_STANDARD = "lu77U_MobileSec.report_generator.pdf_generator"


@pytest.fixture
def standard_builds(monkeypatch):
    """
    Purpose:
        Replace the standard PDF generator module with one whose class records every construction, so a test can prove the comprehensive builder never reaches for it.

    Parameters:
        monkeypatch: pytest's patcher, which restores the module table afterwards.

    Returns:
        The list each construction of the stand-in appends its verbose flag to.
    """
    builds = []

    class _Standard:
        """
        Purpose:
            Stand-in for PDFReportGenerator that records being built and deliberately offers none of the comprehensive generator's methods.
        """
        def __init__(self, verbose=False):
            """
            Purpose:
                Record the construction instead of loading the PDF stack.

            Parameters:
                verbose: The flag the builder passed through.
            """
            builds.append(verbose)

    fake = types.ModuleType(_STANDARD)
    fake.PDFReportGenerator = _Standard
    monkeypatch.setitem(sys.modules, _STANDARD, fake)
    return builds


class TestComprehensiveGeneratorImportFailure:
    """
    Purpose:
        What the comprehensive report builder does when its own generator cannot be imported.

    Implementation notes:
        The builder used to fall back to the standard generator, which has no generate_comprehensive_pdf and whose generate_pdf_report takes only the detection result. The fallback therefore always crashed on first use, and the error the user saw named a method rather than the missing PDF stack.
    """
    def test_the_accessor_raises_and_never_builds_the_standard_generator(self, monkeypatch, standard_builds):
        """
        Purpose:
            Pin that a failed import raises a RuntimeError chained to the ImportError, prints the installation help, and constructs no fallback.

        Parameters:
            monkeypatch: pytest's patcher, used to make the import fail and to observe the help.
            standard_builds: Constructions of the stand-in standard generator.
        """
        monkeypatch.setitem(sys.modules, _COMPREHENSIVE, None)
        helped = []
        builder = crb.ComprehensiveReportBuilder()
        monkeypatch.setattr(builder, "_print_installation_help", helped.append)

        with pytest.raises(RuntimeError, match="PDF generator initialization failed") as excinfo:
            _ = builder._get_pdf_generator()

        assert isinstance(excinfo.value.__cause__, ImportError)
        assert standard_builds == []
        assert len(helped) == 1
        assert isinstance(helped[0], ImportError)
        assert builder.pdf_generator is None

    @pytest.mark.parametrize("entry,label", [
        ("generate_comprehensive_report", "Comprehensive report generation failed"),
        ("generate_framework_only_report", "Framework-only report generation failed"),
    ])
    def test_a_report_request_surfaces_the_import_failure(self, monkeypatch, standard_builds, tmp_path, entry, label):
        """
        Purpose:
            Pin that both report entry points fail with the import error at the root of the chain, rather than an error from a fallback generator.

        Parameters:
            monkeypatch: pytest's patcher, used to make the import fail.
            standard_builds: Constructions of the stand-in standard generator.
            tmp_path: Directory the report would have been written to.
            entry: The builder method under test.
            label: The message that method's RuntimeError leads with.
        """
        monkeypatch.setitem(sys.modules, _COMPREHENSIVE, None)
        builder = crb.ComprehensiveReportBuilder()
        generate = getattr(builder, entry)

        with pytest.raises(RuntimeError, match=label) as excinfo:
            generate(types.SimpleNamespace(), str(tmp_path / "report.pdf"))

        assert isinstance(excinfo.value.__cause__, RuntimeError)
        assert isinstance(excinfo.value.__cause__.__cause__, ImportError)
        assert standard_builds == []

    def test_the_reuse_message_is_logged_only_on_reuse(self, monkeypatch):
        """
        Purpose:
            Pin that the generator is built once and that "Using existing" is traced on the second request, not on the first construction.

        Parameters:
            monkeypatch: pytest's patcher, used to substitute the generator module and capture the trace.
        """
        builds = []
        messages = []

        class _Comprehensive:
            """
            Purpose:
                Stand-in for ComprehensivePDFGenerator that records being built.
            """
            def __init__(self, verbose=False):
                """
                Purpose:
                    Record the construction instead of loading the PDF stack.

                Parameters:
                    verbose: The flag the builder passed through.
                """
                builds.append(verbose)

        def _record(message, unused_verbose=False):
            """
            Purpose:
                Capture a trace line instead of printing it.

            Parameters:
                message: The line the builder traced.
                unused_verbose: The builder's verbose flag, ignored here.
            """
            messages.append(message)

        fake = types.ModuleType(_COMPREHENSIVE)
        fake.ComprehensivePDFGenerator = _Comprehensive
        monkeypatch.setitem(sys.modules, _COMPREHENSIVE, fake)
        monkeypatch.setattr(crb, "verbose_print", _record)
        builder = crb.ComprehensiveReportBuilder()

        first = builder._get_pdf_generator()
        first_messages = list(messages)
        second = builder._get_pdf_generator()
        reuse_messages = messages[len(first_messages):]

        assert second is first
        assert builds == [False]
        assert not any("Using existing" in line for line in first_messages)
        assert any("Using existing" in line for line in reuse_messages)


class _Analysis:
    """
    Purpose:
        Stand-in for androguard's whole-APK analysis, whose class list already spans every DEX file.

    Attributes:
        names: The class names the analysis reports.
        calls: How many times the class list was requested.
    """
    def __init__(self, names):
        """
        Purpose:
            Hold the class names to report.

        Parameters:
            names: The class names, in the order the analysis yields them.
        """
        self.names = names
        self.calls = 0

    def get_classes(self):
        """
        Purpose:
            Yield one class-analysis object per name, counting the request.

        Returns:
            Objects carrying only a name, which is all the detector reads.
        """
        self.calls += 1
        return [types.SimpleNamespace(name=name) for name in self.names]


_CLASSES = ["Lcom/example/MainActivity;", "Lio/flutter/embedding/android/FlutterActivity;"]


class TestFrameworkClassList:
    """
    Purpose:
        The class-name list the framework detectors search.

    Implementation notes:
        The list used to be read from the whole-APK analysis once per DEX file, so a multidex app reported every class two or more times.
    """
    @pytest.mark.parametrize("dex_count", [1, 2, 3])
    def test_each_class_is_listed_once_whatever_the_dex_count(self, dex_count):
        """
        Purpose:
            Pin that every class appears exactly once and the analysis is asked once, however many DEX files the APK has.

        Parameters:
            dex_count: How many DEX files the fake APK carries.
        """
        detector = BaseFrameworkDetector()
        detector.dalvik_files = [object() for _ in range(dex_count)]
        detector.analysis = _Analysis(_CLASSES)

        classes = detector.get_classes()

        assert classes == _CLASSES
        assert detector.analysis.calls == 1

    def test_an_apk_without_dex_files_has_no_classes(self):
        """
        Purpose:
            Pin that the empty-DEX guard still short-circuits before the analysis is consulted.
        """
        detector = BaseFrameworkDetector()
        detector.analysis = _Analysis(_CLASSES)

        classes = detector.get_classes()

        assert classes == []
        assert detector.analysis.calls == 0


def _layout(root, dirs, files):
    """
    Purpose:
        Build a project tree of empty directories and empty files under a root.

    Parameters:
        root: The project root, created along with the first entry beneath it.
        dirs: Directories to create, relative to the root.
        files: Files to create, relative to the root; their parents are created as needed.

    Returns:
        The root as a string, the form the detectors accept.
    """
    for directory in dirs:
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name in files:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")
    return str(root)


class TestProjectDirectoryDetection:
    """
    Purpose:
        Kony and Unity detection from a project directory rather than an APK.

    Implementation notes:
        Both detectors read self.project_files but never assigned it, so every directory scan raised AttributeError inside a broad guard and reported no framework. Detection from an APK was unaffected, which is why it went unnoticed.
    """
    def test_a_kony_project_is_detected(self, tmp_path):
        """
        Purpose:
            Pin that a Kony Visualizer project layout is recognised, including its root project file.

        Parameters:
            tmp_path: Where the project tree is built.
        """
        project = _layout(tmp_path, ["modules/kony", "forms"],
                          ["projectProperties.json", "modules/kony/konyApp.js"])

        result = KonyDetector().detect(project)

        assert result is not None
        assert result["framework"] == "Kony Visualizer"
        assert {"modules/kony", "projectProperties.json", "forms/", "kony*.js files"} <= set(result["indicators"])

    def test_a_unity_project_is_detected(self, tmp_path):
        """
        Purpose:
            Pin that a Unity project layout is recognised by its standard directories and a scene file.

        Parameters:
            tmp_path: Where the project tree is built.
        """
        project = _layout(tmp_path, ["Assets/Scenes", "ProjectSettings", "Library"],
                          ["Assets/Scenes/Main.unity", "ProjectSettings/ProjectVersion.txt"])

        result = UnityDetector().detect(project)

        assert result is not None
        assert result["framework"] == "Unity"
        assert {"Assets/", "ProjectSettings/", "Library/", "*.unity scenes"} <= set(result["indicators"])

    @pytest.mark.parametrize("detector_class,table", [
        (KonyDetector, KONY_PROJECT_FILES),
        (UnityDetector, UNITY_PROJECT_FILES),
    ])
    def test_each_root_project_file_is_enough_on_its_own(self, tmp_path, detector_class, table):
        """
        Purpose:
            Pin that the project-file table is bound and consulted, by detecting a tree that holds nothing but one of its files.

        Parameters:
            tmp_path: Where each single-file project is built.
            detector_class: The detector under test.
            table: The project-file table that detector must use.
        """
        detector = detector_class()
        assert detector.project_files == table
        for name in table:
            project = _layout(tmp_path / name.replace(".", "_"), [], [name])

            result = detector.detect(project)

            assert result is not None, name
            assert result["indicators"] == [name]

    @pytest.mark.parametrize("detector_class", [KonyDetector, UnityDetector])
    def test_an_empty_directory_is_not_detected(self, tmp_path, detector_class):
        """
        Purpose:
            Pin that binding the table did not make every directory look like a project.

        Parameters:
            tmp_path: An empty directory.
            detector_class: The detector under test.
        """
        result = detector_class().detect(str(tmp_path))

        assert result is None


class TestTaxonomyExports:
    """
    Purpose:
        The taxonomy module's declared public surface.

    Implementation notes:
        ALL_CODES is never read inside the taxonomy module, only by the schema, the deduplicator, the validation facade and the tests, so static analysis took it for dead code. Declaring __all__ is what records that it is public, and these tests keep that declaration complete.
    """
    def test_all_codes_is_importable_and_exported(self):
        """
        Purpose:
            Pin that ALL_CODES imports by name, is declared public, and lists every class code in catalogue order.
        """
        assert "ALL_CODES" in taxonomy.__all__
        assert ALL_CODES
        assert ALL_CODES == tuple(entry.code for entry in VULN_CLASSES)

    def test_every_exported_name_resolves(self):
        """
        Purpose:
            Pin that __all__ names nothing the module does not define, which would break a star import.
        """
        missing = [name for name in taxonomy.__all__ if not hasattr(taxonomy, name)]

        assert missing == []

    def test_every_public_definition_is_exported(self):
        """
        Purpose:
            Pin that every public name the module defines at top level is listed in __all__, so a new table cannot be added without being declared.
        """
        source = Path(taxonomy.__file__).read_text(encoding="utf-8")
        defined = set()
        for node in ast.parse(source).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Assign):
                defined.update(target.id for target in node.targets if isinstance(target, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        public = {name for name in defined if not name.startswith("_")}

        assert public == set(taxonomy.__all__)
