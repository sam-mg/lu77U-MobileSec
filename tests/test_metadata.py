#!/usr/bin/env python3
"""
Module: test_metadata

Purpose:
    That the project configuration is the single source of the package's identity and that nothing anywhere holds a hardcoded copy.

Responsibilities:
    Pin the values read out of the project configuration, every user-visible constant derived from them, the fallbacks used when no checkout is present, and the declarations that make the non-importable data directories ship inside a wheel.

Dependencies:
    pytest, tomllib, the metadata module, and the settings, paths, web, CLI and report modules that consume it.

Implementation notes:
    A stale copy of the version is not caught by running the tool, because everything still works and merely reports the wrong number. These assertions compare against the configuration rather than against literals, so the tests never need editing on a release.
"""

import tomllib
from pathlib import Path

import pytest

import lu77U_MobileSec._metadata as _metadata

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

@pytest.fixture(scope="module")
def project():
    """
    Purpose:
        Read the project table out of the project configuration once per module.

    Returns:
        The project table as a mapping.

    Implementation notes:
        Skipped rather than failed when the file is absent, because the suite also runs against an installed wheel where there is no checkout to compare with.
    """
    if not PYPROJECT.is_file():
        pytest.skip("running outside a checkout; no pyproject.toml to compare against")
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]

class TestResolvedFromPyproject:
    """
    Purpose:
        That each identity field the metadata module exposes matches the project configuration.
    """
    def test_name(self, project):
        """
        Purpose:
            Pin that the package name matches the configuration.

        Parameters:
            project: The project table.
        """
        assert _metadata.NAME == project["name"]

    def test_version(self, project):
        """
        Purpose:
            Pin that the version matches the configuration.

        Parameters:
            project: The project table.
        """
        assert _metadata.VERSION == project["version"]

    def test_description(self, project):
        """
        Purpose:
            Pin that the description matches the configuration.

        Parameters:
            project: The project table.
        """
        assert _metadata.DESCRIPTION == project["description"]

    def test_author_and_email(self, project):
        """
        Purpose:
            Pin that the author name and address match the first author in the configuration.

        Parameters:
            project: The project table.
        """
        author = project["authors"][0]
        assert _metadata.AUTHOR == author["name"]
        assert _metadata.EMAIL == author["email"]

    def test_homepage(self, project):
        """
        Purpose:
            Pin that the homepage matches the configuration.

        Parameters:
            project: The project table.
        """
        assert _metadata.HOMEPAGE == project["urls"]["Homepage"]

class TestDerivedConstants:
    """
    Purpose:
        That everything user-visible traces back to the metadata module rather than to a literal of its own.
    """
    def test_package_dunders(self):
        """
        Purpose:
            Pin that the package's own identity attributes come from the metadata module.
        """
        import lu77U_MobileSec as pkg

        assert pkg.__version__ == _metadata.VERSION
        assert pkg.__title__ == _metadata.NAME
        assert pkg.__author__ == _metadata.AUTHOR
        assert pkg.__email__ == _metadata.EMAIL

    def test_settings_module(self):
        """
        Purpose:
            Pin that the application name, version, description and repository link in settings come from the metadata module.
        """
        from lu77U_MobileSec.config import settings

        assert settings.APP_NAME == _metadata.NAME
        assert settings.APP_VERSION == _metadata.VERSION
        assert settings.APP_DESCRIPTION == _metadata.DESCRIPTION
        assert settings.SOCIAL_LINKS["GitHub Repository"] == _metadata.HOMEPAGE

    def test_paths_and_storage(self):
        """
        Purpose:
            Pin that the output directory name, the keychain service name and the scan folder prefix are all derived from the package name.

        Implementation notes:
            These three name things outside the process, so a hardcoded copy drifting from the package name would leave a user with scans in one directory and credentials under another service, with no error to explain it.

        Security considerations:
            The keychain service name is what the stored API keys are filed under, so a change to it silently orphans the user's existing credentials rather than failing visibly.
        """
        from lu77U_MobileSec.config import paths
        from lu77U_MobileSec.config.credentials import SERVICE_NAME
        from lu77U_MobileSec.web.store import _FOLDER_PREFIX

        assert paths.APP_NAME == _metadata.NAME
        assert SERVICE_NAME == _metadata.NAME
        assert _FOLDER_PREFIX == f"{_metadata.NAME}-"

    def test_cli_version_flag(self, capsys):
        """
        Purpose:
            Pin that the version flag prints the name and version from the metadata module and exits.

        Parameters:
            capsys: Captures the printed output.
        """
        from lu77U_MobileSec.cli.parser import parse_args

        with pytest.raises(SystemExit):
            parse_args(["--version"])
        assert capsys.readouterr().out.strip() == f"{_metadata.NAME} {_metadata.VERSION}"

    def test_version_endpoint(self):
        """
        Purpose:
            Pin that the web version endpoint returns exactly the name and version from the metadata module.
        """
        from fastapi.testclient import TestClient

        from lu77U_MobileSec.web.app import create_app

        payload = TestClient(create_app()).get("/api/version").json()
        assert payload == {"name": _metadata.NAME, "version": _metadata.VERSION}

    def test_report_html_carries_current_identity(self):
        """
        Purpose:
            Pin that a rendered report carries the current name, version and homepage, with no unsubstituted placeholder and no trace of the old hardcoded version.

        Implementation notes:
            The report is the artefact that leaves the machine, so a stale version in it misattributes findings to a release that did not produce them. The placeholder and the old literal are both asserted absent, because a template that failed to substitute and a template that substituted the wrong source look identical until one of them is checked for by name.
        """
        from lu77U_MobileSec.report_generator.report_renderer import render_report_html

        html = render_report_html({
            "application_info": {"package_name": "com.example", "app_name": "Example"},
            "vulnerability_analysis": {"vulnerabilities": {}},
        })
        assert f"{_metadata.NAME} Analysis Report" in html
        assert f"v{_metadata.VERSION}" in html
        assert _metadata.HOMEPAGE in html
        assert "__APP_NAME__" not in html
        assert "v1.0.0" not in html

    def test_report_json_metadata(self):
        """
        Purpose:
            Pin that the exported report's metadata names the tool and version from the metadata module.
        """
        from lu77U_MobileSec.report_generator.json_exporter import JSONExporter

        class Result:
            """
            Purpose:
                The smallest stand-in for an analysis result that the metadata builder reads.

            Attributes:
                target_path: The path the scan ran against.
            """
            target_path = "/tmp/app.apk"

        meta = JSONExporter()._build_metadata(Result())
        assert meta["tool"] == _metadata.NAME
        assert meta["version"] == _metadata.VERSION

class TestFallbacks:
    """
    Purpose:
        The paths taken when the project configuration is not the source: parsing an author field and reading an installed distribution.
    """
    def test_author_field_parsing(self):
        """
        Purpose:
            Pin how an author field splits into a name and an address across the shapes it appears in.

        Implementation notes:
            The combined, address-only, name-only and empty forms are all legal in packaging metadata, so the parser has to produce a usable pair from each rather than assuming the combined one.
        """
        assert _metadata._split_author("Sam MG Harish <a@b.com>") == ("Sam MG Harish", "a@b.com")
        assert _metadata._split_author("a@b.com") == ("", "a@b.com")
        assert _metadata._split_author("Just A Name") == ("Just A Name", "")
        assert _metadata._split_author("") == ("", "")

    def test_installed_distribution_is_readable(self):
        """
        Purpose:
            Pin that identity can be read from an installed distribution.

        Implementation notes:
            Inside a wheel this is the only source there is, since no project configuration ships with it. Skipped when the package is not installed in the environment running the suite.
        """
        data = _metadata._from_installed_distribution()
        if data is None:
            pytest.skip("package is not installed in this environment")
        assert data["name"] == _metadata.NAME
        assert data["description"] == _metadata.DESCRIPTION


class TestPackagedDataFiles:
    """
    Purpose:
        That the data directories which are not importable packages are still declared to ship.

    Implementation notes:
        The skills and rules directories hold no package marker, so package discovery does not see them and their contents ship only because the package data declaration lists them. A scan installed from a wheel with those missing loads no skills and runs the rule scanner with no rules, while a source checkout behaves perfectly, so this cannot be caught by running the tool locally.
    """
    def _package_data(self):
        """
        Purpose:
            Read the package data declarations out of the project configuration.

        Returns:
            The package data table as a mapping of package name to patterns.
        """
        root = Path(__file__).resolve().parents[1]
        with (root / "pyproject.toml").open("rb") as handle:
            config = tomllib.load(handle)
        return config["tool"]["setuptools"]["package-data"]

    def test_skills_are_declared_as_package_data(self):
        """
        Purpose:
            Pin that the skills directory is covered by a package data pattern.
        """
        patterns = self._package_data().get("lu77U_MobileSec", [])
        assert any("skills/" in p for p in patterns)

    def test_semgrep_rules_are_declared_as_package_data(self):
        """
        Purpose:
            Pin that the rule directory is covered by a package data pattern.
        """
        patterns = self._package_data().get("lu77U_MobileSec", [])
        assert any("rules/semgrep" in p for p in patterns)

    def test_every_bundled_skill_matches_the_declared_pattern(self):
        """
        Purpose:
            Pin that every file in the skills directory has the extension the declared pattern matches.

        Implementation notes:
            A skill saved with any other extension is silently left out of the wheel, which is the same invisible failure as the directory not being declared at all.
        """
        from lu77U_MobileSec.analyzers.agent.skills_loader import SKILLS_DIR

        stray = [p.name for p in SKILLS_DIR.iterdir()
                 if p.is_file() and p.suffix != ".md"]
        assert not stray, f"not covered by the skills/*.md pattern: {stray}"

    def test_the_wheel_and_the_source_archive_declare_the_same_data(self):
        """
        Purpose:
            Pin that every data file the package carries outside the frontend source is declared for the wheel and for the source archive.

        Implementation notes:
            The Ghidra export script was listed in the package data but not in MANIFEST.in, so an install built from the source archive had no script and native libraries were never decompiled. Each file is checked against the package data globs and against the MANIFEST.in directory and extension it falls under.
        """
        import fnmatch

        root = Path(__file__).resolve().parents[1]
        package = root / "lu77U_MobileSec"
        patterns = self._package_data().get("lu77U_MobileSec", [])
        manifest = [line.split() for line in (root / "MANIFEST.in").read_text().splitlines()
                    if line.startswith("recursive-include ")]
        skipped = ("frontend", "web", "__pycache__")
        files = [p for p in package.rglob("*") if p.is_file() and p.suffix not in (".py", ".pyc")
                 and not set(p.relative_to(package).parts) & set(skipped)]
        assert files
        for path in files:
            rel = path.relative_to(package).as_posix()
            assert any(fnmatch.fnmatch(rel, p) for p in patterns), f"{rel} not in package-data"
            assert any((root / words[1]) in path.parents and any(fnmatch.fnmatch(path.name, g) for g in words[2:])
                       for words in manifest), f"{rel} not in MANIFEST.in"
