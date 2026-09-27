#!/usr/bin/env python3
"""
Module: test_profiles

Purpose:
    The source profile that generalises the agent's file tools across Java/Kotlin, Flutter, React Native and Cordova.

Responsibilities:
    Pin the profile registry and its immutability, what each profile counts as application source, what it treats as framework noise, what it summarises in place of a manifest, and the sandboxing that holds regardless of profile.

Dependencies:
    pytest, the profile definitions and the agent tool surface.

Implementation notes:
    Each framework's decompiled output has a different shape, and the profile is what lets one set of tools read all of them. Getting the noise filters wrong is the expensive failure: a profile that admits framework code spends the agent's budget reading libraries the developer never wrote.
"""

import pytest

from lu77U_MobileSec.analyzers.agent.profiles import (
    CORDOVA, FLUTTER, JAVA_KOTLIN, PROFILES, REACT_NATIVE)
from lu77U_MobileSec.analyzers.agent.tools import AgentTools

class TestProfileRegistry:
    """
    Purpose:
        The registry that maps a profile key to its profile.
    """
    def test_all_profiles_registered_by_key(self):
        """
        Purpose:
            Pin that each profile is reachable by its key.

        Implementation notes:
            The key is what the analyzer, the agent prompt and the core skill are all looked up by, so a profile missing from the registry is a framework the agent cannot be configured for.
        """
        assert PROFILES["java_kotlin"] is JAVA_KOTLIN
        assert PROFILES["flutter"] is FLUTTER
        assert PROFILES["react_native"] is REACT_NATIVE
        assert PROFILES["cordova"] is CORDOVA

    def test_profiles_are_frozen(self):
        """
        Purpose:
            Pin that a profile cannot be mutated after definition.

        Implementation notes:
            The profiles are module-level singletons shared by every concurrent region, so a mutation in one region would change what the others see mid-scan.
        """
        with pytest.raises(Exception):
            JAVA_KOTLIN.key = "mutated"

@pytest.fixture
def java_tree(tmp_path):
    """
    Purpose:
        Build a Java/Kotlin decompiled tree holding application source, framework source, generated source and resources.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "sources" / "com" / "app").mkdir(parents=True)
    (tmp_path / "sources" / "androidx" / "core").mkdir(parents=True)
    (tmp_path / "resources" / "res" / "values").mkdir(parents=True)
    (tmp_path / "sources" / "com" / "app" / "Main.java").write_text("class Main {}\n")
    (tmp_path / "sources" / "com" / "app" / "R.java").write_text("class R {}\n")
    (tmp_path / "sources" / "androidx" / "core" / "Widget.java").write_text("class Widget {}\n")
    (tmp_path / "resources" / "AndroidManifest.xml").write_text("<manifest/>")
    (tmp_path / "resources" / "res" / "values" / "strings.xml").write_text("<resources/>")
    return tmp_path

@pytest.fixture
def flutter_tree(tmp_path):
    """
    Purpose:
        Build a Flutter decompiled tree holding disassembly files and a Dart object pool.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm" / "MainActivity.asm").write_text("main() {}\n")
    (tmp_path / "asm" / "package_flutter_Widget.asm").write_text("build() {}\n")
    (tmp_path / "pp.txt").write_text('"https://api.example.com/secret"\n')
    return tmp_path

@pytest.fixture
def rn_tree(tmp_path):
    """
    Purpose:
        Build a React Native tree holding one application bundle file, a vendor module and the bundle metadata.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "node_modules" / "react-native").mkdir(parents=True)
    (tmp_path / "app.js").write_text("function main() {}\n")
    (tmp_path / "node_modules" / "react-native" / "index.js").write_text("// vendor\n")
    (tmp_path / "package-metadata.json").write_text('{"format": "javascript"}')
    return tmp_path

class TestJavaKotlinDefault:
    """
    Purpose:
        The Java/Kotlin profile, which is still the implicit default everywhere and must reproduce the behaviour that predated profiles exactly.
    """
    def test_default_profile_is_java_kotlin(self, java_tree):
        """
        Purpose:
            Pin that tools built without a profile get the Java/Kotlin one.

        Parameters:
            java_tree: The Java/Kotlin decompiled tree.
        """
        tools = AgentTools(java_tree)
        assert tools.profile is JAVA_KOTLIN

    def test_androidx_is_noise(self, java_tree):
        """
        Purpose:
            Pin that application source is listed and framework source under androidx is not.

        Parameters:
            java_tree: The Java/Kotlin decompiled tree.
        """
        tools = AgentTools(java_tree, profile=JAVA_KOTLIN)
        files = tools.app_source_files()
        assert any("Main.java" in f for f in files)
        assert not any("Widget.java" in f for f in files)

    def test_r_java_is_generated_noise(self, java_tree):
        """
        Purpose:
            Pin that the generated resource identifier class is excluded from the source listing.

        Parameters:
            java_tree: The Java/Kotlin decompiled tree.

        Implementation notes:
            That file is generated, often enormous, and contains nothing a developer wrote, so reading it is a wasted step out of a tight budget.
        """
        tools = AgentTools(java_tree, profile=JAVA_KOTLIN)
        assert not any(f.endswith("R.java") for f in tools.app_source_files())

    def test_manifest_summary(self, java_tree):
        """
        Purpose:
            Pin that the manifest is what gets summarised, under the label naming it.

        Parameters:
            java_tree: The Java/Kotlin decompiled tree.
        """
        tools = AgentTools(java_tree, profile=JAVA_KOTLIN)
        assert "<manifest/>" in tools.manifest_summary()
        assert tools.profile.summary_label == "AndroidManifest.xml"

    def test_resource_files_include_strings_xml(self, java_tree):
        """
        Purpose:
            Pin that resource XML is listed as a resource.

        Parameters:
            java_tree: The Java/Kotlin decompiled tree.
        """
        tools = AgentTools(java_tree, profile=JAVA_KOTLIN)
        assert any("strings.xml" in f for f in tools.app_resource_files())

class TestFlutterProfile:
    """
    Purpose:
        The Flutter profile, where the source is disassembly and the manifest equivalent is the Dart object pool.
    """
    def test_asm_files_are_source(self, flutter_tree):
        """
        Purpose:
            Pin that disassembly files are listed as application source.

        Parameters:
            flutter_tree: The Flutter decompiled tree.
        """
        tools = AgentTools(flutter_tree, profile=FLUTTER)
        files = tools.app_source_files()
        assert any(f.endswith("MainActivity.asm") for f in files)

    def test_manifest_summary_is_object_pool(self, flutter_tree):
        """
        Purpose:
            Pin that the object pool stands in for the manifest, under a label naming it.

        Parameters:
            flutter_tree: The Flutter decompiled tree.

        Implementation notes:
            A Flutter binary has no readable manifest, and the object pool is where the strings a reviewer would look for, such as endpoints, actually live.
        """
        tools = AgentTools(flutter_tree, profile=FLUTTER)
        assert "api.example.com" in tools.manifest_summary()
        assert tools.profile.summary_label == "Dart object pool (pp.txt)"

    def test_resource_files_lists_pp_txt(self, flutter_tree):
        """
        Purpose:
            Pin that the object pool is also reachable through the resource listing.

        Parameters:
            flutter_tree: The Flutter decompiled tree.
        """
        tools = AgentTools(flutter_tree, profile=FLUTTER)
        assert any("pp.txt" in f for f in tools.app_resource_files())

    def test_missing_pp_txt_reports_missing(self, tmp_path):
        """
        Purpose:
            Pin that a tree with no object pool yields a summary saying so rather than raising.

        Parameters:
            tmp_path: Temporary directory holding a tree with disassembly but no object pool.

        Implementation notes:
            The pool is absent whenever the disassembler ran partially, and the agent has to be told that in words rather than meeting an exception mid-turn.
        """
        (tmp_path / "asm").mkdir()
        tools = AgentTools(tmp_path, profile=FLUTTER)
        assert "not found" in tools.manifest_summary() or "not " in tools.manifest_summary()

class TestReactNativeProfile:
    """
    Purpose:
        The React Native profile, where the source is JavaScript and the manifest equivalent is the bundle metadata.
    """
    def test_node_modules_is_noise(self, rn_tree):
        """
        Purpose:
            Pin that the application bundle file is listed and vendor modules are not.

        Parameters:
            rn_tree: The React Native tree.
        """
        tools = AgentTools(rn_tree, profile=REACT_NATIVE)
        files = tools.app_source_files()
        assert any(f.endswith("app.js") for f in files)
        assert not any("node_modules" in f for f in files)

    def test_manifest_summary_is_bundle_metadata(self, rn_tree):
        """
        Purpose:
            Pin that the bundle metadata stands in for the manifest, under a label naming it.

        Parameters:
            rn_tree: The React Native tree.
        """
        tools = AgentTools(rn_tree, profile=REACT_NATIVE)
        assert "javascript" in tools.manifest_summary()
        assert tools.profile.summary_label == "Bundle metadata"

    def test_search_code_respects_extensions(self, rn_tree):
        """
        Purpose:
            Pin that a code search only reads the extensions the profile counts as source.

        Parameters:
            rn_tree: The React Native tree, with a Python file added that must not be searched.

        Implementation notes:
            A decompiled tree can hold leftovers from the tooling that produced it, and searching them returns matches in files that are not part of the application at all.
        """
        (rn_tree / "notes.py").write_text("password = 'x'\n")
        tools = AgentTools(rn_tree, profile=REACT_NATIVE)
        out = tools.search_code("password")
        assert "notes.py" not in out

@pytest.fixture
def cordova_tree(tmp_path):
    """
    Purpose:
        Build a Cordova tree holding the application's web assets, its configuration and the Cordova runtime script.

    Parameters:
        tmp_path: Temporary directory the tree is written into.

    Returns:
        The tree root.
    """
    (tmp_path / "js").mkdir()
    (tmp_path / "config.xml").write_text('<widget id="com.app"/>')
    (tmp_path / "index.html").write_text("<html></html>")
    (tmp_path / "js" / "index.js").write_text("var x = 1;")
    (tmp_path / "cordova.js").write_text("// runtime")
    return tmp_path

class TestCordovaProfile:
    """
    Purpose:
        The Cordova profile, where the source is the web assets and the manifest equivalent is the configuration document.
    """
    def test_cordova_runtime_is_noise(self, cordova_tree):
        """
        Purpose:
            Pin that the application script is listed and the Cordova runtime script is not.

        Parameters:
            cordova_tree: The Cordova tree.
        """
        tools = AgentTools(cordova_tree, profile=CORDOVA)
        files = tools.app_source_files()
        assert any(f.endswith("index.js") for f in files)
        assert not any(f.endswith("cordova.js") for f in files)

    def test_html_counts_as_source(self, cordova_tree):
        """
        Purpose:
            Pin that markup is listed as application source.

        Parameters:
            cordova_tree: The Cordova tree.

        Implementation notes:
            A Cordova app's inline handlers and script tags live in the markup, so excluding it would hide a whole class of injection sink from the agent.
        """
        tools = AgentTools(cordova_tree, profile=CORDOVA)
        assert any(f.endswith("index.html") for f in tools.app_source_files())

    def test_manifest_summary_is_config_xml(self, cordova_tree):
        """
        Purpose:
            Pin that the configuration document stands in for the manifest, under a label naming it.

        Parameters:
            cordova_tree: The Cordova tree.
        """
        tools = AgentTools(cordova_tree, profile=CORDOVA)
        assert "widget" in tools.manifest_summary()
        assert tools.profile.summary_label == "Cordova config.xml"

class TestCrossProfileSandbox:
    """
    Purpose:
        The behaviour that must hold identically under every profile.
    """
    @pytest.mark.parametrize("profile", [JAVA_KOTLIN, FLUTTER, REACT_NATIVE, CORDOVA])
    def test_traversal_still_blocked(self, tmp_path, profile):
        """
        Purpose:
            Pin that a traversal out of the source root is refused under every profile.

        Parameters:
            tmp_path: The sandbox root.
            profile: The profile under test.

        Security considerations:
            The read tool's path comes from the model, so this is the control that keeps a prompt-driven read inside the decompiled tree. It is asserted per profile because the profiles change which files are listed, and a profile-specific resolution path could otherwise escape while the default stayed closed.
        """
        tools = AgentTools(tmp_path, profile=profile)
        assert tools.read_file("../../etc/passwd").startswith("ERROR")
