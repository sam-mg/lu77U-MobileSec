#!/usr/bin/env python3
"""
Module: test_skills

Purpose:
    The bundled agent skills: that they resolve, that something actually loads each one, and that they are this project's own writing.

Responsibilities:
    Pin skill resolution, the wiring from surfaces and contextual rules, the absence of borrowed material, and the content rules.

Dependencies:
    pytest, the skills loader, the attack surfaces and the agent loop's contextual rules.

Implementation notes:
    A skill no code path loads is dead weight the model never sees, and a skill referenced by a name that does not resolve fails silently, because the loader filters unresolvable names rather than raising. A typo therefore costs an agent its guidance with no error anywhere, which is why the wiring is asserted rather than assumed. The borrowed-material markers are deliberately shapes rather than a list of project names, for two reasons: a name list only catches the upstreams someone already thought of, and naming a project here would put that name in this repository, which is the thing being asserted against. They are limited to wording with no ordinary use in technical prose. Two candidates were tried and removed because they describe severity, regular expressions and screenshot handling throughout this codebase, and a check that cries wolf gets deleted rather than fixed. The vendored list names the directories inside the package that hold third-party code, which of course carries its own licences and is not what the borrowed-material checks are about.
"""

import re
from pathlib import Path

import pytest

from lu77U_MobileSec.analyzers.agent.agent_loop import _contextual_skills
from lu77U_MobileSec.analyzers.agent.skills_loader import (
    CORE_SKILLS, SKILLS_DIR, available_skills, load_skills, skill_path)
from lu77U_MobileSec.analyzers.agent.surfaces import ANDROID_SURFACES

OWN = ("vulnerability_classes", "finding_quality", "chain_building",
       "sdk_analysis", "android_analysis", "reading_obfuscated_code",
       "manifest_review", "network_security", "offensive_android",
       "java_kotlin_security", "flutter_dart_security", "react_native_security",
       "cordova_hybrid_security", "xamarin_dotnet_security",
       "native_library_analysis", "packed_app_triage", "frida_hook_recipes",
       "objection_runtime_toolkit", "evidence_discipline",
       "authorized_dynamic_testing", "false_positive_patterns",
       "taint_source_to_sink")


class TestSkillsResolve:
    """
    Purpose:
        That every bundled skill resolves and is reachable from the code that loads them.
    """
    @pytest.mark.parametrize("name", sorted(OWN))
    def test_every_skill_is_loadable(self, name):
        """
        Purpose:
            Pin that each bundled skill resolves to a file with real content in it.

        Parameters:
            name: The skill being checked.
        """
        assert skill_path(name) is not None
        assert len(load_skills([name])) > 500

    def test_every_surface_names_only_real_skills(self):
        """
        Purpose:
            Pin that every skill an attack surface names actually exists.

        Implementation notes:
            The loader drops names it cannot resolve without raising, so a typo here silently costs that surface's agent its guidance and nothing reports it.
        """
        names = available_skills()
        for surface in ANDROID_SURFACES:
            missing = [s for s in surface.skills if s not in names]
            assert not missing, f"{surface.key} references missing skill(s): {missing}"

    def test_every_core_skill_exists(self):
        """
        Purpose:
            Pin that the core skill named for each framework profile resolves.

        Implementation notes:
            The core skill carries the output contract, so a profile pointing at a missing one would leave that framework's agents with no instructions about what to return.
        """
        for profile_key, name in CORE_SKILLS.items():
            assert skill_path(name) is not None, f"{profile_key} -> {name}"

    def test_contextual_rules_only_name_real_skills(self):
        """
        Purpose:
            Pin that the skills added mid-investigation all resolve, across a spread of probe actions.
        """
        names = set(available_skills())
        probes = [
            ("read_file", "AndroidManifest.xml", ""),
            ("search_code", "", "addJavascriptInterface"),
            ("search_code", "", "getIntent deeplink scheme"),
            ("read_file", "BuildConfig.java", "firebase sdk"),
            ("inspect_native", "lib/arm64-v8a/libfoo.so", ""),
            ("search_code", "", "TrustManager ssl cert"),
            ("read_file", "assets/www/index.html", "cordova"),
            ("read_file", "bundle.js", "hermes react-native"),
            ("read_file", "pubspec", "dart methodchannel"),
            ("search_code", "", "objection sslpinning keystore sqlite"),
            ("read_file", "", "am start content:// osv advisory"),
            ("search_code", "", "objection frida sslpinning repackage"),
            ("search_code", "", "exported md5 getInstance allowBackup"),
            ("search_code", "", "getIntent getStringExtra rawQuery loadUrl"),
        ]
        for action, path, pattern in probes:
            for name in _contextual_skills(action, path, pattern):
                assert name in names, f"{action}/{path}/{pattern} -> missing {name}"

    def test_contextual_rules_fire_for_the_kreditbee_shape(self):
        """
        Purpose:
            Pin that searching for the bridge annotation pulls in the class catalogue and the chain guidance.

        Implementation notes:
            The bridge class that was originally missed is found by exactly this search, so it has to bring the guidance the agent needs to classify and chain what it finds.
        """
        loaded = _contextual_skills("search_code", "", "addJavascriptInterface")
        assert "vulnerability_classes" in loaded
        assert "chain_building" in loaded

    def test_contextual_rules_fire_for_runtime_toolkit_signals(self):
        """
        Purpose:
            Pin that runtime-exploration signals pull in the objection toolkit guidance.

        Implementation notes:
            The commands this skill translates are named by their objection or storage terms rather than by a class the scanners see, so each of those terms has to reach the skill on its own or the guidance never loads for the dynamic phase.
        """
        for probe in ("sslpinning disable", "android keystore",
                      "sqlite dump", "objection explore"):
            loaded = _contextual_skills("search_code", "", probe)
            assert "objection_runtime_toolkit" in loaded, probe

    def test_contextual_rules_fire_for_proof_and_dependency_signals(self):
        """
        Purpose:
            Pin that proof, probe, and dependency-state signals pull in the evidence discipline guidance.

        Implementation notes:
            This skill governs what an observation is allowed to claim, so it has to reach the agent exactly when it is about to run a component, probe a host, or read a dependency advisory rather than when it is reading static code, which is why the runtime and advisory terms trigger it directly and inspecting a native library does too.
        """
        for probe in ("am start component", "content:// provider query",
                      "osv advisory for dependency", "reachability of the sink"):
            loaded = _contextual_skills("read_file", "", probe)
            assert "evidence_discipline" in loaded, probe
        assert "evidence_discipline" in _contextual_skills("inspect_native", "lib/x/y.so", "")

    def test_contextual_rules_fire_for_instrumentation_signals(self):
        """
        Purpose:
            Pin that live-instrumentation and scope signals pull in the authorized dynamic testing guidance.

        Implementation notes:
            This skill governs what the agent is allowed to do to a running app, so it has to reach the agent exactly when a step would install, hook, intercept, repackage, or reach out of the APK rather than while it reads static code, which is why the instrumentation and scope terms trigger it directly and inspecting a native library does too.
        """
        for probe in ("objection explore", "frida hook", "sslpinning bypass",
                      "repackage with apktool", "target is out of scope"):
            loaded = _contextual_skills("search_code", "", probe)
            assert "authorized_dynamic_testing" in loaded, probe
        assert "authorized_dynamic_testing" in _contextual_skills("inspect_native", "lib/x/y.so", "")

    def test_contextual_rules_fire_for_decoy_signals(self):
        """
        Purpose:
            Pin that shapes known to produce false positives pull in the false-positive pattern guidance.

        Implementation notes:
            This skill resolves a matched candidate before it becomes a finding, so it has to reach the agent exactly when it looks at one of the decoy shapes -- an exported component, a weak-digest call, a bundled client identifier, a backup flag -- rather than only at report time, because the resolution changes what the agent reads next.
        """
        for probe in ("exported component", "MessageDigest md5",
                      "addJavascriptInterface bridge", "allowBackup manifest flag",
                      "google client_id"):
            loaded = _contextual_skills("search_code", "", probe)
            assert "false_positive_patterns" in loaded, probe

    def test_contextual_rules_fire_for_dataflow_signals(self):
        """
        Purpose:
            Pin that source and sink APIs pull in the source-to-sink tracing guidance.

        Implementation notes:
            This skill supplies the method for walking a path from an attacker-controlled source to a dangerous sink, so it has to reach the agent the moment it reads either end of that path -- an Intent getter feeding a value, or a query/load/exec sink receiving one -- because the path is what turns a matched sink into a finding rather than a lead.
        """
        for probe in ("getIntent getStringExtra", "rawQuery selection",
                      "WebView loadUrl", "Runtime.exec command",
                      "startActivity redirect"):
            loaded = _contextual_skills("search_code", "", probe)
            assert "taint_source_to_sink" in loaded, probe


_BORROWED_MARKERS = (
    "adapted from", "ported from", "originally from",
    "copyright (c)", "copyright ©", "all rights reserved",
    "licensed under", "spdx-license-identifier", "license header",
    "mit license", "apache license", "bsd license", "gnu general public",
    "see notice", "see the notice file",
)

_VENDORED = ("node_modules", "static", "dist")


def _package_sources():
    """
    Purpose:
        Yield every source and documentation file this project wrote and ships.

    Returns:
        Pairs of path and text, skipping the vendored directories.
    """
    root = Path(__file__).resolve().parents[1] / "lu77U_MobileSec"
    for path in root.rglob("*"):
        if path.suffix not in (".py", ".md", ".yml", ".yaml"):
            continue
        if any(part in _VENDORED for part in path.parts):
            continue
        yield path, path.read_text(encoding="utf-8", errors="ignore")


class TestNothingIsBorrowed:
    """
    Purpose:
        That everything shipped here is this project's own writing.

    Implementation notes:
        The tool's guidance is the tool's product, so material lifted from elsewhere is both a licensing question and a quality one: a skill written for another system carries that system's assumptions, and the mismatch shows up as advice the agent cannot act on. These check the shape of an attribution rather than any particular source, so they hold for whatever someone is tempted to paste in next.
    """
    @pytest.mark.parametrize("name", sorted(OWN))
    def test_no_skill_carries_an_attribution(self, name):
        """
        Purpose:
            Pin that no bundled skill reads as borrowed material.

        Parameters:
            name: The skill being checked.
        """
        text = skill_path(name).read_text(encoding="utf-8").lower()
        found = [m for m in _BORROWED_MARKERS if m in text]
        assert not found, f"{name} reads as borrowed material: {found}"

    def test_no_shipped_source_carries_an_attribution(self):
        """
        Purpose:
            Pin that no shipped source file carries an attribution either.

        Implementation notes:
            Catches a licence header surviving a copy-paste anywhere in the package, not only in the skills.
        """
        offenders = {}
        root = Path(__file__).resolve().parents[1] / "lu77U_MobileSec"
        for path, text in _package_sources():
            found = [m for m in _BORROWED_MARKERS if m in text.lower()]
            if found:
                offenders[str(path.relative_to(root))] = found
        assert not offenders, f"reads as borrowed material: {offenders}"

    def test_no_skill_points_at_an_external_repository(self):
        """
        Purpose:
            Pin that no skill sends the agent off to read someone else's repository.

        Implementation notes:
            Guidance that delegates to an external repository is guidance this project has not actually written, and it would break the moment that repository changed.
        """
        for name in OWN:
            text = skill_path(name).read_text(encoding="utf-8").lower()
            assert "github.com" not in text, f"{name} links to an external repository"

    def test_no_notice_file_is_needed(self):
        """
        Purpose:
            Pin that no attribution notice exists, because nothing is adapted.

        Implementation notes:
            A notice left behind would claim a dependency the package does not have.
        """
        assert not (Path(__file__).resolve().parents[1] / "NOTICE").exists()


class TestSkillContent:
    """
    Purpose:
        Content rules the skills have to satisfy.
    """
    @pytest.mark.parametrize("name", sorted(OWN))
    def test_no_ios_material_is_present(self, name):
        """
        Purpose:
            Pin that no skill carries iOS material.

        Parameters:
            name: The skill being checked.

        Implementation notes:
            This tool is Android only, and iOS guidance sends the agent looking for platform features that do not exist in a DEX file, wasting steps out of a tight budget.
        """
        text = skill_path(name).read_text(encoding="utf-8")
        for term in ("IOS-0", "Keychain", "xcrun", "TestFlight", "mobileprovision"):
            assert term not in text, f"{name} still carries iOS material: {term}"

    def test_vuln_class_codes_in_the_catalogue_match_the_chain_table(self):
        """
        Purpose:
            Pin that every class code the chain table matches on is documented in the catalogue skill.

        Implementation notes:
            The chain builder matches on these codes, so a code used in one and absent from the other is a chain that can never fire and nothing would report it.
        """
        from lu77U_MobileSec.validation.chains import CHAIN_PATTERNS

        catalogue = set(re.findall(
            r"\b([A-Z]+-\d\d)\b",
            skill_path("vulnerability_classes").read_text(encoding="utf-8")))
        used = set()
        for pattern in CHAIN_PATTERNS:
            used |= set(pattern.entry_classes) | set(pattern.target_classes)
        assert used <= catalogue, f"chain table uses undocumented codes: {used - catalogue}"

    def test_existing_skills_carry_the_standalone_guidance(self):
        """
        Purpose:
            Pin that every class-listing skill states which of its classes are not vulnerabilities on their own.

        Implementation notes:
            Without that line the agent reports configuration observations at a serious severity, which is exactly the report padding the gates exist to prevent.
        """
        for name in ("java_kotlin_security", "manifest_review", "network_security",
                     "flutter_dart_security", "react_native_security",
                     "cordova_hybrid_security"):
            text = skill_path(name).read_text(encoding="utf-8")
            assert "Never on its own" in text, f"{name} lacks the guidance"

    def test_every_bundled_skill_is_reachable(self):
        """
        Purpose:
            Pin that every bundled skill is loaded by some path.

        Implementation notes:
            Reachability is gathered from the core skills, the surfaces, and the bare string literals in the agent loop, which is where both the contextual rules and the report turn name their skills. A skill nothing loads is a file the model never sees.
        """
        reachable = set(CORE_SKILLS.values())
        for surface in ANDROID_SURFACES:
            reachable |= set(surface.skills)
        source = (Path(__file__).resolve().parents[1] / "lu77U_MobileSec" /
                  "analyzers" / "agent" / "agent_loop.py").read_text()
        reachable |= set(re.findall(r'"([a-z_]+_[a-z_]+)"', source))
        orphans = set(available_skills()) - reachable
        assert not orphans, f"bundled but never loaded: {sorted(orphans)}"
