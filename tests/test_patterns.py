#!/usr/bin/env python3
"""
Module: test_patterns

Purpose:
    The shared credential and endpoint patterns, and that all four graph builders use the same ones.

Responsibilities:
    Pin classification, the public-identifier flag, the extraction helpers, and the single-source-of-truth wiring.

Dependencies:
    pytest, and the shared pattern table with its helpers.

Security considerations:
    The Google key is assembled at runtime rather than written as one literal, so the source carries nothing a secret scanner reports as a leaked credential while the value still matches the pattern under test.
"""

import pytest

from lu77U_MobileSec.analyzers.agent.patterns import (
    SECRET_PATTERNS, SECRET_RE, STRING_LITERAL_RE, classify_secret,
    collect_node_strings, find_endpoints, find_secrets,
)

GOOGLE_API_KEY = "AIza" + "A" * 35


class TestTypedClassification:
    """
    Purpose:
        That a value is classified as the right kind of credential, at the right severity.
    """
    @pytest.mark.parametrize("value,expected,severity", [
        ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID", "Critical"),
        (GOOGLE_API_KEY, "Google API Key", "High"),
        ("sk_live_abcdefghij1234567890", "Stripe Secret Key", "Critical"),
        ("pk_test_abcdefghij1234567890", "Stripe Publishable Key", "Medium"),
        ("https://my-app-123.firebaseio.com", "Firebase Database URL", "Informational"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "GitHub Token", "High"),
        ("ghu_abcdefghijklmnopqrstuvwxyz0123456789", "GitHub Token", "High"),
        ("ghr_abcdefghijklmnopqrstuvwxyz0123456789", "GitHub Token", "High"),
        ("github_pat_" + "a" * 22 + "_" + "b" * 59, "GitHub Fine-Grained Token", "High"),
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", "Critical"),
        ("eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "JWT", "High"),
        ("xoxb-1234567890-abcdefghijkl", "Slack Token", "High"),
        ("192.168.1.50", "Private Network Address", "Low"),
    ])
    def test_known_credential_shapes(self, value, expected, severity):
        """
        Purpose:
            Pin each recognised credential shape to its name and severity.

        Parameters:
            value: The candidate value.
            expected: The pattern name it must match.
            severity: The severity that pattern carries.
        """
        hit = classify_secret(value)
        assert hit is not None and hit.name == expected
        assert hit.severity == severity

    def test_unknown_value_is_unclassified(self):
        """
        Purpose:
            Pin that ordinary text and an empty string classify as nothing.
        """
        assert classify_secret("just some ordinary label text") is None
        assert classify_secret("") is None

    def test_specific_patterns_win_over_generic(self):
        """
        Purpose:
            Pin that a provider-specific key is not claimed by the generic key pattern.

        Implementation notes:
            Ordering decides this, because the first match wins. A generic match would carry the wrong severity and lose the public flag, which is exactly the misclassification the next tests exist to prevent.
        """
        assert classify_secret(GOOGLE_API_KEY).name == "Google API Key"

    @pytest.mark.parametrize("value,name", [
        ("https://my-app-123.firebaseio.com", "Firebase Database URL"),
        ("1:123456789012:android:abcdef0123456789", "Firebase App ID"),
        ("123456789-abcdefghij.apps.googleusercontent.com", "Google OAuth Client ID"),
    ])
    def test_public_identifiers_are_flagged_as_public(self, value, name):
        """
        Purpose:
            Pin that identifiers designed to ship in an app are marked public and scored informational.

        Parameters:
            value: The candidate value.
            name: The pattern name it must match.

        Implementation notes:
            Scoring these as hardcoded credentials put them beside real embedded passwords at the same standards identifier and severity, which inflated the middling count and taught readers to skim the whole hardcoded category. That is how a genuine one gets missed.
        """
        hit = classify_secret(value)
        assert hit is not None and hit.name == name
        assert hit.public is True
        assert hit.severity == "Informational"

    @pytest.mark.parametrize("value,name", [
        ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID"),
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
        ("sk_live_abcdefghij1234567890", "Stripe Secret Key"),
    ])
    def test_real_secrets_are_not_marked_public(self, value, name):
        """
        Purpose:
            Pin that genuine credentials are not marked public.

        Parameters:
            value: The candidate value.
            name: The pattern name it must match.

        Implementation notes:
            The inverse of the previous test, and the more dangerous direction: a real key wrongly marked public would be demoted to informational and effectively hidden.
        """
        hit = classify_secret(value)
        assert hit is not None and hit.name == name
        assert hit.public is False

    def test_severities_are_this_projects_scale(self):
        """
        Purpose:
            Pin that every pattern's severity is one this project's scale recognises.

        Implementation notes:
            A severity outside the scale would normalise to a default downstream, silently re-grading that pattern's findings.
        """
        allowed = {"Critical", "High", "Medium", "Low", "Informational"}
        assert {p.severity for p in SECRET_PATTERNS} <= allowed


class TestFindSecrets:
    """
    Purpose:
        Extracting credential matches from text.
    """
    def test_reports_name_severity_and_line(self):
        """
        Purpose:
            Pin that a match reports its kind, severity and line number.
        """
        text = 'x = 1\nkey = "AKIAIOSFODNN7EXAMPLE"\n'
        found = find_secrets(text)
        assert found[0]["name"] == "AWS Access Key ID"
        assert found[0]["severity"] == "Critical"
        assert found[0]["line"] == 2

    def test_value_is_truncated(self):
        """
        Purpose:
            Pin that a matched value is bounded.

        Implementation notes:
            An unbounded value would put a full credential into the finding and then into the report, which is the opposite of what the report should carry.
        """
        text = 'Bearer ' + "a" * 500
        assert all(len(f["value"]) <= 103 for f in find_secrets(text))

    def test_deduplicates(self):
        """
        Purpose:
            Pin that the same credential appearing twice is reported once.

        Implementation notes:
            Decompiled output repeats a constant many times, and one finding per occurrence would bury everything else.
        """
        text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE"
        assert len([f for f in find_secrets(text) if f["name"] == "AWS Access Key ID"]) == 1

    def test_empty_input(self):
        """
        Purpose:
            Pin that empty text yields no matches.
        """
        assert find_secrets("") == []


class TestFindEndpoints:
    """
    Purpose:
        Extracting endpoints and the properties that make one interesting.
    """
    def test_flags_cleartext_and_sensitive_path(self):
        """
        Purpose:
            Pin that an unencrypted endpoint on an authentication path is flagged on both counts, and a static asset over TLS on neither.

        Implementation notes:
            Both properties are asserted together because either alone is weak: cleartext to a static asset is uninteresting, and an authentication path over TLS is normal.
        """
        found = {e["url"]: e for e in find_endpoints(
            'a="http://api.example.com/api/v1/login" b="https://cdn.example.com/logo.png"')}
        assert found["http://api.example.com/api/v1/login"]["cleartext"] is True
        assert found["http://api.example.com/api/v1/login"]["sensitive_path"] is True
        assert found["https://cdn.example.com/logo.png"]["cleartext"] is False
        assert found["https://cdn.example.com/logo.png"]["sensitive_path"] is False

    def test_empty_input(self):
        """
        Purpose:
            Pin that empty text yields no endpoints.
        """
        assert find_endpoints("") == []


class TestNodeStringCollection:
    """
    Purpose:
        Selecting the string literals worth putting on a graph node.
    """
    def test_keeps_only_secret_looking_literals_and_caps(self):
        """
        Purpose:
            Pin that a credential-shaped literal is kept and an ordinary label is dropped.

        Implementation notes:
            The node summary is prompt context, so an unfiltered list of every literal in a class would be enormous and tell the agent nothing.
        """
        content = 'String a = "plain label";\nString b = "https://api.example.com/token";\n'
        strings = collect_node_strings(content)
        assert "https://api.example.com/token" in strings
        assert "plain label" not in strings

    def test_respects_limit(self):
        """
        Purpose:
            Pin that the collected strings honour the requested cap.
        """
        content = "\n".join(f'x = "https://h{i}.example.com/token"' for i in range(20))
        assert len(collect_node_strings(content, limit=3)) == 3


class TestGraphsShareThePatterns:
    """
    Purpose:
        That the four graph builders share one pattern table.

    Implementation notes:
        Each builder used to carry a verbatim copy, so what counted as a secret drifted between frameworks and a pattern fixed in one stayed broken in the others.
    """
    def test_all_four_graphs_import_the_shared_objects(self):
        """
        Purpose:
            Pin that every graph builder references the shared objects themselves, not a copy.

        Implementation notes:
            Identity is asserted rather than equality, because an equal-but-separate copy is exactly the drift this is guarding against.
        """
        from lu77U_MobileSec.analyzers.agent import code_graph
        from lu77U_MobileSec.analyzers.cordova import graph as cordova_graph
        from lu77U_MobileSec.analyzers.flutter import graph as flutter_graph
        from lu77U_MobileSec.analyzers.react_native import graph as rn_graph

        for mod in (code_graph, cordova_graph, flutter_graph, rn_graph):
            assert mod._SECRET_RE is SECRET_RE
        for mod in (cordova_graph, flutter_graph, rn_graph):
            assert mod._STRING_LITERAL_RE is STRING_LITERAL_RE
