#!/usr/bin/env python3
"""
Module: test_metadata_parity

Purpose:
    That a finding carries the same metadata whichever engine produced it.

Responsibilities:
    Pin the rule engine's default vector, the schema's class requirement, the catalogue fill, and the validator's scoring.

Dependencies:
    pytest, the shared schema, the rule finding type, the CVSS helpers and the validation package.

Implementation notes:
    The two engines used to populate mutually exclusive metadata: on a real scan every agent finding had a vector and a score and none had a CWE, while the rule findings had a CWE and no vector. Any consumer filtering by CWE silently lost the whole agent half, and anything sorting by score lost the whole deterministic half.
"""

import pytest

from lu77U_MobileSec.ai.schema import VULNERABILITY_SCHEMA
from lu77U_MobileSec.analyzers.sast.findings import (
    SastFinding, default_cvss_vector, to_scan_finding)
from lu77U_MobileSec.utils.cvss import severity_from_vector
from lu77U_MobileSec.validation import validate_findings


class TestSastDefaultVector:
    """
    Purpose:
        The stand-in CVSS vector given to a rule finding that states no vector of its own.
    """
    @pytest.mark.parametrize("severity", [
        "Critical", "High", "Medium", "Low", "Informational"])
    def test_the_default_vector_round_trips_to_its_own_severity(self, severity):
        """
        Purpose:
            Pin that the stand-in vector scores back to the severity it stands in for.

        Parameters:
            severity: The severity the default vector is requested for.

        Implementation notes:
            The vector must never contradict the severity it represents. A rule's own severity is authoritative; this only fills the vector and score fields to match it, and a mismatch would let the report show a vector that disagrees with the severity printed beside it.
        """
        vector = default_cvss_vector(severity)
        computed_severity, score = severity_from_vector(vector)
        assert computed_severity == severity
        assert score is not None

    def test_a_rule_with_its_own_vector_keeps_it(self):
        """
        Purpose:
            Pin that a rule stating its own vector is not overwritten by the default.
        """
        finding = to_scan_finding(SastFinding(
            title="x", severity="High", description="x" * 50,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        assert finding["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_a_rule_with_no_vector_gets_the_severity_default(self):
        """
        Purpose:
            Pin that a rule stating no vector receives the default for its severity.
        """
        finding = to_scan_finding(SastFinding(
            title="x", severity="Low", description="x" * 50))
        assert finding["cvss_vector"] == default_cvss_vector("Low")

    def test_every_severity_produces_a_non_empty_vector(self):
        """
        Purpose:
            Pin that no severity leaves a finding without a vector.
        """
        for severity in ("Critical", "High", "Medium", "Low", "Informational"):
            finding = to_scan_finding(SastFinding(
                title="x", severity=severity, description="x" * 50))
            assert finding["cvss_vector"]


class TestAgentSchemaRequiresMetadata:
    """
    Purpose:
        What the response schema demands of the model, and what it deliberately does not.

    Implementation notes:
        The standards identifiers were once required of the model directly, and the numbers behind this module show why that never worked: none of the agent findings on a real scan carried a real one, so each either failed validation or shipped a guess. A single catalogue code is required instead, because the catalogue already carries the correct pair for every class, authored once.
    """
    def test_vuln_class_is_required_instead(self):
        """
        Purpose:
            Pin that the class code is required and the standards identifiers are not.
        """
        required = VULNERABILITY_SCHEMA["items"]["required"]
        assert "vuln_class" in required
        assert "cwe" not in required
        assert "owasp_mobile" not in required

    def test_the_previously_required_fields_are_still_required(self):
        """
        Purpose:
            Pin that relaxing the standards fields did not relax anything else.
        """
        required = VULNERABILITY_SCHEMA["items"]["required"]
        for field in ("title", "cvss_vector", "file", "line", "description",
                     "recommendation"):
            assert field in required


class TestVulnClassFillsMetadata:
    """
    Purpose:
        That a class code fills the standards identifiers without the model writing either.
    """
    def test_an_agent_finding_gets_cwe_and_owasp_from_its_class(self):
        """
        Purpose:
            Pin that a finding naming its class comes out with the catalogue's identifiers attached.
        """
        from lu77U_MobileSec.utils.response_parser import ResponseParser

        out = ResponseParser().normalize_vulnerability({
            "title": "SQLi", "file": "a.java", "line": "1", "description": "x",
            "vuln_class": "CODE-01"})
        assert out["cwe"] == "CWE-89"
        assert out["owasp_mobile"].startswith("M4")

    def test_a_findings_own_cwe_is_never_overwritten(self):
        """
        Purpose:
            Pin that identifiers the finding already carries survive the fill.

        Implementation notes:
            A model that classified precisely should not be overridden by a lookup, which is coarser than the judgement it already made.
        """
        from lu77U_MobileSec.utils.response_parser import ResponseParser

        out = ResponseParser().normalize_vulnerability({
            "title": "x", "file": "a.java", "line": "1", "description": "x",
            "vuln_class": "CODE-01", "cwe": "CWE-999", "owasp_mobile": "M0"})
        assert out["cwe"] == "CWE-999"
        assert out["owasp_mobile"] == "M0"

    def test_an_unknown_class_leaves_metadata_absent_not_fabricated(self):
        """
        Purpose:
            Pin that an unrecognised class leaves the identifiers empty rather than inventing them.

        Implementation notes:
            A fabricated standards identifier is worse than none, because a reader uses it to look the issue up and would be sent to the wrong entry.
        """
        from lu77U_MobileSec.utils.response_parser import ResponseParser

        out = ResponseParser().normalize_vulnerability({
            "title": "x", "file": "a.java", "line": "1", "description": "x",
            "vuln_class": "NOT-A-REAL-CODE"})
        assert not out.get("cwe")
        assert not out.get("owasp_mobile")


class TestValidatorScoresSastVectors:
    """
    Purpose:
        That the validator scores vectors without contradicting a score already present.
    """
    def _sast_finding(self, **overrides):
        """
        Purpose:
            Build a rule-shaped finding, with fields overridable per test.

        Parameters:
            overrides: Fields to replace on the base finding.

        Returns:
            The finding.
        """
        base = {
            "title": "Cleartext traffic permitted", "severity": "High",
            "source": "static-analyzer",
            "cvss_vector": default_cvss_vector("High"),
            "file": "AndroidManifest.xml",
            "description": "x" * 60, "cwe": "CWE-319",
        }
        base.update(overrides)
        return base

    def test_a_vector_with_no_score_gets_one(self):
        """
        Purpose:
            Pin that a finding carrying a vector but no score is scored.
        """
        out = validate_findings([self._sast_finding()])
        assert out[0]["cvss_score"] is not None
        assert out[0]["cvss_score"] > 0

    def test_an_existing_score_is_never_overwritten(self):
        """
        Purpose:
            Pin that a score already computed is left alone.

        Implementation notes:
            The agent's own vector was already scored during normalisation, so re-deriving here from a synthetic default would contradict a number the report has already shown.
        """
        out = validate_findings([self._sast_finding(
            cvss_score=1.2, cvss_vector=default_cvss_vector("Critical"))])
        assert out[0]["cvss_score"] == 1.2

    def test_a_finding_with_no_vector_at_all_is_untouched(self):
        """
        Purpose:
            Pin that a finding with no vector gains no score.

        Implementation notes:
            Inventing a score for an unscored finding would present a guess as a measurement.
        """
        finding = {"title": "App requests 5 dangerous permissions",
                  "severity": "Informational", "description": "x" * 60}
        out = validate_findings([finding])
        assert "cvss_score" not in out[0] or out[0]["cvss_score"] is None

    def test_every_graded_finding_has_cwe_and_cvss_vector_regardless_of_source(self):
        """
        Purpose:
            Pin the parity directly: mixing an agent-shaped and a rule-shaped finding leaves neither missing either field.

        Implementation notes:
            This is the regression guard for the original defect. The two engines are asserted together rather than separately, because the failure was precisely that each was individually fine and the union was unusable.
        """
        agent_like = {
            "title": "Hardcoded RSA test key", "severity": "Critical",
            "source": "agent", "description": "x" * 60,
            "cvss_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-798", "owasp_mobile": "M10",
        }
        sast_like = to_scan_finding(SastFinding(
            title="Cleartext HTTP permitted", severity="High",
            description="x" * 60, cwe="CWE-319",
            owasp_mobile="M5: Insufficient Cryptography"))
        out = validate_findings([agent_like, sast_like])
        for f in out:
            assert f.get("cwe"), f
            assert f.get("cvss_vector"), f
