#!/usr/bin/env python3
"""
Module: test_ghera_benchmark

Purpose:
    The Ghera benchmark harness: its answer key, the rule that proposes a finding as a benchmark's planted issue, the review that settles it, and the totals the wiki and the demo quote.

Responsibilities:
    Pin that the key covers the 60 lean benchmarks with real class codes and working patterns, that a candidate needs both its class and its wording, that a review overrides the automatic match only with a reason, and that the run's bookkeeping resumes rather than requeues.

Dependencies:
    pytest, the taxonomy, and scripts/ghera_benchmark.py loaded as a module.

Implementation notes:
    Nothing here needs the Ghera checkout, a dashboard or a scan folder; the key is read from the repository and everything else is built in the test.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from lu77U_MobileSec.validation.taxonomy import ALL_CODES

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load():
    """
    Purpose:
        Load the benchmark script as a module.

    Returns:
        The module.
    """
    spec = importlib.util.spec_from_file_location("ghera_benchmark", REPO_ROOT / "scripts" / "ghera_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ghera_benchmark"] = module
    spec.loader.exec_module(module)
    return module


gb = _load()
KEY = json.loads(gb.KEY_PATH.read_text(encoding="utf-8"))


class TestAnswerKey:
    """
    Purpose:
        The key the scores are computed from.
    """

    def test_it_covers_the_sixty_lean_benchmarks(self):
        """
        Purpose:
            The same denominator as the published evaluations, spread over Ghera's eight categories as Ghera ships them.
        """
        benches = KEY["benchmarks"]
        assert len(benches) == 60
        counts = {c: sum(1 for k in benches if k.split("/")[0] == c) for c in gb.CATEGORIES}
        assert counts == {"Crypto": 5, "ICC": 17, "Networking": 8, "NonAPI": 2, "Permission": 2,
                          "Storage": 7, "System": 7, "Web": 12}
        assert all(k.endswith("-Lean") for k in benches)

    @pytest.mark.parametrize("bench", sorted(KEY["benchmarks"]))
    def test_each_entry_is_usable(self, bench):
        """
        Purpose:
            Every entry names its issue, files it under classes the taxonomy has, and has a pattern that compiles; every review gives a reason.

        Parameters:
            bench: The benchmark's Category/Name.
        """
        spec = KEY["benchmarks"][bench]
        assert spec["issue"].strip()
        assert spec["classes"] and set(spec["classes"]) <= set(ALL_CODES)
        assert set(spec.get("fields") or ["title"]) <= {"title", "description", "code_snippet", "file"}
        re.compile(spec["pattern"])
        for variant, review in (spec.get("review") or {}).items():
            assert variant in gb.VARIANTS
            assert isinstance(review["detected"], bool) and review["why"].strip()


SPEC = {"classes": ["CRYPTO-01"], "pattern": "ECB"}


def _result(*findings):
    """
    Purpose:
        Build a scan result holding findings under their severity buckets.

    Parameters:
        findings: (bucket, finding) pairs.

    Returns:
        A result.json-shaped mapping.
    """
    groups = {b: [] for b in gb.RANK}
    for bucket, finding in findings:
        groups[bucket].append(finding)
    return {"vulnerability_analysis": {"vulnerabilities": groups}}


class TestMatching:
    """
    Purpose:
        Proposing a finding as the planted issue.
    """

    @pytest.mark.parametrize("finding, expected", [
        ({"vuln_class": "CRYPTO-01", "title": "AES in ECB mode"}, True),
        ({"vuln_class": "CRYPTO-01", "title": "Weak cipher", "code_snippet": 'Cipher.getInstance("AES/ECB/PKCS5Padding")'}, True),
        ({"vuln_class": "CRYPTO-02", "title": "AES in ECB mode with a hardcoded key"}, False),
        ({"vuln_class": "CRYPTO-01", "title": "MD5 used for hashing"}, False),
        ({"vuln_class": "CHAIN-10", "title": "ECB-encrypted data is locally extractable"}, False),
        ({"vuln_class": "CRYPTO-01", "title": "Weak cipher", "duplicate_titles": ["AES/ECB used for tokens"]}, True),
    ])
    def test_class_and_wording_are_both_needed(self, finding, expected):
        """
        Purpose:
            A finding in the right class about something else, or about the issue under the wrong class, is not a candidate; neither is a chain. A title merged into the finding counts.

        Parameters:
            finding: The reported finding.
            expected: Whether it is a candidate.
        """
        assert gb.matches(SPEC, finding) is expected

    def test_an_entry_can_limit_the_fields_searched(self):
        """
        Purpose:
            Pin that a title-only entry ignores wording in the description, as for the network-config note every app gets.
        """
        spec = {"classes": ["NETWORK-03"], "pattern": "pin", "fields": ["title"]}
        note = {"vuln_class": "NETWORK-03", "title": "No network security config declared",
                "description": "The app relies on platform defaults and pins no domain."}
        assert gb.matches(spec, note) is False
        assert gb.matches(spec, dict(note, title="No certificate pinning for the API host")) is True

    def test_severity_decides_the_low_or_above_score(self):
        """
        Purpose:
            A planted issue reported only as Informational counts at any severity but not at Low or above, and every finding is counted.
        """
        info_only = gb.score_scan(SPEC, _result(("info", {"vuln_class": "CRYPTO-01", "title": "ECB"}),
                                                ("info", {"vuln_class": "BUILD-01", "title": "Debuggable"})))
        assert (info_only["auto"], info_only["auto_low"], info_only["findings"], info_only["non_info"]) == (True, False, 2, 0)
        low = gb.score_scan(SPEC, _result(("low", {"vuln_class": "CRYPTO-01", "title": "ECB"})))
        assert (low["auto"], low["auto_low"], low["hits"][0]["severity"]) == (True, True, "low")
        missed = gb.score_scan(SPEC, _result(("high", {"vuln_class": "PLATFORM-01", "title": "Exported"})))
        assert (missed["auto"], missed["auto_low"], missed["hits"]) == (False, False, [])


class TestReview:
    """
    Purpose:
        The human verdict over the automatic match.
    """

    def test_no_review_keeps_the_automatic_answer(self):
        """
        Purpose:
            An unreviewed benchmark is scored by the match alone.
        """
        out = gb.apply_review({"auto": True, "auto_low": False}, None)
        assert (out["detected"], out["detected_low"], "review" in out) == (True, False, False)

    def test_a_review_overrides_in_either_direction_with_its_reason(self):
        """
        Purpose:
            A wrongly matched finding can be ruled out and a missed one ruled in, and the reason is carried into the results.
        """
        ruled_out = gb.apply_review({"auto": True, "auto_low": True}, {"detected": False, "why": "about the key, not the mode"})
        assert (ruled_out["detected"], ruled_out["detected_low"], ruled_out["review"]) == (False, False, "about the key, not the mode")
        ruled_in = gb.apply_review({"auto": False, "auto_low": False}, {"detected": True, "low": True, "why": "filed as CODE-02"})
        assert (ruled_in["detected"], ruled_in["detected_low"]) == (True, True)

    def test_a_review_without_a_reason_is_refused(self):
        """
        Purpose:
            An unexplained override is indistinguishable from moving the number.
        """
        with pytest.raises(ValueError):
            gb.apply_review({"auto": False, "auto_low": False}, {"detected": True, "why": " "})


class TestBookkeeping:
    """
    Purpose:
        Listing benchmarks and resuming a run.
    """

    def test_only_lean_benchmarks_are_listed_with_their_apks(self, tmp_path):
        """
        Purpose:
            The fat benchmark and stray folders are left out, and a benchmark with no Secure app has no Secure APK.

        Parameters:
            tmp_path: pytest fixture.
        """
        for name, variants in (("Crypto/A-Lean", ("Benign", "Secure")), ("ICC/B-Lean", ("Benign",)),
                               ("ICC/Mms-Fat", ("Benign",)), ("Docs/C-Lean", ("Benign",))):
            for variant in variants:
                folder = tmp_path / name / variant
                folder.mkdir(parents=True)
                (folder / f"{name.split('/')[1]}-{variant.lower()}.apk").write_bytes(b"")
        benches = gb.lean_benchmarks(tmp_path)
        assert [k for k, _ in benches] == ["Crypto/A-Lean", "ICC/B-Lean"]
        assert gb.apk_for(benches[1][1], "Secure") is None
        assert gb.apk_for(benches[1][1], "Benign").name == "B-Lean-benign.apk"

    def test_a_resumed_run_adopts_scans_in_flight_and_skips_finished_ones(self):
        """
        Purpose:
            A stopped run picks up where it left off rather than queueing a second scan of an app.
        """
        benches = [("X/A-Lean", Path("a")), ("X/B-Lean", Path("b")), ("X/C-Lean", Path("c")), ("X/D-Lean", Path("d"))]
        state = {"X/A-Lean": {"id": "1", "status": "completed"}, "X/B-Lean": {"id": "2"},
                 "X/C-Lean": {"status": "no-apk"}}
        assert gb.in_flight(state) == ["X/B-Lean"]
        assert [k for k, _ in gb.pending_jobs(benches, state)] == ["X/D-Lean"]

    def test_totals_are_split_by_category(self):
        """
        Purpose:
            The overall and per-category counts the wiki table quotes.
        """
        rows = {
            "Crypto/A-Lean": {"detected": True, "detected_low": True, "findings": 5, "non_info": 2},
            "Crypto/B-Lean": {"detected": True, "detected_low": False, "findings": 4, "non_info": 1},
            "Web/C-Lean": {"detected": False, "detected_low": False, "findings": 3, "non_info": 0},
        }
        summary = gb.summarise(rows)
        assert summary["overall"] == {"scored": 3, "detected": 2, "detected_low": 1, "findings": 12, "non_info": 3}
        assert summary["by_category"]["Crypto"]["detected"] == 2
        assert summary["by_category"]["Web"] == {"scored": 1, "detected": 0, "detected_low": 0, "findings": 3, "non_info": 0}
        assert summary["by_category"]["ICC"]["scored"] == 0
