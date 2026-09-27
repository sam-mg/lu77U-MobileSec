#!/usr/bin/env python3
"""
Module: test_cordova_dvhma

Purpose:
    End-to-end Cordova extraction and graph building against a real DVHMA APK.

Responsibilities:
    Prove the Cordova pipeline works on a genuine hybrid app rather than only on synthetic fixtures.

Dependencies:
    The Cordova graph builder, the payload extractor, the detector, and the shared fixture locator.

Implementation notes:
    DVHMA is a real Cordova app cloned under the gitignored etc directory, so these tests run when that APK is present and skip otherwise.
"""

from lu77U_MobileSec.analyzers.cordova.graph import build_cordova_graph
from lu77U_MobileSec.decompiler.apk_payload import extract_cordova_www
from lu77U_MobileSec.detection.detector import MobileSecurityDetector

from fixtures import DVHMA_CORDOVA_APKS, require_fixture


def test_detector_labels_dvhma_as_cordova():
    """
    Purpose:
        Pin that detection identifies a real Cordova app as Cordova and reads its declared package.

    Implementation notes:
        Guards the decision that routes an app to the Cordova analyzer. Misidentifying this app would send it to JADX, which would decompile the thin Java shell and report nothing about the web assets that hold its logic.
    """
    apk = require_fixture(*DVHMA_CORDOVA_APKS)
    result = MobileSecurityDetector(verbose=False).detect(str(apk))
    assert result.framework_results.get_primary_framework_name() == "Cordova"
    assert (result.basic_info.package_name or "").startswith("de.zertapps.dvhma")


def test_extract_and_graph_real_dvhma(tmp_path):
    """
    Purpose:
        Pin that the web assets extract with their structure intact and that the graph keeps the app's own code while dropping the Cordova runtime.

    Parameters:
        tmp_path: Temporary directory the assets are extracted into.

    Implementation notes:
        Three things are checked together because each is worthless alone: that extraction produced the configuration and entry page, that the runtime was filtered out while the app's own scripts survived, and that the plugins reaching the native bridge were flagged. A graph that kept the runtime would bury the application code the agent needs to examine.
    """
    apk = require_fixture(*DVHMA_CORDOVA_APKS)

    out = extract_cordova_www(str(apk), tmp_path / "www")
    assert out is not None
    rels = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    assert "config.xml" in rels
    assert "index.html" in rels

    graph = build_cordova_graph(out)
    assert graph is not None
    files = {n.file for n in graph.nodes.values()}
    assert "cordova.js" not in files
    assert any(f.startswith("js/") for f in files)
    assert graph.flagged_files()
    assert any("cordova_exec" in n.signals or "webintent" in n.signals
               for n in graph.nodes.values())
