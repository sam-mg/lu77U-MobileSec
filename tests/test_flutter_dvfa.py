#!/usr/bin/env python3
"""
Module: test_flutter_dvfa

Purpose:
    Detection and native-library extraction against a real DVFA Flutter APK.

Responsibilities:
    Cover the front half of the Flutter pipeline, which needs no external tool.

Dependencies:
    The payload extractor, the detector, and the shared fixture locator.

Implementation notes:
    These stop short of running Blutter, which has to be configured separately, so they run whenever a built DVFA APK is present. The full end-to-end Flutter path is verified by hand.
"""

from lu77U_MobileSec.decompiler.apk_payload import (
    available_native_abis, extract_native_libs)
from lu77U_MobileSec.detection.detector import MobileSecurityDetector

from fixtures import DVFA_FLUTTER_APKS, require_fixture


def test_detector_labels_dvfa_as_flutter():
    """
    Purpose:
        Pin that detection identifies a real Flutter app as Flutter.

    Implementation notes:
        A missed Flutter detection is the most costly one this tool can make: the app decompiles cleanly as Java, reports nothing, and reads as safe while the entire application sits unexamined in the Dart snapshot.
    """
    apk = require_fixture(*DVFA_FLUTTER_APKS)
    result = MobileSecurityDetector(verbose=False).detect(str(apk))
    assert result.framework_results.get_primary_framework_name() == "Flutter"


def test_flutter_apk_carries_arm64_libapp(tmp_path):
    """
    Purpose:
        Pin that a real Flutter APK ships the arm64 payload Blutter needs, and that extraction recovers both libraries.

    Parameters:
        tmp_path: Temporary directory the libraries are extracted into.

    Implementation notes:
        Both the Dart snapshot and the engine library are asserted, because Blutter needs the snapshot and the engine library alongside it to resolve the Dart version. Extracting only one produces a run that fails deep inside the tool with an unhelpful error.
    """
    apk = require_fixture(*DVFA_FLUTTER_APKS)
    assert "arm64-v8a" in available_native_abis(str(apk))
    out = extract_native_libs(str(apk), tmp_path / "libs", abis=("arm64-v8a",))
    assert out is not None
    names = {p.name for p in out.iterdir()}
    assert "libapp.so" in names
    assert "libflutter.so" in names
