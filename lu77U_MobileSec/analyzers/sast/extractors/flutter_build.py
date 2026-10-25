#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.flutter_build

Purpose:
    Record, as a deterministic fact, that a Flutter app was shipped as a debug build with its full Dart source.

Responsibilities:
    Recognise the recovered-source layout a debug build produces and emit one finding pointing at the app's own source.

Dependencies:
    The kernel extractor's directory names.

Implementation notes:
    A debug build is decided by the archive, not by reading code, so it should not depend on a model choosing to mention it. It is emitted under BUILD-01 like a debuggable manifest, which the gates treat as a release-process note rather than a standalone vulnerability; what the shipped source reveals -- keys, endpoints, disabled checks in comments -- is what the agent reports separately.
"""

from pathlib import Path
from typing import List

from ..findings import SastFinding
from ....decompiler.dart_kernel import APP_DIR
from ....utils.verbose import plural, verbose_print


def analyze_flutter_build(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Emit the debug-build finding when the analysis root holds recovered Dart source.

    Parameters:
        source_root: The Flutter analysis root.
        verbose: Traces the outcome.

    Returns:
        One finding for a debug build, none otherwise.

    Side effects:
        Lists the recovered source directory.

    Implementation notes:
        The finding cites the app's main.dart when it was recovered, or the first app file otherwise, at line 1, so the report's excerpt shows real recovered source as the evidence that the source shipped.
    """
    app_dir = Path(source_root) / APP_DIR
    if not app_dir.is_dir():
        return []
    files = sorted(app_dir.rglob("*.dart"))
    if not files:
        return []
    main = next((f for f in files if f.name == "main.dart"), files[0])
    rel = main.relative_to(Path(source_root)).as_posix()
    verbose_print(f"Flutter debug build: {plural(len(files), 'app source file')} shipped", verbose)
    return [SastFinding(
        title="Flutter debug build ships the app's full Dart source (kernel_blob.bin)",
        severity="Low", vuln_class="BUILD-01", file=rel, line=1,
        detector="flutter-build",
        description=(
            "The APK is a Flutter debug build: assets/flutter_assets/kernel_blob.bin carries "
            f"the original Dart source of {plural(len(files), 'app file')}, comments included, and "
            "the app runs on the JIT VM with assertions enabled."),
        impact=("Anyone with the APK reads the app's source as written, including comments, "
                "internal endpoints and any logic meant to be hidden."),
        recommendation=("Ship release builds (flutter build apk --release or appbundle), which "
                        "compile Dart ahead of time and do not include kernel_blob.bin."),
        cwe="CWE-489", owasp_mobile="M7: Insufficient Binary Protections")]
